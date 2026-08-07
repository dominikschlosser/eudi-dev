// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wallet

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// captureVerifier stands in for a verifier waiting on its response_uri. Every
// refusal the wallet decides on has to arrive here: OpenID4VP 1.0 §5.6 says
// "Both successful and error responses SHOULD be returned using the supplied
// Response Mode, or if none is supplied, using the default Response Mode", and
// a verifier told nothing waits until it times out.
type captureVerifier struct {
	*httptest.Server
	mu   sync.Mutex
	form url.Values
}

func newCaptureVerifier(t *testing.T) *captureVerifier {
	t.Helper()
	cv := &captureVerifier{}
	cv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parsed, _ := url.ParseQuery(string(body))
		cv.mu.Lock()
		cv.form = parsed
		cv.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(cv.Close)
	return cv
}

func (cv *captureVerifier) received(t *testing.T) url.Values {
	t.Helper()
	cv.mu.Lock()
	defer cv.mu.Unlock()
	if cv.form == nil {
		t.Fatal("verifier received no authorization response at its response_uri")
	}
	return cv.form
}

func authorizeRequest(t *testing.T, srv *Server, params url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	return rec
}

func dcqlQueryParam(t *testing.T, query map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(query)
	if err != nil {
		t.Fatalf("marshaling dcql query: %v", err)
	}
	return string(encoded)
}

// §8.5 access_denied: "The Wallet did not have the requested Credentials to
// satisfy the Authorization Request."
func TestNoMatchingCredentialsReturnsAccessDeniedToTheVerifier(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newCaptureVerifier(t)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"state":         {"s"},
		"response_uri":  {verifier.URL},
		"dcql_query": {dcqlQueryParam(t, map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "nothing",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{"urn:nobody:holds:this"}},
				},
			},
		})},
	}

	rec := authorizeRequest(t, srv, params)

	form := verifier.received(t)
	if got := form.Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want access_denied", got)
	}
	if got := form.Get("state"); got != "s" {
		t.Fatalf("verifier received state %q, want s", got)
	}

	// The local caller still learns what happened.
	if rec.Code != http.StatusOK {
		t.Fatalf("local caller got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	local := decodeJSON(t, rec)
	if local["status"] != "no_match" {
		t.Fatalf("local status %v, want no_match", local["status"])
	}
	if local["error_code"] != "access_denied" {
		t.Fatalf("local error_code %v, want access_denied", local["error_code"])
	}
}

// §8.5 vp_formats_not_supported: "The Wallet does not support any of the
// formats requested by the Verifier". A query naming only a format the wallet
// cannot present never reached the stored credentials at all, so the holdings
// are not the reason and access_denied would misreport it.
func TestAQueryForAnUnsupportedFormatReturnsVPFormatsNotSupported(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newCaptureVerifier(t)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"response_uri":  {verifier.URL},
		"dcql_query": {dcqlQueryParam(t, map[string]any{
			"credentials": []any{
				map[string]any{"id": "ldp", "format": "ldp_vc"},
			},
		})},
	}

	authorizeRequest(t, srv, params)

	if got := verifier.received(t).Get("error"); got != "vp_formats_not_supported" {
		t.Fatalf("verifier received error %q, want vp_formats_not_supported", got)
	}
}

// A request that fails validation names a response endpoint the wallet has no
// reason to trust. §8.5 says the error response "follows the rules as defined
// in [RFC6749]", and RFC 6749 §4.1.2.1 is explicit about this case: the server
// "SHOULD inform the resource owner of the error and MUST NOT automatically
// redirect the user-agent to the invalid redirection URI". So nothing is sent
// to the verifier and the caller is told instead.
func TestValidationFailuresAreNotSentToTheVerifier(t *testing.T) {
	tests := []struct {
		name      string
		params    func(responseURI string) url.Values
		wantLocal string
	}{
		{
			name: "a response type the wallet cannot serve",
			params: func(responseURI string) url.Values {
				return url.Values{
					"client_id":     {"https://verifier.example"},
					"response_type": {"not_a_response_type"},
					"response_mode": {"direct_post"},
					"nonce":         {"n"},
					"state":         {"s"},
					"response_uri":  {responseURI},
				}
			},
			wantLocal: "invalid_request",
		},
		{
			name: "a request_uri_method that is neither get nor post",
			params: func(responseURI string) url.Values {
				return url.Values{
					"client_id":          {"https://verifier.example"},
					"response_type":      {"vp_token"},
					"response_mode":      {"direct_post"},
					"nonce":              {"n"},
					"state":              {"s"},
					"response_uri":       {responseURI},
					"request_uri":        {"https://verifier.example/req"},
					"request_uri_method": {"PATCH"},
				}
			},
			// This path answers before the request is built, so it names the
			// parameter rather than the §8.5 code.
			wantLocal: "request_uri_method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, true)
			verifier := newCaptureVerifier(t)

			rec := authorizeRequest(t, srv, tt.params(verifier.URL))

			if got := verifier.form; got != nil {
				t.Errorf("the verifier was contacted with %v, want nothing sent to an unvalidated request's endpoint", got)
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("local status = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantLocal) {
				t.Errorf("local body = %s, want it to name %s", rec.Body.String(), tt.wantLocal)
			}
		})
	}
}

// A profile violation is found while validating the request, so it falls under
// the same rule: the counterparty is not told through an endpoint the wallet
// has not been able to validate.
func TestAHAIPViolationIsNotSentToTheVerifier(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.RequireHAIP = true
	srv.wallet.ValidationMode = ValidationModeStrict
	verifier := newCaptureVerifier(t)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"state":         {"s"},
		"response_uri":  {verifier.URL},
		"dcql_query": {dcqlQueryParam(t, map[string]any{
			"credentials": []any{
				map[string]any{"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{}},
			},
		})},
	}

	rec := authorizeRequest(t, srv, params)

	if got := verifier.form; got != nil {
		t.Errorf("the verifier was contacted with %v, want nothing sent", got)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("local status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

func TestPresentationAPINoMatchReportsAccessDeniedToTheVerifier(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newCaptureVerifier(t)

	query := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"state":         {"s"},
		"response_uri":  {verifier.URL},
		"dcql_query": {dcqlQueryParam(t, map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "nothing",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{"urn:nobody:holds:this"}},
				},
			},
		})},
	}
	body, err := json.Marshal(map[string]any{"uri": "openid4vp://authorize?" + query.Encode()})
	if err != nil {
		t.Fatalf("marshaling body: %v", err)
	}

	rec := serverRequest(t, srv, "POST", "/api/presentations", string(body))

	if got := verifier.received(t).Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want access_denied", got)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("local caller got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if local := decodeJSON(t, rec); local["status"] != "no_match" {
		t.Fatalf("local status %v, want no_match", local["status"])
	}
}

func dcAPIRefusal(t *testing.T, srv *Server, request map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"digital": map[string]any{
			"requests": []any{
				map[string]any{"protocol": BrowserAPIProtocolOpenID4VPUnsigned, "data": request},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshaling browser request: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://rp.example")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Digital Credentials API caller got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	result := decodeJSON(t, rec)
	data, ok := result["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected a data object in the browser result, got %T", result["data"])
	}
	return data
}

// Appendix A.4: "Protocol error responses are returned as an object within the
// data property. This object has a single property with the name error and a
// value containing the error response code as defined in Section 8.5."
func TestDCAPIErrorObjectCarriesOnlyTheErrorCode(t *testing.T) {
	srv := newTestServer(t, true)

	data := dcAPIRefusal(t, srv, map[string]any{
		"response_type": "vp_token",
		"response_mode": "dc_api",
		"nonce":         "browser-nonce",
		"state":         "browser-state",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "nothing",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{"urn:nobody:holds:this"}},
				},
			},
		},
	})

	if data["error"] != "access_denied" {
		t.Fatalf("error object carried %v, want access_denied", data["error"])
	}
	if len(data) != 1 {
		t.Fatalf("error object has %d members, want exactly one: %#v", len(data), data)
	}
}

// The same door, a malformed request instead of an empty wallet.
func TestDCAPIMalformedRequestReturnsAnErrorObject(t *testing.T) {
	srv := newTestServer(t, true)

	data := dcAPIRefusal(t, srv, map[string]any{
		"response_type": "not_a_response_type",
		"response_mode": "dc_api",
		"nonce":         "browser-nonce",
		"state":         "browser-state",
	})

	if data["error"] != "invalid_request" {
		t.Fatalf("error object carried %v, want invalid_request", data["error"])
	}
	if len(data) != 1 {
		t.Fatalf("error object has %d members, want exactly one: %#v", len(data), data)
	}
}

// OID4VP 1.0 Appendix A.4: "Protocol error responses are returned as an object
// within the data property. This object has a single property with the name
// error and a value containing the error response code as defined in Section
// 8.5." That holds for dc_api.jwt too. A Verifier that asked for an encrypted
// response and receives a JWE where the error object belongs reads a response
// rather than a refusal, which is how a wallet that correctly rejected a
// request looks like one that answered it.
func TestDCAPIErrorIsNotEncryptedUnderTheEncryptedResponseMode(t *testing.T) {
	w := generateTestWallet(t)
	params := PresentationParams{
		ResponseMode:   "dc_api.jwt",
		RequestOrigin:  "https://verifier.example",
		ClientMetadata: map[string]any{},
	}

	response, err := w.BuildAuthorizationErrorResponse("invalid_request", "nonce is required", "some-state", params)
	if err != nil {
		t.Fatalf("BuildAuthorizationErrorResponse: %v", err)
	}
	if response.ResponseJWT != "" {
		t.Errorf("the error was encrypted: %s", response.ResponseJWT)
	}
	if got := response.Plain["error"]; got != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", got)
	}

	result, err := BuildBrowserAPIResult(BrowserAPIProtocolOpenID4VPUnsigned, response)
	if err != nil {
		t.Fatalf("BuildBrowserAPIResult: %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("data = %#v, want an object", result.Data)
	}
	if len(data) != 1 {
		t.Errorf("the error object has %d members, want exactly one: %v", len(data), data)
	}
	if data["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", data["error"])
	}
	if _, encrypted := data["response"]; encrypted {
		t.Error("the error object carries an encrypted response")
	}
}
