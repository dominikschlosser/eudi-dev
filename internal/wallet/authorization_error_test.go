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

// §8.5 collects the malformed-request cases under invalid_request. A request
// the wallet refuses to act on is one the verifier is still waiting for.
func TestAMalformedRequestReturnsInvalidRequestToTheVerifier(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newCaptureVerifier(t)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"not_a_response_type"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"state":         {"s"},
		"response_uri":  {verifier.URL},
	}

	rec := authorizeRequest(t, srv, params)

	form := verifier.received(t)
	if got := form.Get("error"); got != "invalid_request" {
		t.Fatalf("verifier received error %q, want invalid_request", got)
	}
	if got := form.Get("state"); got != "s" {
		t.Fatalf("verifier received state %q, want s", got)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("local caller got %d, want 400", rec.Code)
	}
}

// §8.5 invalid_request_uri_method: "The value of the request_uri_method
// request parameter is neither get nor post (case-sensitive)."
func TestABadRequestURIMethodReturnsItsOwnErrorCodeToTheVerifier(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newCaptureVerifier(t)

	params := url.Values{
		"client_id":          {"https://verifier.example"},
		"response_type":      {"vp_token"},
		"response_mode":      {"direct_post"},
		"nonce":              {"n"},
		"state":              {"s"},
		"response_uri":       {verifier.URL},
		"request_uri":        {"https://verifier.example/request"},
		"request_uri_method": {"PUT"},
	}

	rec := authorizeRequest(t, srv, params)

	if got := verifier.received(t).Get("error"); got != "invalid_request_uri_method" {
		t.Fatalf("verifier received error %q, want invalid_request_uri_method", got)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("local caller got %d, want 400", rec.Code)
	}
}

// §8.5 invalid_transaction_data covers a transaction_data object that
// "contains an unknown or unsupported transaction data type value". This
// wallet supports no type, so every object in the structure is unsupported.
func TestUnsupportedTransactionDataReturnsInvalidTransactionDataToTheVerifier(t *testing.T) {
	srv := newStrictTestServer(t, true)
	verifier := newCaptureVerifier(t)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"state":         {"s"},
		"response_uri":  {verifier.URL},
		"transaction_data": {dcqlQueryParam(t, map[string]any{
			"type": "urn:example:unknown",
		})},
	}

	rec := authorizeRequest(t, srv, params)

	if got := verifier.received(t).Get("error"); got != "invalid_transaction_data" {
		t.Fatalf("verifier received error %q, want invalid_transaction_data", got)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("local caller got %d, want 400", rec.Code)
	}
}

// A profile violation is a request the wallet will not act on, which §8.5
// makes an invalid_request the verifier is owed.
func TestAHAIPViolationIsReportedToTheVerifier(t *testing.T) {
	srv := newTestServer(t, true)
	// --haip decides that the profile checks run, the mode decides that a
	// violation refuses the request rather than being reported.
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
				map[string]any{"id": "pid", "format": "dc+sd-jwt"},
			},
		})},
	}

	rec := authorizeRequest(t, srv, params)

	if got := verifier.received(t).Get("error"); got != "invalid_request" {
		t.Fatalf("verifier received error %q, want invalid_request", got)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("local caller got %d, want 400", rec.Code)
	}
}

// The presentation API is a second door onto the same flow, so a refusal
// reached through it owes the verifier the same response.
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
