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
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// txCodeIssuer serves a pre-authorized offer that requires a transaction
// code and refuses any token request that does not carry the right one.
func txCodeIssuer(t *testing.T, w *Wallet, wantCode string) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"token_endpoint":      serverURL + "/token",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential"},
				},
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			switch form.Get("tx_code") {
			case "":
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{
					"error": "invalid_request", "error_description": "Missing required 'tx_code' in request",
				})
			case wantCode:
				json.NewEncoder(rw).Encode(map[string]any{
					"access_token": "test-access-token", "token_type": "Bearer", "c_nonce": "test-c-nonce",
				})
			default:
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{
					"error": "invalid_grant", "error_description": "Invalid 'tx_code' provided",
				})
			}

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	serverURL = srv.URL

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "test-pre-auth-code",
				"tx_code": map[string]any{
					"input_mode":  "numeric",
					"length":      float64(4),
					"description": "The code from your letter",
				},
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
}

// TestApproveRequest_CarriesTxCodeIntoIssuance covers the wallet UI's path: the
// offer arrives with no code, the dialog asks for one, and it reaches the token
// request with the approval.
func TestApproveRequest_CarriesTxCodeIntoIssuance(t *testing.T) {
	w := generateTestWallet(t)
	srv, offerURI := txCodeIssuer(t, w, "1234")
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, nil)

	for _, tc := range []struct {
		name    string
		code    string
		wantErr string
	}{
		{"correct code", "1234", ""},
		{"wrong code", "9999", "Invalid 'tx_code'"},
		{"no code", "", "Missing required 'tx_code'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			consentReq, _, err := prepareIssuanceConsentRequest(offerURI)
			if err != nil {
				t.Fatalf("prepareIssuanceConsentRequest: %v", err)
			}
			// The dialog needs enough to build its input.
			details := consentReq.OfferDetails
			if !details.TxCode {
				t.Fatal("offer details do not report a required transaction code")
			}
			if details.TxCodeInputMode != "numeric" || details.TxCodeLength != 4 {
				t.Errorf("input shape = %q/%d, want numeric/4", details.TxCodeInputMode, details.TxCodeLength)
			}
			if details.TxCodeDescription != "The code from your letter" {
				t.Errorf("description = %q, want the issuer's own wording", details.TxCodeDescription)
			}

			w.CreateConsentRequest(consentReq)
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.awaitOfferConsent(noopResponseWriter{}, consentReq, "test issuer", false, "")
			}()

			consentReq.ResultCh <- ConsentResult{Approved: true, TxCode: tc.code}
			submission := <-consentReq.SubmissionCh
			<-done

			if tc.wantErr == "" {
				if submission.Error != "" {
					t.Fatalf("issuance failed: %s", submission.Error)
				}
				return
			}
			if !strings.Contains(submission.Error, tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", submission.Error, tc.wantErr)
			}
		})
	}
}

// TestDescribeCredentialOffer_TxCodeShape covers the members the dialog needs
// to size and label its input, and the fallback hint when the issuer gives no
// description of its own.
func TestDescribeCredentialOffer_TxCodeShape(t *testing.T) {
	for _, tc := range []struct {
		name      string
		txCode    map[string]any
		wantHint  string
		wantMode  string
		wantLen   int
		wantDescr string
	}{
		{
			name:     "numeric with length",
			txCode:   map[string]any{"input_mode": "numeric", "length": float64(6)},
			wantHint: "6 numeric characters", wantMode: "numeric", wantLen: 6,
		},
		{
			name:      "issuer description wins the hint",
			txCode:    map[string]any{"input_mode": "text", "length": float64(8), "description": "From the letter"},
			wantHint:  "From the letter",
			wantMode:  "text",
			wantLen:   8,
			wantDescr: "From the letter",
		},
		{
			name:     "empty object still requires a code",
			txCode:   map[string]any{},
			wantHint: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offer := &oid4vc.CredentialOffer{
				CredentialIssuer: "https://issuer.invalid",
				Grants:           oid4vc.OfferGrants{PreAuthorizedCode: "code", TxCode: tc.txCode},
			}
			// An empty tx_code object is still a tx_code, but the parser only
			// records a non-empty map, so exercise the describe path directly.
			if len(tc.txCode) == 0 {
				offer.Grants.TxCode = map[string]any{"input_mode": ""}
			}
			details := describeCredentialOffer(offer)
			if !details.TxCode {
				t.Fatal("expected tx_code to be reported as required")
			}
			if details.TxCodeHint != tc.wantHint {
				t.Errorf("hint = %q, want %q", details.TxCodeHint, tc.wantHint)
			}
			if details.TxCodeInputMode != tc.wantMode {
				t.Errorf("input_mode = %q, want %q", details.TxCodeInputMode, tc.wantMode)
			}
			if details.TxCodeLength != tc.wantLen {
				t.Errorf("length = %d, want %d", details.TxCodeLength, tc.wantLen)
			}
			if details.TxCodeDescription != tc.wantDescr {
				t.Errorf("description = %q, want %q", details.TxCodeDescription, tc.wantDescr)
			}
		})
	}
}
