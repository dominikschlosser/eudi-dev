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
	"sync/atomic"
	"testing"
)

// grantMismatchIssuer serves an issuer that lists two authorization servers:
// its own, which takes the pre-authorized code grant, and a second one that
// only does authorization_code. The offer names the second for a
// pre-authorized grant, which is the shape a real issuer produced. Its token
// endpoint then refuses in its own error format rather than OAuth's, so the
// error code is the HTTP status text and the reason is only in the body.
//
// namesGrants leaves grant_types_supported off the second server, which
// RFC 8414 §2 allows: then nothing was stated, and the flow proceeds.
func grantMismatchIssuer(t *testing.T, w *Wallet, namesGrants bool) (*httptest.Server, string, *atomic.Int32) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string
	var limitedTokenCalls atomic.Int32

	issueToken := func(rw http.ResponseWriter) {
		json.NewEncoder(rw).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"c_nonce":      "test-c-nonce",
		})
	}

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				// The issuer's own server first, the limited one second, so
				// picking the first entry would have passed by accident.
				"authorization_servers": []any{serverURL, serverURL + "/limited"},
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format":                "dc+sd-jwt",
						"vct":                   "urn:test:credential",
						"proof_types_supported": map[string]any{"jwt": map[string]any{"proof_signing_alg_values_supported": []any{"ES256"}}},
					},
				},
			})

		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server/limited"):
			meta := map[string]any{
				"issuer":                 serverURL + "/limited",
				"token_endpoint":         serverURL + "/limited/token",
				"authorization_endpoint": serverURL + "/limited/authorize",
			}
			if namesGrants {
				meta["grant_types_supported"] = []any{"authorization_code", "refresh_token"}
			}
			json.NewEncoder(rw).Encode(meta)

		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                 serverURL,
				"token_endpoint":         serverURL + "/token",
				"authorization_endpoint": serverURL + "/authorize",
				"grant_types_supported":  []any{"authorization_code", "refresh_token", preAuthorizedCodeGrant},
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/limited/token"):
			limitedTokenCalls.Add(1)
			if !namesGrants {
				issueToken(rw)
				return
			}
			// Not an OAuth 2.0 error response: error carries the HTTP status
			// text and the reason is in a field of the server's own.
			rw.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(rw).Encode(map[string]any{
				"statusCode": 400,
				"message":    `Invalid grant_type, must be "authorization_code" or "refresh_token"`,
				"error":      "Bad Request",
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			issueToken(rw)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			io.Copy(io.Discard, r.Body)
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
			preAuthorizedCodeGrant: map[string]any{
				"pre-authorized_code":  "test-pre-auth-code",
				"authorization_server": serverURL + "/limited",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)), &limitedTokenCalls
}

// findLogEntry returns the first entry with the given event, or nil.
func findLogEntry(entries []LogEntry, event string) *LogEntry {
	for i, e := range entries {
		if e.Details != nil && e.Details["event"] == event {
			return &entries[i]
		}
	}
	return nil
}

// TestProcessCredentialOffer_AuthorizationServerCannotTakeGrant covers an
// offer naming an authorization server that says it does not support the
// grant the offer carries. §4.1.1 defines authorization_server as the one to
// use "with this grant type", and §12.2.4 has the wallet read
// grant_types_supported for exactly this, so the mismatch is reported rather
// than left to come back as a refusal from the token endpoint.
func TestProcessCredentialOffer_AuthorizationServerCannotTakeGrant(t *testing.T) {
	t.Run("debug warns and lets the flow run into it", func(t *testing.T) {
		w := generateTestWallet(t)
		srv, offerURI, tokenCalls := grantMismatchIssuer(t, w, true)
		defer srv.Close()

		oldClient := httpClient
		httpClient = srv.Client()
		defer func() { httpClient = oldClient }()

		_, err := w.ProcessCredentialOffer(offerURI)
		if err == nil {
			t.Fatal("expected the token request to be refused")
		}
		if tokenCalls.Load() != 1 {
			t.Errorf("token endpoint called %d times, want 1: debug mode reports and continues", tokenCalls.Load())
		}

		entries := w.GetLog()
		warning := findLogEntry(entries, "authorization_server_grant_unsupported")
		if warning == nil {
			t.Fatal("expected an authorization_server_grant_unsupported entry")
		}
		if warning.Severity != severityWarning {
			t.Errorf("severity = %q, want %q", warning.Severity, severityWarning)
		}
		if !strings.Contains(warning.Detail, preAuthorizedCodeGrant) {
			t.Errorf("detail does not name the grant: %s", warning.Detail)
		}
		if !strings.Contains(warning.Detail, srv.URL+"/limited") {
			t.Errorf("detail does not name the server: %s", warning.Detail)
		}

		// The refusal the server sent, whole. Its own error field is the HTTP
		// status text, so without the body the entry says only "Bad Request".
		var response *LogEntry
		for i := range entries {
			if entries[i].Action == "issuance" && strings.HasPrefix(entries[i].Detail, "Token response from") {
				response = &entries[i]
			}
		}
		if response == nil {
			t.Fatal("expected a token response entry")
		}
		if got := response.Details["status_code"]; got != 400 {
			t.Errorf("status_code = %v, want 400", got)
		}
		body, _ := response.Details["response_body"].(string)
		if !strings.Contains(body, "Invalid grant_type") {
			t.Errorf("response_body does not carry the server's reason: %q", body)
		}
		// The headline stays the refusal itself, so the entry fits on a line.
		if msg, _ := response.Details["error"].(string); msg != "Bad Request" {
			t.Errorf("error = %q, want the refusal code alone", msg)
		}
	})

	t.Run("strict refuses before the code is spent", func(t *testing.T) {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeStrict
		srv, offerURI, tokenCalls := grantMismatchIssuer(t, w, true)
		defer srv.Close()

		oldClient := httpClient
		httpClient = srv.Client()
		defer func() { httpClient = oldClient }()

		_, err := w.ProcessCredentialOffer(offerURI)
		if err == nil {
			t.Fatal("expected the offer to be refused")
		}
		if !strings.Contains(err.Error(), preAuthorizedCodeGrant) {
			t.Errorf("error does not name the grant: %v", err)
		}
		if tokenCalls.Load() != 0 {
			t.Errorf("token endpoint called %d times, want 0: the offer is still redeemable", tokenCalls.Load())
		}
	})

	t.Run("a server stating no grants is not a finding", func(t *testing.T) {
		w := generateTestWallet(t)
		srv, offerURI, _ := grantMismatchIssuer(t, w, false)
		defer srv.Close()

		oldClient := httpClient
		httpClient = srv.Client()
		defer func() { httpClient = oldClient }()

		result, err := w.ProcessCredentialOffer(offerURI)
		if err != nil {
			t.Fatalf("ProcessCredentialOffer: %v", err)
		}
		if result.CredentialID == "" {
			t.Error("expected a credential to be imported")
		}
		if entry := findLogEntry(w.GetLog(), "authorization_server_grant_unsupported"); entry != nil {
			t.Errorf("RFC 8414 §2 makes grant_types_supported optional, so silence is not a finding: %s", entry.Detail)
		}
	})
}
