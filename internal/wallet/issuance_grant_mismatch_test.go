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

// grantMismatchIssuer serves an issuer that advertises three authorization
// servers: one whose metadata is unreachable, its own, and a limited one that
// only does authorization_code. The offer names the limited one for a
// pre-authorized grant, the shape a real issuer produced. The limited token
// endpoint refuses in its own error format, so the error code is the HTTP
// status text and the reason is only in the body.
//
// limitedNamesGrants leaves grant_types_supported off the limited server,
// which RFC 8414 §2 allows: then nothing was stated, and the flow proceeds.
// ownStatesPreAuth controls whether the issuer's own server states support
// for the pre-authorized code grant, making it a fallback candidate.
func grantMismatchIssuer(t *testing.T, w *Wallet, limitedNamesGrants, ownStatesPreAuth bool) (*httptest.Server, string, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string
	var limitedTokenCalls, ownTokenCalls atomic.Int32

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
				// The unreachable server sits first, so the fallback has to
				// skip past it to reach the issuer's own.
				"authorization_servers": []any{serverURL + "/down", serverURL, serverURL + "/limited"},
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
			if limitedNamesGrants {
				meta["grant_types_supported"] = []any{"authorization_code", "refresh_token"}
			}
			json.NewEncoder(rw).Encode(meta)

		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			meta := map[string]any{
				"issuer":                 serverURL,
				"token_endpoint":         serverURL + "/token",
				"authorization_endpoint": serverURL + "/authorize",
			}
			if ownStatesPreAuth {
				meta["grant_types_supported"] = []any{"authorization_code", "refresh_token", preAuthorizedCodeGrant}
			}
			json.NewEncoder(rw).Encode(meta)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/limited/token"):
			limitedTokenCalls.Add(1)
			if !limitedNamesGrants {
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
			ownTokenCalls.Add(1)
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
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)), &limitedTokenCalls, &ownTokenCalls
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
// grant_types_supported for exactly this. In debug mode the wallet then
// moves to an advertised server that states support for the grant.
func TestProcessCredentialOffer_AuthorizationServerCannotTakeGrant(t *testing.T) {
	t.Run("debug falls back to an advertised server that states the grant", func(t *testing.T) {
		w := generateTestWallet(t)
		srv, offerURI, limitedTokenCalls, ownTokenCalls := grantMismatchIssuer(t, w, true, true)
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
		if ownTokenCalls.Load() != 1 {
			t.Errorf("issuer's own token endpoint called %d times, want 1", ownTokenCalls.Load())
		}
		if limitedTokenCalls.Load() != 0 {
			t.Errorf("limited token endpoint called %d times, want 0", limitedTokenCalls.Load())
		}

		entries := w.GetLog()
		warning := findLogEntry(entries, "authorization_server_grant_unsupported")
		if warning == nil {
			t.Fatal("expected an authorization_server_grant_unsupported entry")
		}
		if warning.Severity != severityWarning {
			t.Errorf("severity = %q, want %q", warning.Severity, severityWarning)
		}

		fallback := findLogEntry(entries, "authorization_server_fallback")
		if fallback == nil {
			t.Fatal("expected an authorization_server_fallback entry")
		}
		if fallback.Severity != severityWarning {
			t.Errorf("severity = %q, want %q", fallback.Severity, severityWarning)
		}
		if !strings.Contains(fallback.Detail, srv.URL) || !strings.Contains(fallback.Detail, srv.URL+"/limited") {
			t.Errorf("detail does not name both servers: %s", fallback.Detail)
		}
		if !strings.Contains(fallback.Detail, preAuthorizedCodeGrant) {
			t.Errorf("detail does not name the grant: %s", fallback.Detail)
		}
	})

	t.Run("debug proceeds at the named server when nothing else states the grant", func(t *testing.T) {
		w := generateTestWallet(t)
		srv, offerURI, limitedTokenCalls, ownTokenCalls := grantMismatchIssuer(t, w, true, false)
		defer srv.Close()

		oldClient := httpClient
		httpClient = srv.Client()
		defer func() { httpClient = oldClient }()

		_, err := w.ProcessCredentialOffer(offerURI)
		if err == nil {
			t.Fatal("expected the token request to be refused")
		}
		if limitedTokenCalls.Load() != 1 {
			t.Errorf("limited token endpoint called %d times, want 1: debug mode reports and continues", limitedTokenCalls.Load())
		}
		if ownTokenCalls.Load() != 0 {
			t.Errorf("issuer's own token endpoint called %d times, want 0", ownTokenCalls.Load())
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

		unavailable := findLogEntry(entries, "authorization_server_fallback_unavailable")
		if unavailable == nil {
			t.Fatal("expected an authorization_server_fallback_unavailable entry")
		}
		if unavailable.Severity != severityWarning {
			t.Errorf("severity = %q, want %q", unavailable.Severity, severityWarning)
		}
		if !strings.Contains(unavailable.Detail, preAuthorizedCodeGrant) {
			t.Errorf("detail does not name the grant: %s", unavailable.Detail)
		}

		// The refusal the server sent, whole. Its own error field is the HTTP
		// status text, and the reason is in a message member next to it.
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
		// The headline carries the code and the sentence that explains it, the
		// way an error_description would be read, and the rest of the body
		// stays in the details. "Bad Request" alone names nothing.
		msg, _ := response.Details["error"].(string)
		if !strings.HasPrefix(msg, "Bad Request: ") || !strings.Contains(msg, "Invalid grant_type") {
			t.Errorf("error = %q, want the refusal code and the server's reason", msg)
		}
	})

	t.Run("strict refuses before the code is spent", func(t *testing.T) {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeStrict
		srv, offerURI, limitedTokenCalls, ownTokenCalls := grantMismatchIssuer(t, w, true, true)
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
		if limitedTokenCalls.Load() != 0 {
			t.Errorf("limited token endpoint called %d times, want 0: the offer is still redeemable", limitedTokenCalls.Load())
		}
		if ownTokenCalls.Load() != 0 {
			t.Errorf("issuer's own token endpoint called %d times, want 0: the offer is still redeemable", ownTokenCalls.Load())
		}
	})

	t.Run("a server stating no grants is not a finding", func(t *testing.T) {
		w := generateTestWallet(t)
		srv, offerURI, _, _ := grantMismatchIssuer(t, w, false, true)
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
			t.Errorf("a server stating no grant_types_supported has said nothing, so it is not a finding: %s", entry.Detail)
		}
	})
}

// TestFallbackAuthorizationServer_SingleAdvertisedServer pins that the
// fallback handles any number of advertised servers: with a single entry
// there is no candidate, so the wallet says so and stays.
func TestFallbackAuthorizationServer_SingleAdvertisedServer(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{"authorization_servers": []any{"https://as.example"}}
	oauthMeta := map[string]any{"grant_types_supported": []any{"authorization_code"}}
	if _, _, ok := w.fallbackAuthorizationServer(metadata, "https://as.example", oauthMeta, preAuthorizedCodeGrant); ok {
		t.Fatal("a single advertised server leaves no candidate to move to")
	}
	if findLogEntry(w.GetLog(), "authorization_server_fallback_unavailable") == nil {
		t.Error("expected an authorization_server_fallback_unavailable entry")
	}
}
