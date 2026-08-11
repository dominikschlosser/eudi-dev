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
)

// setupNoneAuthIssuer mimics a real-world issuer (the Procivis One trial) that
// advertises token_endpoint_auth_methods_supported = ["none"]: it authenticates
// no client at the token endpoint. It also advertises a DPoP algorithm and hands
// out Bearer tokens, and it resolves its token endpoint through separate
// Authorization Server metadata rather than a token_endpoint in the issuer
// metadata, all as that issuer does.
//
// Its token endpoint answers invalid_request whenever a request carries client
// authentication it did not ask for (an OAuth-Client-Attestation header), the
// way an authorization server that only offers "none" rejects a request that
// authenticates anyway. gotAttestation records whether the wallet sent one.
func setupNoneAuthIssuer(t *testing.T, w *Wallet, gotAttestation *bool) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)

	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"nonce_endpoint":        serverURL + "/nonce",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"vct":    "urn:test:credential",
					},
				},
			})

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                serverURL,
				"token_endpoint":                        serverURL + "/token",
				"authorization_endpoint":                serverURL + "/authorize",
				"token_endpoint_auth_methods_supported": []string{"none"},
				"dpop_signing_alg_values_supported":     []string{"ES256"},
				"grant_types_supported":                 []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/token"):
			if r.Header.Get("OAuth-Client-Attestation") != "" {
				if gotAttestation != nil {
					*gotAttestation = true
				}
				// The server offered only "none". A client that authenticates
				// with an attestation it never asked for is a malformed request.
				rw.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_request"})
				return
			}
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
				rw.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(rw).Encode(map[string]string{"error": "unsupported_grant_type"})
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/nonce"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "nonce-from-endpoint"})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/credential"):
			if r.Header.Get("Authorization") == "" {
				rw.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_token"})
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credentials": []any{map[string]any{"credential": credRaw}},
			})

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
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
	return srv, offerURI
}

// TestProcessCredentialOffer_HAIPForcesAttestationAgainstNoneAuthIssuer
// reproduces the failure seen against the Procivis One trial issuer: with HAIP
// on, the wallet authenticates at the token endpoint with a wallet attestation
// (HAIP 1.0 §4.4.1 is unconditional about it), but that issuer offers only the
// "none" method and rejects the unexpected client authentication with
// invalid_request. The surfaced error is "token exchange: invalid_request".
//
// The point is that HAIP, not the validation mode, forces the attestation:
// attestsClient returns true whenever RequireHAIP is set, whatever the
// authorization server advertises. Debug mode does not relax it. Turning HAIP
// off is what lets a non-HAIP issuer complete the flow.
func TestProcessCredentialOffer_HAIPForcesAttestationAgainstNoneAuthIssuer(t *testing.T) {
	t.Run("HAIP on: attestation forced, issuer rejects it", func(t *testing.T) {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeDebug
		w.RequireHAIP = true
		w.IssuerURL = "https://wallet.example"
		w.BaseURL = "https://wallet.example"

		sentAttestation := false
		srv, offerURI := setupNoneAuthIssuer(t, w, &sentAttestation)
		defer srv.Close()

		oldClient := httpClient
		httpClient = srv.Client()
		defer func() { httpClient = oldClient }()

		_, err := w.ProcessCredentialOffer(offerURI)
		if err == nil {
			t.Fatal("expected issuance to fail against a none-auth issuer under HAIP")
		}
		if !strings.Contains(err.Error(), "token exchange") || !strings.Contains(err.Error(), "invalid_request") {
			t.Fatalf("expected a token exchange invalid_request error, got %v", err)
		}
		if !sentAttestation {
			t.Fatal("expected the wallet to send a client attestation the issuer never asked for")
		}
	})

	t.Run("HAIP off: no attestation, issuance completes", func(t *testing.T) {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeDebug
		w.RequireHAIP = false

		sentAttestation := false
		srv, offerURI := setupNoneAuthIssuer(t, w, &sentAttestation)
		defer srv.Close()

		oldClient := httpClient
		httpClient = srv.Client()
		defer func() { httpClient = oldClient }()

		result, err := w.ProcessCredentialOffer(offerURI)
		if err != nil {
			t.Fatalf("expected issuance to complete with HAIP off, got %v", err)
		}
		if sentAttestation {
			t.Fatal("wallet must not authenticate at a none-auth token endpoint when HAIP is off")
		}
		if result == nil || result.CredentialID == "" {
			t.Fatal("expected a credential to be imported")
		}
	})
}
