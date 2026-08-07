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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestAttestsClient covers the decision to authenticate with the wallet
// attestation. The authorization server metadata is the signal the
// specification defines, and the override exists because advertising it is
// only a SHOULD (draft-ietf-oauth-attestation-based-client-auth §8, §10.1).
func TestAttestsClient(t *testing.T) {
	advertised := map[string]any{
		"token_endpoint_auth_methods_supported": []any{"attest_jwt_client_auth"},
	}
	silent := map[string]any{
		"token_endpoint": "https://issuer.invalid/token",
	}
	otherMethod := map[string]any{
		"token_endpoint_auth_methods_supported": []any{"client_secret_post"},
	}

	for _, tc := range []struct {
		name  string
		meta  map[string]any
		haip  bool
		force bool
		want  bool
	}{
		{"advertised", advertised, false, false, true},
		{"silent metadata", silent, false, false, false},
		{"silent metadata, override on", silent, false, true, true},
		{"another method", otherMethod, false, false, false},
		{"another method, override on", otherMethod, false, true, true},
		{"no metadata at all", nil, false, false, false},
		// HAIP 1.0 §4.4.1 makes client authentication unconditional, so a
		// wallet enforcing it never needs the metadata or the override.
		{"haip, silent metadata", silent, true, false, true},
		{"haip, no metadata at all", nil, true, false, true},
		{"haip, another method", otherMethod, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &Wallet{RequireHAIP: tc.haip, ForceClientAttestation: tc.force}
			if got := w.attestsClient(tc.meta); got != tc.want {
				t.Errorf("attestsClient = %v, want %v", got, tc.want)
			}
		})
	}
}

// silentAttestationIssuer serves an issuer that requires client attestation on
// its token endpoint while advertising nothing about it. A wallet that reads
// only the metadata is right to send none, so this issuer is unreachable
// without the override.
func silentAttestationIssuer(t *testing.T, w *Wallet) (*httptest.Server, string, *int) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string
	attestedRequests := 0

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"credential_endpoint":   serverURL + "/credential",
				"token_endpoint":        serverURL + "/token",
				"authorization_servers": []any{serverURL},
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential"},
				},
			})

		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			// No token_endpoint_auth_methods_supported, and it even claims the
			// pre-authorized grant takes anonymous access.
			json.NewEncoder(rw).Encode(map[string]any{
				"issuer":         serverURL,
				"token_endpoint": serverURL + "/token",
				"pre-authorized_grant_anonymous_access_supported": true,
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			attestation := r.Header.Get("OAuth-Client-Attestation")
			pop := r.Header.Get("OAuth-Client-Attestation-PoP")
			if attestation == "" || pop == "" {
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{
					"error":             "invalid_client",
					"error_description": "Missing required client attestation parameters",
				})
				return
			}
			attestedRequests++
			if typ := decodeJWTPart(t, attestation, 0)["typ"]; typ != "oauth-client-attestation+jwt" {
				t.Errorf("attestation typ = %v, want oauth-client-attestation+jwt", typ)
			}
			if typ := decodeJWTPart(t, pop, 0)["typ"]; typ != "oauth-client-attestation-pop+jwt" {
				t.Errorf("PoP typ = %v, want oauth-client-attestation-pop+jwt", typ)
			}
			if aud := decodeJWTPart(t, pop, 1)["aud"]; aud != serverURL {
				t.Errorf("PoP aud = %v, want the authorization server %q", aud, serverURL)
			}
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token", "token_type": "Bearer", "c_nonce": "test-c-nonce",
			})

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
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)), &attestedRequests
}

// TestForceClientAttestation_ReachesSilentIssuer covers the override end to
// end: off, the wallet correctly sends nothing and the issuer refuses. On, the
// attestation goes out and the credential is issued.
func TestForceClientAttestation_ReachesSilentIssuer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		force   bool
		wantErr string
	}{
		{"off by default", false, "invalid_client"},
		{"forced on", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.ForceClientAttestation = tc.force
			srv, offerURI, attested := silentAttestationIssuer(t, w)
			defer srv.Close()

			oldClient := httpClient
			httpClient = srv.Client()
			defer func() { httpClient = oldClient }()

			_, err := w.ProcessCredentialOffer(offerURI)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
				}
				if *attested != 0 {
					t.Errorf("wallet attested %d times with the override off, want 0", *attested)
				}
				return
			}
			if err != nil {
				t.Fatalf("ProcessCredentialOffer: %v", err)
			}
			if *attested != 1 {
				t.Errorf("issuer saw %d attested token requests, want 1", *attested)
			}
		})
	}
}

// TestForceClientAttestation_DoesNotDisplacePrivateKeyJWT covers an
// authorization server that authenticates its clients with private_key_jwt:
// the client assertion already authenticates the request, so the override must
// not add an attestation the server never asked for.
func TestForceClientAttestation_DoesNotDisplacePrivateKeyJWT(t *testing.T) {
	w := generateTestWallet(t)
	w.ForceClientAttestation = true
	meta := map[string]any{
		"token_endpoint_auth_methods_supported": []any{"private_key_jwt"},
	}
	if method := detectTokenEndpointAuthMethod(meta); method != "private_key_jwt" {
		t.Fatalf("detected %q, want private_key_jwt", method)
	}
	// attestsClient is true under the override, so the authorization code path
	// guards on the detected method as well. This documents that pairing.
	if !w.attestsClient(meta) {
		t.Error("override should make attestsClient true even for private_key_jwt metadata")
	}
}
