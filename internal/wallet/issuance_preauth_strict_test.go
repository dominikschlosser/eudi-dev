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

// strictPreAuthIssuer serves a pre-authorized_code issuer that requires
// DPoP-bound tokens, client (wallet) attestation, and key attestation in the
// proof. The combination the Animo playground enables by default. Each
// requirement is enforced, so a wallet that omits one gets the same error an
// issuer would send.
func strictPreAuthIssuer(t *testing.T, w *Wallet, requireDPoP, requireClientAttestation, requireKeyAttestation bool) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		writeErr := func(status int, code, desc string) {
			rw.WriteHeader(status)
			json.NewEncoder(rw).Encode(map[string]string{"error": code, "error_description": desc})
		}

		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			jwtProof := map[string]any{"proof_signing_alg_values_supported": []any{"ES256"}}
			if requireKeyAttestation {
				jwtProof["key_attestations_required"] = map[string]any{
					"key_storage":         []any{"iso_18045_high"},
					"user_authentication": []any{"iso_18045_high"},
				}
			}
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"credential_endpoint":   serverURL + "/credential",
				"token_endpoint":        serverURL + "/token",
				"authorization_servers": []any{serverURL},
				// Batch issuance and key attestation together: a jwt proof
				// carrying an attestation has to stay a single entry.
				"batch_credential_issuance": map[string]any{"batch_size": float64(10)},
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format":                "dc+sd-jwt",
						"vct":                   "urn:test:credential",
						"scope":                 "test-config",
						"proof_types_supported": map[string]any{"jwt": jwtProof},
					},
				},
			})

		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			meta := map[string]any{
				"issuer":                                serverURL,
				"token_endpoint":                        serverURL + "/token",
				"authorization_endpoint":                serverURL + "/authorize",
				"pushed_authorization_request_endpoint": serverURL + "/par",
				"require_pushed_authorization_requests": true,
				"code_challenge_methods_supported":      []any{"S256"},
			}
			if requireDPoP {
				meta["dpop_signing_alg_values_supported"] = []any{"ES256"}
			}
			if requireClientAttestation {
				meta["token_endpoint_auth_methods_supported"] = []any{"attest_jwt_client_auth"}
			}
			json.NewEncoder(rw).Encode(meta)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
				writeErr(http.StatusBadRequest, "unsupported_grant_type", form.Get("grant_type"))
				return
			}
			if requireDPoP && r.Header.Get("DPoP") == "" {
				writeErr(http.StatusBadRequest, "invalid_dpop_proof", "DPoP proof is required")
				return
			}
			if requireClientAttestation {
				if r.Header.Get("OAuth-Client-Attestation") == "" || r.Header.Get("OAuth-Client-Attestation-PoP") == "" {
					writeErr(http.StatusBadRequest, "invalid_client", "wallet attestation is required")
					return
				}
			}
			tokenType := "Bearer"
			if requireDPoP {
				tokenType = "DPoP"
			}
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   tokenType,
				"c_nonce":      "test-c-nonce",
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			wantAuth := "Bearer test-access-token"
			if requireDPoP {
				wantAuth = "DPoP test-access-token"
				if r.Header.Get("DPoP") == "" {
					writeErr(http.StatusUnauthorized, "invalid_token", "DPoP proof is required")
					return
				}
			}
			if r.Header.Get("Authorization") != wantAuth {
				writeErr(http.StatusUnauthorized, "invalid_token", "expected "+wantAuth)
				return
			}
			if requireKeyAttestation {
				body, _ := io.ReadAll(r.Body)
				var reqBody map[string]any
				json.Unmarshal(body, &reqBody)
				proofs, _ := reqBody["proofs"].(map[string]any)
				jwts, _ := proofs["jwt"].([]any)
				if len(jwts) == 0 {
					writeErr(http.StatusBadRequest, "invalid_proof", "no proof")
					return
				}
				if len(jwts) != 1 {
					writeErr(http.StatusBadRequest, "invalid_proof",
						"only a single proofs entry is supported when the jwt proof header contains key_attestation")
					return
				}
				header := decodeJWTPart(t, jwts[0].(string), 0)
				attestation, _ := header["key_attestation"].(string)
				if attestation == "" {
					writeErr(http.StatusBadRequest, "invalid_proof", "key attestation is required")
					return
				}
				attHeader := decodeJWTPart(t, attestation, 0)
				if attHeader["typ"] != "key-attestation+jwt" {
					t.Errorf("key attestation typ = %v, want key-attestation+jwt", attHeader["typ"])
				}
				attPayload := decodeJWTPart(t, attestation, 1)
				if attPayload["nonce"] != "test-c-nonce" {
					t.Errorf("key attestation nonce = %v, want test-c-nonce", attPayload["nonce"])
				}
				if keys, _ := attPayload["attested_keys"].([]any); len(keys) != 1 {
					t.Errorf("key attestation attests %d keys, want the single proof key", len(keys))
				}
				for _, claim := range []string{"key_storage", "user_authentication"} {
					values, _ := attPayload[claim].([]any)
					if len(values) != 1 || values[0] != "iso_18045_high" {
						t.Errorf("key attestation %s = %v, want the required [iso_18045_high]", claim, attPayload[claim])
					}
				}
			}
			json.NewEncoder(rw).Encode(map[string]any{"credential": credRaw})

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
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
}

// TestProcessCredentialOffer_PreAuthHonorsIssuerProtections covers the
// pre-authorized code flow against an issuer that requires DPoP, wallet
// attestation, and key attestation. The flow used to send none of them, so
// only an issuer with all three turned off could issue to this wallet.
func TestProcessCredentialOffer_PreAuthHonorsIssuerProtections(t *testing.T) {
	for _, tc := range []struct {
		name                                               string
		requireDPoP, requireClientAttest, requireKeyAttest bool
	}{
		{"all", true, true, true},
		{"dpop only", true, false, false},
		{"client attestation only", false, true, false},
		{"key attestation only", false, false, true},
		{"none", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			srv, offerURI := strictPreAuthIssuer(t, w, tc.requireDPoP, tc.requireClientAttest, tc.requireKeyAttest)
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
		})
	}
}

// TestIssuanceProofKeys_KeyAttestationKeepsOneProof covers batch issuance and
// key attestation meeting: the attestation stands for the key that signed its
// proof, so the batch has to collapse to a single entry.
func TestIssuanceProofKeys_KeyAttestationKeepsOneProof(t *testing.T) {
	holder := testKey(t)
	metadata := map[string]any{
		"batch_credential_issuance": map[string]any{"batch_size": float64(10)},
		"credential_configurations_supported": map[string]any{
			"attested": map[string]any{
				"proof_types_supported": map[string]any{
					"jwt": map[string]any{"key_attestations_required": map[string]any{}},
				},
			},
			"plain": map[string]any{
				"proof_types_supported": map[string]any{"jwt": map[string]any{}},
			},
		},
	}

	keys, err := issuanceProofKeys(holder, metadata, "attested")
	if err != nil {
		t.Fatalf("issuanceProofKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("key attestation config produced %d proof keys, want 1", len(keys))
	}

	keys, err = issuanceProofKeys(holder, metadata, "plain")
	if err != nil {
		t.Fatalf("issuanceProofKeys: %v", err)
	}
	if len(keys) != batchProofKeyCount {
		t.Errorf("plain config produced %d proof keys, want %d", len(keys), batchProofKeyCount)
	}
}

// TestAccessTokenScheme covers the Authorization scheme a token response
// implies. RFC 9449 §5 marks a DPoP-bound token with token_type "DPoP".
func TestAccessTokenScheme(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resp     map[string]any
		sentDPoP bool
		want     string
	}{
		{"dpop token", map[string]any{"token_type": "DPoP"}, true, "DPoP"},
		{"dpop token lowercase", map[string]any{"token_type": "dpop"}, true, "DPoP"},
		{"bearer token", map[string]any{"token_type": "Bearer"}, false, "Bearer"},
		{"server ignored the proof", map[string]any{"token_type": "Bearer"}, true, "Bearer"},
		{"omitted after a proof", map[string]any{}, true, "DPoP"},
		{"omitted without a proof", map[string]any{}, false, "Bearer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := accessTokenScheme(tc.resp, tc.sentDPoP); got != tc.want {
				t.Errorf("accessTokenScheme = %q, want %q", got, tc.want)
			}
		})
	}
}
