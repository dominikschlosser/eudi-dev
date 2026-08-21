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
	"slices"
	"sort"
	"strings"
	"testing"
)

// abcaIssuerConfig shapes the authorization server a test wallet talks to:
// which client authentication methods and proof of possession methods its
// metadata advertises, whether it advertises DPoP, and whether the token
// endpoint opens with a challenge demand.
type abcaIssuerConfig struct {
	authMethods []string
	// popMethods is client_attestation_pop_methods_supported; nil omits the
	// parameter, which is what a draft-07 or draft-08 server publishes.
	popMethods []string
	dpop       bool
	// requireCombined refuses a token request that carries a dedicated PoP
	// header or lacks the attestation, the way a dpop_combined-only server
	// does.
	requireCombined bool
	// requireAttestation refuses a token request that lacks the
	// OAuth-Client-Attestation header.
	requireAttestation bool
	// challengeValue makes the token endpoint demand a server-provided
	// challenge: the first request is answered with use_attestation_challenge
	// and this value in the OAuth-Client-Attestation-Challenge header, and
	// only a PoP carrying it in the challenge claim is accepted.
	challengeValue string
	// refuseFirstAsStale answers the first token request with
	// use_fresh_attestation, the error a server uses for an attestation it
	// deems too old (§6.2).
	refuseFirstAsStale bool
}

// abcaCapture records what the token endpoint saw, JWT by JWT.
type abcaCapture struct {
	tokenRequests int
	attestations  []string
	pops          []string
	dpops         []string
}

// abcaTestIssuer serves a pre-authorized code issuer whose ABCA behavior the
// config selects, and records what the wallet sent.
func abcaTestIssuer(t *testing.T, w *Wallet, cfg abcaIssuerConfig) (*httptest.Server, string, *abcaCapture) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string
	capture := &abcaCapture{}

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
			meta := map[string]any{
				"issuer":                                serverURL,
				"token_endpoint":                        serverURL + "/token",
				"token_endpoint_auth_methods_supported": cfg.authMethods,
			}
			if cfg.popMethods != nil {
				meta["client_attestation_pop_methods_supported"] = cfg.popMethods
			}
			if cfg.dpop {
				meta["dpop_signing_alg_values_supported"] = []any{"ES256"}
			}
			json.NewEncoder(rw).Encode(meta)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			capture.tokenRequests++
			attestation := r.Header.Get("OAuth-Client-Attestation")
			pop := r.Header.Get("OAuth-Client-Attestation-PoP")
			dpop := r.Header.Get("DPoP")
			if attestation != "" {
				capture.attestations = append(capture.attestations, attestation)
			}
			if pop != "" {
				capture.pops = append(capture.pops, pop)
			}
			if dpop != "" {
				capture.dpops = append(capture.dpops, dpop)
			}
			refuse := func(code, description string) {
				rw.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(rw).Encode(map[string]string{"error": code, "error_description": description})
			}
			if cfg.requireAttestation && attestation == "" {
				refuse("invalid_client", "client attestation is required")
				return
			}
			if cfg.requireCombined {
				if pop != "" {
					refuse("invalid_client", "this server takes only dpop_combined proofs, not a dedicated PoP JWT")
					return
				}
				if dpop == "" {
					refuse("invalid_client", "dpop_combined needs a DPoP proof")
					return
				}
			}
			if cfg.refuseFirstAsStale && capture.tokenRequests == 1 {
				refuse("use_fresh_attestation", "the client attestation is not fresh enough")
				return
			}
			if cfg.challengeValue != "" {
				challenge := ""
				if pop != "" {
					challenge, _ = decodeJWTPart(t, pop, 1)["challenge"].(string)
				} else if dpop != "" {
					challenge, _ = decodeJWTPart(t, dpop, 1)["challenge"].(string)
				}
				if challenge != cfg.challengeValue {
					rw.Header().Set("OAuth-Client-Attestation-Challenge", cfg.challengeValue)
					rw.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(rw).Encode(map[string]string{"error": "use_attestation_challenge"})
					return
				}
			}
			tokenType := "Bearer"
			if dpop != "" {
				tokenType = "DPoP"
			}
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token", "token_type": tokenType, "c_nonce": "test-c-nonce",
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
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)), capture
}

func runABCAOffer(t *testing.T, w *Wallet, cfg abcaIssuerConfig) (*abcaCapture, error) {
	t.Helper()
	srv, offerURI, capture := abcaTestIssuer(t, w, cfg)
	t.Cleanup(srv.Close)

	oldClient := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = oldClient })

	_, err := w.ProcessCredentialOffer(offerURI)
	return capture, err
}

// TestAttestationShapePerVCIVersion pins the version-exact emission the ADR
// decided: the configured OpenID4VCI version selects the ABCA draft that
// OpenID4VCI version pins (1.0 pins draft-07 per its §14.7, the 1.1 editor
// draft pins draft-08), and the attestation and PoP JWTs carry exactly that
// draft's claims. Draft-07 §5.1/§5.2 require iss in both JWTs; draft-08
// removed iss from both, and neither draft defines exp or nbf for the PoP.
func TestAttestationShapePerVCIVersion(t *testing.T) {
	for _, tc := range []struct {
		version VCIVersion
		wantISS bool
	}{
		{VCIVersion10, true},
		{VCIVersion11, false},
	} {
		t.Run(string(tc.version), func(t *testing.T) {
			w := generateTestWallet(t)
			w.VCIVersion = tc.version
			w.IssuerURL = "https://wallet.example"
			w.VCIClientID = "test-wallet-client"

			capture, err := runABCAOffer(t, w, abcaIssuerConfig{
				authMethods:        []string{"attest_jwt_client_auth"},
				requireAttestation: true,
			})
			if err != nil {
				t.Fatalf("ProcessCredentialOffer: %v", err)
			}
			if len(capture.attestations) != 1 || len(capture.pops) != 1 {
				t.Fatalf("issuer saw %d attestations and %d PoPs, want 1 and 1", len(capture.attestations), len(capture.pops))
			}

			attestation := decodeJWTPart(t, capture.attestations[0], 1)
			pop := decodeJWTPart(t, capture.pops[0], 1)

			if _, present := attestation["iss"]; present != tc.wantISS {
				t.Errorf("attestation iss present = %v, want %v (%v)", present, tc.wantISS, attestation)
			}
			if _, present := pop["iss"]; present != tc.wantISS {
				t.Errorf("PoP iss present = %v, want %v (%v)", present, tc.wantISS, pop)
			}
			if tc.wantISS {
				if attestation["iss"] != "https://wallet.example" {
					t.Errorf("attestation iss = %v, want the wallet's issuer URL", attestation["iss"])
				}
				if pop["iss"] != "test-wallet-client" {
					t.Errorf("PoP iss = %v, want the client_id", pop["iss"])
				}
			}
			wantAttestation := []string{"cnf", "exp", "iat", "sub"}
			wantPoP := []string{"aud", "iat", "jti"}
			if tc.wantISS {
				wantAttestation = []string{"cnf", "exp", "iat", "iss", "nbf", "sub"}
				wantPoP = []string{"aud", "iat", "iss", "jti"}
			}
			if got := sortedKeys(attestation); !slices.Equal(got, wantAttestation) {
				t.Errorf("attestation claims = %v, want exactly %v", got, wantAttestation)
			}
			if got := sortedKeys(pop); !slices.Equal(got, wantPoP) {
				t.Errorf("PoP claims = %v, want exactly %v", got, wantPoP)
			}
		})
	}
}

// TestCombinedModeAgainstDPoPOnlyServer covers a draft-10 server that offers
// only attest_jwt_client_auth_dpop (§5.2): the DPoP proof is the possession
// proof, so the wallet sends the attestation header and no dedicated PoP. The
// configured version pins an earlier draft, so using the mechanism is warned
// about and still done.
func TestCombinedModeAgainstDPoPOnlyServer(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth_dpop"},
		dpop:               true,
		requireAttestation: true,
		requireCombined:    true,
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if len(capture.attestations) == 0 {
		t.Error("issuer saw no client attestation")
	}
	if len(capture.pops) != 0 {
		t.Errorf("issuer saw %d dedicated PoP JWTs, want none in combined mode", len(capture.pops))
	}
	if len(capture.dpops) == 0 {
		t.Error("issuer saw no DPoP proof, which is the possession proof in combined mode")
	}
	if !hasWarningContaining(w, "draft-10") {
		t.Error("expected a warning that dpop_combined is a draft-10 mechanism beyond the configured draft")
	}
}

// TestPopMethodsMetadataSelectsCombined covers the draft-10
// client_attestation_pop_methods_supported parameter: a server naming only
// dpop_combined takes the DPoP proof as the possession proof, so the wallet
// must not send a dedicated PoP JWT.
func TestPopMethodsMetadataSelectsCombined(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth"},
		popMethods:         []string{"dpop_combined"},
		dpop:               true,
		requireAttestation: true,
		requireCombined:    true,
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if len(capture.attestations) == 0 {
		t.Error("issuer saw no client attestation")
	}
	if len(capture.pops) != 0 {
		t.Errorf("issuer saw %d dedicated PoP JWTs, want none when the server accepts only dpop_combined", len(capture.pops))
	}
}

// TestUseAttestationChallengeRetry covers the header-based challenge
// conversation every supported draft defines: a server may demand a
// server-provided challenge with the use_attestation_challenge error and hand
// it over in the OAuth-Client-Attestation-Challenge header, and the client
// MUST use that challenge for the next PoP.
func TestUseAttestationChallengeRetry(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth"},
		requireAttestation: true,
		challengeValue:     "server-challenge-1",
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if capture.tokenRequests != 2 {
		t.Fatalf("issuer saw %d token requests, want the refused first and the retried second", capture.tokenRequests)
	}
	if len(capture.pops) == 0 {
		t.Fatal("issuer saw no PoP JWTs")
	}
	last := decodeJWTPart(t, capture.pops[len(capture.pops)-1], 1)
	if last["challenge"] != "server-challenge-1" {
		t.Errorf("retried PoP challenge = %v, want the served challenge", last["challenge"])
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestUseFreshAttestationRetry covers the second §6.2 retry signal: a server
// refusing the attestation as stale gets one retried request, carrying a
// newly minted attestation.
func TestUseFreshAttestationRetry(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth"},
		requireAttestation: true,
		refuseFirstAsStale: true,
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if capture.tokenRequests != 2 {
		t.Fatalf("issuer saw %d token requests, want the refused first and the retried second", capture.tokenRequests)
	}
	if len(capture.attestations) != 2 || capture.attestations[0] == capture.attestations[1] {
		t.Errorf("retried request must carry a newly minted attestation, got %d attestations", len(capture.attestations))
	}
}

// TestClientAttestorChallengeUse pins the challenge lifecycle: a challenge
// served in a response header goes into exactly the next PoP, and the request
// after that carries one from the challenge endpoint.
func TestClientAttestorChallengeUse(t *testing.T) {
	w := generateTestWallet(t)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		json.NewEncoder(rw).Encode(map[string]any{"attestation_challenge": "endpoint-challenge"})
	}))
	defer srv.Close()
	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	attestor := w.attestorFor(&ClientAuthentication{
		Method: ClientAuthAttestation, ClientID: "c", Audience: "https://as.example",
		ChallengeEndpoint: srv.URL,
	})
	header := http.Header{}
	header.Set("OAuth-Client-Attestation-Challenge", "served-challenge")
	attestor.observe(header)

	for _, want := range []string{"served-challenge", "endpoint-challenge"} {
		headers, err := attestor.headers()
		if err != nil {
			t.Fatalf("headers: %v", err)
		}
		pop := decodeJWTPart(t, headers["OAuth-Client-Attestation-PoP"], 1)
		if pop["challenge"] != want {
			t.Errorf("PoP challenge = %v, want %q", pop["challenge"], want)
		}
	}
}

// TestCombinedModeWithoutDPoPMetadata covers a server whose only client
// authentication method is attest_jwt_client_auth_dpop while its metadata
// names no DPoP algorithms: the method itself says the request carries a DPoP
// proof, so the wallet sends one, with the attestation and no dedicated PoP.
func TestCombinedModeWithoutDPoPMetadata(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth_dpop"},
		requireAttestation: true,
		requireCombined:    true,
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if len(capture.dpops) == 0 {
		t.Error("issuer saw no DPoP proof, which the combined method makes the possession proof")
	}
	if len(capture.pops) != 0 {
		t.Errorf("issuer saw %d dedicated PoP JWTs, want none in combined mode", len(capture.pops))
	}
}

// TestDedicatedPoPPreferredWhenBothMethodsOffered pins the method choice: the
// dedicated PoP JWT works with and without DPoP, so a server offering both
// attestation methods gets attest_jwt_client_auth.
func TestDedicatedPoPPreferredWhenBothMethodsOffered(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth_dpop", "attest_jwt_client_auth"},
		dpop:               true,
		requireAttestation: true,
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if len(capture.pops) != 1 {
		t.Errorf("issuer saw %d dedicated PoP JWTs, want the dedicated method used", len(capture.pops))
	}
}

// TestStoredABCADraftDrivesEmission pins the persistence contract of
// ClientAuthentication.ABCADraft: a refresh emits the shape of the draft the
// issuance was resolved under, whatever the wallet is configured to now.
func TestStoredABCADraftDrivesEmission(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.IssuerURL = "https://wallet.example"

	headers, err := createClientAttestationHeaders(w, &ClientAuthentication{
		Method: ClientAuthAttestation, ClientID: "c", Audience: "https://as.example", ABCADraft: 7,
	}, "")
	if err != nil {
		t.Fatalf("createClientAttestationHeaders: %v", err)
	}
	attestation := decodeJWTPart(t, headers["OAuth-Client-Attestation"], 1)
	pop := decodeJWTPart(t, headers["OAuth-Client-Attestation-PoP"], 1)
	if attestation["iss"] != "https://wallet.example" || pop["iss"] != "c" {
		t.Errorf("stored draft-07 record must emit the draft-07 shape, got attestation iss %v and PoP iss %v", attestation["iss"], pop["iss"])
	}
}

// TestCombinedModeChallengeInDPoPProof pins where the challenge travels in
// combined mode: the DPoP proof is the possession proof, so the served
// challenge lands in its challenge claim on the retried request.
func TestCombinedModeChallengeInDPoPProof(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth_dpop"},
		dpop:               true,
		requireAttestation: true,
		requireCombined:    true,
		challengeValue:     "combined-challenge-1",
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if capture.tokenRequests != 2 {
		t.Fatalf("issuer saw %d token requests, want the refused first and the retried second", capture.tokenRequests)
	}
	if len(capture.dpops) == 0 {
		t.Fatal("issuer saw no DPoP proofs")
	}
	last := decodeJWTPart(t, capture.dpops[len(capture.dpops)-1], 1)
	if last["challenge"] != "combined-challenge-1" {
		t.Errorf("retried DPoP proof challenge = %v, want the served challenge", last["challenge"])
	}
}
