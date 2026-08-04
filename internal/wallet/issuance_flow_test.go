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
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// mockIssuerOpts configures the mock issuer for tests.
type mockIssuerOpts struct {
	// tokenCNonce, if non-empty, is returned in the token response.
	tokenCNonce string
	// nonceEndpoint, if true, serves a nonce endpoint.
	nonceEndpoint bool
	// tokenAuthorizationDetails, if non-empty, is returned in the token response.
	tokenAuthorizationDetails []any
	// credentialResponse is the raw JSON object returned by the credential endpoint.
	// If nil, a default response with a single SD-JWT credential is returned.
	credentialResponse map[string]any
	// credentialConfigFormat overrides the format in credential_configurations_supported.
	credentialConfigFormat string
	// inspectCredentialRequest validates the credential request body sent by the wallet.
	inspectCredentialRequest func(*testing.T, map[string]any)
	// offerViaURI, if true, exposes the offer through credential_offer_uri instead of inline JSON.
	offerViaURI bool
	// oneShotOfferURI, if true, the credential_offer_uri succeeds once and then returns HTTP 400.
	oneShotOfferURI bool
	// onOfferFetch is called whenever the credential_offer_uri endpoint is dereferenced.
	onOfferFetch func()
}

func setupMockIssuer(t *testing.T, w *Wallet, opts mockIssuerOpts) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)

	credResp := opts.credentialResponse
	if credResp == nil {
		credResp = map[string]any{"credential": credRaw}
	}

	configFormat := opts.credentialConfigFormat
	if configFormat == "" {
		configFormat = "dc+sd-jwt"
	}

	// Use a closure-based handler to capture serverURL dynamically.
	var serverURL string
	var offerFetches int
	var offerMu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			meta := map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"token_endpoint":      serverURL + "/token",
				"display": []any{
					map[string]any{"name": "Test Issuer", "locale": "en-US"},
				},
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": configFormat,
						"vct":    "urn:test:credential",
						"display": []any{
							map[string]any{"name": "Test Credential", "description": "A credential for tests"},
						},
						"claims": []any{
							map[string]any{"path": []any{"given_name"}},
							map[string]any{"path": []any{"address", "locality"}},
						},
					},
				},
			}
			if opts.nonceEndpoint {
				meta["nonce_endpoint"] = serverURL + "/nonce"
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(meta)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{"error": "unsupported_grant_type"})
				return
			}
			resp := map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
			}
			if opts.tokenCNonce != "" {
				resp["c_nonce"] = opts.tokenCNonce
			}
			if opts.tokenAuthorizationDetails != nil {
				resp["authorization_details"] = opts.tokenAuthorizationDetails
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(resp)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/nonce"):
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "nonce-from-endpoint"})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-access-token" {
				rw.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_token"})
				return
			}
			if opts.inspectCredentialRequest != nil {
				body, _ := io.ReadAll(r.Body)
				var reqBody map[string]any
				if err := json.Unmarshal(body, &reqBody); err != nil {
					t.Fatalf("credential request JSON: %v", err)
				}
				opts.inspectCredentialRequest(t, reqBody)
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(credResp)

		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/credential-offer"):
			if opts.onOfferFetch != nil {
				opts.onOfferFetch()
			}
			offerMu.Lock()
			offerFetches++
			currentFetch := offerFetches
			offerMu.Unlock()
			if opts.oneShotOfferURI && currentFetch > 1 {
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{"error": "offer_expired"})
				return
			}
			offer := map[string]any{
				"credential_issuer":            serverURL,
				"credential_configuration_ids": []string{"test-config"},
				"grants": map[string]any{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
						"pre-authorized_code": "test-pre-auth-code",
					},
				},
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(offer)

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))

	serverURL = srv.URL

	// Build the credential offer URI
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
	if opts.offerViaURI {
		offerURI = "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(serverURL+"/credential-offer")
	}

	return srv, offerURI
}

func generateTestCredential(t *testing.T, w *Wallet) string {
	t.Helper()
	cred, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test-issuer.example",
		VCT:       "TestIssuedCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"given_name": "Test", "family_name": "User"},
		Key:       w.IssuerKey,
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("generating test credential: %v", err)
	}
	return cred
}

func decodeJWTPart(t *testing.T, token string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", token)
	}
	if index < 0 || index > 1 {
		t.Fatalf("invalid JWT part index %d", index)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatalf("decoding JWT part %d: %v", index, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parsing JWT part %d JSON: %v", index, err)
	}
	return out
}

func TestCreateClientAttestationHeaders(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"

	headers, err := createClientAttestationHeaders(w, "wallet-client", "https://issuer.example", "challenge-123")
	if err != nil {
		t.Fatalf("createClientAttestationHeaders: %v", err)
	}

	attestationJWT := headers["OAuth-Client-Attestation"]
	popJWT := headers["OAuth-Client-Attestation-PoP"]
	if attestationJWT == "" || popJWT == "" {
		t.Fatalf("expected both attestation headers, got %v", headers)
	}

	attestationHeader := decodeJWTPart(t, attestationJWT, 0)
	attestationPayload := decodeJWTPart(t, attestationJWT, 1)
	if attestationHeader["typ"] != "oauth-client-attestation+jwt" {
		t.Fatalf("expected oauth client attestation typ, got %v", attestationHeader["typ"])
	}
	if attestationPayload["iss"] != "https://wallet.example" {
		t.Fatalf("expected attestation iss to use wallet issuer URL, got %v", attestationPayload["iss"])
	}
	if attestationPayload["sub"] != "wallet-client" {
		t.Fatalf("expected attestation sub wallet-client, got %v", attestationPayload["sub"])
	}
	cnf, ok := attestationPayload["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("expected cnf object, got %T", attestationPayload["cnf"])
	}
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("expected cnf.jwk object, got %T", cnf["jwk"])
	}
	if jwk["kty"] != "EC" {
		t.Fatalf("expected holder EC JWK, got %v", jwk["kty"])
	}

	popHeader := decodeJWTPart(t, popJWT, 0)
	popPayload := decodeJWTPart(t, popJWT, 1)
	if popHeader["typ"] != "oauth-client-attestation-pop+jwt" {
		t.Fatalf("expected attestation pop typ, got %v", popHeader["typ"])
	}
	if popPayload["iss"] != "wallet-client" {
		t.Fatalf("expected pop iss wallet-client, got %v", popPayload["iss"])
	}
	if popPayload["aud"] != "https://issuer.example" {
		t.Fatalf("expected pop aud https://issuer.example, got %v", popPayload["aud"])
	}
	if popPayload["challenge"] != "challenge-123" {
		t.Fatalf("expected pop challenge challenge-123, got %v", popPayload["challenge"])
	}
}

func TestCreateClientAttestationHeaders_UniquePoPJTI(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"

	first, err := createClientAttestationHeaders(w, "wallet-client", "https://issuer.example", "challenge-123")
	if err != nil {
		t.Fatalf("first createClientAttestationHeaders: %v", err)
	}
	second, err := createClientAttestationHeaders(w, "wallet-client", "https://issuer.example", "challenge-123")
	if err != nil {
		t.Fatalf("second createClientAttestationHeaders: %v", err)
	}

	firstPayload := decodeJWTPart(t, first["OAuth-Client-Attestation-PoP"], 1)
	secondPayload := decodeJWTPart(t, second["OAuth-Client-Attestation-PoP"], 1)
	if firstPayload["jti"] == secondPayload["jti"] {
		t.Fatalf("expected distinct PoP jti values, got %v", firstPayload["jti"])
	}
}

func TestFetchAttestationChallenge_AttestationChallengeField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST challenge request, got %s", r.Method)
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"attestation_challenge": "challenge-123",
		})
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	challenge, err := fetchAttestationChallenge(map[string]any{"challenge_endpoint": srv.URL})
	if err != nil {
		t.Fatalf("fetchAttestationChallenge: %v", err)
	}
	if challenge != "challenge-123" {
		t.Fatalf("expected challenge-123, got %q", challenge)
	}
}

func TestDoDPoPRequest_RegeneratesExtraHeadersOnRetry(t *testing.T) {
	w := generateTestWallet(t)

	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		value := r.Header.Get("OAuth-Client-Attestation-PoP")
		if value == "" {
			t.Fatal("expected OAuth-Client-Attestation-PoP header")
		}

		mu.Lock()
		seen = append(seen, value)
		attempt := len(seen)
		mu.Unlock()

		if attempt == 1 {
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("DPoP-Nonce", "nonce-1")
			rw.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(rw).Encode(map[string]any{"error": "use_dpop_nonce"})
			return
		}

		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	nonce := ""
	_, _, err := doDPoPRequest(http.MethodPost, srv.URL, "application/json", []byte(`{}`), "", "", w.HolderKey, &nonce, func() (map[string]string, error) {
		return createClientAttestationHeaders(w, "wallet-client", srv.URL, "")
	})
	if err != nil {
		t.Fatalf("doDPoPRequest: %v", err)
	}
	if nonce != "nonce-1" {
		t.Fatalf("expected DPoP nonce to be updated, got %q", nonce)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(seen))
	}
	if seen[0] == seen[1] {
		t.Fatal("expected retried request to use a fresh client attestation PoP JWT")
	}
}

func TestCreateCredentialProofHeader_KeyAttestation(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{
		"credential_configurations_supported": map[string]any{
			"pid": map[string]any{
				"proof_types_supported": map[string]any{
					"jwt": map[string]any{
						"key_attestations_required": []any{"jwt"},
					},
				},
			},
		},
	}

	header, err := createCredentialProofHeader(w, metadata, "pid", "nonce-123", nil)
	if err != nil {
		t.Fatalf("createCredentialProofHeader: %v", err)
	}
	if header == nil {
		t.Fatal("expected key attestation header")
	}
	keyAttestationJWT, ok := header["key_attestation"].(string)
	if !ok || keyAttestationJWT == "" {
		t.Fatalf("expected key_attestation JWT, got %v", header["key_attestation"])
	}

	keyAttestationHeader := decodeJWTPart(t, keyAttestationJWT, 0)
	keyAttestationPayload := decodeJWTPart(t, keyAttestationJWT, 1)
	if keyAttestationHeader["typ"] != "key-attestation+jwt" {
		t.Fatalf("expected key attestation typ, got %v", keyAttestationHeader["typ"])
	}
	if keyAttestationPayload["nonce"] != "nonce-123" {
		t.Fatalf("expected nonce nonce-123, got %v", keyAttestationPayload["nonce"])
	}
	attestedKeys, ok := keyAttestationPayload["attested_keys"].([]any)
	if !ok || len(attestedKeys) != 1 {
		t.Fatalf("expected one attested key, got %v", keyAttestationPayload["attested_keys"])
	}
}

func TestProcessCredentialOffer_HappyPath(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		inspectCredentialRequest: func(t *testing.T, reqBody map[string]any) {
			t.Helper()
			if _, ok := reqBody["proof"]; ok {
				t.Fatal("credential request must not use legacy proof field")
			}
			proofs, ok := reqBody["proofs"].(map[string]any)
			if !ok {
				t.Fatalf("expected proofs object, got %T", reqBody["proofs"])
			}
			jwts, ok := proofs["jwt"].([]any)
			if !ok || len(jwts) != 1 {
				t.Fatalf("expected single jwt proof, got %v", proofs["jwt"])
			}
			if reqBody["credential_configuration_id"] != "test-config" {
				t.Fatalf("expected credential_configuration_id=test-config, got %v", reqBody["credential_configuration_id"])
			}
		},
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}
	if result.Format != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %s", result.Format)
	}
	if result.Issuer != srv.URL {
		t.Errorf("expected issuer %s, got %s", srv.URL, result.Issuer)
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].ID != result.CredentialID {
		t.Errorf("credential ID mismatch")
	}

	logs := w.GetLog()
	for _, event := range []string{
		"credential_offer",
		"issuer_metadata_request",
		"issuer_metadata_response",
		"oauth_metadata_request",
		"oauth_metadata_response",
		"token_request",
		"token_response",
		"credential_request",
		"credential_response",
		"credential_imported",
	} {
		assertWalletLogEvent(t, logs, event)
	}
}

func TestProcessCredentialOffer_NonceFallback(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce:   "",
		nonceEndpoint: true,
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer with nonce fallback: %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
}

func TestProcessCredentialOffer_Draft14CredentialsArray(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		credentialResponse: map[string]any{
			"credentials": []any{
				map[string]any{"credential": credRaw},
			},
		},
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer (draft 14): %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}
	if result.Format != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %s", result.Format)
	}
}

func TestProcessCredentialOffer_AuthCodeRequiresClientConfiguration(t *testing.T) {
	w := generateTestWallet(t)

	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                serverURL,
				"authorization_endpoint":                serverURL + "/authorize",
				"pushed_authorization_request_endpoint": serverURL + "/par",
				"token_endpoint":                        serverURL + "/token",
				"token_endpoint_auth_methods_supported": []string{"attest_jwt_client_auth"},
				"dpop_signing_alg_values_supported":     []string{"ES256"},
			})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "some-state",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	_, err := w.ProcessCredentialOffer(offerURI)
	if err == nil {
		t.Fatal("expected error when authorization_code flow has no wallet client configuration")
	}
	if !strings.Contains(err.Error(), "configured wallet client_id and redirect_uri") {
		t.Errorf("expected error about missing client configuration, got: %v", err)
	}
}

func TestProcessCredentialOffer_AuthCodeBrowserFallback(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIClientID = "wallet-client"

	walletSrv := NewServer(w, 0, nil)
	addr, err := walletSrv.ListenAndServeBackground()
	if err != nil {
		t.Fatalf("ListenAndServeBackground: %v", err)
	}
	defer walletSrv.Shutdown()
	w.BaseURL = addr
	w.VCIRedirectURI = addr + "/callback"

	credRaw := generateTestCredential(t, w)
	var (
		serverURL string
		parState  string
	)

	issuer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                serverURL,
				"authorization_endpoint":                serverURL + "/authorize",
				"pushed_authorization_request_endpoint": serverURL + "/par",
				"token_endpoint":                        serverURL + "/token",
				"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
				"dpop_signing_alg_values_supported":     []string{"ES256"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/par":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			parState = form.Get("state")
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"request_uri": serverURL + "/request-uri/example",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			http.Redirect(rw, r, serverURL+"/login?state="+url.QueryEscape(parState), http.StatusFound)
		case r.Method == http.MethodGet && r.URL.Path == "/login":
			redirect := w.VCIRedirectURI + "?code=issued-code&state=" + url.QueryEscape(r.URL.Query().Get("state"))
			http.Redirect(rw, r, redirect, http.StatusFound)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if got := form.Get("code"); got != "issued-code" {
				t.Fatalf("token request code = %q, want issued-code", got)
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-c-nonce",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/credential":
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{"credential": credRaw})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()
	serverURL = issuer.URL

	oldClient := httpClient
	httpClient = issuer.Client()
	defer func() { httpClient = oldClient }()

	oldBrowser := openAuthorizationBrowser
	openAuthorizationBrowser = func(authURL string) error {
		go func() {
			resp, err := issuer.Client().Get(authURL)
			if err == nil && resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
		return nil
	}
	defer func() { openAuthorizationBrowser = oldBrowser }()

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "issuer-state-1",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if parState == "" {
		t.Fatal("expected PAR request to include state")
	}
	if result.CredentialID == "" {
		t.Fatal("expected imported credential ID")
	}
}

func TestProcessCredentialOffer_AuthCodeDirectRedirect(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"

	credRaw := generateTestCredential(t, w)
	var (
		serverURL string
		parState  string
	)

	issuer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                serverURL,
				"authorization_endpoint":                serverURL + "/authorize",
				"pushed_authorization_request_endpoint": serverURL + "/par",
				"token_endpoint":                        serverURL + "/token",
				"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
				"dpop_signing_alg_values_supported":     []string{"ES256"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/par":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			parState = form.Get("state")
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"request_uri": serverURL + "/request-uri/example",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			redirect := w.VCIRedirectURI + "?code=issued-code&state=" + url.QueryEscape(parState)
			http.Redirect(rw, r, redirect, http.StatusFound)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if got := form.Get("code"); got != "issued-code" {
				t.Fatalf("token request code = %q, want issued-code", got)
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-c-nonce",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/credential":
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{"credential": credRaw})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()
	serverURL = issuer.URL

	oldClient := httpClient
	httpClient = issuer.Client()
	defer func() { httpClient = oldClient }()

	oldBrowser := openAuthorizationBrowser
	openAuthorizationBrowser = func(string) error {
		t.Fatal("did not expect browser fallback for direct authorization redirect")
		return nil
	}
	defer func() { openAuthorizationBrowser = oldBrowser }()

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "issuer-state-1",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if parState == "" {
		t.Fatal("expected PAR request to include state")
	}
	if result.CredentialID == "" {
		t.Fatal("expected imported credential ID")
	}
}

func TestValidateAuthorizationCodeResponse_StrictChecksStateAndIssuer(t *testing.T) {
	tests := []struct {
		name           string
		values         url.Values
		expectedState  string
		expectedIssuer string
		wantErr        string
	}{
		{
			name: "valid",
			values: url.Values{
				"code":  {"issued-code"},
				"state": {"expected-state"},
				"iss":   {"https://issuer.example"},
			},
			expectedState:  "expected-state",
			expectedIssuer: "https://issuer.example",
		},
		{
			name: "missing state",
			values: url.Values{
				"code": {"issued-code"},
				"iss":  {"https://issuer.example"},
			},
			expectedState:  "expected-state",
			expectedIssuer: "https://issuer.example",
			wantErr:        "missing state",
		},
		{
			name: "issuer mismatch",
			values: url.Values{
				"code":  {"issued-code"},
				"state": {"expected-state"},
				"iss":   {"https://other.example"},
			},
			expectedState:  "expected-state",
			expectedIssuer: "https://issuer.example",
			wantErr:        "issuer",
		},
		{
			name: "missing issuer",
			values: url.Values{
				"code":  {"issued-code"},
				"state": {"expected-state"},
			},
			expectedState:  "expected-state",
			expectedIssuer: "https://issuer.example",
			wantErr:        "missing issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthorizationCodeResponse(ValidationModeStrict, tt.values, tt.expectedState, tt.expectedIssuer)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateAuthorizationCodeResponse() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateAuthorizationCodeResponse() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestProcessCredentialOffer_StrictRejectsAuthorizationServerIssuerMismatchBeforePAR(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"

	var (
		serverURL string
		parCalls  int
	)
	issuer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                serverURL + "/wrong",
				"authorization_endpoint":                serverURL + "/authorize",
				"pushed_authorization_request_endpoint": serverURL + "/par",
				"token_endpoint":                        serverURL + "/token",
				"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
				"dpop_signing_alg_values_supported":     []string{"ES256"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/par":
			parCalls++
			rw.WriteHeader(http.StatusBadRequest)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()
	serverURL = issuer.URL

	oldClient := httpClient
	httpClient = issuer.Client()
	defer func() { httpClient = oldClient }()

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "issuer-state-1",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	_, err := w.ProcessCredentialOffer(offerURI)
	if err == nil || !strings.Contains(err.Error(), "authorization server issuer") {
		t.Fatalf("ProcessCredentialOffer() error = %v, want authorization server issuer error", err)
	}
	if parCalls != 0 {
		t.Fatalf("PAR calls = %d, want 0", parCalls)
	}
}

func TestProcessCredentialOffer_StrictRejectsMissingAuthorizationResponseIssuerBeforeToken(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"

	var (
		serverURL  string
		parState   string
		tokenCalls int
	)
	issuer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                serverURL,
				"authorization_endpoint":                serverURL + "/authorize",
				"pushed_authorization_request_endpoint": serverURL + "/par",
				"token_endpoint":                        serverURL + "/token",
				"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
				"dpop_signing_alg_values_supported":     []string{"ES256"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/par":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			parState = form.Get("state")
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"request_uri": serverURL + "/request-uri/example",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			redirect := w.VCIRedirectURI + "?code=issued-code&state=" + url.QueryEscape(parState)
			http.Redirect(rw, r, redirect, http.StatusFound)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			tokenCalls++
			rw.WriteHeader(http.StatusBadRequest)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()
	serverURL = issuer.URL

	oldClient := httpClient
	httpClient = issuer.Client()
	defer func() { httpClient = oldClient }()

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "issuer-state-1",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	_, err := w.ProcessCredentialOffer(offerURI)
	if err == nil || !strings.Contains(err.Error(), "missing issuer") {
		t.Fatalf("ProcessCredentialOffer() error = %v, want missing issuer error", err)
	}
	if tokenCalls != 0 {
		t.Fatalf("token calls = %d, want 0", tokenCalls)
	}
}

func TestProcessCredentialOffer_TxCodeSentInTokenRequest(t *testing.T) {
	w := generateTestWallet(t)

	credRaw := generateTestCredential(t, w)
	var receivedTxCode string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			meta := map[string]any{
				"credential_issuer":   "", // will be replaced
				"credential_endpoint": "",
				"token_endpoint":      "",
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(meta)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			receivedTxCode = form.Get("tx_code")
			resp := map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-nonce",
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(resp)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(map[string]any{"credential": credRaw})

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Patch metadata responses to use actual server URL
	srvURL := srv.URL
	origHandler := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer") {
			meta := map[string]any{
				"credential_issuer":   srvURL,
				"credential_endpoint": srvURL + "/credential",
				"token_endpoint":      srvURL + "/token",
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(meta)
			return
		}
		origHandler.ServeHTTP(rw, r)
	})

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	// Set tx_code on wallet
	w.TxCode = "123456"

	offer := map[string]any{
		"credential_issuer":            srvURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "test-code",
				"tx_code":             map[string]any{"length": 6},
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	_, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if receivedTxCode != "123456" {
		t.Errorf("expected tx_code=123456 in token request, got %q", receivedTxCode)
	}

	// Verify tx_code was cleared
	if w.TxCode != "" {
		t.Errorf("expected TxCode to be cleared after use, got %q", w.TxCode)
	}
}

func TestProcessCredentialOffer_NoTxCodeWhenNotSet(t *testing.T) {
	w := generateTestWallet(t)

	var receivedForm string

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-nonce",
	})
	defer srv.Close()

	// Wrap the server to capture the token request form body
	origHandler := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token") {
			body, _ := io.ReadAll(r.Body)
			receivedForm = string(body)
			// Reconstruct body for the original handler
			r.Body = io.NopCloser(strings.NewReader(receivedForm))
		}
		origHandler.ServeHTTP(rw, r)
	})

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	// Don't set TxCode
	_, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if strings.Contains(receivedForm, "tx_code") {
		t.Errorf("expected no tx_code in token request when not set, but got: %s", receivedForm)
	}
}

func TestProcessCredentialOffer_Draft14RawStringArray(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		credentialResponse: map[string]any{
			"credentials": []any{credRaw},
		},
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer (draft 14 raw strings): %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}
}

func TestProcessCredentialOffer_VerifiesViaIssuerMetadata(t *testing.T) {
	w := generateTestWallet(t)

	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var issuer string
	metaSrv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer" {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"issuer": issuer,
			"jwks": map[string]any{
				"keys": []any{mock.SigningJWKMap(&key.PublicKey)},
			},
		})
	}))
	defer metaSrv.Close()
	issuer = metaSrv.URL

	credRaw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    issuer,
		VCT:       "TestIssuedCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"given_name": "Test", "family_name": "User"},
		Key:       key,
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce:        "test-c-nonce",
		credentialResponse: map[string]any{"credential": credRaw},
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if result.VerificationStatus != "pass" {
		t.Fatalf("expected verification pass, got %q (%s)", result.VerificationStatus, result.VerificationDetail)
	}
}

func TestProcessCredentialOffer_UsesCredentialIdentifierFromAuthorizationDetails(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		tokenAuthorizationDetails: []any{
			map[string]any{
				"type":                        "openid_credential",
				"credential_configuration_id": "test-config",
				"credential_identifiers":      []any{"credential-id-123"},
			},
		},
		inspectCredentialRequest: func(t *testing.T, reqBody map[string]any) {
			t.Helper()
			if reqBody["credential_identifier"] != "credential-id-123" {
				t.Fatalf("expected credential_identifier, got %v", reqBody["credential_identifier"])
			}
			if _, ok := reqBody["credential_configuration_id"]; ok {
				t.Fatalf("did not expect credential_configuration_id when credential_identifier is present")
			}
		},
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
}

// The consent dialog has to say what is being issued, not just name a host.
// Everything beyond the offer comes from the issuer's metadata, which is
// optional, so this also pins the degraded cases.
func TestIssuanceConsentDescribesTheOffer(t *testing.T) {
	srv := newTestServer(t, false)
	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{})
	defer issuer.Close()

	req, _, err := prepareIssuanceConsentRequest(offerURI)
	if err != nil {
		t.Fatalf("prepareIssuanceConsentRequest: %v", err)
	}
	details := req.OfferDetails
	if details == nil {
		t.Fatal("the consent request carries no offer details")
	}

	if details.IssuerName != "Test Issuer" {
		t.Errorf("issuer name = %q, want the name from the issuer metadata", details.IssuerName)
	}
	if details.Grant != "pre-authorized code" {
		t.Errorf("grant = %q, want the flow the offer uses", details.Grant)
	}
	if len(details.Credentials) != 1 {
		t.Fatalf("expected one offered credential, got %d", len(details.Credentials))
	}

	cred := details.Credentials[0]
	if cred.ID != "test-config" {
		t.Errorf("configuration id = %q", cred.ID)
	}
	if cred.Name != "Test Credential" || cred.Description != "A credential for tests" {
		t.Errorf("display name/description not taken from the metadata: %+v", cred)
	}
	if cred.Format != "dc+sd-jwt" || cred.VCT != "urn:test:credential" {
		t.Errorf("format/vct not resolved: %+v", cred)
	}
	// Nested claim paths are what a user most needs to see, so they must be
	// rendered as a path rather than dropped.
	want := []string{"given_name", "address.locality"}
	if len(cred.Claims) != len(want) {
		t.Fatalf("claims = %v, want %v", cred.Claims, want)
	}
	for i, claim := range want {
		if cred.Claims[i] != claim {
			t.Errorf("claim %d = %q, want %q", i, cred.Claims[i], claim)
		}
	}

	// The marshalled form is what the UI actually consumes.
	if _, ok := MarshalConsentRequest(req)["offer_details"]; !ok {
		t.Error("offer_details missing from the marshalled consent request")
	}
}

// An offer delivered by reference is resolved for the dialog too, so the user
// sees what they are approving rather than a bare hostname. It is fetched
// again after approval, which the specification permits.
func TestIssuanceConsentResolvesOfferByReference(t *testing.T) {
	srv := newTestServer(t, false)
	fetched := make(chan struct{}, 4)
	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{
		offerViaURI:  true,
		onOfferFetch: func() { fetched <- struct{}{} },
	})
	defer issuer.Close()

	req, _, err := prepareIssuanceConsentRequest(offerURI)
	if err != nil {
		t.Fatalf("prepareIssuanceConsentRequest: %v", err)
	}
	select {
	case <-fetched:
	default:
		t.Fatal("the credential_offer_uri should be fetched to describe the offer")
	}

	details := req.OfferDetails
	if details == nil || len(details.Credentials) != 1 {
		t.Fatalf("a by-reference offer should be described like any other: %+v", details)
	}
	if details.Credentials[0].Name != "Test Credential" {
		t.Errorf("display name not resolved: %+v", details.Credentials[0])
	}
}

// An offer whose URI cannot be fetched must still produce a dialog: naming
// the host and the failure beats refusing to ask.
func TestIssuanceConsentSurvivesUnresolvableOfferURI(t *testing.T) {
	req, _, err := prepareIssuanceConsentRequest("openid-credential-offer://?credential_offer_uri=https://issuer.invalid/offer/1")
	if err != nil {
		t.Fatalf("prepareIssuanceConsentRequest: %v", err)
	}
	if req.OfferDetails == nil || req.OfferDetails.ResolveError == "" {
		t.Fatalf("the resolve failure should be recorded: %+v", req.OfferDetails)
	}
	if req.ClientID == "" {
		t.Error("the dialog still needs something to name the issuer by")
	}
}

// An issuer that publishes no metadata must still produce a usable dialog.
func TestIssuanceConsentSurvivesMissingIssuerMetadata(t *testing.T) {
	offer := `{"credential_issuer":"https://issuer.invalid","credential_configuration_ids":["some-config"],` +
		`"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc","tx_code":{"length":6,"input_mode":"numeric"}}}}`
	req, _, err := prepareIssuanceConsentRequest("openid-credential-offer://?credential_offer=" + url.QueryEscape(offer))
	if err != nil {
		t.Fatalf("prepareIssuanceConsentRequest: %v", err)
	}
	details := req.OfferDetails
	if details == nil {
		t.Fatal("no offer details")
	}
	if details.MetadataError == "" {
		t.Error("the unreachable metadata should be recorded, not hidden")
	}
	if len(details.Credentials) != 1 || details.Credentials[0].ID != "some-config" {
		t.Errorf("the offered configuration should still be listed: %+v", details.Credentials)
	}
	if !details.TxCode || details.TxCodeHint != "6 numeric characters" {
		t.Errorf("tx_code requirement not surfaced: %+v", details)
	}
}
