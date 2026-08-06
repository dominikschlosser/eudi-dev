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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

func TestBuildWalletMetadata_Basic(t *testing.T) {
	w := &Wallet{}
	meta := BuildWalletMetadata(w)

	if meta["vp_formats_supported"] == nil {
		t.Fatal("expected vp_formats_supported")
	}
	if meta["request_object_signing_alg_values_supported"] == nil {
		t.Fatal("expected request_object_signing_alg_values_supported")
	}
	// Should not have encryption keys without RequireEncryptedRequest
	if meta["jwks"] != nil {
		t.Error("should not include jwks without RequireEncryptedRequest")
	}

	// Appendix B names issuerauth_alg_values for mso_mdoc, and its values are
	// COSE algorithm identifiers (-7 is ECDSA with SHA-256).
	vpFormats := meta["vp_formats_supported"].(map[string]any)
	mdoc := vpFormats["mso_mdoc"].(map[string]any)
	algValues := mdoc["issuerauth_alg_values"].([]int)
	if len(algValues) != 1 || algValues[0] != -7 {
		t.Fatalf("expected mso_mdoc issuerauth_alg_values [-7], got %v", algValues)
	}
}

func TestBuildWalletMetadata_WithEncryption(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	w := &Wallet{
		RequireEncryptedRequest: true,
		RequestEncryptionKey:    key,
	}
	meta := BuildWalletMetadata(w)

	jwks, ok := meta["jwks"].(map[string]any)
	if !ok {
		t.Fatal("expected jwks map")
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("expected at least one key in jwks")
	}
	jwk := keys[0].(map[string]any)
	if jwk["kty"] != "EC" {
		t.Errorf("expected kty EC, got %s", jwk["kty"])
	}
	if jwk["use"] != "enc" {
		t.Errorf("expected use enc, got %s", jwk["use"])
	}
	if jwk["alg"] != "ECDH-ES" {
		t.Errorf("expected alg ECDH-ES, got %s", jwk["alg"])
	}

	algSupported := meta["authorization_encryption_alg_values_supported"].([]string)
	if len(algSupported) != 1 || algSupported[0] != "ECDH-ES" {
		t.Errorf("unexpected alg_values_supported: %v", algSupported)
	}
	encSupported := meta["authorization_encryption_enc_values_supported"].([]string)
	if len(encSupported) != 2 {
		t.Errorf("expected 2 enc values, got %d", len(encSupported))
	}
}

func TestGenerateWalletNonce(t *testing.T) {
	nonce1, err := GenerateWalletNonce()
	if err != nil {
		t.Fatal(err)
	}
	if nonce1 == "" {
		t.Fatal("expected non-empty nonce")
	}

	nonce2, err := GenerateWalletNonce()
	if err != nil {
		t.Fatal(err)
	}
	if nonce1 == nonce2 {
		t.Error("expected unique nonces")
	}
}

func TestMakeFetchRequestURI_GET(t *testing.T) {
	// Set up a test server that returns a JWT on GET
	jwt := makeTestJWT(map[string]any{"alg": "none"}, map[string]any{
		"client_id":     "test-client",
		"response_type": "vp_token",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(jwt))
	}))
	defer srv.Close()

	w := &Wallet{}
	fetch := MakeFetchRequestURI(w, nil)
	result, err := fetch(srv.URL, "get")
	if err != nil {
		t.Fatal(err)
	}
	if result != jwt {
		t.Errorf("expected JWT, got %s", result)
	}
	logs := w.GetLog()
	assertWalletLogEvent(t, logs, "request_object_fetch_request")
	assertWalletLogEvent(t, logs, "request_object_fetch_response")
}

func TestMakeFetchRequestURI_POST(t *testing.T) {
	// Set up a test server that expects POST with wallet_metadata and wallet_nonce
	var receivedContentType string
	var receivedWalletMetadata string
	var receivedWalletNonce string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		receivedContentType = r.Header.Get("Content-Type")
		r.ParseForm()
		receivedWalletMetadata = r.Form.Get("wallet_metadata")
		receivedWalletNonce = r.Form.Get("wallet_nonce")

		// Return signed-style JWT that includes the wallet_nonce
		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id":     "test-client",
			"response_type": "vp_token",
			"wallet_nonce":  receivedWalletNonce,
		})
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		w.Write([]byte(jwt))
	}))
	defer srv.Close()

	wallet := &Wallet{}
	var logs []string
	logFn := func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}

	fetch := MakeFetchRequestURI(wallet, logFn)
	result, err := fetch(srv.URL, "post")
	if err != nil {
		t.Fatal(err)
	}

	if receivedContentType != "application/x-www-form-urlencoded" {
		t.Errorf("expected form-urlencoded content type, got %s", receivedContentType)
	}
	if receivedWalletMetadata == "" {
		t.Error("expected wallet_metadata to be sent")
	}
	if receivedWalletNonce == "" {
		t.Error("expected wallet_nonce to be sent")
	}

	// Verify wallet_metadata is valid JSON
	var meta map[string]any
	if err := json.Unmarshal([]byte(receivedWalletMetadata), &meta); err != nil {
		t.Errorf("wallet_metadata is not valid JSON: %v", err)
	}

	if !isJWT(result) {
		t.Error("expected JWT result")
	}
	walletLogs := wallet.GetLog()
	assertWalletLogEvent(t, walletLogs, "request_object_fetch_request")
	assertWalletLogEvent(t, walletLogs, "request_object_fetch_response")
}

func TestMakeFetchRequestURI_POST_WalletNonceMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return JWT with wrong wallet_nonce
		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id":    "test-client",
			"wallet_nonce": "wrong-nonce",
		})
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		w.Write([]byte(jwt))
	}))
	defer srv.Close()

	wallet := &Wallet{}
	fetch := MakeFetchRequestURI(wallet, nil)
	_, err := fetch(srv.URL, "post")
	if err == nil {
		t.Fatal("expected error for wallet_nonce mismatch")
	}
	if !contains(err.Error(), "wallet_nonce mismatch") {
		t.Errorf("expected wallet_nonce mismatch error, got: %v", err)
	}
}

func TestMakeFetchRequestURI_POST_AllowsMissingWalletNonce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id": "test-client",
		})
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		w.Write([]byte(jwt))
	}))
	defer srv.Close()

	wallet := &Wallet{}
	fetch := MakeFetchRequestURI(wallet, nil)
	result, err := fetch(srv.URL, "post")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isJWT(result) {
		t.Fatalf("expected JWT result, got %q", result)
	}
}

func TestMakeFetchRequestURI_POST_AllowsUnsignedRequestObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwt := makeTestJWT(map[string]any{"alg": "none"}, map[string]any{
			"client_id": "test-client",
		})
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		w.Write([]byte(jwt))
	}))
	defer srv.Close()

	wallet := &Wallet{}
	fetch := MakeFetchRequestURI(wallet, nil)
	result, err := fetch(srv.URL, "post")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isJWT(result) {
		t.Fatalf("expected JWT result, got %q", result)
	}
}

func TestValidateClientMetadata_RejectsInvalidVPFormatsSupportedValue(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"vp_formats_supported": []any{},
			},
		},
	}

	err := ValidateClientMetadata(reqObj.Payload["client_metadata"].(map[string]any))
	if err == nil {
		t.Fatal("expected error for non-object vp_formats_supported")
	}
	if !contains(err.Error(), "vp_formats_supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateClientMetadata_RejectsInvalidMDocAlgValuesSupported(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"vp_formats_supported": map[string]any{
					"mso_mdoc": map[string]any{
						"alg_values_supported": []any{"ES256"},
					},
				},
			},
		},
	}

	err := ValidateClientMetadata(reqObj.Payload["client_metadata"].(map[string]any))
	if err == nil {
		t.Fatal("expected error for string mso_mdoc alg_values_supported entry")
	}
	if !contains(err.Error(), "COSE algorithm number") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateClientMetadata_AcceptsNumericMDocAlgValuesSupported(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"vp_formats_supported": map[string]any{
					"mso_mdoc": map[string]any{
						"alg_values_supported": []any{-7.0},
					},
					"dc+sd-jwt": map[string]any{
						"alg_values_supported": []any{"ES256"},
					},
				},
			},
		},
	}

	if err := ValidateClientMetadata(reqObj.Payload["client_metadata"].(map[string]any)); err != nil {
		t.Fatalf("expected valid client_metadata, got %v", err)
	}
}

func TestDecryptRequestObjectJWE(t *testing.T) {
	// Generate wallet encryption key
	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a JWT payload
	jwt := makeTestJWT(map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"}, map[string]any{
		"client_id":     "test-verifier",
		"response_type": "vp_token",
		"nonce":         "test-nonce",
	})

	// Encrypt the JWT using the wallet's public key (simulating verifier behavior)
	jweStr, _, err := EncryptJWE([]byte(jwt), &walletKey.PublicKey, "test-kid", "ECDH-ES", "A128GCM", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt with wallet's private key
	decrypted, err := DecryptRequestObjectJWE(jweStr, walletKey)
	if err != nil {
		t.Fatalf("DecryptRequestObjectJWE: %v", err)
	}

	if decrypted != jwt {
		t.Errorf("decrypted JWT doesn't match original")
	}
}

func TestMakeFetchRequestURI_POST_Encrypted(t *testing.T) {
	walletKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	wallet := &Wallet{
		RequireEncryptedRequest: true,
		RequestEncryptionKey:    walletKey,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		walletNonce := r.Form.Get("wallet_nonce")
		walletMetaStr := r.Form.Get("wallet_metadata")

		// Parse wallet_metadata to get the encryption key
		var meta map[string]any
		json.Unmarshal([]byte(walletMetaStr), &meta)
		jwks := meta["jwks"].(map[string]any)
		keys := jwks["keys"].([]any)
		jwk := keys[0].(map[string]any)

		// Build the public key from the JWK
		xB64 := jwk["x"].(string)
		yB64 := jwk["y"].(string)
		pubKey, _, err := ecdsaPublicKeyFromJWK(ValidationModeStrict, xB64, yB64)
		if err != nil {
			t.Fatalf("parsing wallet encryption key: %v", err)
		}

		// Create a JWT with the wallet_nonce
		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id":     "test-verifier",
			"response_type": "vp_token",
			"wallet_nonce":  walletNonce,
		})

		// Encrypt the JWT with the wallet's public key
		jweStr, _, err := EncryptJWE([]byte(jwt), pubKey, "verifier-kid", "ECDH-ES", "A128GCM", nil, nil)
		if err != nil {
			t.Fatalf("encrypting request object: %v", err)
		}

		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		w.Write([]byte(jweStr))
	}))
	defer srv.Close()

	fetch := MakeFetchRequestURI(wallet, nil)
	result, err := fetch(srv.URL, "post")
	if err != nil {
		t.Fatalf("fetch with encrypted response: %v", err)
	}

	if !isJWT(result) {
		t.Error("expected decrypted JWT result")
	}

	// Verify the JWT content
	_, payload, _, err := format.ParseJWTParts(result)
	if err != nil {
		t.Fatal(err)
	}
	if payload["client_id"] != "test-verifier" {
		t.Errorf("unexpected client_id in decrypted JWT: %v", payload["client_id"])
	}
}

func TestMakeFetchRequestURI_POST_RequireEncryptedRequestRejectsPlainJWT(t *testing.T) {
	walletKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	wallet := &Wallet{
		RequireEncryptedRequest: true,
		RequestEncryptionKey:    walletKey,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id":     "test-verifier",
			"response_type": "vp_token",
		})
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		w.Write([]byte(jwt))
	}))
	defer srv.Close()

	fetch := MakeFetchRequestURI(wallet, nil)
	_, err = fetch(srv.URL, "post")
	if err == nil {
		t.Fatal("expected error when encrypted request objects are required but verifier returned plain JWT")
	}
	if !contains(err.Error(), "must be a compact JWE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseWithOptionsRequestURIMethodPost(t *testing.T) {
	// Set up a test server that returns a JWT on POST
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		walletNonce := r.Form.Get("wallet_nonce")
		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id":     "test-client",
			"response_type": "vp_token",
			"nonce":         "verifier-nonce",
			"wallet_nonce":  walletNonce,
		})
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		w.Write([]byte(jwt))
	}))
	defer srv.Close()

	wallet := &Wallet{}
	opts := oid4vc.ParseOptions{
		FetchRequestURI: MakeFetchRequestURI(wallet, nil),
	}

	uri := fmt.Sprintf("openid4vp://authorize?client_id=test-client&request_uri=%s&request_uri_method=post&response_type=vp_token",
		srv.URL)

	authReq, err := ParseAuthorizationRequestWithOptions(uri, opts)
	if err != nil {
		t.Fatal(err)
	}

	if authReq.ClientID != "test-client" {
		t.Errorf("expected client_id test-client, got %s", authReq.ClientID)
	}
	if authReq.RequestURIMethod != "post" {
		t.Errorf("expected request_uri_method post, got %s", authReq.RequestURIMethod)
	}
	if authReq.RequestObject == nil {
		t.Fatal("expected request object to be parsed")
	}
	if authReq.Nonce != "verifier-nonce" {
		t.Errorf("expected nonce from request object, got %s", authReq.Nonce)
	}
}

// makeTestJWT creates a minimal unsigned JWT for testing.
func makeTestJWT(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return format.EncodeBase64URL(h) + "." + format.EncodeBase64URL(p) + ".testsig"
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// OID4VP 1.0 §10.1: "client_id_prefixes_supported ... If omitted, the default
// value is pre-registered." A Verifier reads this to choose a prefix (§5.9.1),
// so a wallet that stays silent is understood to accept pre-registered clients
// only and will never be sent an x509_hash request.
func TestWalletMetadataAdvertisesTheClientIDPrefixesItAccepts(t *testing.T) {
	meta := BuildWalletMetadata(generateTestWallet(t))

	prefixes, _ := meta["client_id_prefixes_supported"].([]string)
	if len(prefixes) == 0 {
		t.Fatalf("wallet metadata advertises no client_id_prefixes_supported: %v", meta)
	}
	listed := map[string]bool{}
	for _, p := range prefixes {
		listed[p] = true
	}
	for _, want := range []string{"x509_hash", "pre-registered"} {
		if !listed[want] {
			t.Errorf("%s is not advertised: %v", want, prefixes)
		}
	}
	// The reserved prefix of §5.9.3 is one the wallet "MUST NOT accept ... in
	// requests", so advertising it would invite exactly that.
	if listed["origin"] {
		t.Error("the reserved origin prefix is advertised as supported")
	}
}

// Appendix B names the members of each format profile. The generic
// alg_values_supported is not one of them, so a Verifier reading it learns
// nothing about what this wallet can verify.
func TestWalletMetadataNamesTheFormatProfileMembers(t *testing.T) {
	meta := BuildWalletMetadata(generateTestWallet(t))

	formats, _ := meta["vp_formats_supported"].(map[string]any)
	sdjwt, _ := formats["dc+sd-jwt"].(map[string]any)
	if sdjwt == nil {
		t.Fatalf("no dc+sd-jwt profile: %v", formats)
	}
	if _, present := sdjwt["sd-jwt_alg_values"]; !present {
		t.Errorf("dc+sd-jwt does not name sd-jwt_alg_values: %v", sdjwt)
	}
	if _, present := sdjwt["kb-jwt_alg_values"]; !present {
		t.Errorf("dc+sd-jwt does not name kb-jwt_alg_values: %v", sdjwt)
	}

	mdoc, _ := formats["mso_mdoc"].(map[string]any)
	if mdoc == nil {
		t.Fatalf("no mso_mdoc profile: %v", formats)
	}
	if _, present := mdoc["issuerauth_alg_values"]; !present {
		t.Errorf("mso_mdoc does not name issuerauth_alg_values: %v", mdoc)
	}
	if _, present := mdoc["deviceauth_alg_values"]; !present {
		t.Errorf("mso_mdoc does not name deviceauth_alg_values: %v", mdoc)
	}
	for _, profile := range []map[string]any{sdjwt, mdoc} {
		if _, present := profile["alg_values_supported"]; present {
			t.Errorf("a format profile still carries alg_values_supported, which Appendix B does not define: %v", profile)
		}
	}
}
