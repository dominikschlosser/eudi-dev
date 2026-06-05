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
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
)

func TestResolveCredentialIdentifier_FromAuthDetails(t *testing.T) {
	tokenResp := map[string]any{
		"access_token": "token123",
		"authorization_details": []any{
			map[string]any{
				"type":                        "openid_credential",
				"credential_configuration_id": "pid-config",
				"credential_identifiers":      []any{"cred-id-abc", "cred-id-def"},
			},
		},
	}

	got := resolveCredentialIdentifier(tokenResp, []string{"pid-config"})
	if got != "cred-id-abc" {
		t.Errorf("expected cred-id-abc, got %s", got)
	}
}

func TestResolveCredentialIdentifier_FallbackToConfigID(t *testing.T) {
	tokenResp := map[string]any{
		"access_token": "token123",
	}

	got := resolveCredentialIdentifier(tokenResp, []string{"pid-config"})
	if got != "" {
		t.Errorf("expected empty string, got %s", got)
	}
}

func TestResolveCredentialIdentifier_EmptyAuthDetails(t *testing.T) {
	tokenResp := map[string]any{
		"access_token":          "token123",
		"authorization_details": []any{},
	}

	got := resolveCredentialIdentifier(tokenResp, []string{"fallback"})
	if got != "" {
		t.Errorf("expected empty string, got %s", got)
	}
}

func TestResolveCredentialIdentifier_NoConfigIDs(t *testing.T) {
	tokenResp := map[string]any{
		"access_token": "token123",
	}

	got := resolveCredentialIdentifier(tokenResp, nil)
	if got != "" {
		t.Errorf("expected empty string, got %s", got)
	}
}

func TestExtractCredential_SingleField(t *testing.T) {
	resp := map[string]any{
		"credential": "eyJhbGci...",
	}

	got := extractCredential(resp)
	if got != "eyJhbGci..." {
		t.Errorf("expected eyJhbGci..., got %s", got)
	}
}

func TestExtractCredential_CredentialsArray(t *testing.T) {
	resp := map[string]any{
		"credentials": []any{
			map[string]any{
				"credential": "eyJhbGci-from-array",
			},
		},
	}

	got := extractCredential(resp)
	if got != "eyJhbGci-from-array" {
		t.Errorf("expected eyJhbGci-from-array, got %s", got)
	}
}

func TestExtractCredential_CredentialsArrayRawStrings(t *testing.T) {
	resp := map[string]any{
		"credentials": []any{
			"raw-credential-string",
		},
	}

	got := extractCredential(resp)
	if got != "raw-credential-string" {
		t.Errorf("expected raw-credential-string, got %s", got)
	}
}

func TestExtractCredential_Empty(t *testing.T) {
	resp := map[string]any{
		"status": "ok",
	}

	got := extractCredential(resp)
	if got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestExtractCredential_EmptyCredentialsArray(t *testing.T) {
	resp := map[string]any{
		"credentials": []any{},
	}

	got := extractCredential(resp)
	if got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestBuildCredentialResponseEncryptionRequest(t *testing.T) {
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	metadata := map[string]any{
		"credential_response_encryption": map[string]any{
			"alg_values_supported": []any{"ECDH-ES+A256KW", "ECDH-ES"},
			"enc_values_supported": []any{"A256GCM", "A128GCM"},
		},
	}

	got := buildCredentialResponseEncryptionRequest(metadata, holderKey)
	if got == nil {
		t.Fatal("expected credential response encryption request")
	}
	if got["enc"] != "A128GCM" {
		t.Fatalf("expected preferred enc A128GCM, got %v", got["enc"])
	}
	jwk, ok := got["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("expected jwk object, got %T", got["jwk"])
	}
	if jwk["alg"] != "ECDH-ES" {
		t.Fatalf("expected preferred alg ECDH-ES, got %v", jwk["alg"])
	}
	if jwk["use"] != "enc" {
		t.Fatalf("expected use=enc, got %v", jwk["use"])
	}
}

func TestPrepareCredentialRequestBody_EncryptsWhenIssuerAdvertisesRequestEncryption(t *testing.T) {
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubJWK := mock.PublicKeyJWKMap(&issuerKey.PublicKey)
	encJWK := map[string]any{
		"kty": pubJWK["kty"],
		"crv": pubJWK["crv"],
		"x":   pubJWK["x"],
		"y":   pubJWK["y"],
		"kid": "issuer-enc-key",
		"use": "enc",
		"alg": "ECDH-ES",
	}
	metadata := map[string]any{
		"credential_request_encryption": map[string]any{
			"jwks": map[string]any{
				"keys": []any{encJWK},
			},
			"enc_values_supported": []any{"A256GCM", "A128GCM"},
			"encryption_required":  false,
		},
	}
	reqBody := map[string]any{
		"credential_configuration_id": "test-config",
		"proofs": map[string]any{
			"jwt": []string{"proof-jwt"},
		},
	}

	body, contentType, err := prepareCredentialRequestBody(metadata, reqBody)
	if err != nil {
		t.Fatalf("prepareCredentialRequestBody: %v", err)
	}
	if contentType != "application/jwt" {
		t.Fatalf("contentType = %q, want application/jwt", contentType)
	}
	parts := strings.Split(string(body), ".")
	if len(parts) != 5 {
		t.Fatalf("expected compact JWE with 5 parts, got %d", len(parts))
	}
	headerJSON, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decode JWE header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("parse JWE header: %v", err)
	}
	if header["alg"] != "ECDH-ES" || header["enc"] != "A256GCM" || header["kid"] != "issuer-enc-key" || header["cty"] != "json" {
		t.Fatalf("unexpected JWE header: %v", header)
	}
	decrypted, err := DecryptCompactJWE(string(body), issuerKey)
	if err != nil {
		t.Fatalf("DecryptCompactJWE: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(decrypted), &got); err != nil {
		t.Fatalf("parse decrypted payload: %v", err)
	}
	if got["credential_configuration_id"] != "test-config" {
		t.Fatalf("decrypted credential_configuration_id = %v", got["credential_configuration_id"])
	}
}

func TestParseCredentialResponseBody_EncryptedJWE(t *testing.T) {
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwe, _, err := EncryptJWE([]byte(`{"credential":"encrypted-credential"}`), &holderKey.PublicKey, "kid1", "ECDH-ES", "A128GCM", nil, nil)
	if err != nil {
		t.Fatalf("EncryptJWE: %v", err)
	}

	got, err := parseCredentialResponseBody([]byte(jwe), holderKey)
	if err != nil {
		t.Fatalf("parseCredentialResponseBody: %v", err)
	}
	if got["credential"] != "encrypted-credential" {
		t.Fatalf("expected decrypted credential, got %v", got["credential"])
	}
}

func TestResolveCredentialFormat(t *testing.T) {
	metadata := map[string]any{
		"credential_configurations_supported": map[string]any{
			"pid-sdjwt": map[string]any{
				"format": "dc+sd-jwt",
			},
			"pid-mdoc": map[string]any{
				"format": "mso_mdoc",
			},
		},
	}

	tests := []struct {
		name     string
		configID string
		want     string
	}{
		{"sd-jwt config", "pid-sdjwt", "dc+sd-jwt"},
		{"mdoc config", "pid-mdoc", "mso_mdoc"},
		{"unknown config", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveCredentialFormat(metadata, tt.configID)
			if got != tt.want {
				t.Errorf("resolveCredentialFormat(%s) = %s, want %s", tt.configID, got, tt.want)
			}
		})
	}
}

func TestResolveCredentialFormat_NoConfigs(t *testing.T) {
	metadata := map[string]any{}
	got := resolveCredentialFormat(metadata, "anything")
	if got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestGetTokenEndpoint_DirectInMetadata(t *testing.T) {
	metadata := map[string]any{
		"token_endpoint": "https://issuer.example/token",
	}
	got := getTokenEndpoint(metadata, nil, "https://issuer.example")
	if got != "https://issuer.example/token" {
		t.Errorf("expected direct token_endpoint, got %s", got)
	}
}

func TestGetTokenEndpoint_Fallback(t *testing.T) {
	metadata := map[string]any{}
	got := getTokenEndpoint(metadata, nil, "https://issuer.example")
	// Falls back to issuer + /token when no OAuth metadata can be fetched
	if got != "https://issuer.example/token" {
		t.Errorf("expected fallback token endpoint, got %s", got)
	}
}

func TestGetCredentialEndpoint_DirectInMetadata(t *testing.T) {
	metadata := map[string]any{
		"credential_endpoint": "https://issuer.example/credential",
	}
	got := getCredentialEndpoint(metadata, "https://issuer.example")
	if got != "https://issuer.example/credential" {
		t.Errorf("expected direct credential_endpoint, got %s", got)
	}
}

func TestGetCredentialEndpoint_Fallback(t *testing.T) {
	metadata := map[string]any{}
	got := getCredentialEndpoint(metadata, "https://issuer.example")
	if got != "https://issuer.example/credential" {
		t.Errorf("expected fallback credential endpoint, got %s", got)
	}
}

func TestGetCredentialEndpoint_TrailingSlash(t *testing.T) {
	metadata := map[string]any{}
	got := getCredentialEndpoint(metadata, "https://issuer.example/")
	if got != "https://issuer.example/credential" {
		t.Errorf("expected trimmed trailing slash, got %s", got)
	}
}

func TestGetAuthorizationServer_PreservesTrailingSlash(t *testing.T) {
	got := getAuthorizationServer(map[string]any{}, "https://issuer.example/test/")
	if got != "https://issuer.example/test/" {
		t.Fatalf("expected trailing slash to be preserved, got %s", got)
	}
}

func TestGetAuthorizationServer_FromMetadataPreservesTrailingSlash(t *testing.T) {
	metadata := map[string]any{
		"authorization_servers": []any{"https://issuer.example/authz/"},
	}
	got := getAuthorizationServer(metadata, "https://issuer.example/test/")
	if got != "https://issuer.example/authz/" {
		t.Fatalf("expected authorization_servers entry to be preserved, got %s", got)
	}
}

func TestWellKnownURL_PathlessIssuer(t *testing.T) {
	got, err := wellKnownURL("https://issuer.example", "openid-credential-issuer")
	if err != nil {
		t.Fatalf("wellKnownURL: %v", err)
	}
	if got != "https://issuer.example/.well-known/openid-credential-issuer" {
		t.Fatalf("expected pathless well-known URL, got %s", got)
	}
}

func TestWellKnownURL_PreservesTrailingSlashInIssuerPath(t *testing.T) {
	got, err := wellKnownURL("https://issuer.example/test/issuer/", "openid-credential-issuer")
	if err != nil {
		t.Fatalf("wellKnownURL: %v", err)
	}
	if got != "https://issuer.example/.well-known/openid-credential-issuer/test/issuer/" {
		t.Fatalf("expected trailing slash to be preserved, got %s", got)
	}
}

func TestParseIssuerMetadataResponse_SignedJWT(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}

	raw, err := signCredentialIssuerMetadataJWT(w, w.IssuerURL, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("signing issuer metadata: %v", err)
	}

	metadata, err := parseIssuerMetadataResponse([]byte(raw), "application/openidvci-issuer-metadata+jwt")
	if err != nil {
		t.Fatalf("parsing signed issuer metadata: %v", err)
	}
	if metadata["credential_issuer"] != w.IssuerURL {
		t.Fatalf("expected credential_issuer %s, got %v", w.IssuerURL, metadata["credential_issuer"])
	}

	issuerInfo, ok := metadata["issuer_info"].([]any)
	if !ok || len(issuerInfo) != 1 {
		t.Fatalf("expected single issuer_info entry, got %v", metadata["issuer_info"])
	}
	entry, ok := issuerInfo[0].(map[string]any)
	if !ok {
		t.Fatalf("expected issuer_info object, got %T", issuerInfo[0])
	}
	if entry["format"] != "registrar_dataset" {
		t.Fatalf("expected registrar_dataset issuer_info, got %v", entry["format"])
	}
	record, ok := entry["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected issuer_info data object, got %T", entry["data"])
	}
	if record["registryURI"] != w.IssuerURL+"/api/registrar/wrp" {
		t.Fatalf("expected registryURI %s, got %v", w.IssuerURL+"/api/registrar/wrp", record["registryURI"])
	}
	provides, ok := record["providesAttestations"].([]any)
	if !ok || len(provides) != 2 {
		t.Fatalf("expected 2 providesAttestations entries, got %v", record["providesAttestations"])
	}
}

func TestParseIssuerMetadataResponse_RejectsTamperedSignedJWT(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}

	raw, err := signCredentialIssuerMetadataJWT(w, w.IssuerURL, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("signing issuer metadata: %v", err)
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", raw)
	}
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	tamperedPayload := strings.Replace(string(payloadBytes), mock.DefaultPIDVCT, "urn:example:tampered", 1)
	if tamperedPayload == string(payloadBytes) {
		t.Fatal("expected signed issuer metadata payload to contain default PID VCT")
	}
	parts[1] = format.EncodeBase64URL([]byte(tamperedPayload))
	tampered := strings.Join(parts, ".")

	if _, err := parseIssuerMetadataResponse([]byte(tampered), "application/openidvci-issuer-metadata+jwt"); err == nil {
		t.Fatal("expected tampered signed issuer metadata to fail verification")
	}
}

func TestParseIssuerMetadataResponse_JSONWithDots(t *testing.T) {
	raw := []byte(`{
		"credential_issuer":"http://localhost:8080/realms/wallet-app-demo",
		"credential_configurations_supported":{
			"membership-credential":{
				"format":"dc+sd-jwt",
				"vct":"https://credentials.example.com/membership"
			}
		}
	}`)

	metadata, err := parseIssuerMetadataResponse(raw, "application/json")
	if err != nil {
		t.Fatalf("parsing metadata JSON: %v", err)
	}
	if metadata["credential_issuer"] != "http://localhost:8080/realms/wallet-app-demo" {
		t.Fatalf("unexpected credential_issuer: %v", metadata["credential_issuer"])
	}
}
