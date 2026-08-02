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

package validate

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/trustlist"
)

// CanResolveJWTIssuerMetadata reports whether the token has enough information
// for kid-based issuer metadata key resolution.
func CanResolveJWTIssuerMetadata(token *sdjwt.Token) bool {
	if token == nil {
		return false
	}
	iss, _ := token.Payload["iss"].(string)
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(iss)), "https://") {
		return false
	}
	kid, _ := token.Header["kid"].(string)
	if strings.TrimSpace(kid) == "" {
		return false
	}
	alg, _ := token.Header["alg"].(string)
	if strings.EqualFold(strings.TrimSpace(alg), "none") {
		return false
	}
	return len(token.Signature) > 0
}

// ResolveJWTIssuerMetadataKey resolves a signing key from the issuer metadata
// endpoint referenced by the token's iss claim and kid header.
func ResolveJWTIssuerMetadataKey(token *sdjwt.Token, tlCerts []trustlist.CertInfo) (crypto.PublicKey, string, error) {
	if !CanResolveJWTIssuerMetadata(token) {
		return nil, "", nil
	}

	iss, _ := token.Payload["iss"].(string)
	kid, _ := token.Header["kid"].(string)
	metadataURL := strings.TrimRight(strings.TrimSpace(iss), "/") + "/.well-known/jwt-vc-issuer"

	doc, err := fetchIssuerMetadataDocument(metadataURL)
	if err != nil {
		return nil, "", fmt.Errorf("fetching issuer metadata: %w", err)
	}
	if issuer, _ := doc["issuer"].(string); issuer != "" && strings.TrimRight(issuer, "/") != strings.TrimRight(iss, "/") {
		return nil, "", fmt.Errorf("issuer metadata issuer mismatch: got %s want %s", issuer, iss)
	}

	jwk, err := findIssuerMetadataJWK(doc, kid)
	if err != nil {
		return nil, "", err
	}

	if len(tlCerts) > 0 {
		if key, err := extractAndValidateJWKX5C(jwk, tlCerts); err == nil && key != nil {
			return key, "issuer metadata (x5c chain verified)", nil
		}
	}

	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return nil, "", fmt.Errorf("encoding issuer JWK: %w", err)
	}
	key, err := keys.ParsePublicKey(jwkJSON)
	if err != nil {
		return nil, "", fmt.Errorf("parsing issuer JWK: %w", err)
	}
	return key, "issuer metadata", nil
}

// VerifyJWTSignature verifies the token signature using, in order:
// x5c + trust list, explicitly provided keys, then kid-based issuer metadata.
func VerifyJWTSignature(token *sdjwt.Token, pubKeys []crypto.PublicKey, tlCerts []trustlist.CertInfo) (*sdjwt.VerifyResult, string, error) {
	if token == nil {
		return nil, "", fmt.Errorf("token is nil")
	}

	if x5cKey, err := ExtractAndValidateX5C(token.Header, tlCerts); err == nil && x5cKey != nil {
		return sdjwt.Verify(token, x5cKey), "x5c chain", nil
	}

	var best *sdjwt.VerifyResult
	for _, key := range pubKeys {
		result := sdjwt.Verify(token, key)
		best = result
		if result.SignatureValid {
			return result, "provided key", nil
		}
	}
	if best != nil {
		if key, source, err := ResolveJWTIssuerMetadataKey(token, tlCerts); err == nil && key != nil {
			result := sdjwt.Verify(token, key)
			if result.SignatureValid {
				return result, source, nil
			}
		}
		return best, "provided key", nil
	}

	key, source, err := ResolveJWTIssuerMetadataKey(token, tlCerts)
	if err != nil {
		return nil, "", err
	}
	if key == nil {
		return nil, "", nil
	}
	return sdjwt.Verify(token, key), source, nil
}

func fetchIssuerMetadataDocument(metadataURL string) (map[string]any, error) {
	req, err := http.NewRequest("GET", metadataURL, nil)
	if err != nil {
		return nil, err
	}
	// Some issuers (e.g. Procivis One) reject requests without an Accept header.
	req.Header.Set("Accept", "application/json")
	resp, err := format.HTTPClientForURL(metadataURL).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("issuer metadata request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parsing issuer metadata: %w", err)
	}
	return doc, nil
}

func findIssuerMetadataJWK(doc map[string]any, kid string) (map[string]any, error) {
	jwks, ok := doc["jwks"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("issuer metadata does not contain jwks")
	}
	keysRaw, ok := jwks["keys"].([]any)
	if !ok || len(keysRaw) == 0 {
		return nil, fmt.Errorf("issuer metadata does not contain jwks.keys")
	}

	var first map[string]any
	for _, raw := range keysRaw {
		jwk, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if first == nil {
			first = jwk
		}
		if keyKid, _ := jwk["kid"].(string); strings.TrimSpace(keyKid) == strings.TrimSpace(kid) {
			return jwk, nil
		}
	}
	if strings.TrimSpace(kid) == "" && first != nil {
		return first, nil
	}
	return nil, fmt.Errorf("no issuer metadata JWK found for kid %s", kid)
}

func extractAndValidateJWKX5C(jwk map[string]any, tlCerts []trustlist.CertInfo) (crypto.PublicKey, error) {
	x5cRaw, ok := jwk["x5c"]
	if !ok || len(tlCerts) == 0 {
		return nil, nil
	}

	entries, err := normalizeX5CEntries(x5cRaw)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	certs := make([]*x509.Certificate, 0, len(entries))
	for _, b64 := range entries {
		der, err := format.DecodeBase64Std(b64)
		if err != nil {
			return nil, fmt.Errorf("decoding jwk x5c certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing jwk x5c certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return ValidateCertChain(certs, tlCerts)
}

func normalizeX5CEntries(raw any) ([]string, error) {
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, entry := range v {
			s, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("x5c entry is not a string")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("x5c is not an array")
	}
}
