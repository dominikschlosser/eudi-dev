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
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// CreateSelfIssuedIDToken creates a SIOPv2 self-issued ID token JWT signed by the wallet's holder key.
func (w *Wallet) CreateSelfIssuedIDToken(nonce, clientID string) (string, error) {
	subJWK := mock.PublicKeyJWKMap(&w.HolderKey.PublicKey)
	thumbprint, err := jwkThumbprint(&w.HolderKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("computing JWK thumbprint: %w", err)
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"jwk": subJWK,
	}

	now := time.Now()
	payload := map[string]any{
		"iss":     "https://self-issued.me/v2",
		"sub":     thumbprint,
		"aud":     clientID,
		"nonce":   nonce,
		"iat":     now.Unix(),
		"exp":     now.Add(5 * time.Minute).Unix(),
		"sub_jwk": subJWK,
	}

	return signJWT(header, payload, w.HolderKey)
}

// jwkThumbprint computes the JWK thumbprint per RFC 7638 for a P-256 public key.
// The thumbprint is the base64url-encoded SHA-256 hash of the canonical JWK representation
// with members sorted lexicographically: {"crv","kty","x","y"}.
func jwkThumbprint(key *ecdsa.PublicKey) (string, error) {
	jwk := mock.PublicKeyJWKMap(key)

	// RFC 7638: canonical form uses sorted required members only
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`,
		jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])

	h := sha256.Sum256([]byte(canonical))
	return format.EncodeBase64URL(h[:]), nil
}

// ResponseTypeContains checks if a space-separated response_type string contains the given value.
func ResponseTypeContains(responseType, target string) bool {
	for _, rt := range strings.Fields(responseType) {
		if rt == target {
			return true
		}
	}
	return false
}

// ResponseTypeRequiresVP reports whether a request requires a vp_token response.
// Empty response_type defaults to vp_token per the current wallet behavior.
func ResponseTypeRequiresVP(responseType string) bool {
	return responseType == "" || ResponseTypeContains(responseType, "vp_token")
}
