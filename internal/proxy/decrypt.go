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

package proxy

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jwe"
)

// DecryptJWEWithCEK decrypts a JWE compact serialization using the provided
// content encryption key (CEK). The CEK is the raw AES key bytes that were
// derived during ECDH-ES key agreement.
// This is intended for debugging: the wallet includes the CEK in a debug
// header so the proxy can decrypt JARM responses.
// DecryptJWEWithCEK decrypts a compact JWE whose content encryption key is
// already known.
func DecryptJWEWithCEK(compact string, cek []byte) ([]byte, error) {
	return jwe.DecryptWithCEK(compact, cek)
}

// DecryptJWEWithJWK decrypts a compact JWE addressed to the EC private key in
// jwkJSON.
func DecryptJWEWithJWK(compact string, jwkJSON string) ([]byte, error) {
	key, err := parseECPrivateKeyJWK(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing JWK private key: %w", err)
	}
	return jwe.Decrypt(compact, key)
}

// parseECPrivateKeyJWK parses an EC private key from a JWK JSON string.
func parseECPrivateKeyJWK(jwkJSON string) (*ecdh.PrivateKey, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		D   string `json:"d"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		return nil, err
	}
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	dBytes, err := format.DecodeBase64URL(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("decoding d: %w", err)
	}

	return ecdh.P256().NewPrivateKey(dBytes)
}
