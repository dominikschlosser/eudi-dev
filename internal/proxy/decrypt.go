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
	"crypto/ecdsa"
	"fmt"

	"github.com/dominikschlosser/eudi-dev/internal/jwe"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
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
// The decoding is shared with the rest of the toolkit, which is what keeps
// this from being a fourth opinion on what a JWK looks like.
func parseECPrivateKeyJWK(jwkJSON string) (*ecdh.PrivateKey, error) {
	parsed, err := keys.ParseJWKPrivate([]byte(jwkJSON))
	if err != nil {
		return nil, err
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type: %T", parsed)
	}
	return ecKey.ECDH()
}
