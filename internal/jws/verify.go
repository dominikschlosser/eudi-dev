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

package jws

import (
	"crypto"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
)

// SupportedAlgorithms are the signature algorithms this toolkit verifies. The
// list is passed to every parse rather than inferred from the token, so a
// token cannot choose how it is checked. "none" is deliberately absent.
var SupportedAlgorithms = []josev4.SignatureAlgorithm{
	josev4.ES256, josev4.ES384, josev4.ES512,
	josev4.RS256, josev4.RS384, josev4.RS512,
	josev4.PS256, josev4.PS384, josev4.PS512,
}

// Verify checks a compact JWS against key and returns its payload. It is the
// one copy of this: the fixed-width r||s encoding and the algorithm-to-hash
// mapping are easy to get subtly wrong per package.
func Verify(compact string, key crypto.PublicKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("verification requires a public key")
	}
	parsed, err := josev4.ParseSigned(compact, SupportedAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("parsing JWS: %w", err)
	}
	payload, err := parsed.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	return payload, nil
}

// Valid reports whether a compact JWS verifies against key. It is the form
// the callers that only branch on the outcome want.
func Valid(compact string, key crypto.PublicKey) bool {
	_, err := Verify(compact, key)
	return err == nil
}
