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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSignVerifies(t *testing.T) {
	key := testKey(t)
	token, err := Sign(map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{"iss": "https://issuer.example"}, key)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected three JWS parts, got %d", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Error("the signature does not verify against the signing key")
	}
}

// A signature whose r or s is left unpadded is shorter than P-256 requires,
// which some verifiers accept and others reject. Small values are where that
// shows up, so sign until one turns up rather than trusting a single run.
func TestSignatureIsAlwaysFullWidth(t *testing.T) {
	key := testKey(t)
	for i := range 200 {
		digest := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		sig, err := Signature(key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 64 {
			t.Fatalf("signature %d is %d bytes, want 64", i, len(sig))
		}
	}
}

func TestSignRejectsAMissingKey(t *testing.T) {
	if _, err := Sign(map[string]any{"alg": "ES256"}, map[string]any{}, nil); err == nil {
		t.Error("signing without a key was accepted")
	}
}
