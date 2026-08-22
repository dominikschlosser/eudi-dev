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

package mock

import (
	"crypto/elliptic"
	"encoding/json"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/keys"
)

func TestGenerateKey_ReturnsP256(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %s", key.Curve.Params().Name)
	}
}

func TestGenerateKey_UniqueKeys(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key1.Equal(key2) {
		t.Error("two generated keys should not be identical")
	}
}

func TestPublicKeyJWK_ValidJSON(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwkStr := PublicKeyJWK(&key.PublicKey)

	var jwk map[string]string
	if err := json.Unmarshal([]byte(jwkStr), &jwk); err != nil {
		t.Fatalf("PublicKeyJWK returned invalid JSON: %v", err)
	}

	if jwk["kty"] != "EC" {
		t.Errorf("expected kty EC, got %s", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("expected crv P-256, got %s", jwk["crv"])
	}
	if jwk["x"] == "" {
		t.Error("missing x coordinate")
	}
	if jwk["y"] == "" {
		t.Error("missing y coordinate")
	}
	if _, ok := jwk["d"]; ok {
		t.Error("public JWK should not contain d parameter")
	}
}

func TestPublicKeyJWK_RoundTripParse(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwkStr := PublicKeyJWK(&key.PublicKey)

	parsed, err := keys.ParsePublicKey([]byte(jwkStr))
	if err != nil {
		t.Fatalf("ParsePublicKey from JWK: %v", err)
	}

	if parsed == nil {
		t.Fatal("parsed key is nil")
	}
}

func TestPrivateKeyJWK_ValidJSON(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwkStr := PrivateKeyJWK(key)

	var jwk map[string]string
	if err := json.Unmarshal([]byte(jwkStr), &jwk); err != nil {
		t.Fatalf("PrivateKeyJWK returned invalid JSON: %v", err)
	}

	if jwk["kty"] != "EC" {
		t.Errorf("expected kty EC, got %s", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("expected crv P-256, got %s", jwk["crv"])
	}
	if jwk["x"] == "" {
		t.Error("missing x coordinate")
	}
	if jwk["y"] == "" {
		t.Error("missing y coordinate")
	}
	if jwk["d"] == "" {
		t.Error("private JWK should contain d parameter")
	}
}

func TestPrivateKeyJWK_RoundTripParse(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwkStr := PrivateKeyJWK(key)

	parsed, err := keys.ParsePrivateKey([]byte(jwkStr))
	if err != nil {
		t.Fatalf("ParsePrivateKey from JWK: %v", err)
	}

	if parsed == nil {
		t.Fatal("parsed key is nil")
	}
}
