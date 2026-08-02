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

package statuslist

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

func TestGenerateStatusListJWT_ValidStructure(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)

	cfg := StatusListConfig{
		URI:    "https://example.com/statuslists/1",
		Issuer: "https://example.com",
	}
	jwt, err := GenerateStatusListJWT(bitstring, key, cfg)
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// Check header
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parsing header: %v", err)
	}
	if header["alg"] != "ES256" {
		t.Errorf("expected alg ES256, got %v", header["alg"])
	}
	if header["typ"] != "statuslist+jwt" {
		t.Errorf("expected typ statuslist+jwt, got %v", header["typ"])
	}

	// Check payload
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	if payload["sub"] != "https://example.com/statuslists/1" {
		t.Errorf("expected sub=https://example.com/statuslists/1, got %v", payload["sub"])
	}
	if payload["iss"] != "https://example.com" {
		t.Errorf("expected iss=https://example.com, got %v", payload["iss"])
	}
	if payload["ttl"] != float64(43200) {
		t.Errorf("expected default ttl=43200, got %v", payload["ttl"])
	}

	sl, ok := payload["status_list"].(map[string]any)
	if !ok {
		t.Fatal("missing status_list in payload")
	}
	if sl["bits"] != float64(1) {
		t.Errorf("expected bits=1, got %v", sl["bits"])
	}
	if _, ok := sl["lst"].(string); !ok {
		t.Fatal("missing lst in status_list")
	}
}

func TestGenerateStatusListJWT_RoundTrip(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)
	// Set index 3 to revoked
	bitstring[0] = 1 << 3

	jwt, err := GenerateStatusListJWT(bitstring, key, StatusListConfig{URI: "https://example.com/statuslists/1"})
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	// Parse the JWT payload
	parts := strings.SplitN(jwt, ".", 3)
	payloadBytes, _ := format.DecodeBase64URL(parts[1])
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)

	sl := payload["status_list"].(map[string]any)
	lst := sl["lst"].(string)

	// Decode and decompress
	compressed, err := format.DecodeBase64URL(lst)
	if err != nil {
		t.Fatalf("decoding lst: %v", err)
	}

	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("zlib reader: %v", err)
	}
	decompressed, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("decompressing: %v", err)
	}

	// Verify bitstring matches
	if len(decompressed) != len(bitstring) {
		t.Fatalf("decompressed length %d != original %d", len(decompressed), len(bitstring))
	}
	if !bytes.Equal(decompressed, bitstring) {
		t.Error("decompressed bitstring does not match original")
	}

	// Check index 3 is revoked
	status, err := extractStatus(decompressed, 3, 1)
	if err != nil {
		t.Fatalf("extractStatus: %v", err)
	}
	if status != 1 {
		t.Errorf("expected index 3 to be revoked (1), got %d", status)
	}

	// Check index 0 is valid
	status, err = extractStatus(decompressed, 0, 1)
	if err != nil {
		t.Fatalf("extractStatus: %v", err)
	}
	if status != 0 {
		t.Errorf("expected index 0 to be valid (0), got %d", status)
	}
}

func TestGenerateStatusListJWT_AllZeros(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)

	jwt, err := GenerateStatusListJWT(bitstring, key, StatusListConfig{URI: "https://example.com/statuslists/1"})
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	if jwt == "" {
		t.Fatal("expected non-empty JWT")
	}
}

func TestGenerateStatusListJWT_WithCertChain(t *testing.T) {
	key := generateTestKey(t)

	// Generate a CA cert and leaf cert like the wallet does
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := mock.GenerateLeafCert(caKey, caCert, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	bitstring := make([]byte, 16)
	jwt, err := GenerateStatusListJWT(bitstring, key, StatusListConfig{
		URI:       "https://example.com/statuslists/1",
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatalf("GenerateStatusListJWT with cert chain: %v", err)
	}

	// Parse header and verify x5c is present
	parts := strings.SplitN(jwt, ".", 3)
	headerBytes, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerBytes, &header)

	x5c, ok := header["x5c"].([]any)
	if !ok {
		t.Fatal("expected x5c array in header")
	}
	if len(x5c) != 2 {
		t.Fatalf("expected 2 certificates in x5c, got %d", len(x5c))
	}

	// First cert should be the leaf, second the CA
	if _, ok := x5c[0].(string); !ok {
		t.Error("expected string certificate in x5c[0]")
	}
	if _, ok := x5c[1].(string); !ok {
		t.Error("expected string certificate in x5c[1]")
	}
}

func TestGenerateStatusListJWT_WithoutCertChain(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)

	jwt, err := GenerateStatusListJWT(bitstring, key, StatusListConfig{URI: "https://example.com/statuslists/1"})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	headerBytes, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerBytes, &header)

	if header["x5c"] != nil {
		t.Error("expected no x5c when cert chain not provided")
	}
}
