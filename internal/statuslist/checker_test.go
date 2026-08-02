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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

func TestExtractStatusRef(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		want   *StatusRef
	}{
		{
			"valid ref",
			map[string]any{
				"status": map[string]any{
					"status_list": map[string]any{
						"uri": "https://example.com/status",
						"idx": float64(42),
					},
				},
			},
			&StatusRef{URI: "https://example.com/status", Idx: 42},
		},
		{
			"no status field",
			map[string]any{"iss": "test"},
			nil,
		},
		{
			"no status_list",
			map[string]any{
				"status": map[string]any{"other": "value"},
			},
			nil,
		},
		{
			"empty uri",
			map[string]any{
				"status": map[string]any{
					"status_list": map[string]any{
						"uri": "",
						"idx": float64(0),
					},
				},
			},
			nil,
		},
		{
			"int64 idx",
			map[string]any{
				"status": map[string]any{
					"status_list": map[string]any{
						"uri": "https://example.com/status",
						"idx": int64(7),
					},
				},
			},
			&StatusRef{URI: "https://example.com/status", Idx: 7},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractStatusRef(tt.claims)
			if tt.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			if got.URI != tt.want.URI || got.Idx != tt.want.Idx {
				t.Errorf("got {URI:%q, Idx:%d}, want {URI:%q, Idx:%d}", got.URI, got.Idx, tt.want.URI, tt.want.Idx)
			}
		})
	}
}

func TestExtractStatus(t *testing.T) {
	// Build a bitstring: byte 0 = 0b00000101 (idx 0 = 1, idx 1 = 0, idx 2 = 1)
	bitstring := []byte{0x05, 0x00}

	tests := []struct {
		idx  int
		bits int
		want int
	}{
		{0, 1, 1},
		{1, 1, 0},
		{2, 1, 1},
		{3, 1, 0},
		{8, 1, 0},
	}
	for _, tt := range tests {
		got, err := extractStatus(bitstring, tt.idx, tt.bits)
		if err != nil {
			t.Errorf("extractStatus(idx=%d) error: %v", tt.idx, err)
			continue
		}
		if got != tt.want {
			t.Errorf("extractStatus(idx=%d, bits=%d) = %d, want %d", tt.idx, tt.bits, got, tt.want)
		}
	}
}

func TestExtractStatus_TwoBits(t *testing.T) {
	// 2-bit status: byte 0 = 0b00001001 = idx0=01, idx1=00, idx2=10, idx3=00
	bitstring := []byte{0x09}

	tests := []struct {
		idx  int
		want int
	}{
		{0, 1},
		{1, 2},
		{2, 0},
		{3, 0},
	}
	for _, tt := range tests {
		got, err := extractStatus(bitstring, tt.idx, 2)
		if err != nil {
			t.Errorf("extractStatus(idx=%d) error: %v", tt.idx, err)
			continue
		}
		if got != tt.want {
			t.Errorf("extractStatus(idx=%d, bits=2) = %d, want %d", tt.idx, got, tt.want)
		}
	}
}

func TestExtractStatus_OutOfRange(t *testing.T) {
	bitstring := []byte{0x00}
	_, err := extractStatus(bitstring, 100, 1)
	if err == nil {
		t.Error("expected out of range error")
	}
}

func TestCheck_WithMockServer(t *testing.T) {
	// Create a status list bitstring: all zeros (all valid)
	bitstring := make([]byte, 16)
	// Set index 5 to revoked (bit 5 = 1)
	bitstring[0] = 1 << 5

	// Compress with zlib
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(bitstring)
	w.Close()

	lst := base64.RawURLEncoding.EncodeToString(buf.Bytes())

	payload := map[string]any{
		"status_list": map[string]any{
			"bits": float64(1),
			"lst":  lst,
		},
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	statusJWT := "eyJhbGciOiJub25lIn0." + payloadB64 + "."

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		w.Write([]byte(statusJWT))
	}))
	defer server.Close()

	// Test valid credential (index 0)
	result, err := Check(&StatusRef{URI: server.URL, Idx: 0})
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !result.IsValid {
		t.Errorf("index 0: expected valid, got status=%d", result.Status)
	}

	// Test revoked credential (index 5)
	result, err = Check(&StatusRef{URI: server.URL, Idx: 5})
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if result.IsValid {
		t.Errorf("index 5: expected revoked, got status=%d", result.Status)
	}
	if result.Status != 1 {
		t.Errorf("index 5: status = %d, want 1", result.Status)
	}
}

func TestCheck_WithLocalTLSServer(t *testing.T) {
	bitstring := make([]byte, 16)

	jwt, err := GenerateStatusListJWT(bitstring, mustGenerateKey(t), StatusListConfig{
		URI: "https://127.0.0.1/status",
	})
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte(jwt))
	}))
	defer server.Close()

	result, err := Check(&StatusRef{URI: server.URL, Idx: 0})
	if err != nil {
		t.Fatalf("Check() against local TLS server: %v", err)
	}
	if !result.IsValid {
		t.Fatalf("expected valid status, got %d", result.Status)
	}
}

func TestCheck_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	_, err := Check(&StatusRef{URI: server.URL, Idx: 0})
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func mustGenerateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestCheckWithOptions_SignatureVerification(t *testing.T) {
	// Generate issuer key and cert chain (like the wallet does)
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := mock.GenerateLeafCert(caKey, caCert, &issuerKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a status list JWT with x5c chain
	bitstring := make([]byte, 16)
	statusJWT, err := GenerateStatusListJWT(bitstring, issuerKey, StatusListConfig{
		URI:       "https://example.com/statuslists/1",
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Serve it
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		w.Write([]byte(statusJWT))
	}))
	defer server.Close()

	// Check with trust list containing the CA cert
	opts := CheckOptions{
		TrustListCerts: []TrustCert{{Raw: caCert.Raw}},
	}
	result, err := CheckWithOptions(&StatusRef{URI: server.URL, Idx: 0}, opts)
	if err != nil {
		t.Fatalf("CheckWithOptions error: %v", err)
	}
	if result.SignatureValid == nil {
		t.Fatal("expected SignatureValid to be set")
	}
	if !*result.SignatureValid {
		t.Errorf("expected valid signature, got info: %s", result.SignatureInfo)
	}
	if result.IsValid != true {
		t.Errorf("expected status valid, got %d", result.Status)
	}
}

func TestCheckWithOptions_UntrustedCert(t *testing.T) {
	// Generate issuer key and cert chain
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := mock.GenerateLeafCert(caKey, caCert, &issuerKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a DIFFERENT CA (not in trust list)
	otherCAKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherCACert, err := mock.GenerateCACert(otherCAKey)
	if err != nil {
		t.Fatal(err)
	}

	bitstring := make([]byte, 16)
	statusJWT, err := GenerateStatusListJWT(bitstring, issuerKey, StatusListConfig{
		URI:       "https://example.com/statuslists/1",
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(statusJWT))
	}))
	defer server.Close()

	// Check with a trust list that does NOT contain the signing CA
	opts := CheckOptions{
		TrustListCerts: []TrustCert{{Raw: otherCACert.Raw}},
	}
	result, err := CheckWithOptions(&StatusRef{URI: server.URL, Idx: 0}, opts)
	if err != nil {
		t.Fatalf("CheckWithOptions error: %v", err)
	}
	if result.SignatureValid == nil {
		t.Fatal("expected SignatureValid to be set")
	}
	if *result.SignatureValid {
		t.Error("expected signature validation to fail with untrusted CA")
	}
}

func TestCheckWithOptions_NoX5C(t *testing.T) {
	// Status list JWT without x5c should report signature invalid when trust list provided
	bitstring := make([]byte, 16)
	key := generateTestKey(t)
	statusJWT, err := GenerateStatusListJWT(bitstring, key, StatusListConfig{URI: "https://example.com/statuslists/1"}) // no cert chain
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(statusJWT))
	}))
	defer server.Close()

	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}

	opts := CheckOptions{
		TrustListCerts: []TrustCert{{Raw: caCert.Raw}},
	}
	result, err := CheckWithOptions(&StatusRef{URI: server.URL, Idx: 0}, opts)
	if err != nil {
		t.Fatalf("CheckWithOptions error: %v", err)
	}
	if result.SignatureValid == nil {
		t.Fatal("expected SignatureValid to be set")
	}
	if *result.SignatureValid {
		t.Error("expected signature invalid when no x5c in status list JWT")
	}
	if result.SignatureInfo != "no x5c header in status list JWT" {
		t.Errorf("unexpected info: %s", result.SignatureInfo)
	}
}

func TestZlibDecompress(t *testing.T) {
	data := []byte("hello world")

	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(data)
	w.Close()

	got, err := zlibDecompress(buf.Bytes())
	if err != nil {
		t.Fatalf("zlibDecompress() error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}
}
