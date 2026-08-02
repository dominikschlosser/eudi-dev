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
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/trustlist"
)

func newIssuerMetadataServer(t *testing.T, issuer string, jwks []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer,
			"jwks":   map[string]any{"keys": jwks},
		})
	}))
}

func TestVerifyJWTSignature_UsesIssuerMetadata(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	srv := newIssuerMetadataServer(t, "", nil)
	defer srv.Close()

	issuer := srv.URL
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer,
			"jwks":   map[string]any{"keys": []any{mock.SigningJWKMap(&key.PublicKey)}},
		})
	})

	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    issuer,
		VCT:       "urn:test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	result, source, err := VerifyJWTSignature(token, nil, nil)
	if err != nil {
		t.Fatalf("VerifyJWTSignature: %v", err)
	}
	if result == nil {
		t.Fatal("expected verify result")
	}
	if !result.SignatureValid {
		t.Fatalf("expected signature valid, got errors: %v", result.Errors)
	}
	if !strings.Contains(source, "issuer metadata") {
		t.Fatalf("expected issuer metadata source, got %q", source)
	}
}

// newX5CToken builds a signed SD-JWT that carries its certificate chain and
// points at an unreachable issuer, so any network lookup would fail.
func newX5CToken(t *testing.T) (*sdjwt.Token, []trustlist.CertInfo) {
	t.Helper()
	caCert, caKey, caDER := generateCACert(t)
	leafCert, leafKey, _ := generateLeafCert(t, caCert, caKey)

	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://localhost:1",
		VCT:       "urn:test:x5c",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       leafKey,
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}
	anchors := []trustlist.CertInfo{{PublicKey: caCert.PublicKey, Raw: caDER}}
	return token, anchors
}

func TestVerifyJWTSignature_X5CLeafOfflineWithoutTrustList(t *testing.T) {
	token, _ := newX5CToken(t)

	// No keys and no trust list: the embedded leaf certificate verifies the
	// signature without any network access (the issuer URL is unreachable).
	result, source, err := VerifyJWTSignature(token, nil, nil)
	if err != nil {
		t.Fatalf("VerifyJWTSignature: %v", err)
	}
	if result == nil || !result.SignatureValid {
		t.Fatalf("expected valid signature via x5c leaf, got %+v", result)
	}
	if source != SourceX5CLeaf {
		t.Fatalf("expected source %q, got %q", SourceX5CLeaf, source)
	}
}

func TestVerifyJWTSignature_X5CChainOutranksLeaf(t *testing.T) {
	token, anchors := newX5CToken(t)

	result, source, err := VerifyJWTSignature(token, nil, anchors)
	if err != nil {
		t.Fatalf("VerifyJWTSignature: %v", err)
	}
	if result == nil || !result.SignatureValid {
		t.Fatalf("expected valid signature via x5c chain, got %+v", result)
	}
	if source != "x5c chain" {
		t.Fatalf("expected x5c chain source, got %q", source)
	}
}

func TestVerifyJWTSignature_UnmatchedTrustListDoesNotFallBackToLeaf(t *testing.T) {
	token, _ := newX5CToken(t)

	// An explicit trust list that does not anchor the chain must not be
	// silently downgraded to a leaf-only pass. The issuer is unreachable, so
	// verification errors instead.
	otherCA, _, otherDER := generateCACert(t)
	foreign := []trustlist.CertInfo{{PublicKey: otherCA.PublicKey, Raw: otherDER}}

	result, source, err := VerifyJWTSignature(token, nil, foreign)
	if err == nil && result != nil && result.SignatureValid && source == SourceX5CLeaf {
		t.Fatal("leaf-only pass despite an explicit trust list")
	}
}
