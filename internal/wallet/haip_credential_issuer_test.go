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
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// The check has to see a real credential the same way the issuance flow does:
// parse it, find the chain in the x5c header, and compare against iss.
func TestHAIPCredentialIssuerViolationsOnRealCredentials(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"

	chain, err := w.SigningCertChainForIssuedAttestation(IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: mock.DefaultPIDVCT})
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	sameNames := func() []string { return chain[0].DNSNames }

	// What this wallet issues: the leaf names the issuer, so nothing to report.
	bound, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       mock.DefaultPIDVCT,
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "ERIKA"},
		Key:       w.IssuerKey,
		CertChain: chain,
	})
	if err != nil {
		t.Fatalf("generating a bound credential: %v", err)
	}
	if got := w.haipCredentialIssuerViolations(bound); len(got) > 0 {
		t.Errorf("a credential whose leaf names %v reported %v", sameNames(), got)
	}

	// What an issuer that leaves the leaf unnamed produces, which is what a
	// conformant verifier refuses.
	unnamedLeaf, err := mock.GenerateLeafCert(w.CAKey, w.CertChain[len(w.CertChain)-1], &w.IssuerKey.PublicKey)
	if err != nil {
		t.Fatalf("generating a leaf without names: %v", err)
	}
	unbound, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       mock.DefaultPIDVCT,
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "ERIKA"},
		Key:       w.IssuerKey,
		CertChain: []*x509.Certificate{unnamedLeaf, w.CertChain[len(w.CertChain)-1]},
	})
	if err != nil {
		t.Fatalf("generating an unbound credential: %v", err)
	}
	got := w.haipCredentialIssuerViolations(unbound)
	if len(got) != 1 {
		t.Fatalf("expected one violation, got %v", got)
	}
	if !strings.Contains(got[0], "https://issuer.example") {
		t.Errorf("the violation does not name the issuer it could not bind: %q", got[0])
	}

	// An issuer whose key comes from its metadata carries no x5c, and this
	// check is not the one that binds it.
	noChain, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       mock.DefaultPIDVCT,
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "ERIKA"},
		Key:       w.IssuerKey,
	})
	if err != nil {
		t.Fatalf("generating a credential without a chain: %v", err)
	}
	if got := w.haipCredentialIssuerViolations(noChain); len(got) > 0 {
		t.Errorf("a credential without x5c reported %v", got)
	}
}

// The profile decides whether the check runs, the mode decides what a finding
// does. A wallet not asked for HAIP says nothing about a credential another
// issuer bound loosely, which is the difference between a profile check and a
// protocol one.
func TestIssuanceHAIPCredentialIssuerGating(t *testing.T) {
	unboundCredential := func(t *testing.T, w *Wallet) string {
		t.Helper()
		leaf, err := mock.GenerateLeafCert(w.CAKey, w.CertChain[len(w.CertChain)-1], &w.IssuerKey.PublicKey)
		if err != nil {
			t.Fatalf("generating a leaf without names: %v", err)
		}
		cred, err := mock.GenerateSDJWT(mock.SDJWTConfig{
			Issuer:    "https://test-issuer.example",
			VCT:       "TestIssuedCred",
			ExpiresIn: 24 * time.Hour,
			Claims:    map[string]any{"given_name": "Test"},
			Key:       w.IssuerKey,
			HolderKey: &w.HolderKey.PublicKey,
			CertChain: []*x509.Certificate{leaf, w.CertChain[len(w.CertChain)-1]},
		})
		if err != nil {
			t.Fatalf("generating an unbound credential: %v", err)
		}
		return cred
	}

	const finding = "named by no subject alternative name"

	t.Run("silent without HAIP", func(t *testing.T) {
		w := generateTestWallet(t)
		srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
			credentialResponse: map[string]any{"credentials": []any{map[string]any{"credential": unboundCredential(t, w)}}},
		})
		defer srv.Close()

		if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
			t.Fatalf("ProcessCredentialOffer: %v", err)
		}
		if hasWarningContaining(w, finding) {
			t.Error("a wallet not asked for HAIP reported a HAIP finding")
		}
	})

	t.Run("warns in debug", func(t *testing.T) {
		w := generateTestWallet(t)
		w.RequireHAIP = true
		w.ValidationMode = ValidationModeDebug
		srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
			credentialResponse: map[string]any{"credentials": []any{map[string]any{"credential": unboundCredential(t, w)}}},
		})
		defer srv.Close()

		if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
			t.Fatalf("debug mode must collect the credential anyway: %v", err)
		}
		if !hasWarningContaining(w, finding) {
			t.Error("expected a warning naming the unbound issuer")
		}
		if len(w.GetCredentials()) == 0 {
			t.Error("debug mode dropped the credential instead of warning")
		}
	})

	t.Run("refuses in strict", func(t *testing.T) {
		w := generateTestWallet(t)
		w.RequireHAIP = true
		w.ValidationMode = ValidationModeStrict
		srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
			credentialResponse: map[string]any{"credentials": []any{map[string]any{"credential": unboundCredential(t, w)}}},
		})
		defer srv.Close()

		_, err := w.ProcessCredentialOffer(offerURI)
		if err == nil {
			t.Fatal("strict mode accepted a credential the profile refuses")
		}
		if !strings.Contains(err.Error(), "HAIP") {
			t.Errorf("error does not name the profile: %v", err)
		}
	})
}
