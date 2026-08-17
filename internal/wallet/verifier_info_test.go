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
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// signTestRegistrationCertificate issues an rc-wrp+jwt with the wallet's own
// signing material, the way the demo verifier does.
func signTestRegistrationCertificate(t *testing.T, w *Wallet, purpose any) string {
	t.Helper()
	chain, err := w.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	now := time.Now()
	claims := map[string]any{
		"sub":  "LEIEU-TEST-VERIFIER",
		"name": "Test Verifier",
		"iat":  now.Unix(),
	}
	if purpose != nil {
		claims["purpose"] = purpose
	}
	raw, err := SignRegistrationCertificateJWT(claims, w.IssuerKey, chain)
	if err != nil {
		t.Fatalf("signing registration certificate: %v", err)
	}
	return raw
}

func verifierInfoPayload(entries ...map[string]any) map[string]any {
	list := make([]any, 0, len(entries))
	for _, entry := range entries {
		list = append(list, entry)
	}
	return map[string]any{"verifier_info": list}
}

// The purpose of the request comes out of the registration certificate in
// verifier_info (OpenID4VP 1.0 §5.1), which is what the consent dialog shows.
func TestVerifierInfoPurposes(t *testing.T) {
	w := generateTestWallet(t)

	t.Run("a plain purpose string is read", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		purposes, findings := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(findings) != 0 {
			t.Errorf("findings = %v, want none", findings)
		}
		if len(purposes) != 1 || purposes[0] != "Checking your ticket" {
			t.Errorf("purposes = %v, want the certificate's purpose", purposes)
		}
	})

	t.Run("a localized purpose prefers English", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, []any{
			map[string]any{"lang": "de", "value": "Ticketpruefung"},
			map[string]any{"lang": "en", "value": "Ticket check"},
		})
		purposes, _ := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(purposes) != 1 || purposes[0] != "Ticket check" {
			t.Errorf("purposes = %v, want the English content", purposes)
		}
	})

	t.Run("a localized purpose without English falls back to the first", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, []any{
			map[string]any{"lang": "de", "value": "Ticketpruefung"},
			map[string]any{"lang": "fr", "value": "Verification du billet"},
		})
		purposes, _ := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(purposes) != 1 || purposes[0] != "Ticketpruefung" {
			t.Errorf("purposes = %v, want the first content", purposes)
		}
	})

	t.Run("the sub is the registered entity, not the client_id", func(t *testing.T) {
		// ETSI TS 119 475 puts the legal entity identifier in sub (the EUDI
		// reference certificate carries an LEI there), so it is not held
		// against the request's client_id.
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		purposes, findings := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(findings) != 0 {
			t.Errorf("findings = %v, want none", findings)
		}
		if len(purposes) != 1 {
			t.Errorf("purposes = %v, want the purpose shown for a foreign sub", purposes)
		}
	})

	t.Run("a broken signature is not shown", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		parts := strings.Split(cert, ".")
		tampered := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4] + "AAAA"
		purposes, findings := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": tampered},
		))
		if len(purposes) != 0 {
			t.Errorf("purposes = %v, want none for a tampered certificate", purposes)
		}
		if len(findings) != 1 || !strings.Contains(findings[0], "signature") {
			t.Errorf("findings = %v, want one naming the signature", findings)
		}
	})

	t.Run("a JWT of another type is passed over", func(t *testing.T) {
		// The request object itself is a JWT in the payload's neighborhood,
		// so only rc-wrp+jwt is read.
		other, err := SignRequestObjectJWT(map[string]any{"purpose": "not a certificate"}, w.IssuerKey, nil)
		if err != nil {
			t.Fatalf("signing JWT: %v", err)
		}
		purposes, findings := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "jwt", "data": other},
		))
		if len(purposes) != 0 || len(findings) != 0 {
			t.Errorf("purposes = %v findings = %v, want a foreign JWT ignored", purposes, findings)
		}
	})

	t.Run("verifier_info arriving as a JSON string is read", func(t *testing.T) {
		// Over plain request parameters the array is a URL query value.
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		encoded, err := json.Marshal([]map[string]any{{"format": "registration_cert", "data": cert}})
		if err != nil {
			t.Fatalf("encoding verifier_info: %v", err)
		}
		purposes, _ := verifierInfoPurposes(map[string]any{"verifier_info": string(encoded)})
		if len(purposes) != 1 || purposes[0] != "Checking your ticket" {
			t.Errorf("purposes = %v, want the certificate's purpose", purposes)
		}
	})

	t.Run("duplicate purposes are shown once", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		purposes, _ := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(purposes) != 1 {
			t.Errorf("purposes = %v, want the duplicate collapsed", purposes)
		}
	})

	t.Run("a request without verifier_info has no purposes", func(t *testing.T) {
		purposes, findings := verifierInfoPurposes(map[string]any{"client_id": "x509_hash:test-verifier"})
		if len(purposes) != 0 || len(findings) != 0 {
			t.Errorf("purposes = %v findings = %v, want nothing", purposes, findings)
		}
	})
}

// The demo reset replaces key and chain together, so DefaultSigningMaterial
// must return a pair whose leaf wraps the key.
func TestDefaultSigningMaterialPairsKeyAndChain(t *testing.T) {
	w := generateTestWallet(t)
	key, chain, err := w.DefaultSigningMaterial()
	if err != nil {
		t.Fatalf("DefaultSigningMaterial() error = %v", err)
	}
	if key == nil || len(chain) == 0 {
		t.Fatal("expected a key and a chain")
	}
	leafKey, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("leaf certificate does not hold an EC key")
	}
	if !leafKey.Equal(&key.PublicKey) {
		t.Error("the leaf certificate does not wrap the returned signing key")
	}
}

// A request sent as plain parameters has no payload document, so its
// verifier_info used to be dropped: the same certificate showed its purpose
// in a signed request object but not on the bare query string.
func TestPlainParameterRequestShowsThePurpose(t *testing.T) {
	srv := newTestServer(t, false)
	cert := signTestRegistrationCertificate(t, srv.wallet, "Checking who you are")
	verifierInfo, err := json.Marshal([]map[string]any{{"format": "registration_cert", "data": cert}})
	if err != nil {
		t.Fatalf("encoding verifier_info: %v", err)
	}

	dcql, err := json.Marshal(map[string]any{
		"credentials": []any{map[string]any{
			"id":     "pid",
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
			"claims": []any{map[string]any{"path": []any{"given_name"}}},
		}},
	})
	if err != nil {
		t.Fatalf("encoding dcql: %v", err)
	}

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"purpose-nonce"},
		"response_uri":  {"https://verifier.example/response"},
		"dcql_query":    {string(dcql)},
		"verifier_info": {string(verifierInfo)},
	}

	done := make(chan struct{})
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		srv.mux.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()

	var pending []*ConsentRequest
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		if pending = srv.wallet.GetPendingRequests(); len(pending) > 0 {
			break
		}
	}
	if len(pending) == 0 {
		t.Fatal("no pending consent request appeared")
	}
	if len(pending[0].Purposes) != 1 || pending[0].Purposes[0] != "Checking who you are" {
		t.Errorf("Purposes = %v, want the certificate's purpose", pending[0].Purposes)
	}

	denyReq := httptest.NewRequest("POST", "/api/requests/"+pending[0].ID+"/deny", nil)
	srv.mux.ServeHTTP(httptest.NewRecorder(), denyReq)
	<-done
}

// A certificate without a readable x5c cannot be signature-checked, so its
// purpose is not shown.
func TestVerifierInfoPurposesHidesAnUncheckableCertificate(t *testing.T) {
	w := generateTestWallet(t)
	cert, err := SignRegistrationCertificateJWT(map[string]any{
		"sub":     "LEIEU-TEST-VERIFIER",
		"purpose": "Checking your ticket",
	}, w.IssuerKey, nil)
	if err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	purposes, findings := verifierInfoPurposes(verifierInfoPayload(
		map[string]any{"format": "registration_cert", "data": cert},
	))
	if len(purposes) != 0 {
		t.Errorf("purposes = %v, want none for a certificate without x5c", purposes)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "cannot be checked") {
		t.Errorf("findings = %v, want one saying the signature cannot be checked", findings)
	}
}
