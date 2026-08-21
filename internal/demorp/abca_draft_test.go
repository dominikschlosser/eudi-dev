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

package demorp

import (
	"bytes"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

// captureLog collects everything the package logs while fn runs.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	fn()
	return buf.String()
}

// TestAttestationCnfPrivateKeyRejected enforces the validation rule every
// supported ABCA draft states: the key in the attestation's cnf claim must
// not be a private key.
func TestAttestationCnfPrivateKeyRejected(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	privateJWK := holderJWK(t, clientKey)
	privateJWK["d"] = format.EncodeBase64URL(clientKey.D.Bytes())
	attestation := signES256(t, provider.key,
		map[string]any{
			"alg": "ES256",
			"typ": "oauth-client-attestation+jwt",
			"x5c": []any{base64.StdEncoding.EncodeToString(provider.leaf.Raw)},
		},
		map[string]any{
			"sub": "wallet",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"cnf": map[string]any{"jwk": privateJWK},
		},
	)

	dpopKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating DPoP key: %v", err)
	}
	rec := pushAuthorizationRequest(t, d.IssuerHandler(), "wallet", dpopKey, "abc", map[string]string{
		"OAuth-Client-Attestation":     attestation,
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "private key") {
		t.Errorf("body = %s, want it to name the private key material", rec.Body.String())
	}
}

// TestDuplicateAttestationHeaderRejected enforces the "precisely one header
// field" rule of the ABCA validation checklist, for both header fields.
func TestDuplicateAttestationHeaderRejected(t *testing.T) {
	for _, doubled := range []string{"OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP"} {
		t.Run(doubled, func(t *testing.T) {
			d, _, _ := newDemoRP(t)
			provider := foreignWalletProvider(t)
			clientKey, err := mock.GenerateKey()
			if err != nil {
				t.Fatalf("generating client key: %v", err)
			}
			dpopKey, err := mock.GenerateKey()
			if err != nil {
				t.Fatalf("generating DPoP key: %v", err)
			}

			form := url.Values{
				"client_id":             {"wallet"},
				"response_type":         {"code"},
				"code_challenge_method": {"S256"},
				"code_challenge":        {"abc"},
				"redirect_uri":          {"http://wallet.example/cb"},
			}
			req := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("DPoP", dpopProof(t, dpopKey, "POST", demoIssuerID+"/par"))
			req.Header.Set("OAuth-Client-Attestation", provider.attest(t, "wallet", clientKey))
			req.Header.Set("OAuth-Client-Attestation-PoP", attestationPoP(t, clientKey, demoIssuerID))
			req.Header.Add(doubled, req.Header.Get(doubled))
			rec := httptest.NewRecorder()
			d.IssuerHandler().ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "precisely one") {
				t.Errorf("body = %s, want the single-header rule named", rec.Body.String())
			}
		})
	}
}

// TestAttestationAlgRejected enforces the algorithm check of the validation
// checklist on both JWTs: the advertised algorithms are the acceptable ones,
// and a JWT naming another is refused with the algorithm named.
func TestAttestationAlgRejected(t *testing.T) {
	for _, tc := range []struct {
		name           string
		attestationAlg string
		popAlg         string
	}{
		{"attestation", "ES384", "ES256"},
		{"PoP", "ES256", "ES384"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, _ := newDemoRP(t)
			provider := foreignWalletProvider(t)
			clientKey, err := mock.GenerateKey()
			if err != nil {
				t.Fatalf("generating client key: %v", err)
			}
			dpopKey, err := mock.GenerateKey()
			if err != nil {
				t.Fatalf("generating DPoP key: %v", err)
			}

			attestation := signES256(t, provider.key,
				map[string]any{
					"alg": tc.attestationAlg,
					"typ": "oauth-client-attestation+jwt",
					"x5c": []any{base64.StdEncoding.EncodeToString(provider.leaf.Raw)},
				},
				map[string]any{
					"sub": "wallet",
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(5 * time.Minute).Unix(),
					"cnf": map[string]any{"jwk": holderJWK(t, clientKey)},
				},
			)
			pop := signES256(t, clientKey,
				map[string]any{"alg": tc.popAlg, "typ": "oauth-client-attestation-pop+jwt"},
				map[string]any{"aud": demoIssuerID, "iat": time.Now().Unix(), "jti": "pop-alg-test"},
			)
			rec := pushAuthorizationRequest(t, d.IssuerHandler(), "wallet", dpopKey, "abc", map[string]string{
				"OAuth-Client-Attestation":     attestation,
				"OAuth-Client-Attestation-PoP": pop,
			})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "ES384") {
				t.Errorf("body = %s, want the refused algorithm named", rec.Body.String())
			}
		})
	}
}

// TestPoPIssuerMismatchRejected enforces that a PoP naming another client in
// iss authenticates nobody: the value has to match the request's client_id.
func TestPoPIssuerMismatchRejected(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	dpopKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating DPoP key: %v", err)
	}

	pop := signES256(t, clientKey,
		map[string]any{"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt"},
		map[string]any{"iss": "somebody-else", "aud": demoIssuerID, "iat": time.Now().Unix(), "jti": "pop-iss-test"},
	)
	rec := pushAuthorizationRequest(t, d.IssuerHandler(), "wallet", dpopKey, "abc", map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "wallet", clientKey),
		"OAuth-Client-Attestation-PoP": pop,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "somebody-else") {
		t.Errorf("body = %s, want the mismatching iss named", rec.Body.String())
	}
}

// TestCrossDraftShapeWarnsButAccepts pins the tolerant acceptance the ADR
// decided: material that violates the ABCA draft the configured OpenID4VCI
// version pins, while being correct under another supported draft, is
// accepted with a logged warning. At OpenID4VCI 1.0 the pinned draft is -07,
// which requires iss in both JWTs; the test helpers build the draft-08/-10
// shape without it.
func TestCrossDraftShapeWarnsButAccepts(t *testing.T) {
	t.Run("draft-08 shape at a draft-07 configuration", func(t *testing.T) {
		d, w, _ := newDemoRP(t)
		w.VCIVersion = wallet.VCIVersion10
		provider := foreignWalletProvider(t)
		clientKey, err := mock.GenerateKey()
		if err != nil {
			t.Fatalf("generating client key: %v", err)
		}
		dpopKey, err := mock.GenerateKey()
		if err != nil {
			t.Fatalf("generating DPoP key: %v", err)
		}

		var rec *httptest.ResponseRecorder
		logged := captureLog(t, func() {
			rec = pushAuthorizationRequest(t, d.IssuerHandler(), "wallet", dpopKey, "abc", map[string]string{
				"OAuth-Client-Attestation":     provider.attest(t, "wallet", clientKey),
				"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
			})
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want the draft-08 shape accepted (%s)", rec.Code, rec.Body.String())
		}
		for _, want := range []string{"client attestation omits iss", "client attestation PoP omits iss"} {
			if !strings.Contains(logged, want) {
				t.Errorf("log = %q, want a warning that the %s", logged, want)
			}
		}
	})

	t.Run("combined proof at a pre-draft-10 configuration", func(t *testing.T) {
		d, w, _ := newDemoRP(t)
		w.VCIVersion = wallet.VCIVersion11
		provider := foreignWalletProvider(t)
		clientKey, err := mock.GenerateKey()
		if err != nil {
			t.Fatalf("generating client key: %v", err)
		}

		var rec *httptest.ResponseRecorder
		logged := captureLog(t, func() {
			rec = pushAuthorizationRequest(t, d.IssuerHandler(), "wallet", clientKey, "abc", map[string]string{
				"OAuth-Client-Attestation": provider.attest(t, "wallet", clientKey),
			})
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want the combined proof accepted (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(logged, "draft-10") {
			t.Errorf("log = %q, want a warning naming dpop_combined as a draft-10 mechanism", logged)
		}
	})
}

// TestPopMethodsNoneInOptionalMode pins the metadata a server that lets the
// attestation be omitted publishes: draft-10 defines the none entry of
// client_attestation_pop_methods_supported exactly for that signal.
func TestPopMethodsNoneInOptionalMode(t *testing.T) {
	d, _, _ := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)

	code, metadata := doJSON(t, d.IssuerHandler(), "GET", "/.well-known/oauth-authorization-server", "", nil)
	if code != http.StatusOK {
		t.Fatalf("metadata request: %d %v", code, metadata)
	}
	methods, _ := metadata["client_attestation_pop_methods_supported"].([]any)
	found := false
	for _, m := range methods {
		if m == "none" {
			found = true
		}
	}
	if !found {
		t.Errorf("client_attestation_pop_methods_supported = %v, want it to include none in optional mode", methods)
	}
}
