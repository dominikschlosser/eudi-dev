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
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

func haipCompliantParams() (*AuthorizationRequestParams, *oid4vc.RequestObjectJWT) {
	params := &AuthorizationRequestParams{
		ClientID:     "x509_hash:abc123",
		ResponseMode: "dc_api.jwt",
		DCQLQuery:    map[string]any{"credentials": []any{}},
	}
	reqObj := &oid4vc.RequestObjectJWT{
		Header:  map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"},
		Payload: map[string]any{},
	}
	return params, reqObj
}

func TestValidateHAIPCompliance(t *testing.T) {
	tests := []struct {
		name           string
		modifyParams   func(p *AuthorizationRequestParams)
		modifyReqObj   func(r *oid4vc.RequestObjectJWT)
		useNilReqObj   bool
		wantViolations int    // minimum expected violations (0 = compliant)
		wantContain    string // substring expected in at least one violation
	}{
		{
			name:           "fully compliant",
			wantViolations: 0,
		},
		{
			name:           "wrong response_mode",
			modifyParams:   func(p *AuthorizationRequestParams) { p.ResponseMode = "direct_post" },
			wantViolations: 1,
			wantContain:    "response_mode",
		},
		{
			name:           "wrong client_id scheme",
			modifyParams:   func(p *AuthorizationRequestParams) { p.ClientID = "redirect_uri:https://example.com" },
			wantViolations: 1,
			wantContain:    "client_id",
		},
		{
			name:           "missing request object (JAR)",
			useNilReqObj:   true,
			wantViolations: 1,
			wantContain:    "JAR",
		},
		{
			name:           "missing DCQL query",
			modifyParams:   func(p *AuthorizationRequestParams) { p.DCQLQuery = nil },
			wantViolations: 1,
			wantContain:    "DCQL",
		},
		{
			name: "web-origin unsigned browser flow",
			modifyParams: func(p *AuthorizationRequestParams) {
				p.ClientID = "web-origin:https://wallet.example"
				p.ResponseMode = "dc_api.jwt"
				p.RequestOrigin = "https://wallet.example"
			},
			useNilReqObj:   true,
			wantViolations: 0,
		},
		{
			name: "web-origin unsigned browser flow with matching expected origins",
			modifyParams: func(p *AuthorizationRequestParams) {
				p.ClientID = "web-origin:https://wallet.example"
				p.ResponseMode = "dc_api.jwt"
				p.RequestOrigin = "https://wallet.example"
				p.RequestPayload = map[string]any{
					"expected_origins": []any{"https://wallet.example"},
				}
			},
			useNilReqObj:   true,
			wantViolations: 0,
		},
		{
			name:           "wrong algorithm",
			modifyReqObj:   func(r *oid4vc.RequestObjectJWT) { r.Header["alg"] = "RS256" },
			wantViolations: 1,
			wantContain:    "ES256",
		},
		{
			name: "wrong expected origins",
			modifyParams: func(p *AuthorizationRequestParams) {
				p.ClientID = "web-origin:https://wallet.example"
				p.ResponseMode = "dc_api.jwt"
				p.RequestOrigin = "https://wallet.example"
				p.RequestPayload = map[string]any{
					"expected_origins": []any{"https://other.example"},
				}
			},
			useNilReqObj:   true,
			wantViolations: 1,
			wantContain:    "expected_origins",
		},
		{
			name: "multiple violations",
			modifyParams: func(p *AuthorizationRequestParams) {
				p.ClientID = "redirect_uri:https://example.com"
				p.ResponseMode = "direct_post"
				p.DCQLQuery = nil
			},
			useNilReqObj:   true,
			wantViolations: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, reqObj := haipCompliantParams()
			if tt.modifyParams != nil {
				tt.modifyParams(params)
			}
			if tt.modifyReqObj != nil {
				tt.modifyReqObj(reqObj)
			}
			if tt.useNilReqObj {
				reqObj = nil
			}

			violations := ValidateHAIPCompliance(params, reqObj)

			if tt.wantViolations == 0 {
				if len(violations) != 0 {
					t.Errorf("expected 0 violations, got %d: %v", len(violations), violations)
				}
				return
			}

			if len(violations) < tt.wantViolations {
				t.Errorf("expected at least %d violations, got %d: %v", tt.wantViolations, len(violations), violations)
			}

			if tt.wantContain != "" {
				found := false
				for _, v := range violations {
					if contains(v, tt.wantContain) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected violation containing %q, got: %v", tt.wantContain, violations)
				}
			}
		})
	}
}

// contains and containsSubstring are defined in requestobj_test.go

// The per-request override has to work in both directions. Turning HAIP on
// for one request is what the conformance harness does for its HAIP modules;
// turning it off is what lets anyone test a non-HAIP verifier against a
// wallet that enforces HAIP globally, such as the public demo.
func TestHAIPPerRequestOverride(t *testing.T) {
	on, off := true, false
	tests := []struct {
		name         string
		serverHAIP   bool
		requestHAIP  *bool
		wantEnforced bool
	}{
		{"absent inherits enforcement", true, nil, true},
		{"absent inherits tolerance", false, nil, false},
		{"explicit true enables", false, &on, true},
		{"explicit false disables", true, &off, false},
		{"explicit true on enforcing stays on", true, &on, true},
		{"explicit false on tolerant stays off", false, &off, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := generateTestWallet(t)
			src.RequireHAIP = tc.serverHAIP

			clone, err := cloneWalletForPresentation(src, presentationRequestOptions{
				RequireHAIP: tc.requestHAIP,
			})
			if err != nil {
				t.Fatalf("cloneWalletForPresentation: %v", err)
			}
			if clone.RequireHAIP != tc.wantEnforced {
				t.Errorf("RequireHAIP = %v, want %v", clone.RequireHAIP, tc.wantEnforced)
			}
			if src.RequireHAIP != tc.serverHAIP {
				t.Errorf("the server setting must not be mutated, got %v", src.RequireHAIP)
			}
		})
	}
}

func TestParseHAIPHeader(t *testing.T) {
	tests := []struct {
		header string
		want   *bool
	}{
		{"", nil},
		{"true", boolPtr(true)},
		{"false", boolPtr(false)},
		{"1", boolPtr(true)},
		{"0", boolPtr(false)},
		{"nonsense", nil}, // unparseable inherits, rather than silently enforcing
	}
	for _, tc := range tests {
		got := parseHAIPHeader(tc.header)
		switch {
		case tc.want == nil && got != nil:
			t.Errorf("parseHAIPHeader(%q) = %v, want nil", tc.header, *got)
		case tc.want != nil && got == nil:
			t.Errorf("parseHAIPHeader(%q) = nil, want %v", tc.header, *tc.want)
		case tc.want != nil && *got != *tc.want:
			t.Errorf("parseHAIPHeader(%q) = %v, want %v", tc.header, *got, *tc.want)
		}
	}
}

func boolPtr(v bool) *bool { return &v }

func haipCompliantIssuance() (*oid4vc.CredentialOffer, map[string]any) {
	offer := &oid4vc.CredentialOffer{
		CredentialIssuer: "https://issuer.example",
		Grants:           oid4vc.OfferGrants{IssuerState: "abc"},
	}
	meta := map[string]any{
		"authorization_endpoint":                "https://issuer.example/authorize",
		"grant_types_supported":                 []any{"authorization_code"},
		"require_pushed_authorization_requests": true,
		"code_challenge_methods_supported":      []any{"S256"},
		"dpop_signing_alg_values_supported":     []any{"ES256"},
		"token_endpoint_auth_methods_supported": []any{"attest_jwt_client_auth"},
	}
	return offer, meta
}

func TestValidateHAIPIssuanceCompliance(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*oid4vc.CredentialOffer, map[string]any)
		wantSub string
	}{
		{name: "compliant issuer"},
		{
			// HAIP 1.0 §4 requires an issuer to support the authorization
			// code flow. It says nothing about the pre-authorized code flow,
			// so an offer using it is not a violation.
			name: "pre-authorized code offer is accepted",
			mutate: func(o *oid4vc.CredentialOffer, _ map[string]any) {
				o.Grants = oid4vc.OfferGrants{PreAuthorizedCode: "code"}
			},
		},
		{
			name: "authorization code offer whose issuer does not advertise the flow",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				m["grant_types_supported"] = []any{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}
			},
			wantSub: "must support the authorization code flow",
		},
		{
			name: "plain http issuer",
			mutate: func(o *oid4vc.CredentialOffer, _ map[string]any) {
				o.CredentialIssuer = "http://issuer.example"
			},
			wantSub: "must be an https URL",
		},
		{
			name: "PAR not required for an authorization code offer",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				m["require_pushed_authorization_requests"] = false
			},
			wantSub: "must require pushed authorization requests",
		},
		{
			// §4 scopes PAR to "when using the Authorization Endpoint", which
			// a pre-authorized code offer never reaches. The same goes for
			// PKCE and the flow-support advertisement.
			name: "pre-authorized code offer is judged on transport only",
			mutate: func(o *oid4vc.CredentialOffer, m map[string]any) {
				o.Grants = oid4vc.OfferGrants{PreAuthorizedCode: "code"}
				m["require_pushed_authorization_requests"] = false
				m["code_challenge_methods_supported"] = []any{"plain"}
				delete(m, "grant_types_supported")
				delete(m, "dpop_signing_alg_values_supported")
			},
		},
		{
			name: "pre-authorized code offer over plain http is still rejected",
			mutate: func(o *oid4vc.CredentialOffer, _ map[string]any) {
				o.Grants = oid4vc.OfferGrants{PreAuthorizedCode: "code"}
				o.CredentialIssuer = "http://issuer.example"
			},
			wantSub: "must be an https URL",
		},
		{
			name: "no PKCE S256",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				m["code_challenge_methods_supported"] = []any{"plain"}
			},
			wantSub: "must support PKCE with S256",
		},
		{
			name: "no DPoP",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				delete(m, "dpop_signing_alg_values_supported")
			},
			wantSub: "must support DPoP",
		},
		{
			name: "no client authentication",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				m["token_endpoint_auth_methods_supported"] = []any{"client_secret_post"}
			},
			wantSub: "must authenticate the client",
		},
		{
			name: "unreadable authorization server metadata",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				for k := range m {
					delete(m, k)
				}
			},
			wantSub: "must support the authorization code flow",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			offer, meta := haipCompliantIssuance()
			if tc.mutate != nil {
				tc.mutate(offer, meta)
			}
			violations := ValidateHAIPIssuanceCompliance(offer, meta)
			if tc.wantSub == "" {
				if len(violations) != 0 {
					t.Fatalf("expected a compliant issuer, got %v", violations)
				}
				return
			}
			if len(violations) == 0 {
				t.Fatalf("expected a violation containing %q, got none", tc.wantSub)
			}
			var found bool
			for _, v := range violations {
				if strings.Contains(v, tc.wantSub) {
					found = true
				}
			}
			if !found {
				t.Errorf("violations %v do not mention %q", violations, tc.wantSub)
			}
		})
	}
}

// A local demo instance serves plain http on loopback, and rejecting it for
// that alone would make the profile untestable locally.
func TestHAIPIssuanceAllowsLoopbackHTTP(t *testing.T) {
	for _, issuer := range []string{"http://localhost:8085/issuer", "http://127.0.0.1:8085/issuer", "https://eudi-test.dev/issuer"} {
		offer, meta := haipCompliantIssuance()
		offer.CredentialIssuer = issuer
		if violations := ValidateHAIPIssuanceCompliance(offer, meta); len(violations) != 0 {
			t.Errorf("issuer %q rejected: %v", issuer, violations)
		}
	}
	offer, meta := haipCompliantIssuance()
	offer.CredentialIssuer = "http://issuer.example/issuer"
	if violations := ValidateHAIPIssuanceCompliance(offer, meta); len(violations) == 0 {
		t.Error("a public plain-http issuer must still be rejected")
	}
}

// A pre-authorized code offer from an issuer that meets the profile must be
// accepted. HAIP 1.0 §4 requires support for the authorization code flow. It
// neither requires nor forbids the pre-authorized code flow, and scopes PAR
// to "when using the Authorization Endpoint", which this offer never reaches.
func TestHAIPIssuanceAcceptsCompliantPreAuthorizedOffer(t *testing.T) {
	offer := &oid4vc.CredentialOffer{
		CredentialIssuer: "https://issuer.example",
		Grants:           oid4vc.OfferGrants{PreAuthorizedCode: "abc"},
	}
	meta := map[string]any{
		"authorization_endpoint":                "https://issuer.example/authorize",
		"grant_types_supported":                 []any{"authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"dpop_signing_alg_values_supported":     []any{"ES256"},
		"token_endpoint_auth_methods_supported": []any{"attest_jwt_client_auth"},
		// Deliberately absent: PAR and PKCE, which this offer never uses.
	}
	if violations := ValidateHAIPIssuanceCompliance(offer, meta); len(violations) != 0 {
		t.Errorf("a compliant pre-authorized code offer was rejected: %v", violations)
	}
}
