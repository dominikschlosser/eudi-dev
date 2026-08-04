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
