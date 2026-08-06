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

package web

import (
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
)

// draft-ietf-oauth-sd-jwt-vc-18 §2.2.1: "The Issuer MUST include the typ
// header parameter in the SD-JWT. The typ value MUST use dc+sd-jwt", with
// vc+sd-jwt accepted for the transitional period the same section names.
func TestCheckSDJWTType(t *testing.T) {
	tests := []struct {
		name   string
		header map[string]any
		want   string
	}{
		{name: "dc+sd-jwt", header: map[string]any{"typ": "dc+sd-jwt"}, want: "pass"},
		{name: "vc+sd-jwt", header: map[string]any{"typ": "vc+sd-jwt"}, want: "pass"},
		{name: "plain JWT", header: map[string]any{"typ": "JWT"}, want: "fail"},
		{name: "mixed case", header: map[string]any{"typ": "DC+SD-JWT"}, want: "fail"},
		{name: "missing", header: map[string]any{"alg": "ES256"}, want: "fail"},
		{name: "not a string", header: map[string]any{"typ": 7}, want: "fail"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSDJWTType(&sdjwt.Token{Header: tt.header})
			if got.Status != tt.want {
				t.Errorf("CheckSDJWTType(%v).Status = %q (%s), want %q", tt.header, got.Status, got.Detail, tt.want)
			}
		})
	}
}

// RFC 9901 §4.2.4.2: a digest placeholder is an object of the form
// {"...": "<digest>"} and "There MUST NOT be any other keys in the object."
// An object carrying a second key references no disclosure, so the disclosure
// whose digest it names is unaccounted for.
func TestCheckSDJWTIntegrity_PlaceholderWithExtraKeyIsNoReference(t *testing.T) {
	const digest = "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"

	token := &sdjwt.Token{
		Payload: map[string]any{
			"iss":           "https://issuer.example",
			"nationalities": []any{map[string]any{"...": digest, "hint": "FR"}},
		},
		Disclosures: []sdjwt.Disclosure{{Digest: digest, IsArrayEntry: true, Value: "FR"}},
	}

	if got := CheckSDJWTIntegrity(token); got.Status != "fail" {
		t.Errorf("CheckSDJWTIntegrity().Status = %q (%s), want fail", got.Status, got.Detail)
	}

	// The same disclosure behind a well-formed placeholder is accounted for.
	token.Payload["nationalities"] = []any{map[string]any{"...": digest}}
	if got := CheckSDJWTIntegrity(token); got.Status != "pass" {
		t.Errorf("CheckSDJWTIntegrity().Status = %q (%s), want pass", got.Status, got.Detail)
	}
}
