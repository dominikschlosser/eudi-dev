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
	"encoding/base64"
	"encoding/json"
	"testing"
)

func buildPlainJWTForTest(t *testing.T, payload map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT"})
	body, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body) + ".signature"
}

// A W3C JWT VC (jwt_vc_json) names its type in the type array, not a vct claim,
// so the wallet reads the type from there for the listing rather than falling
// back to the format.
func TestJWTVCType(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{"type array in the vc claim", map[string]any{"vc": map[string]any{"type": []any{"VerifiableCredential", "NFEmployeeCredential"}}}, "NFEmployeeCredential"},
		{"type array at the payload root", map[string]any{"type": []any{"VerifiableCredential", "NFStudentCredential"}}, "NFStudentCredential"},
		{"only the base type", map[string]any{"type": []any{"VerifiableCredential"}}, ""},
		{"no type at all", map[string]any{"iss": "x"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jwtVCType(tc.payload); got != tc.want {
				t.Errorf("jwtVCType = %q, want %q", got, tc.want)
			}
		})
	}
}

// Importing a W3C JWT VC stores its type, so the listing shows the credential
// type and not "jwt_vc_json".
func TestImportPlainJWTStoresTheVCType(t *testing.T) {
	w := generateTestWallet(t)
	jwt := buildPlainJWTForTest(t, map[string]any{
		"iss": "https://issuer.example",
		"vc":  map[string]any{"type": []any{"VerifiableCredential", "NFEmployeeCredential"}},
	})

	cred, err := w.importPlainJWT(jwt, "", "")
	if err != nil {
		t.Fatalf("importPlainJWT: %v", err)
	}
	if cred.Format != "jwt_vc_json" {
		t.Errorf("format = %q, want jwt_vc_json", cred.Format)
	}
	if cred.VCT != "NFEmployeeCredential" {
		t.Errorf("VCT = %q, want NFEmployeeCredential (the type, not the format)", cred.VCT)
	}
}
