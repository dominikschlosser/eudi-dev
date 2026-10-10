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

// W3C JWT VC uses a type array instead of the SD-JWT VC vct claim.
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

func TestImportPlainJWTStoresTheVCType(t *testing.T) {
	w := generateTestWallet(t)
	jwt := buildPlainJWTForTest(t, map[string]any{
		"iss": "https://issuer.example",
		"vc":  map[string]any{"type": []any{"VerifiableCredential", "NFEmployeeCredential"}},
	})

	cred, err := w.parsePlainJWTEntry(jwt, "", "")
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

// A credential stored by eudi-dev 2 keeps its client ID for refresh.
func TestRehydrateMovesTheLegacyClientID(t *testing.T) {
	var cred StoredCredential
	if err := json.Unmarshal([]byte(`{"id":"x","renewal":{"issuer":"https://i.example","client_auth":{"method":"attestation","client_id":"wallet-client"}}}`), &cred); err != nil {
		t.Fatal(err)
	}
	if err := cred.Rehydrate(); err != nil {
		t.Fatal(err)
	}
	if cred.Renewal.ClientID != "wallet-client" || cred.Renewal.ClientAuth.LegacyClientID != "" {
		t.Errorf("renewal = %+v, client auth = %+v", cred.Renewal, cred.Renewal.ClientAuth)
	}
}
