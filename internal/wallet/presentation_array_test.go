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
	"slices"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
)

// importNationalitiesPID imports an SD-JWT PID whose nationalities array has
// selectively disclosable elements (the mock's per-element array encoding).
func importNationalitiesPID(t *testing.T, w *Wallet) StoredCredential {
	t.Helper()
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       mock.DefaultPIDVCT,
		Claims:    mock.SDJWTPIDClaims,
		Key:       w.IssuerKey,
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	cred, err := w.ImportCredential(raw)
	if err != nil {
		t.Fatalf("ImportCredential: %v", err)
	}
	return *cred
}

func presentedNationalities(t *testing.T, w *Wallet, m CredentialMatch) any {
	t.Helper()
	cred, _ := w.GetCredential(m.CredentialID)
	presentation, err := w.createSDJWTPresentation(cred, m.SelectedKeys, "nonce", "verifier", w.HolderKey)
	if err != nil {
		t.Fatalf("createSDJWTPresentation: %v", err)
	}
	token, err := sdjwt.Parse(presentation)
	if err != nil {
		t.Fatalf("parsing presentation: %v", err)
	}
	return token.ResolvedClaims["nationalities"]
}

func nationalitiesQuery(path ...any) map[string]any {
	return map[string]any{"credentials": []any{map[string]any{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		"claims": []any{map[string]any{"path": path}},
	}}}
}

// A whole path onto an array of selectively disclosable elements discloses the
// array but none of its elements (OpenID4VP 1.0 §7.1 selects elements with a
// null or an index). The wallet marks the claim so the consent dialog and the
// activity log can warn.
func TestPresentation_BareArrayPathDisclosesEmptyArray(t *testing.T) {
	w := generateTestWallet(t)
	importNationalitiesPID(t, w)

	matches := w.EvaluateDCQL(nationalitiesQuery("nationalities"))
	if len(matches) != 1 {
		t.Fatalf("want one match, got %d", len(matches))
	}
	if !slices.Contains(matches[0].EmptyArrayClaims, "nationalities") {
		t.Fatalf("EmptyArrayClaims = %v, want it to name nationalities", matches[0].EmptyArrayClaims)
	}
	if arr, ok := presentedNationalities(t, w, matches[0]).([]any); !ok || len(arr) != 0 {
		t.Errorf("disclosed nationalities = %v, want an empty array", presentedNationalities(t, w, matches[0]))
	}
}

// Ending the path with null selects the elements, so they are disclosed and the
// claim is not flagged.
func TestPresentation_NullArrayPathDisclosesElements(t *testing.T) {
	w := generateTestWallet(t)
	importNationalitiesPID(t, w)

	matches := w.EvaluateDCQL(nationalitiesQuery("nationalities", nil))
	if len(matches) != 1 {
		t.Fatalf("want one match, got %d", len(matches))
	}
	if len(matches[0].EmptyArrayClaims) != 0 {
		t.Errorf("EmptyArrayClaims = %v, want none for a null selection", matches[0].EmptyArrayClaims)
	}
	arr, ok := presentedNationalities(t, w, matches[0]).([]any)
	if !ok || len(arr) != 1 || arr[0] != "NL" {
		t.Errorf("disclosed nationalities = %v, want [NL]", presentedNationalities(t, w, matches[0]))
	}
}
