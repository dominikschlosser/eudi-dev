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

package registrar

import "testing"

// ETSI TS 119 475 V1.2.1 Table 2 maps each identifier type to a legal person
// semantics identifier of ETSI EN 319 412-1 V1.6.1 §5.1.4.
func TestTheSemanticsIdentifierFollowsTheIdentifierType(t *testing.T) {
	for _, tc := range []struct {
		id      Identifier
		country string
		want    string
	}{
		// LEG-5.1.4-07 b and its example 2.
		{Identifier{Type: EUIDIdentifierType, Identifier: "DED2601V.HRB12345"}, "", "NTRDE-DED2601V.HRB12345"},
		{Identifier{Type: EUIDIdentifierType, Identifier: "ELGEMI.123456789"}, "", "NTREL-ELGEMI.123456789"},
		{Identifier{Type: LEIIdentifierType, Identifier: "529900T8BM49AURSDO55"}, "", "LEIXG-529900T8BM49AURSDO55"},
		// LEG-5.1.4-04 and example 1.
		{Identifier{Type: VATINIdentifierType, Identifier: "BE0876866142"}, "", "VATBE-0876866142"},
		{Identifier{Type: VATINIdentifierType, Identifier: "EL123456789"}, "", "VATEL-123456789"},
		{Identifier{Type: TINIdentifierType, Identifier: "12345678901"}, "DE", "VATDE-12345678901"},
		{Identifier{Type: EORIIdentifierType, Identifier: "DE1234567"}, "", "EORDE-1234567"},
		{Identifier{Type: ExciseIdentifierType, Identifier: "DE00012345678"}, "", "EXCDE-00012345678"},
	} {
		got, err := SemanticIdentifier(tc.id, tc.country)
		if err != nil || got != tc.want {
			t.Errorf("%s %s: %q, %v, want %q", tc.id.Type, tc.id.Identifier, got, err, tc.want)
		}
	}
}

// An identifier without a type may be a certificate's semantics identifier.
func TestAnUntypedIdentifierTakesTheTypeItsValueShows(t *testing.T) {
	for value, want := range map[string]Identifier{
		"NLTEST.1A2B":                {Type: EUIDIdentifierType, Identifier: "NLTEST.1A2B"},
		"NTRDE-DED2601V.HRB12345":    {Type: EUIDIdentifierType, Identifier: "DED2601V.HRB12345"},
		"LEIXG-529900T8BM49AURSDO55": {Type: LEIIdentifierType, Identifier: "529900T8BM49AURSDO55"},
		"VATBE-0876866142":           {Type: VATINIdentifierType, Identifier: "BE0876866142"},
	} {
		if got := typedIdentifier(value); got != want {
			t.Errorf("%s: %+v, want %+v", value, got, want)
		}
	}
}

// A VATIN and a TIN that map to the same semantics identifier name the same
// party, so the second registration is refused.
func TestIdentifiersCompareByTheirSemanticsIdentifier(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "VAT Shop", Country: "NL", Identifier: []Identifier{{Type: VATINIdentifierType, Identifier: "NL123456789"}}}); err != nil {
		t.Fatal(err)
	}
	_, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "TIN Shop", Country: "NL", Identifier: []Identifier{{Type: TINIdentifierType, Identifier: "123456789"}}})
	if err == nil {
		t.Error("a TIN with the semantics identifier of a registered VATIN was registered")
	}
}

// An update through the semantics identifier keeps one identifier.
func TestAnUpdateThroughTheSemanticsIdentifierKeepsOneIdentifier(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	semantic, err := SemanticIdentifier(rp.Identifier[0], rp.Country)
	if err != nil {
		t.Fatal(err)
	}
	rp.Identifier = []Identifier{{Identifier: semantic}}
	updated, err := w.UpdateRelyingParty(rp)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Identifier) != 1 {
		t.Errorf("identifiers %+v, want one", updated.Identifier)
	}
}
