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

import (
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// registerTestRelyingParty registers a relying party whose intended use asks
// for the PID's given_name.
func registerTestRelyingParty(t *testing.T, w *testWallet) WalletRelyingParty {
	t.Helper()
	rp, err := w.RegisterRelyingParty(WalletRelyingParty{
		TradeName: "Example Shop",
		Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{{
			Purpose: []MultiLangString{{Lang: "en", Content: "Age check"}},
			Credentials: []RegisteredCredential{{
				Format: "dc+sd-jwt",
				Meta:   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				Claims: []RegisteredClaim{{Path: []any{"given_name"}}},
			}},
		}}}},
	})
	if err != nil {
		t.Fatalf("RegisterRelyingParty: %v", err)
	}
	return rp
}

func issueTestRegistrationCertificate(t *testing.T, w *testWallet, rp WalletRelyingParty) *RegistrationCertificateResult {
	t.Helper()
	result, err := w.IssueRegistrationCertificate(RegistrationCertificateRequest{
		Identifier:            rp.Identifier[0].Identifier,
		IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier,
	})
	if err != nil {
		t.Fatalf("IssueRegistrationCertificate: %v", err)
	}
	return result
}

// TS 119 475 V1.2.1 §5.1.1 links the certificates through the access
// certificate's organizationIdentifier.
func TestTheAccessCertificateFillsTheRelyingPartyFields(t *testing.T) {
	w := generateTestWallet(t)
	_, chain, err := w.AccessSigningMaterial()
	if err != nil {
		t.Fatalf("AccessSigningMaterial: %v", err)
	}
	access := chain[0]
	claims, err := RegistrationCertificateClaimsFor("https://wallet.example", RegistrationCertificateContent{Name: "Example Shop"}, access, nil, time.Now())
	if err != nil {
		t.Fatalf("RegistrationCertificateClaimsFor: %v", err)
	}
	identifier, legalName, country := AccessCertificateSubject(access)
	if claims["sub"] != identifier || claims["sub_ln"] != legalName || claims["country"] != country {
		t.Errorf("sub %v, sub_ln %v, country %v, want %q, %q and %q from the access certificate",
			claims["sub"], claims["sub_ln"], claims["country"], identifier, legalName, country)
	}
}

func TestRegistrationCertificateRequestsAreChecked(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	use := rp.Services[0].IntendedUses[0].IntendedUseIdentifier
	for _, tc := range []struct {
		name string
		req  RegistrationCertificateRequest
		want string
	}{
		{"unknown relying party", RegistrationCertificateRequest{Identifier: "LEIXG-1", IntendedUseIdentifier: use}, "not registered"},
		{"unknown intended use", RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: "x"}, "no intended use"},
		{"over 12 months", RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: use, Validity: "9000h"}, "exceeds the 12 months"},
		{"bad validity", RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: use, Validity: "soon"}, "not a positive Go duration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := w.IssueRegistrationCertificate(tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// A relying party that shows its certificate on every request keeps one
// certificate until its registered content changes.
func TestTheCurrentCertificateLastsUntilTheRegistrationChanges(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	req := RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier}
	current := func() string {
		t.Helper()
		result, _, err := w.CurrentRegistrationCertificate(req)
		if err != nil {
			t.Fatal(err)
		}
		return result.RegistrationCertificate
	}
	first := current()
	if again := current(); again != first {
		t.Error("a second request issued a new certificate")
	}
	rp.Services[0].IntendedUses[0].Purpose = []MultiLangString{{Lang: "en", Content: "Ticket check"}}
	if _, changed, err := w.EnsureRelyingParty(rp); err != nil || !changed {
		t.Fatalf("EnsureRelyingParty: changed %v, %v", changed, err)
	}
	if _, changed, err := w.EnsureRelyingParty(rp); err != nil || changed {
		t.Fatalf("EnsureRelyingParty with the same content: changed %v, %v", changed, err)
	}
	if after := current(); after == first {
		t.Error("the changed registration kept its old certificate")
	}
}

// A revoked certificate is not current, so the next request gets a new one.
func TestARevokedCertificateIsNotCurrent(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	req := RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier}
	first, _, err := w.CurrentRegistrationCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.SetRegistrationCertificatesRevoked(req.Identifier, RegistrationScope{}, true); err != nil {
		t.Fatal(err)
	}
	second, issued, err := w.CurrentRegistrationCertificate(req)
	if err != nil || !issued || second.RegistrationCertificate == first.RegistrationCertificate {
		t.Errorf("after revocation: issued %v (%v), want a new certificate", issued, err)
	}
}
