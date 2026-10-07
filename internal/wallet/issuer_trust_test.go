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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
)

func TestTheWalletsOwnPIDsValidateWithThePIDTrustedList(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.RequireARF = true
	for _, c := range w.GetCredentials() {
		if got := w.trustAnchorFindings(receivedCredential(c.Raw)); len(got) != 0 {
			t.Errorf("%s %s: %v", c.Format, credentialLabel(c), got)
		}
	}
}

// A PID from another wallet's CA is not on this wallet's PID Provider LoTE
// (ARF ISSU_07). Strict mode refuses it and debug mode warns.
func TestAForeignPIDFailsTheTrustAnchorCheck(t *testing.T) {
	w := generateTestWallet(t)
	w.RequireARF = true
	for _, c := range generateTestWalletWithPID(t).GetCredentials() {
		findings := w.trustAnchorFindings(receivedCredential(c.Raw))
		if len(findings) != 1 || !strings.HasPrefix(findings[0], "ARF ISSU_07: ") {
			t.Fatalf("%s: findings %v", c.Format, findings)
		}
		resp := map[string]any{"credentials": []any{map[string]any{"credential": c.Raw}}}
		w.ValidationMode = ValidationModeStrict
		if err := w.checkReceivedCredentials(resp, "https://issuer.example"); err == nil {
			t.Errorf("%s: strict mode accepted the credential", c.Format)
		}
		w.ValidationMode = ValidationModeDebug
		if err := w.checkReceivedCredentials(resp, "https://issuer.example"); err != nil {
			t.Errorf("%s: debug mode refused: %v", c.Format, err)
		}
	}
}

// Every copy of a batch is signed on its own, so every copy is checked.
func TestEveryCopyOfABatchIsChecked(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.RequireARF = true
	w.ValidationMode = ValidationModeStrict
	own := w.GetCredentials()[0].Raw
	foreign := generateTestWalletWithPID(t).GetCredentials()[0].Raw
	resp := map[string]any{"credentials": []any{map[string]any{"credential": own}, map[string]any{"credential": foreign}}}
	if err := w.checkReceivedCredentials(resp, "https://issuer.example"); err == nil {
		t.Error("strict mode accepted a batch with a foreign copy")
	}
}

// An attestation entry can link any list of trusted entities. The wallet
// fetches it (ARF ISSU_08 to ISSU_10).
func TestAnAttestationIsCheckedAgainstAFetchedList(t *testing.T) {
	const vct = "urn:example:diploma:1"
	issuer := generateTestWallet(t)
	result, err := issuer.IssueCredential(IssueOptions{Format: "sdjwt", VCT: vct, Claims: map[string]any{"degree": "MSc"}})
	if err != nil {
		t.Fatal(err)
	}
	serveList := func(w *Wallet) string {
		group, ok := DefaultTrustListGroupForWallet(w)
		if !ok {
			t.Fatal("no trusted list for the attestation")
		}
		list, err := GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, "/api/trustlists/"+group.ID)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(list)) }))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	isLOTE := true
	for _, tc := range []struct {
		name, list string
		want       bool
	}{
		{"the issuer's list", serveList(issuer), false},
		{"another wallet's list", serveList(generateTestWallet(t)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.RequireARF = true
			if _, err := w.AddCatalogAttestation(CatalogAttestation{
				Name:        "Diploma",
				Credentials: []CatalogCredential{{Format: "dc+sd-jwt", Type: vct}},
				Schema:      AttestationSchema{TrustedAuthorities: []TrustAuthority{{FrameworkType: "etsi_tl", Value: tc.list, IsLOTE: &isLOTE}}},
			}, w.RegistrarBase()); err != nil {
				t.Fatal(err)
			}
			findings := w.trustAnchorFindings(receivedCredential(result.Raw))
			if got := len(findings) == 1 && strings.HasPrefix(findings[0], "ARF ISSU_08 to ISSU_10: "); got != tc.want {
				t.Errorf("findings %v", findings)
			}
		})
	}
}

// ISSU_10 applies only when the wallet has the issuer's trust anchors.
func TestAnAttestationWithoutATrustedListIsNotChecked(t *testing.T) {
	w := generateTestWallet(t)
	w.RequireARF = true
	ticket := StoredCredential{Format: "dc+sd-jwt", VCT: credtype.DemoTicketVCT, Raw: "not checked"}
	if got := w.trustAnchorFindings(ticket); len(got) != 0 {
		t.Errorf("findings %v", got)
	}
}

func TestTheTrustAnchorCheckNeedsARF(t *testing.T) {
	w := generateTestWallet(t)
	for _, c := range generateTestWalletWithPID(t).GetCredentials() {
		if got := w.trustAnchorFindings(receivedCredential(c.Raw)); len(got) != 0 {
			t.Errorf("findings without --arf: %v", got)
		}
	}
}

func TestAnOfferOutsideTheCatalogueWarns(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{"credential_configurations_supported": map[string]any{
		"pid":     map[string]any{"format": "dc+sd-jwt", "vct": credtype.PIDVCT},
		"unknown": map[string]any{"format": "dc+sd-jwt", "vct": "urn:example:unknown:1"},
	}}
	if got := w.catalogueFindings(metadata, []string{"pid", "unknown"}); len(got) != 0 {
		t.Errorf("findings without --arf: %v", got)
	}
	w.RequireARF = true
	got := w.catalogueFindings(metadata, []string{"pid", "unknown"})
	if len(got) != 1 || !strings.Contains(got[0], "urn:example:unknown:1") {
		t.Fatalf("findings %v, want one for the unknown type", got)
	}
	w.ValidationMode = ValidationModeStrict
	w.reportCatalogueFindings("https://issuer.example", got)
	log := w.GetLog()
	if last := log[len(log)-1]; last.Severity != "warning" || last.Details["event"] != "catalogue_finding" {
		t.Errorf("last log entry %+v, want a catalogue warning", last)
	}
}
