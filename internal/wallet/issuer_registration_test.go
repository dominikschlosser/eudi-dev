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
	"encoding/json"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

const testDiplomaVCT = "urn:example:diploma:1"

// registerTestIssuer registers an attestation provider that issues the
// diploma as SD-JWT VC.
func registerTestIssuer(t *testing.T, w *Wallet, entitlement string, provides ...ProvidedAttestation) WalletRelyingParty {
	t.Helper()
	if len(provides) == 0 {
		provides = []ProvidedAttestation{{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{testDiplomaVCT}}}}
	}
	rp, err := w.RegisterRelyingParty(WalletRelyingParty{
		TradeName: "Example University",
		Services: []WalletRelyingPartyService{{
			ServiceIdentifier:    "diplomas",
			Entitlements:         []string{entitlement},
			ProvidesAttestations: provides,
		}},
	}, w.RegistrarBase())
	if err != nil {
		t.Fatalf("RegisterRelyingParty: %v", err)
	}
	return rp
}

func issueTestIssuerInfo(t *testing.T, w *Wallet, rp WalletRelyingParty) *RegistrationCertificateResult {
	t.Helper()
	result, err := w.IssueRegistrationCertificate(RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier})
	if err != nil {
		t.Fatalf("IssueRegistrationCertificate: %v", err)
	}
	return result
}

func TestAnIssuerGetsOneCertificateForItsService(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestIssuer(t, w, nonQEAAProviderEntitlement)
	result := issueTestIssuerInfo(t, w, rp)
	if result.VerifierInfo != "" || result.IssuerInfo == "" {
		t.Fatalf("result %+v, want issuer_info and no verifier_info", result)
	}

	var info []IssuerInfoEntry
	if err := json.Unmarshal([]byte(result.IssuerInfo), &info); err != nil {
		t.Fatal(err)
	}
	// ETSI TS 119 472-3 V1.1.1 §4.2.3: a registrar_dataset with identifier,
	// srvDescription, registryURI and providesAttestations, and the registration
	// certificate in a registration_cert entry.
	if len(info) != 2 || info[0].Format != "registrar_dataset" || info[1].Format != "registration_cert" || info[1].Data != result.RegistrationCertificate {
		t.Fatalf("issuer_info %+v", info)
	}
	dataset, _ := info[0].Data.(map[string]any)
	for _, field := range []string{"identifier", "srvDescription", "registryURI", "providesAttestations"} {
		if dataset[field] == nil {
			t.Errorf("registrar_dataset has no %s: %v", field, dataset)
		}
	}

	registrations, problems := verifyRegistrationEntries(infoEntries(map[string]any{"issuer_info": result.IssuerInfo}, "issuer_info"))
	if len(registrations) != 1 || len(problems) != 0 {
		t.Fatalf("registrations %d, problems %v", len(registrations), problems)
	}
	cert := registrations[0].claims
	// A provider certificate has no intended use (ARF RPRC_05), so it has no
	// purpose, privacy policy or credentials. It carries the policy of ETSI TS
	// 119 475 V1.2.1 OVR-6.1.3-01.
	for _, absent := range []string{"credentials", "purpose", "privacy_policy"} {
		if _, ok := cert[absent]; ok {
			t.Errorf("provider certificate has %s", absent)
		}
	}
	if policies, _ := cert["policy_id"].([]any); len(policies) != 1 || policies[0] != "0.4.0.19475.3.1" {
		t.Errorf("policy_id %v", cert["policy_id"])
	}
	if provided := listOfMaps(cert["provides_attestations"]); len(provided) != 1 || provided[0]["format"] != "dc+sd-jwt" || credentialTypes(provided[0]["meta"])[0] != testDiplomaVCT {
		t.Errorf("provides_attestations %v", cert["provides_attestations"])
	}
}

func TestIssuerRegistrationsAreChecked(t *testing.T) {
	w := generateTestWallet(t)
	diploma := []ProvidedAttestation{{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{testDiplomaVCT}}}}
	for _, tc := range []struct {
		name    string
		service WalletRelyingPartyService
		want    string
	}{
		{"attestations without a provider entitlement", WalletRelyingPartyService{ProvidesAttestations: diploma}, "needs an attestation provider entitlement"},
		{"attestations with the service provider entitlement", WalletRelyingPartyService{Entitlements: []string{serviceProviderEntitlement}, ProvidesAttestations: diploma}, "needs an attestation provider entitlement"},
		{"a provider without attestations", WalletRelyingPartyService{Entitlements: []string{pidProviderEntitlement}}, "RPRC_15"},
		{"an unknown entitlement only", WalletRelyingPartyService{Entitlements: []string{"https://example.com/entitled"}}, "Annex A.2"},
		{"an attestation in another format", WalletRelyingPartyService{Entitlements: []string{nonQEAAProviderEntitlement}, ProvidesAttestations: []ProvidedAttestation{{Format: "jwt_vc_json", Meta: map[string]any{"vct_values": []string{"x"}}}}}, "not dc+sd-jwt or mso_mdoc"},
		{"an attestation without a type", WalletRelyingPartyService{Entitlements: []string{nonQEAAProviderEntitlement}, ProvidesAttestations: []ProvidedAttestation{{Format: "mso_mdoc", Meta: map[string]any{}}}}, "needs its type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "Example", Services: []WalletRelyingPartyService{tc.service}}, w.RegistrarBase())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// A provider that also requests attributes registers as a service provider
// too (ARF RPRC_05 note).
func TestAProviderWithAnIntendedUseIsAServiceProviderToo(t *testing.T) {
	w := generateTestWallet(t)
	rp, err := w.RegisterRelyingParty(WalletRelyingParty{
		TradeName: "Example University",
		Services: []WalletRelyingPartyService{{
			Entitlements:         []string{nonQEAAProviderEntitlement},
			ProvidesAttestations: []ProvidedAttestation{{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{testDiplomaVCT}}}},
			IntendedUses: []IntendedUse{{Credentials: []RegisteredCredential{{
				Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{mock.DefaultPIDVCT}}, Claims: []RegisteredClaim{{Path: []any{"family_name"}}},
			}}}},
		}},
	}, w.RegistrarBase())
	if err != nil {
		t.Fatal(err)
	}
	if got := rp.Services[0].Entitlements; len(got) != 2 || got[1] != serviceProviderEntitlement {
		t.Fatalf("entitlements %v, want the provider entitlement and the service provider entitlement", got)
	}
	// With an intended use and a provider service the request has to say which.
	use := rp.Services[0].IntendedUses[0].IntendedUseIdentifier
	if result, err := w.IssueRegistrationCertificate(RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: use}); err != nil || result.VerifierInfo == "" {
		t.Fatalf("intended use certificate: %v %+v", err, result)
	}
	if result, err := w.IssueRegistrationCertificate(RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier}); err != nil || result.IssuerInfo == "" {
		t.Fatalf("provider certificate: %v %+v", err, result)
	}
}

func TestAVerifierHasNoProviderCertificate(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	_, err := w.IssueRegistrationCertificate(RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier})
	if err == nil || !strings.Contains(err.Error(), "0 attestation provider services") {
		t.Fatalf("got %v", err)
	}
}

func TestProviderCertificatesFollowTheRegistration(t *testing.T) {
	srv, ts := registrarServer(t)
	w := srv.wallet
	rp := registerTestIssuer(t, w, nonQEAAProviderEntitlement)
	certOf := func(result *RegistrationCertificateResult) map[string]any {
		registrations, _ := verifyRegistrationEntries(infoEntries(map[string]any{"issuer_info": result.IssuerInfo}, "issuer_info"))
		return registrations[0].claims
	}
	first := certOf(issueTestIssuerInfo(t, w, rp))
	second := certOf(issueTestIssuerInfo(t, w, rp))
	if got := registrationStatusFindings(first, ts.Client()); len(got) != 1 || !strings.Contains(got[0], "revoked") {
		t.Fatalf("the replaced certificate: %v, want revoked", got)
	}
	if got := registrationStatusFindings(second, ts.Client()); len(got) != 0 {
		t.Fatalf("the new certificate: %v", got)
	}

	// Revoking the service revokes its certificate, and activating restores it.
	scope := RegistrationScope{ServiceIdentifier: "diplomas"}
	if n, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, scope, true); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if n, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, scope, false); err != nil || n != 1 {
		t.Fatalf("activate: %d %v", n, err)
	}
	if _, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{ServiceIdentifier: "unknown"}, true); err == nil {
		t.Fatal("an unknown service was accepted")
	}
	if _, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{ServiceIdentifier: "diplomas", IntendedUseIdentifier: "elsewhere"}, true); err == nil {
		t.Fatal("an intended use outside the service was accepted")
	}

	// An update that adds an attestation type changes the certificate content,
	// so the certificate is revoked for good.
	rp.Services[0].ProvidesAttestations = append(rp.Services[0].ProvidesAttestations, ProvidedAttestation{Format: "mso_mdoc", Meta: map[string]any{"doctype_value": "org.example.diploma.1"}})
	if _, err := w.UpdateRelyingParty(rp, w.RegistrarBase()); err != nil {
		t.Fatal(err)
	}
	if got := registrationStatusFindings(second, ts.Client()); len(got) != 1 {
		t.Fatalf("after the update: %v, want revoked", got)
	}
	if n, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, scope, false); err != nil || n != 0 {
		t.Fatalf("activating a superseded certificate: %d %v", n, err)
	}
}
