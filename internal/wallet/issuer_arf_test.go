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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

// signedTestIssuerMetadata signs issuer metadata with an access certificate,
// as ARF ISSU_32 requires, and parses it as the wallet does. It offers one
// configuration of the given type.
func signedTestIssuerMetadata(t *testing.T, key *ecdsa.PrivateKey, chain []*x509.Certificate, format, typ, issuerInfo string) (map[string]any, []*x509.Certificate) {
	t.Helper()
	config := map[string]any{"format": format}
	if format == "mso_mdoc" {
		config["doctype"] = typ
	} else {
		config["vct"] = typ
	}
	payload := map[string]any{
		"iss":                                 "https://issuer.example",
		"sub":                                 "https://issuer.example",
		"iat":                                 time.Now().Unix(),
		"credential_issuer":                   "https://issuer.example",
		"credential_endpoint":                 "https://issuer.example/credential",
		"credential_configurations_supported": map[string]any{"offered": config},
	}
	if issuerInfo != "" {
		var info []any
		if err := json.Unmarshal([]byte(issuerInfo), &info); err != nil {
			t.Fatal(err)
		}
		payload["issuer_info"] = info
	}
	raw, err := signJSONWebSignature(payload, key, map[string]any{"alg": "ES256", "typ": signedIssuerMetadataTyp, "x5c": buildJWSX5C(chain)})
	if err != nil {
		t.Fatal(err)
	}
	metadata, signerChain, err := parseIssuerMetadataDocument([]byte(raw), "application/jwt", "https://issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	return metadata, signerChain
}

// arfIssuerFindings checks metadata as a wallet with --arf does before it
// requests the offered configuration.
func arfIssuerFindings(checking *Wallet, metadata map[string]any, chain []*x509.Certificate) []string {
	checking.RequireARF = true
	return checking.issuerARFCheck(metadata, chain, []string{"offered"})
}

func TestARFAcceptsARegisteredIssuer(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestIssuer(t, w, registrar.NonQEAAProviderEntitlement)
	key, chain := issueTestAccessCertificate(t, w, rp.Identifier[0].Identifier)
	metadata, signer := signedTestIssuerMetadata(t, key, chain, "dc+sd-jwt", testDiplomaVCT, issueTestIssuerInfo(t, w, rp).IssuerInfo)
	if got := arfIssuerFindings(w, metadata, signer); len(got) != 0 {
		t.Fatalf("findings %v", got)
	}
}

func TestARFChecksHowAnIssuerAuthenticates(t *testing.T) {
	w := generateTestWallet(t)
	eaa := registerTestIssuer(t, w, registrar.NonQEAAProviderEntitlement)
	eaaKey, eaaChain := issueTestAccessCertificate(t, w, eaa.Identifier[0].Identifier)
	eaaInfo := issueTestIssuerInfo(t, w, eaa).IssuerInfo
	pidProvider := registerTestIssuer(t, w, registrar.PIDProviderEntitlement, registrar.ProvidedAttestation{Format: "dc+sd-jwt", Type: mock.DefaultPIDVCT})
	pidInfo := issueTestIssuerInfo(t, w, pidProvider).IssuerInfo

	for _, tc := range []struct {
		name string
		run  func() []string
		want string
	}{
		{"unsigned metadata", func() []string {
			metadata, _ := signedTestIssuerMetadata(t, eaaKey, eaaChain, "dc+sd-jwt", testDiplomaVCT, eaaInfo)
			return arfIssuerFindings(w, metadata, nil)
		}, "ARF ISSU_34: the Credential Issuer Metadata is not signed"},
		{"no registration certificate", func() []string {
			metadata, chain := signedTestIssuerMetadata(t, eaaKey, eaaChain, "dc+sd-jwt", testDiplomaVCT, "")
			return arfIssuerFindings(w, metadata, chain)
		}, "ARF RPRC_22a: the issuer metadata carries no registration certificate"},
		{"an unregistered attestation type", func() []string {
			metadata, chain := signedTestIssuerMetadata(t, eaaKey, eaaChain, "dc+sd-jwt", "urn:example:other", eaaInfo)
			return arfIssuerFindings(w, metadata, chain)
		}, "ARF RPRC_23 and ISSU_34b: the issuer's registration certificate does not list urn:example:other"},
		{"a PID from an EAA provider", func() []string {
			metadata, chain := signedTestIssuerMetadata(t, eaaKey, eaaChain, "dc+sd-jwt", mock.DefaultPIDVCT, eaaInfo)
			return arfIssuerFindings(w, metadata, chain)
		}, "ARF ISSU_24a: the issuer's registration certificate does not register it as a PID Provider"},
		{"another provider's registration certificate", func() []string {
			metadata, chain := signedTestIssuerMetadata(t, eaaKey, eaaChain, "dc+sd-jwt", mock.DefaultPIDVCT, pidInfo)
			return arfIssuerFindings(w, metadata, chain)
		}, "ARF RPRC_22b"},
		{"a revoked registration certificate", func() []string {
			if _, err := w.Registrar().SetRegistrationCertificatesRevoked(eaa.Identifier[0].Identifier, registrar.RegistrationScope{}, true); err != nil {
				t.Fatal(err)
			}
			defer w.Registrar().SetRegistrationCertificatesRevoked(eaa.Identifier[0].Identifier, registrar.RegistrationScope{}, false)
			metadata, chain := signedTestIssuerMetadata(t, eaaKey, eaaChain, "dc+sd-jwt", testDiplomaVCT, eaaInfo)
			return arfIssuerFindings(w, metadata, chain)
		}, "ARF RPRC_22a: the registrar revoked the registration certificate"},
		{"an access certificate from an unknown authority", func() []string {
			other := generateTestWallet(t)
			key, chain := issueTestAccessCertificate(t, other, registerTestIssuer(t, other, registrar.NonQEAAProviderEntitlement).Identifier[0].Identifier)
			metadata, signer := signedTestIssuerMetadata(t, key, chain, "dc+sd-jwt", testDiplomaVCT, eaaInfo)
			return arfIssuerFindings(w, metadata, signer)
		}, "ARF ISSU_34: the access certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.run()
			if !strings.Contains(strings.Join(got, "\n"), tc.want) {
				t.Fatalf("findings %v, want %q", got, tc.want)
			}
		})
	}
}

// A registration certificate needs a registrar's signature. The relying party
// access CA signs any visitor's CSR, so it doesn't count (ARF ISSU_33a).
func TestARFRefusesAnIssuerRegistrationFromTheAccessCA(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestIssuer(t, w, registrar.NonQEAAProviderEntitlement)
	key, chain := issueTestAccessCertificate(t, w, rp.Identifier[0].Identifier)
	claims, err := registrar.RegistrationCertificateClaimsFor(w.RegistrarBase(), registrar.ProviderCertificateContent(rp, rp.Services[0]), nil, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	forged, err := registrar.SignRegistrationCertificateJWT(claims, key, chain)
	if err != nil {
		t.Fatal(err)
	}
	info, err := registrar.IssuerInfoValue(registrar.RegistrarDatasetFor(rp, rp.Services[0]), forged)
	if err != nil {
		t.Fatal(err)
	}
	metadata, signer := signedTestIssuerMetadata(t, key, chain, "dc+sd-jwt", testDiplomaVCT, info)
	if got := strings.Join(arfIssuerFindings(w, metadata, signer), "\n"); !strings.Contains(got, "ARF ISSU_33a") {
		t.Fatalf("findings %q, want ISSU_33a", got)
	}
}

// The wallet's own issuer passes the checks: it signs its metadata with its
// access certificate and carries a registration certificate from its
// registrar.
func TestARFAcceptsTheWalletsOwnIssuer(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"
	w.IssuedAttestations = []IssuedAttestationSpec{
		{Format: "dc+sd-jwt", VCT: mock.DefaultPIDVCT},
		{Format: "mso_mdoc", DocType: mock.PIDNamespace},
		{Format: "dc+sd-jwt", VCT: testDiplomaVCT},
	}
	metadata, err := buildOpenIDCredentialIssuerMetadata(w, w.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignCredentialIssuerMetadata(w, w.IssuerURL, metadata, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	parsed, chain, err := parseIssuerMetadataDocument([]byte(signed), "application/jwt", w.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	w.RequireARF = true
	configurations := make([]string, 0)
	for id := range parsed["credential_configurations_supported"].(map[string]any) {
		configurations = append(configurations, id)
	}
	if len(configurations) == 0 {
		t.Fatal("the wallet's issuer offers no configuration")
	}
	if got := w.issuerARFCheck(parsed, chain, configurations); len(got) != 0 {
		t.Fatalf("findings %v", got)
	}
}

func TestStrictARFRefusesAnUnregisteredIssuer(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	if err := w.reportARFIssuanceFindings("https://issuer.example", []string{"ARF RPRC_22a: no certificate"}); err == nil {
		t.Fatal("strict mode accepted an ARF finding")
	}
	w.ValidationMode = ValidationModeDebug
	if err := w.reportARFIssuanceFindings("https://issuer.example", []string{"ARF RPRC_22a: no certificate"}); err != nil {
		t.Fatalf("debug mode refused: %v", err)
	}
}

// provides_attestations names types, so an entry without one authorises
// nothing, and an offered configuration needs a type to be checked.
func TestARFChecksOfferedTypesStrictly(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestIssuer(t, w, registrar.NonQEAAProviderEntitlement)
	key, chain := issueTestAccessCertificate(t, w, rp.Identifier[0].Identifier)
	info := issueTestIssuerInfo(t, w, rp).IssuerInfo

	metadata, signer := signedTestIssuerMetadata(t, key, chain, "dc+sd-jwt", "", info)
	if got := strings.Join(arfIssuerFindings(w, metadata, signer), "\n"); !strings.Contains(got, "names no vct or doctype") {
		t.Errorf("offer without a type: %q", got)
	}
	w.RequireARF = true
	if got := strings.Join(w.issuerARFCheck(metadata, signer, []string{"missing"}), "\n"); !strings.Contains(got, "has no configuration missing") {
		t.Errorf("unknown configuration: %q", got)
	}
	if providesType([]registeredCredential{{format: "dc+sd-jwt"}}, "dc+sd-jwt", []string{testDiplomaVCT}) {
		t.Error("a listed entry without a type authorised a type")
	}
	if providesType([]registeredCredential{{format: "mso_mdoc", types: []string{testDiplomaVCT}}}, "dc+sd-jwt", []string{testDiplomaVCT}) {
		t.Error("a type in another format matched")
	}
}

// A PID next to another attestation needs both entitlements (ISSU_24a and
// ISSU_34a).
func TestARFChecksEachKindInAMixedOffer(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestIssuer(t, w, registrar.PIDProviderEntitlement,
		registrar.ProvidedAttestation{Format: "dc+sd-jwt", Type: mock.DefaultPIDVCT},
		registrar.ProvidedAttestation{Format: "dc+sd-jwt", Type: testDiplomaVCT})
	key, chain := issueTestAccessCertificate(t, w, rp.Identifier[0].Identifier)
	metadata, signer := signedTestIssuerMetadata(t, key, chain, "dc+sd-jwt", mock.DefaultPIDVCT, issueTestIssuerInfo(t, w, rp).IssuerInfo)
	supported := metadata["credential_configurations_supported"].(map[string]any)
	supported["diploma"] = map[string]any{"format": "dc+sd-jwt", "vct": testDiplomaVCT}
	w.RequireARF = true
	got := w.issuerARFCheck(metadata, signer, []string{"offered", "diploma"})
	if len(got) != 1 || !strings.Contains(got[0], "ARF ISSU_34a") {
		t.Fatalf("findings %v, want only the missing EAA provider entitlement", got)
	}
}

func TestDebugModeLogsTheIssuerFindingsAndGoesOn(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.reportARFIssuanceFindings("https://issuer.example", []string{"ARF RPRC_22a: one", "ARF RPRC_23: two"}); err != nil {
		t.Fatal(err)
	}
	log := w.GetLog()
	last := log[len(log)-1]
	if last.Severity != "warning" || last.Details["event"] != "arf_finding" || !strings.Contains(last.Detail, "2 ARF findings") {
		t.Fatalf("log entry %+v", last)
	}
}

func TestSignedMetadataIsServedWhenPreferred(t *testing.T) {
	for accept, want := range map[string]bool{
		"application/jwt;q=0":                     false,
		"application/jwt;q=0.9, application/json": false,
		"application/jwt":                         true,
		"application/jwt, application/json;q=0.5": true,
		"application/json, application/jwt":       false,
		"application/json":                        false,
		"":                                        false,
		"*/*":                                     false,
		"application/jwt;q=0.4, */*;q=0.5":        false,
	} {
		if got := PrefersSignedIssuerMetadata(accept); got != want {
			t.Errorf("Accept %q: %v, want %v", accept, got, want)
		}
	}
}
