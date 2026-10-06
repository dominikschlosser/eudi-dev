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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

func pidQueryForRegistration() map[string]any {
	return map[string]any{"credentials": []any{map[string]any{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		"claims": []any{map[string]any{"path": []any{"given_name"}}},
	}}}
}

// registerTestRelyingParty registers a relying party whose intended use asks
// for the PID's given_name.
func registerTestRelyingParty(t *testing.T, w *Wallet) WalletRelyingParty {
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
	}, w.RegistrarBase())
	if err != nil {
		t.Fatalf("RegisterRelyingParty: %v", err)
	}
	return rp
}

func issueTestRegistrationCertificate(t *testing.T, w *Wallet, rp WalletRelyingParty) *RegistrationCertificateResult {
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

// A registration certificate created by the wallet passes the wallet's own
// ETSI TS 119 475 content checks and the ARF RPRC_21 over-asking check for the
// registered query.
func TestACreatedRegistrationCertificatePassesTheWalletsChecks(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	rp := registerTestRelyingParty(t, w)
	result := issueTestRegistrationCertificate(t, w, rp)

	var verifierInfo []map[string]any
	if err := json.Unmarshal([]byte(result.VerifierInfo), &verifierInfo); err != nil {
		t.Fatalf("verifier_info %q is not a JSON array: %v", result.VerifierInfo, err)
	}
	if verifierInfo[0]["format"] != "registration_cert" || verifierInfo[0]["data"] != result.RegistrationCertificate {
		t.Fatalf("verifier_info %v, want the certificate as registration_cert", verifierInfo)
	}
	certs, findings := verifiedRegistrationCertificates(map[string]any{"verifier_info": result.VerifierInfo})
	if len(certs) != 1 || len(findings) != 0 {
		t.Fatalf("certificates %d, findings %v, want one verified certificate", len(certs), findings)
	}
	if got := registrationCertificateContentFindings(certs[0]); len(got) != 0 {
		t.Errorf("content findings %v, want none", got)
	}
	if got := overAskingFindings(certs[0], pidQueryForRegistration()); len(got) != 0 {
		t.Errorf("over-asking findings %v, want none", got)
	}
	if got := purposeStrings(certs[0]["purpose"]); len(got) != 1 || got[0] != "Age check" {
		t.Errorf("purpose %v, want Age check", got)
	}
	if certs[0]["sub"] != rp.Identifier[0].Identifier || certs[0]["registry_uri"] != rp.RegistryURI {
		t.Errorf("sub %v, registry_uri %v, want the registration's", certs[0]["sub"], certs[0]["registry_uri"])
	}
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
	identifier, legalName, country := accessCertificateSubject(access)
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

// ARF RPRC_17a: the registration certificate names the relying party of the
// access certificate that signs the request.
func TestTheRegistrationCertificateMatchesTheAccessCertificate(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	access, err := w.IssueAccessCertificate(AccessCertificateRequest{Identifier: rp.Identifier[0].Identifier, CSR: testAccessCSR(t, key)})
	if err != nil {
		t.Fatalf("IssueAccessCertificate: %v", err)
	}
	block, _ := pem.Decode([]byte(access.Certificate))
	accessCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certs, _ := verifiedRegistrationCertificates(map[string]any{"verifier_info": issueTestRegistrationCertificate(t, w, rp).VerifierInfo})
	if got := registrationBindingFindings(certs[0], accessCert); len(got) != 0 {
		t.Errorf("findings %v for the relying party's own access certificate, want none", got)
	}

	_, demoChain, err := w.AccessSigningMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if got := registrationBindingFindings(certs[0], demoChain[0]); len(got) != 1 || !strings.Contains(got[0], "RPRC_17a") {
		t.Errorf("findings %v for another relying party's access certificate, want the RPRC_17a warning", got)
	}
	// An intermediary's certificate names the relying party in act.sub (ETSI
	// TS 119 475 GEN-5.2.4-09).
	intermediary := map[string]any{"sub": "LEIXG-INTERMEDIARY", "act": map[string]any{"sub": rp.Identifier[0].Identifier}}
	if got := registrationBindingFindings(intermediary, accessCert); len(got) != 0 {
		t.Errorf("findings %v for an intermediary acting for the relying party, want none", got)
	}
}

// ARF RPA_10: the consent dialog links the registered privacy policy.
func TestTheConsentDialogLinksThePrivacyPolicy(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	rp := registerTestRelyingParty(t, w)
	result := issueTestRegistrationCertificate(t, w, rp)
	purposes, policies := consentRegistration(&AuthorizationRequestParams{
		RequestPayload: map[string]any{"verifier_info": result.VerifierInfo},
	})
	if len(purposes) != 1 || len(policies) != 1 || policies[0] != "https://wallet.example/privacy-policy" {
		t.Errorf("purposes %v, privacy policies %v, want the registered purpose and policy", purposes, policies)
	}
}
