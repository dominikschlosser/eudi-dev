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
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
)

func TestGenerateTrustListJWT_ValidSignature(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("GenerateCACert: %v", err)
	}

	jwt, err := GenerateTrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("GenerateTrustListJWT: %v", err)
	}

	// Parse the JWT and verify signature
	token, err := sdjwt.Parse(jwt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	result := sdjwt.Verify(token, &caKey.PublicKey)
	if !result.SignatureValid {
		t.Errorf("expected valid signature, got errors: %v", result.Errors)
	}
}

func TestGenerateTrustListJWT_Header(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	caCert, _ := mock.GenerateCACert(caKey)

	jwt, err := GenerateTrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("GenerateTrustListJWT: %v", err)
	}

	// Decode header
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parsing header: %v", err)
	}

	if alg, _ := header["alg"].(string); alg != "ES256" {
		t.Errorf("expected alg ES256, got %q", alg)
	}
	if typ, _ := header["typ"].(string); typ != "JWT" {
		t.Errorf("expected typ JWT, got %q", typ)
	}
}

func TestGenerateTrustListJWT_PayloadStructure(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	caCert, _ := mock.GenerateCACert(caKey)

	jwt, err := GenerateTrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("GenerateTrustListJWT: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	lote, ok := payload["LoTE"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level LoTE object, got %T", payload["LoTE"])
	}
	if _, ok := lote["ListAndSchemeInformation"]; !ok {
		t.Error("expected ListAndSchemeInformation in LoTE payload")
	}
	if _, ok := lote["TrustedEntitiesList"]; !ok {
		t.Error("expected TrustedEntitiesList in LoTE payload")
	}
	schemeInfo, ok := lote["ListAndSchemeInformation"].(map[string]any)
	if !ok {
		t.Fatal("expected ListAndSchemeInformation object")
	}
	if schemeInfo["LoTEVersionIdentifier"] != float64(1) {
		t.Errorf("expected LoTEVersionIdentifier 1, got %v", schemeInfo["LoTEVersionIdentifier"])
	}
	if schemeInfo["LoTESequenceNumber"] != float64(1) {
		t.Errorf("expected LoTESequenceNumber 1, got %v", schemeInfo["LoTESequenceNumber"])
	}
	if schemeInfo["LoTEType"] != localTrustListType {
		t.Errorf("expected local LoTEType %s, got %v", localTrustListType, schemeInfo["LoTEType"])
	}
	if _, ok := schemeInfo["ListIssueDateTime"].(string); !ok {
		t.Errorf("expected ListIssueDateTime string, got %T", schemeInfo["ListIssueDateTime"])
	}
	if _, ok := schemeInfo["NextUpdate"].(string); !ok {
		t.Errorf("expected NextUpdate string, got %T", schemeInfo["NextUpdate"])
	}

	// Verify the trusted entities list has entries with certificate data
	entities, ok := lote["TrustedEntitiesList"].([]any)
	if !ok || len(entities) == 0 {
		t.Fatal("expected non-empty TrustedEntitiesList")
	}
}

func TestGenerateTrustListJWTForWallet_PIDProfileMatchesETSIShape(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.IssuerURL = "https://wallet.example:8443"

	jwt, err := GenerateTrustListJWTForWallet(w, w.IssuerURL)
	if err != nil {
		t.Fatalf("GenerateTrustListJWTForWallet: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	lote, ok := payload["LoTE"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level LoTE object, got %T", payload["LoTE"])
	}
	schemeInfo, ok := lote["ListAndSchemeInformation"].(map[string]any)
	if !ok {
		t.Fatalf("expected ListAndSchemeInformation object, got %T", lote["ListAndSchemeInformation"])
	}
	if schemeInfo["LoTEType"] != pidTrustListType {
		t.Fatalf("expected PID LoTEType %s, got %v", pidTrustListType, schemeInfo["LoTEType"])
	}
	if schemeInfo["StatusDeterminationApproach"] != pidStatusDetermination {
		t.Fatalf("expected PID status determination %s, got %v", pidStatusDetermination, schemeInfo["StatusDeterminationApproach"])
	}
	if schemeInfo["SchemeTerritory"] != "EU" {
		t.Fatalf("expected EU scheme territory, got %v", schemeInfo["SchemeTerritory"])
	}
	rules, ok := schemeInfo["SchemeTypeCommunityRules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected one SchemeTypeCommunityRules entry, got %v", schemeInfo["SchemeTypeCommunityRules"])
	}
	rule, ok := rules[0].(map[string]any)
	if !ok || rule["uriValue"] != pidSchemeCommunityRules {
		t.Fatalf("expected PID scheme rule %s, got %v", pidSchemeCommunityRules, rules)
	}
}

func TestTrustListGroupsForWallet_MixedProfiles(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.RegisterIssuedAttestation(applyPIDTrustProfileDefaults(IssuedAttestationSpec{
		Format: "dc+sd-jwt",
		VCT:    mock.DefaultPIDVCT,
	})); err != nil {
		t.Fatalf("registering PID attestation: %v", err)
	}
	if err := w.RegisterIssuedAttestation(applyLocalTrustProfileDefaults(IssuedAttestationSpec{
		Format:  "mso_mdoc",
		DocType: "org.iso.23220.photoid.1",
		Entitlements: []string{
			nonQEAAProviderEntitlement,
		},
	})); err != nil {
		t.Fatalf("registering local attestation: %v", err)
	}

	groups := TrustListGroupsForWallet(w)
	if len(groups) != 2 {
		t.Fatalf("expected 2 trust-list groups, got %d", len(groups))
	}
	if groups[0].ID != "pid" {
		t.Fatalf("expected pid group first, got %s", groups[0].ID)
	}
	if groups[1].ID != "local" {
		t.Fatalf("expected local group second, got %s", groups[1].ID)
	}

	defaultGroup, ok := DefaultTrustListGroupForWallet(w)
	if !ok {
		t.Fatal("expected default trust-list group")
	}
	if defaultGroup.ID != "pid" {
		t.Fatalf("expected default group pid, got %s", defaultGroup.ID)
	}
}

func TestBuildTrustListIndexEntries_UsesRelativePathAndOptionalAdvertisedURL(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.RegisterIssuedAttestation(applyPIDTrustProfileDefaults(IssuedAttestationSpec{
		Format: "dc+sd-jwt",
		VCT:    mock.DefaultPIDVCT,
	})); err != nil {
		t.Fatalf("registering PID attestation: %v", err)
	}

	entries := BuildTrustListIndexEntries(w, "")
	if len(entries) != 1 {
		t.Fatalf("expected one trust-list entry, got %d", len(entries))
	}
	if entries[0].Path != "/api/trustlists/pid" {
		t.Fatalf("expected pid path, got %s", entries[0].Path)
	}
	if entries[0].AdvertisedURL != "" {
		t.Fatalf("expected empty advertised_url without issuer, got %s", entries[0].AdvertisedURL)
	}
	if entries[0].URL != "" {
		t.Fatalf("expected empty legacy url without issuer, got %s", entries[0].URL)
	}

	entries = BuildTrustListIndexEntries(w, "https://wallet.example:8443")
	if len(entries) != 1 {
		t.Fatalf("expected one trust-list entry, got %d", len(entries))
	}
	if entries[0].AdvertisedURL != "https://wallet.example:8443/api/trustlists/pid" {
		t.Fatalf("expected advertised_url, got %s", entries[0].AdvertisedURL)
	}
	if entries[0].URL != entries[0].AdvertisedURL {
		t.Fatalf("expected legacy url alias to match advertised_url, got %s vs %s", entries[0].URL, entries[0].AdvertisedURL)
	}
}

func TestSigningCertChainForProfile_UsesSharedCAWithDistinctLeafs(t *testing.T) {
	w := generateTestWallet(t)
	pidSpec := applyPIDTrustProfileDefaults(IssuedAttestationSpec{
		Format: "dc+sd-jwt",
		VCT:    mock.DefaultPIDVCT,
	})
	localSpec := applyLocalTrustProfileDefaults(IssuedAttestationSpec{
		Format:  "mso_mdoc",
		DocType: "org.iso.23220.photoid.1",
	})

	pidChain, err := w.SigningCertChainForIssuedAttestation(pidSpec)
	if err != nil {
		t.Fatalf("SigningCertChainForIssuedAttestation(pid): %v", err)
	}
	localChain, err := w.SigningCertChainForIssuedAttestation(localSpec)
	if err != nil {
		t.Fatalf("SigningCertChainForIssuedAttestation(local): %v", err)
	}
	if len(pidChain) != 2 || len(localChain) != 2 {
		t.Fatalf("expected leaf+CA chains, got pid=%d local=%d", len(pidChain), len(localChain))
	}
	if bytes.Equal(pidChain[0].Raw, localChain[0].Raw) {
		t.Fatal("expected distinct leaf certificates for pid and local profiles")
	}
	if !bytes.Equal(pidChain[1].Raw, localChain[1].Raw) {
		t.Fatal("expected pid and local profiles to share the same CA certificate")
	}
	pidPub, ok := pidChain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected ECDSA public key for pid leaf")
	}
	localPub, ok := localChain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected ECDSA public key for local leaf")
	}
	if !pidPub.Equal(localPub) || !pidPub.Equal(&w.IssuerKey.PublicKey) {
		t.Fatal("expected profile-specific leaf certificates to share the wallet issuer public key")
	}
}

func TestGenerateTrustListJWT_WrongKeyVerification(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	otherKey, _ := mock.GenerateKey()
	caCert, _ := mock.GenerateCACert(caKey)

	jwt, err := GenerateTrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("GenerateTrustListJWT: %v", err)
	}

	token, _ := sdjwt.Parse(jwt)
	result := sdjwt.Verify(token, &otherKey.PublicKey)
	if result.SignatureValid {
		t.Error("expected invalid signature with wrong key")
	}
}
