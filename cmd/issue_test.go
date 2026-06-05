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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/config"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
	"github.com/dominikschlosser/oid4vc-dev/internal/trustlist"
	"github.com/dominikschlosser/oid4vc-dev/internal/validate"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

// --- omitClaims unit tests ---

func TestOmitClaims_RemovesSpecifiedClaims(t *testing.T) {
	result := omitClaims(mock.SDJWTPIDClaims, []string{"place_of_birth", "address", "nationalities"})

	for _, name := range []string{"place_of_birth", "address", "nationalities"} {
		if _, ok := result[name]; ok {
			t.Errorf("%s should have been omitted", name)
		}
	}

	for _, name := range []string{"family_name", "given_name", "birthdate"} {
		if _, ok := result[name]; !ok {
			t.Errorf("%s should still be present", name)
		}
	}

	expectedCount := len(mock.SDJWTPIDClaims) - 3
	if len(result) != expectedCount {
		t.Errorf("expected %d claims, got %d", expectedCount, len(result))
	}
}

func TestOmitClaims_EmptyOmitReturnsOriginal(t *testing.T) {
	result := omitClaims(mock.SDJWTPIDClaims, nil)
	if len(result) != len(mock.SDJWTPIDClaims) {
		t.Errorf("expected %d claims, got %d", len(mock.SDJWTPIDClaims), len(result))
	}
}

func TestOmitClaims_OmitNonexistentClaimIsNoOp(t *testing.T) {
	result := omitClaims(mock.DefaultClaims, []string{"nonexistent_claim"})
	if len(result) != len(mock.DefaultClaims) {
		t.Errorf("expected %d claims, got %d", len(mock.DefaultClaims), len(result))
	}
}

func TestOmitClaims_TrimsWhitespace(t *testing.T) {
	result := omitClaims(mock.SDJWTPIDClaims, []string{" place_of_birth ", " address"})

	if _, ok := result["place_of_birth"]; ok {
		t.Error("place_of_birth should have been omitted (with whitespace trimming)")
	}
	if _, ok := result["address"]; ok {
		t.Error("address should have been omitted (with whitespace trimming)")
	}
}

func TestOmitClaims_DoesNotMutateOriginal(t *testing.T) {
	original := map[string]any{"a": 1, "b": 2, "c": 3}
	result := omitClaims(original, []string{"b"})

	if len(result) != 2 {
		t.Errorf("expected 2 claims in result, got %d", len(result))
	}
	if len(original) != 3 {
		t.Errorf("original should not be mutated, expected 3 claims, got %d", len(original))
	}
}

func TestOmitClaims_OmitAllClaims(t *testing.T) {
	claims := map[string]any{"a": 1, "b": 2}
	result := omitClaims(claims, []string{"a", "b"})
	if len(result) != 0 {
		t.Errorf("expected 0 claims, got %d", len(result))
	}
}

// --- resolveIssueClaimsForFormat tests ---

func TestResolveIssueClaims_DefaultWhenEmpty(t *testing.T) {
	issuePID = false
	issueClaims = ""
	issueOmit = nil

	claims, err := resolveIssueClaimsForFormat("sdjwt")
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if len(claims) != len(mock.DefaultClaims) {
		t.Errorf("expected %d default claims, got %d", len(mock.DefaultClaims), len(claims))
	}
}

func TestResolveIssueClaims_PIDWhenFlagged_SDJWT(t *testing.T) {
	issuePID = true
	issueClaims = ""
	issueOmit = nil

	claims, err := resolveIssueClaimsForFormat("sdjwt")
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if len(claims) != len(mock.SDJWTPIDClaims) {
		t.Errorf("expected %d SD-JWT PID claims, got %d", len(mock.SDJWTPIDClaims), len(claims))
	}
}

func TestResolveIssueClaims_PIDWhenFlagged_MDOC(t *testing.T) {
	issuePID = true
	issueClaims = ""
	issueOmit = nil

	claims, err := resolveIssueClaimsForFormat("mdoc")
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if len(claims) != len(mock.MDOCPIDClaims) {
		t.Errorf("expected %d mDoc PID claims, got %d", len(mock.MDOCPIDClaims), len(claims))
	}
}

func TestResolveIssueClaims_PIDWithOmit(t *testing.T) {
	issuePID = true
	issueClaims = ""
	issueOmit = []string{"place_of_birth", "sex"}

	claims, err := resolveIssueClaimsForFormat("sdjwt")
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}

	expected := len(mock.SDJWTPIDClaims) - 2
	if len(claims) != expected {
		t.Errorf("expected %d claims, got %d", expected, len(claims))
	}
	if _, ok := claims["place_of_birth"]; ok {
		t.Error("place_of_birth should be omitted")
	}
	if _, ok := claims["sex"]; ok {
		t.Error("sex should be omitted")
	}
}

func TestResolveIssueClaims_JSONString(t *testing.T) {
	issuePID = false
	issueClaims = `{"name":"Test","active":true}`
	issueOmit = nil

	claims, err := resolveIssueClaimsForFormat("sdjwt")
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if claims["name"] != "Test" {
		t.Errorf("expected name=Test, got %v", claims["name"])
	}
	if claims["active"] != true {
		t.Errorf("expected active=true, got %v", claims["active"])
	}
}

func TestResolveIssueClaims_JSONStringWithOmit(t *testing.T) {
	issuePID = false
	issueClaims = `{"a":1,"b":2,"c":3}`
	issueOmit = []string{"b"}

	claims, err := resolveIssueClaimsForFormat("sdjwt")
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if len(claims) != 2 {
		t.Errorf("expected 2 claims, got %d", len(claims))
	}
	if _, ok := claims["b"]; ok {
		t.Error("b should be omitted")
	}
}

func TestResolveIssueClaims_FileReference(t *testing.T) {
	tmpDir := t.TempDir()
	claimsFile := filepath.Join(tmpDir, "claims.json")
	if err := os.WriteFile(claimsFile, []byte(`{"file_claim":"works"}`), 0644); err != nil {
		t.Fatalf("writing claims file: %v", err)
	}

	issuePID = false
	issueClaims = "@" + claimsFile
	issueOmit = nil

	claims, err := resolveIssueClaimsForFormat("sdjwt")
	if err != nil {
		t.Fatalf("resolveIssueClaimsForFormat: %v", err)
	}
	if claims["file_claim"] != "works" {
		t.Errorf("expected file_claim=works, got %v", claims["file_claim"])
	}
}

func TestResolveIssueClaims_InvalidJSON(t *testing.T) {
	issuePID = false
	issueClaims = `{not json}`
	issueOmit = nil

	_, err := resolveIssueClaimsForFormat("sdjwt")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBuildIssueAttestationSpec_AutoNonPIDDefaults(t *testing.T) {
	issueTrustProfile = "auto"
	issueEntitlements = nil
	issueTrustListType = ""
	issueStatusDetermination = ""
	issueSchemeCommunityRule = ""
	issueSchemeTerritory = ""
	issueTrustEntityName = ""
	issueIssuanceServiceType = ""
	issueRevocationServiceType = ""
	issueIssuanceServiceName = ""
	issueRevocationServiceName = ""

	spec, err := buildIssueAttestationSpec(&wallet.StoredCredential{
		Format: "dc+sd-jwt",
		VCT:    "urn:test:employee:1",
	})
	if err != nil {
		t.Fatalf("buildIssueAttestationSpec: %v", err)
	}
	if spec.TrustListType != "http://uri.etsi.org/19602/LoTEType/local" {
		t.Fatalf("expected local trust-list type, got %s", spec.TrustListType)
	}
	if len(spec.Entitlements) != 1 || spec.Entitlements[0] != "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider" {
		t.Fatalf("expected Non_Q_EAA entitlement, got %v", spec.Entitlements)
	}
}

func TestBuildIssueAttestationSpec_RespectsExplicitOverrides(t *testing.T) {
	issueTrustProfile = "local"
	issueEntitlements = []string{"https://uri.etsi.org/19475/Entitlement/Service_Provider"}
	issueTrustListType = "http://example.com/LoTEType/Custom"
	issueStatusDetermination = "http://example.com/status"
	issueSchemeCommunityRule = "http://example.com/rules"
	issueSchemeTerritory = "DE"
	issueTrustEntityName = "Custom Entity"
	issueIssuanceServiceType = "http://example.com/SvcType/Custom/Issuance"
	issueRevocationServiceType = "http://example.com/SvcType/Custom/Revocation"
	issueIssuanceServiceName = "Custom Issuance"
	issueRevocationServiceName = "Custom Revocation"

	spec, err := buildIssueAttestationSpec(&wallet.StoredCredential{
		Format:  "mso_mdoc",
		DocType: "org.iso.23220.photoid.1",
	})
	if err != nil {
		t.Fatalf("buildIssueAttestationSpec: %v", err)
	}
	if spec.TrustListType != "http://example.com/LoTEType/Custom" {
		t.Fatalf("expected custom trust-list type, got %s", spec.TrustListType)
	}
	if spec.IssuanceServiceType != "http://example.com/SvcType/Custom/Issuance" {
		t.Fatalf("expected custom issuance service type, got %s", spec.IssuanceServiceType)
	}
	if spec.RevocationServiceType != "http://example.com/SvcType/Custom/Revocation" {
		t.Fatalf("expected custom revocation service type, got %s", spec.RevocationServiceType)
	}
	if spec.EntityName != "Custom Entity" {
		t.Fatalf("expected custom entity name, got %s", spec.EntityName)
	}
}

func TestResolveIssueClaims_MissingFile(t *testing.T) {
	issuePID = false
	issueClaims = "@/nonexistent/path/claims.json"
	issueOmit = nil

	_, err := resolveIssueClaimsForFormat("sdjwt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// --- end-to-end cobra command tests ---

func TestIssueSDJWT_EndToEnd(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	// Reset flags to defaults
	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:eudi:pid:1"
	issueExpires = "24h"

	rootCmd.SetArgs([]string{"issue", "sdjwt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt: %v", err)
	}
}

func TestIssueSDJWT_WithPID(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--pid"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --pid: %v", err)
	}
}

func TestIssueSDJWT_WithPIDAndOmit(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--pid", "--omit", "place_of_birth,sex"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --pid --omit: %v", err)
	}
}

func TestIssueSDJWT_WithCustomClaims(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueKeyPath = ""
	issueOmit = nil
	issuePID = false

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--claims", `{"custom":"claim"}`})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --claims: %v", err)
	}
}

func TestIssueSDJWTToWallet_UsesWalletIssuerContext(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:test:employee:1"
	issueExpires = "24h"
	issueNBF = ""
	issuePID = false
	issueOmit = nil
	issueToWallet = false
	issueStatusListURI = ""
	issueStatusListIdx = 0
	issueTrustProfile = "auto"
	issueEntitlements = nil
	issueTrustListType = ""
	issueStatusDetermination = ""
	issueSchemeCommunityRule = ""
	issueSchemeTerritory = ""
	issueTrustEntityName = ""
	issueIssuanceServiceType = ""
	issueRevocationServiceType = ""
	issueIssuanceServiceName = ""
	issueRevocationServiceName = ""
	walletDir = ""

	rootCmd.SetArgs([]string{"issue", "--wallet-dir", wDir, "sdjwt", "--wallet", "--vct", "urn:test:employee:1"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --wallet: %v", err)
	}

	store := wallet.NewWalletStore(wDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("loading wallet: %v", err)
	}
	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if len(w.StatusEntries) != 1 {
		t.Fatalf("expected 1 wallet-managed status entry, got %d", len(w.StatusEntries))
	}
	token, err := sdjwt.Parse(creds[0].Raw)
	if err != nil {
		t.Fatalf("parsing wallet-issued SD-JWT: %v", err)
	}
	wantIssuer := wallet.LocalIssuerURL(config.DefaultWalletPort+1, false)
	if token.Payload["iss"] != wantIssuer {
		t.Fatalf("expected iss %s, got %v", wantIssuer, token.Payload["iss"])
	}
	status, ok := token.Payload["status"].(map[string]any)
	if !ok {
		t.Fatal("expected status claim on wallet-issued SD-JWT")
	}
	statusList, ok := status["status_list"].(map[string]any)
	if !ok {
		t.Fatal("expected status_list claim on wallet-issued SD-JWT")
	}
	if got := statusList["uri"]; got != wantIssuer+"/api/statuslist" {
		t.Fatalf("expected status list uri %s/api/statuslist, got %v", wantIssuer, got)
	}

	tlJWT, err := wallet.GenerateTrustListJWTForWallet(w, w.IssuerURL)
	if err != nil {
		t.Fatalf("GenerateTrustListJWTForWallet: %v", err)
	}
	tl, err := trustlist.Parse(tlJWT)
	if err != nil {
		t.Fatalf("trustlist.Parse: %v", err)
	}
	if len(tl.Entities) == 0 || len(tl.Entities[0].Services) == 0 {
		t.Fatal("expected trust list services")
	}
	key, err := validate.ExtractAndValidateX5C(token.Header, tl.Entities[0].Services[0].Certificates)
	if err != nil {
		t.Fatalf("validating wallet-issued SD-JWT x5c against trust list: %v", err)
	}
	if key == nil {
		t.Fatal("expected trust-list-validated x5c key")
	}
}

func TestIssueSDJWT_WithCustomIssuerVCTExp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--iss", "https://custom.example", "--vct", "custom:type", "--exp", "1h"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt with custom flags: %v", err)
	}
}

func TestIssueSDJWT_WithKeyFile(t *testing.T) {
	// Generate a key and write it as JWK to a temp file
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.jwk")
	if err := os.WriteFile(keyFile, []byte(mock.PrivateKeyJWK(key)), 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueOmit = nil
	issuePID = false
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:eudi:pid:1"
	issueExpires = "24h"

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--key", keyFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --key: %v", err)
	}
}

func TestIssueSDJWT_InvalidExpDuration(t *testing.T) {
	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:eudi:pid:1"

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--exp", "not-a-duration"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid --exp duration")
	}
}

func TestIssueMDOC_EndToEnd(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false
	issueExpires = "720h"
	issueNBF = ""
	issueDocType = "eu.europa.ec.eudi.pid.1"
	issueNamespace = "eu.europa.ec.eudi.pid.1"

	rootCmd.SetArgs([]string{"issue", "mdoc"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue mdoc: %v", err)
	}
}

func TestIssueMDOC_WithPID(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issueExpires = "720h"
	issueNBF = ""

	rootCmd.SetArgs([]string{"issue", "mdoc", "--pid"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue mdoc --pid: %v", err)
	}
}

func TestIssueMDOC_WithCustomDocType(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false
	issueExpires = "720h"
	issueNBF = ""

	rootCmd.SetArgs([]string{"issue", "mdoc", "--doc-type", "com.example.test", "--namespace", "com.example.test"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue mdoc with custom doc-type: %v", err)
	}
}

func TestIssueMDOC_WithClaimsFile(t *testing.T) {
	tmpDir := t.TempDir()
	claimsFile := filepath.Join(tmpDir, "claims.json")
	if err := os.WriteFile(claimsFile, []byte(`{"test":"value"}`), 0644); err != nil {
		t.Fatalf("writing claims file: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueKeyPath = ""
	issueOmit = nil
	issuePID = false
	issueExpires = "720h"
	issueNBF = ""
	issueDocType = "eu.europa.ec.eudi.pid.1"
	issueNamespace = "eu.europa.ec.eudi.pid.1"

	rootCmd.SetArgs([]string{"issue", "mdoc", "--claims", "@" + claimsFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue mdoc --claims @file: %v", err)
	}
}

func TestIssueMDOC_InvalidKeyFile(t *testing.T) {
	issueClaims = ""
	issueOmit = nil
	issuePID = false
	issueExpires = "720h"
	issueNBF = ""
	issueDocType = "eu.europa.ec.eudi.pid.1"
	issueNamespace = "eu.europa.ec.eudi.pid.1"

	rootCmd.SetArgs([]string{"issue", "mdoc", "--key", "/nonexistent/key.pem"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent key file")
	}
}

// --- claims data tests ---

func TestDefaultClaims_HasExpectedFields(t *testing.T) {
	required := []string{"given_name", "family_name", "birthdate"}
	for _, name := range required {
		if _, ok := mock.DefaultClaims[name]; !ok {
			t.Errorf("DefaultClaims missing %q", name)
		}
	}
}

func TestSDJWTPIDClaims_HasExpectedFields(t *testing.T) {
	required := []string{
		"family_name", "given_name", "birthdate",
		"age_equal_or_over", "age_in_years", "age_birth_year",
		"birth_family_name", "birth_given_name",
		"place_of_birth",
		"address",
		"sex", "nationalities",
		"email", "phone_number", "picture",
		"date_of_issuance", "date_of_expiry",
		"personal_administrative_number",
		"issuing_authority",
		"issuing_country", "document_number", "issuing_jurisdiction",
	}
	for _, name := range required {
		if _, ok := mock.SDJWTPIDClaims[name]; !ok {
			t.Errorf("SDJWTPIDClaims missing %q", name)
		}
	}

	if len(mock.SDJWTPIDClaims) != 22 {
		t.Errorf("expected 22 SD-JWT PID claims, got %d", len(mock.SDJWTPIDClaims))
	}

	// address should be a nested object
	addr, ok := mock.SDJWTPIDClaims["address"].(map[string]any)
	if !ok {
		t.Fatal("address should be a map")
	}
	for _, field := range []string{"formatted", "street_address", "house_number", "locality", "postal_code", "country", "region"} {
		if _, ok := addr[field]; !ok {
			t.Errorf("address missing subclaim %q", field)
		}
	}

	ageEqualOrOver, ok := mock.SDJWTPIDClaims["age_equal_or_over"].(map[string]any)
	if !ok {
		t.Fatal("age_equal_or_over should be a map")
	}
	if v, ok := ageEqualOrOver["18"].(bool); !ok || !v {
		t.Errorf("expected age_equal_or_over.18=true, got %v", ageEqualOrOver["18"])
	}

	pob, ok := mock.SDJWTPIDClaims["place_of_birth"].(map[string]any)
	if !ok {
		t.Fatal("place_of_birth should be a map")
	}
	if _, ok := pob["locality"]; !ok {
		t.Error("place_of_birth missing subclaim \"locality\"")
	}
	if len(pob) != 1 {
		t.Errorf("expected place_of_birth to only contain locality, got %d entries", len(pob))
	}

	// nationalities should be an array
	nats, ok := mock.SDJWTPIDClaims["nationalities"].([]any)
	if !ok {
		t.Fatal("nationalities should be an array")
	}
	if len(nats) == 0 {
		t.Error("nationalities should not be empty")
	}

	if _, ok := mock.SDJWTPIDClaims["administrative_number"]; ok {
		t.Error("administrative_number should not be present in SD-JWT PID claims")
	}
	if _, ok := mock.SDJWTPIDClaims["trust_anchor"]; ok {
		t.Error("trust_anchor should not be present in SD-JWT PID claims")
	}
}

func TestMDOCPIDClaims_HasExpectedFields(t *testing.T) {
	required := []string{
		"family_name", "given_name", "birth_date",
		"age_over_18", "age_in_years", "age_birth_year",
		"family_name_birth", "given_name_birth",
		"birth_place",
		"resident_address", "resident_country", "resident_state", "resident_city",
		"resident_postal_code", "resident_street", "resident_house_number",
		"personal_administrative_number",
		"sex", "nationality",
		"email_address", "mobile_phone_number",
		"issuance_date", "expiry_date",
		"issuing_authority",
		"issuing_country", "document_number", "issuing_jurisdiction",
		"trust_anchor",
	}
	for _, name := range required {
		if _, ok := mock.MDOCPIDClaims[name]; !ok {
			t.Errorf("MDOCPIDClaims missing %q", name)
		}
	}

	if len(mock.MDOCPIDClaims) != 28 {
		t.Errorf("expected 28 mDoc PID claims, got %d", len(mock.MDOCPIDClaims))
	}

	birthPlace, ok := mock.MDOCPIDClaims["birth_place"].(map[string]any)
	if !ok {
		t.Fatal("birth_place should be a map")
	}
	if birthPlace["locality"] != "BERLIN" {
		t.Errorf("expected birth_place.locality BERLIN, got %v", birthPlace["locality"])
	}

	if _, ok := mock.MDOCPIDClaims["administrative_number"]; ok {
		t.Error("administrative_number should not be present in mDoc PID claims")
	}
}

func TestPIDClaims_TypesAreCorrect(t *testing.T) {
	ageEqualOrOver, ok := mock.SDJWTPIDClaims["age_equal_or_over"].(map[string]any)
	if !ok {
		t.Fatal("age_equal_or_over should be a map")
	}
	if v, ok := ageEqualOrOver["18"].(bool); !ok || !v {
		t.Error("age_equal_or_over.18 should be bool true")
	}
	if v, ok := mock.SDJWTPIDClaims["sex"].(int); !ok || v != 2 {
		t.Errorf("sex should be int 2, got %T %v", mock.SDJWTPIDClaims["sex"], mock.SDJWTPIDClaims["sex"])
	}
	if v, ok := mock.SDJWTPIDClaims["family_name"].(string); !ok || !strings.Contains(v, "MUSTERMANN") {
		t.Errorf("family_name should be string containing MUSTERMANN, got %v", v)
	}
}
