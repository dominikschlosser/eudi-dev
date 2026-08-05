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
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/internal/validate"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
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

	claims, err := resolveIssueClaimsForFormat("sdjwt", nil)
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

	tpl, err := credtemplate.Load("german-pid-sdjwt", t.TempDir())
	if err != nil {
		t.Fatalf("loading PID template: %v", err)
	}
	claims, err := resolveIssueClaimsForFormat("sdjwt", tpl)
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

	tpl, err := credtemplate.Load("german-pid-mdoc", t.TempDir())
	if err != nil {
		t.Fatalf("loading PID template: %v", err)
	}
	claims, err := resolveIssueClaimsForFormat("mdoc", tpl)
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
	issueOmit = []string{"place_of_birth", "address"}

	tpl, err := credtemplate.Load("german-pid-sdjwt", t.TempDir())
	if err != nil {
		t.Fatalf("loading PID template: %v", err)
	}
	claims, err := resolveIssueClaimsForFormat("sdjwt", tpl)
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
	if _, ok := claims["address"]; ok {
		t.Error("address should be omitted")
	}
}

func TestResolveIssueClaims_JSONString(t *testing.T) {
	issuePID = false
	issueClaims = `{"name":"Test","active":true}`
	issueOmit = nil

	claims, err := resolveIssueClaimsForFormat("sdjwt", nil)
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

	claims, err := resolveIssueClaimsForFormat("sdjwt", nil)
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

	claims, err := resolveIssueClaimsForFormat("sdjwt", nil)
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

	_, err := resolveIssueClaimsForFormat("sdjwt", nil)
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

	_, err := resolveIssueClaimsForFormat("sdjwt", nil)
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

// The PID claim sets mirror the credentials the German PID provider issues
// (see internal/mock/claims.go). These pin the exact sets: a claim silently
// added or dropped changes what every default PID, template and demo
// credential contains, and drifting from the real thing is the whole failure
// mode worth catching.
func TestSDJWTPIDClaims_HasExpectedFields(t *testing.T) {
	want := map[string]bool{
		"family_name": true, "given_name": true, "birth_name": true,
		"title": true, "also_known_as": true, "birthdate": true,
		"date_of_expiry": true, "age_equal_or_over": true,
		"place_of_birth": true, "address": true, "nationalities": true,
		"issuing_authority": true, "issuing_country": true,
		"source_document_type": true,
	}
	assertClaimSet(t, "SDJWTPIDClaims", mock.SDJWTPIDClaims, want)

	// Listed in the rulebook but explicitly not issued: the German eID does
	// not supply them, so a realistic PID must not carry them either.
	for _, name := range []string{
		"sex", "picture", "email", "phone_number", "document_number",
		"personal_administrative_number", "issuing_jurisdiction", "trust_anchor",
		"age_in_years", "age_birth_year", "birth_family_name", "birth_given_name",
		"administrative_number",
	} {
		if _, ok := mock.SDJWTPIDClaims[name]; ok {
			t.Errorf("%q is not part of the German PID and must not be present", name)
		}
	}

	addr, ok := mock.SDJWTPIDClaims["address"].(map[string]any)
	if !ok {
		t.Fatal("address should be a map")
	}
	assertClaimSet(t, "address", addr, map[string]bool{
		"street_address": true, "postal_code": true, "locality": true,
		"region": true, "country": true,
	})

	// All six thresholds, computed from the birthdate at issuance.
	ages, ok := mock.SDJWTPIDClaims["age_equal_or_over"].(map[string]any)
	if !ok {
		t.Fatal("age_equal_or_over should be a map")
	}
	assertClaimSet(t, "age_equal_or_over", ages, map[string]bool{
		"12": true, "14": true, "16": true, "18": true, "21": true, "65": true,
	})
	for _, over := range []string{"12", "14", "16", "18", "21"} {
		if v, ok := ages[over].(bool); !ok || !v {
			t.Errorf("age_equal_or_over.%s should be true, got %v", over, ages[over])
		}
	}
	if v, ok := ages["65"].(bool); !ok || v {
		t.Errorf("age_equal_or_over.65 should be false for a 1964 birthdate, got %v", ages["65"])
	}

	pob, ok := mock.SDJWTPIDClaims["place_of_birth"].(map[string]any)
	if !ok {
		t.Fatal("place_of_birth should be a map")
	}
	assertClaimSet(t, "place_of_birth", pob, map[string]bool{
		"locality": true, "no_place_info": true,
	})

	nats, ok := mock.SDJWTPIDClaims["nationalities"].([]any)
	if !ok || len(nats) != 1 || nats[0] != "DE" {
		t.Errorf("nationalities should be [\"DE\"], got %v", mock.SDJWTPIDClaims["nationalities"])
	}
}

func TestMDOCPIDClaims_HasExpectedFields(t *testing.T) {
	// All of it in eu.europa.ec.eudi.pid.1: the default PID is the
	// country-independent one, so nothing is namespaced separately.
	want := map[string]bool{
		"family_name": true, "given_name": true, "birth_date": true,
		"expiry_date": true, "birth_place": true, "nationality": true,
		"resident_street": true, "resident_postal_code": true,
		"resident_city": true, "resident_state": true, "resident_country": true,
		"issuing_authority": true, "issuing_country": true,
		"birth_name": true, "academic_title": true,
		"also_known_as": true, "no_place_info": true,
		"source_document_type": true,
		"age_over_12":          true, "age_over_14": true,
		"age_over_16": true, "age_over_18": true,
		"age_over_21": true, "age_over_65": true,
	}
	assertClaimSet(t, "MDOCPIDClaims", mock.MDOCPIDClaims, want)

	for _, name := range []string{
		"sex", "portrait", "email_address", "mobile_phone_number", "document_number",
		"personal_administrative_number", "issuing_jurisdiction", "trust_anchor",
		"age_in_years", "age_birth_year", "family_name_birth", "given_name_birth",
		"resident_address", "resident_house_number", "administrative_number",
		// The rulebook is explicit that the German PID carries no issuance
		// date: only the technical validFrom of the credential.
		"issuance_date",
	} {
		if _, ok := mock.MDOCPIDClaims[name]; ok {
			t.Errorf("%q is not part of the German PID and must not be present", name)
		}
	}

	birthPlace, ok := mock.MDOCPIDClaims["birth_place"].(map[string]any)
	if !ok {
		t.Fatal("birth_place should be a map")
	}
	if birthPlace["locality"] != "BERLIN" {
		t.Errorf("expected birth_place.locality BERLIN, got %v", birthPlace["locality"])
	}
}

// The two formats describe one person, so the shared values must agree.
func TestPIDClaims_TypesAreCorrect(t *testing.T) {
	if mock.SDJWTPIDClaims["family_name"] != mock.MDOCPIDClaims["family_name"] {
		t.Error("family_name differs between the SD-JWT and mDoc PID")
	}
	if mock.SDJWTPIDClaims["given_name"] != mock.MDOCPIDClaims["given_name"] {
		t.Error("given_name differs between the SD-JWT and mDoc PID")
	}
	if mock.SDJWTPIDClaims["birthdate"] != mock.MDOCPIDClaims["birth_date"] {
		t.Error("the birthdate differs between the SD-JWT and mDoc PID")
	}
	if v, ok := mock.SDJWTPIDClaims["family_name"].(string); !ok || !strings.Contains(v, "MUSTERMANN") {
		t.Errorf("family_name should be string containing MUSTERMANN, got %v", v)
	}

	// The expiry is a calendar day with no time component, in both formats,
	// and the rulebook puts it five years out.
	if mock.SDJWTPIDClaims["date_of_expiry"] != mock.MDOCPIDClaims["expiry_date"] {
		t.Error("the expiry differs between the SD-JWT and mDoc PID")
	}
	v, ok := mock.MDOCPIDClaims["expiry_date"].(string)
	if !ok {
		t.Fatalf("expiry_date should be a string, got %T", mock.MDOCPIDClaims["expiry_date"])
	}
	expiry, err := time.Parse(time.DateOnly, v)
	if err != nil {
		t.Fatalf("expiry_date = %q is not a calendar date: %v", v, err)
	}
	if years := expiry.Year() - time.Now().UTC().Year(); years != 5 {
		t.Errorf("expiry_date is %d years out, want 5", years)
	}
}

// assertClaimSet fails when claims is not exactly want.
func assertClaimSet(t *testing.T, label string, claims map[string]any, want map[string]bool) {
	t.Helper()
	for name := range want {
		if _, ok := claims[name]; !ok {
			t.Errorf("%s is missing %q", label, name)
		}
	}
	for name := range claims {
		if !want[name] {
			t.Errorf("%s has unexpected claim %q", label, name)
		}
	}
	if len(claims) != len(want) {
		t.Errorf("%s has %d claims, want %d", label, len(claims), len(want))
	}
}
