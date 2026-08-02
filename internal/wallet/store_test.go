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
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

func TestWalletStore_LoadOrCreate_NewWallet(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	if w.HolderKey == nil {
		t.Fatal("expected non-nil holder key")
	}
	if w.IssuerKey == nil {
		t.Fatal("expected non-nil issuer key")
	}
	if w.CAKey == nil || len(w.CertChain) < 2 {
		t.Fatal("expected shared CA-backed certificate chain")
	}
	if len(w.Credentials) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(w.Credentials))
	}

	// Keys should be persisted
	if _, err := os.Stat(filepath.Join(dir, "holder.pem")); err != nil {
		t.Errorf("expected holder.pem to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "issuer.pem")); err != nil {
		t.Errorf("expected issuer.pem to exist: %v", err)
	}
}

func TestWalletStore_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// Add a credential
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating SD-JWT: %v", err)
	}
	if _, err := w.ImportCredential(sdjwt); err != nil {
		t.Fatalf("importing: %v", err)
	}
	if len(w.IssuedAttestations) != 1 {
		t.Fatalf("expected 1 issued-attestation entry after import, got %d", len(w.IssuedAttestations))
	}
	if w.IssuedAttestations[0].VCT != "TestCred" {
		t.Fatalf("expected issued-attestation VCT TestCred, got %s", w.IssuedAttestations[0].VCT)
	}

	// Save
	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load again
	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}

	creds := w2.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential after reload, got %d", len(creds))
	}
	if creds[0].VCT != "TestCred" {
		t.Errorf("expected VCT TestCred, got %s", creds[0].VCT)
	}
	if len(creds[0].Disclosures) == 0 {
		t.Error("expected disclosures to be rehydrated")
	}
	if len(w2.IssuedAttestations) != 1 {
		t.Fatalf("expected 1 issued-attestation entry after reload, got %d", len(w2.IssuedAttestations))
	}
	if w2.IssuedAttestations[0].TrustListType != localTrustListType {
		t.Fatalf("expected persisted local trust-list type, got %s", w2.IssuedAttestations[0].TrustListType)
	}
}

func TestWalletStore_SaveAndLoad_PersistsIssuerURLs(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://localhost:8086"

	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}
	if w2.BaseURL != w.BaseURL {
		t.Fatalf("expected BaseURL %s, got %s", w.BaseURL, w2.BaseURL)
	}
	if w2.IssuerURL != w.IssuerURL {
		t.Fatalf("expected IssuerURL %s, got %s", w.IssuerURL, w2.IssuerURL)
	}
}

func TestWalletStore_SaveAndLoad_PersistsLog(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	w.AddLogDetails("presentation", "Received presentation request from verifier.example", true, map[string]any{
		"client_id":      "verifier.example",
		"response_uri":   "https://verifier.example/callback",
		"request_object": map[string]any{"nonce": "n-1"},
	})

	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}

	logs := w2.GetLog()
	if len(logs) != 1 {
		t.Fatalf("expected 1 persisted log entry, got %d", len(logs))
	}
	if logs[0].Action != "presentation" {
		t.Fatalf("expected action presentation, got %s", logs[0].Action)
	}
	if logs[0].Details["client_id"] != "verifier.example" {
		t.Fatalf("expected client_id detail, got %v", logs[0].Details["client_id"])
	}
	requestObject, ok := logs[0].Details["request_object"].(map[string]any)
	if !ok {
		t.Fatalf("expected request_object detail, got %T", logs[0].Details["request_object"])
	}
	if requestObject["nonce"] != "n-1" {
		t.Fatalf("expected nonce n-1, got %v", requestObject["nonce"])
	}
}

func TestWalletStore_ClearLog(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	w.AddLog("issuance", "Received credential", true)
	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := store.ClearLog(); err != nil {
		t.Fatalf("ClearLog: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after clear: %v", err)
	}
	if got := len(w2.GetLog()); got != 0 {
		t.Fatalf("expected cleared log, got %d entries", got)
	}
}

func TestWalletStore_ClearLog_PreventsOldInMemoryLogsFromResurrecting(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	w.AddLog("issuance", "old credential", true)
	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.ClearLog(); err != nil {
		t.Fatalf("ClearLog: %v", err)
	}

	time.Sleep(time.Millisecond)
	w.AddLog("issuance", "new credential", true)
	if err := store.Save(w); err != nil {
		t.Fatalf("Save after clean: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}
	logs := w2.GetLog()
	if len(logs) != 1 {
		t.Fatalf("expected only the new log entry, got %d", len(logs))
	}
	if logs[0].Detail != "new credential" {
		t.Fatalf("expected new credential log, got %q", logs[0].Detail)
	}
}

func TestWalletStore_KeyPersistence(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w1, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// Load again — same keys should be used
	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate second time: %v", err)
	}

	if !w1.HolderKey.Equal(w2.HolderKey) {
		t.Error("expected same holder key across loads")
	}
	if !w1.IssuerKey.Equal(w2.IssuerKey) {
		t.Error("expected same issuer key across loads")
	}
}

func TestNewWalletStore_DefaultDir(t *testing.T) {
	store := NewWalletStore("")
	if store.Dir == "" {
		t.Error("expected non-empty default dir")
	}
}

func TestWalletStore_PathHelpers(t *testing.T) {
	store := NewWalletStore("/tmp/test-wallet")
	if store.walletPath() != "/tmp/test-wallet/wallet.json" {
		t.Errorf("wrong wallet path: %s", store.walletPath())
	}
	if store.holderKeyPath() != "/tmp/test-wallet/holder.pem" {
		t.Errorf("wrong holder key path: %s", store.holderKeyPath())
	}
	if store.issuerKeyPath() != "/tmp/test-wallet/issuer.pem" {
		t.Errorf("wrong issuer key path: %s", store.issuerKeyPath())
	}
	if store.issuerTLSCertPath() != "/tmp/test-wallet/wallet-tls-cert.pem" {
		t.Errorf("wrong issuer TLS cert path: %s", store.issuerTLSCertPath())
	}
	if store.issuerTLSKeyPath() != "/tmp/test-wallet/wallet-tls-key.pem" {
		t.Errorf("wrong issuer TLS key path: %s", store.issuerTLSKeyPath())
	}
	if store.sharedCACertPath() != "/tmp/wallet-ca-cert.pem" {
		t.Errorf("wrong wallet CA cert path: %s", store.sharedCACertPath())
	}
	if store.sharedCAKeyPath() != "/tmp/wallet-ca-key.pem" {
		t.Errorf("wrong wallet CA key path: %s", store.sharedCAKeyPath())
	}
}

func TestDefaultWalletDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("EUDI_DEV_HOME", "")
	t.Setenv("OID4VC_DEV_HOME", "")

	// Fresh system: the new state directory is used.
	dir := DefaultWalletDir()
	if !strings.Contains(dir, ".eudi-dev") || !strings.HasSuffix(dir, "wallet") {
		t.Errorf("expected .eudi-dev wallet dir, got %s", dir)
	}

	// A legacy state directory keeps being used after the rename.
	if err := os.MkdirAll(filepath.Join(home, ".oid4vc-dev"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir = DefaultWalletDir()
	if !strings.Contains(dir, ".oid4vc-dev") {
		t.Errorf("expected legacy .oid4vc-dev fallback, got %s", dir)
	}
}

func TestWalletStore_LoadOrCreateIssuerTLSCertificate_Persists(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	cert1, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate: %v", err)
	}
	cert2, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate second time: %v", err)
	}

	if len(cert1.Certificate) == 0 || len(cert2.Certificate) == 0 {
		t.Fatal("expected persisted issuer TLS certificate")
	}
	if !bytes.Equal(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Fatal("expected issuer TLS certificate to persist across loads")
	}
	_, caCert, err := store.LoadOrCreateSharedCA()
	if err != nil {
		t.Fatalf("LoadOrCreateSharedCA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	leaf, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost"}); err != nil {
		t.Fatalf("expected wallet TLS cert to chain to shared CA: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wallet-tls-cert.pem")); err != nil {
		t.Fatalf("expected wallet-tls-cert.pem to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wallet-tls-key.pem")); err != nil {
		t.Fatalf("expected wallet-tls-key.pem to exist: %v", err)
	}
}

func TestWalletStore_LoadOrCreateIssuerTLSCertificate_MigratesLegacyPaths(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	certPEM, keyPEM, err := generateIssuerTLSCertificatePEM("localhost")
	if err != nil {
		t.Fatalf("generateIssuerTLSCertificatePEM: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "issuer-tls-cert.pem"), certPEM, 0644); err != nil {
		t.Fatalf("write legacy cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "issuer-tls-key.pem"), keyPEM, 0600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}

	cert, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected migrated wallet TLS certificate")
	}
	if _, err := os.Stat(filepath.Join(dir, "wallet-tls-cert.pem")); err != nil {
		t.Fatalf("expected wallet-tls-cert.pem to exist after migration: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wallet-tls-key.pem")); err != nil {
		t.Fatalf("expected wallet-tls-key.pem to exist after migration: %v", err)
	}
}

func TestWalletStore_LoadOrCreateIssuerTLSCertificate_RegeneratesForNewHost(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	cert1, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate localhost: %v", err)
	}
	cert2, err := store.LoadOrCreateIssuerTLSCertificate("issuer.example")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate issuer.example: %v", err)
	}

	if bytes.Equal(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Fatal("expected issuer TLS certificate to regenerate for a different host")
	}
}

func TestWalletStore_LoadOrCreateSharedCA_SameParentDir(t *testing.T) {
	root := t.TempDir()
	store1 := NewWalletStore(filepath.Join(root, "wallet-a"))
	store2 := NewWalletStore(filepath.Join(root, "wallet-b"))

	_, cert1, err := store1.LoadOrCreateSharedCA()
	if err != nil {
		t.Fatalf("store1 LoadOrCreateSharedCA: %v", err)
	}
	_, cert2, err := store2.LoadOrCreateSharedCA()
	if err != nil {
		t.Fatalf("store2 LoadOrCreateSharedCA: %v", err)
	}

	if !bytes.Equal(cert1.Raw, cert2.Raw) {
		t.Fatal("expected stores under the same parent directory to share the same CA certificate")
	}
}

func TestWalletStore_LoadOrCreate_UsesSharedCA(t *testing.T) {
	root := t.TempDir()
	store1 := NewWalletStore(filepath.Join(root, "wallet-a"))
	store2 := NewWalletStore(filepath.Join(root, "wallet-b"))

	w1, err := store1.LoadOrCreate()
	if err != nil {
		t.Fatalf("store1 LoadOrCreate: %v", err)
	}
	w2, err := store2.LoadOrCreate()
	if err != nil {
		t.Fatalf("store2 LoadOrCreate: %v", err)
	}
	if len(w1.CertChain) < 2 || len(w2.CertChain) < 2 {
		t.Fatal("expected CA-backed cert chains on both wallets")
	}
	if !bytes.Equal(w1.CertChain[len(w1.CertChain)-1].Raw, w2.CertChain[len(w2.CertChain)-1].Raw) {
		t.Fatal("expected both wallets to use the same shared CA certificate")
	}
}
