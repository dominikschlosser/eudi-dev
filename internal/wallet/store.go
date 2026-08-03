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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// WalletStore handles file-based persistence for the wallet.
type WalletStore struct {
	Dir string
}

var walletRuntimeRegistry sync.Map

// walletJSON is the on-disk format of wallet.json.
type walletJSON struct {
	Credentials        []StoredCredential      `json:"credentials"`
	IssuedAttestations []IssuedAttestationSpec `json:"issued_attestations,omitempty"`
	Log                []LogEntry              `json:"log,omitempty"`
	StatusEntries      map[string]StatusEntry  `json:"status_entries,omitempty"`
	StatusListCounter  int                     `json:"status_list_counter,omitempty"`
	BaseURL            string                  `json:"base_url,omitempty"`
	IssuerURL          string                  `json:"issuer_url,omitempty"`
	Port               int                     `json:"port,omitempty"`
}

// DefaultWalletDir returns the default wallet storage directory inside the
// tool's state directory (~/.eudi-dev, with a legacy ~/.oid4vc-dev fallback).
func DefaultWalletDir() string {
	return filepath.Join(config.BaseDir(), "wallet")
}

// NewWalletStore creates a new WalletStore for the given directory.
func NewWalletStore(dir string) *WalletStore {
	if dir == "" {
		dir = DefaultWalletDir()
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return &WalletStore{Dir: dir}
}

func (s *WalletStore) runtime() *WalletRuntime {
	key := s.Dir
	if key == "" {
		key = DefaultWalletDir()
	}
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
	}
	runtime, _ := walletRuntimeRegistry.LoadOrStore(key, newWalletRuntime())
	return runtime.(*WalletRuntime)
}

// ensureDir creates the wallet directory if it doesn't exist.
func (s *WalletStore) ensureDir() error {
	return os.MkdirAll(s.Dir, 0700)
}

// walletPath returns the path to wallet.json.
func (s *WalletStore) walletPath() string {
	return filepath.Join(s.Dir, "wallet.json")
}

// holderKeyPath returns the path to the holder private key.
func (s *WalletStore) holderKeyPath() string {
	return filepath.Join(s.Dir, "holder.pem")
}

// issuerKeyPath returns the path to the issuer private key.
func (s *WalletStore) issuerKeyPath() string {
	return filepath.Join(s.Dir, "issuer.pem")
}

func (s *WalletStore) sharedStateDir() string {
	parent := filepath.Dir(s.Dir)
	if parent == "." || parent == "" {
		return s.Dir
	}
	return parent
}

func (s *WalletStore) sharedCAKeyPath() string {
	return filepath.Join(s.sharedStateDir(), "wallet-ca-key.pem")
}

func (s *WalletStore) sharedCACertPath() string {
	return filepath.Join(s.sharedStateDir(), "wallet-ca-cert.pem")
}

// issuerTLSCertPath returns the path to the wallet HTTPS certificate.
func (s *WalletStore) issuerTLSCertPath() string {
	return filepath.Join(s.Dir, "wallet-tls-cert.pem")
}

// issuerTLSKeyPath returns the path to the wallet HTTPS private key.
func (s *WalletStore) issuerTLSKeyPath() string {
	return filepath.Join(s.Dir, "wallet-tls-key.pem")
}

func (s *WalletStore) logCleanMarkerPath() string {
	return filepath.Join(s.Dir, "wallet-log-cleaned-at")
}

func (s *WalletStore) legacyIssuerTLSCertPath() string {
	return filepath.Join(s.Dir, "issuer-tls-cert.pem")
}

func (s *WalletStore) legacyIssuerTLSKeyPath() string {
	return filepath.Join(s.Dir, "issuer-tls-key.pem")
}

// LoadOrCreate loads the wallet from disk, or creates a new empty wallet if none exists.
// Keys are loaded or auto-generated as needed.
func (s *WalletStore) LoadOrCreate() (*Wallet, error) {
	if err := s.ensureDir(); err != nil {
		return nil, fmt.Errorf("creating wallet directory: %w", err)
	}

	holderKey, issuerKey, err := s.LoadOrCreateKeys()
	if err != nil {
		return nil, err
	}
	caKey, caCert, err := s.LoadOrCreateSharedCA()
	if err != nil {
		return nil, err
	}

	w := New(holderKey, issuerKey, false)
	w.runtime = s.runtime()
	w.TemplatesDir = filepath.Join(s.Dir, "templates")
	if err := w.SetCertificateAuthority(caKey, caCert); err != nil {
		return nil, fmt.Errorf("configuring shared wallet CA: %w", err)
	}

	data, err := os.ReadFile(s.walletPath())
	if err != nil {
		if os.IsNotExist(err) {
			return w, nil
		}
		return nil, fmt.Errorf("reading wallet.json: %w", err)
	}

	var wj walletJSON
	if err := json.Unmarshal(data, &wj); err != nil {
		return nil, fmt.Errorf("parsing wallet.json: %w", err)
	}

	w.Credentials = wj.Credentials
	w.IssuedAttestations = dedupeIssuedAttestations(wj.IssuedAttestations)
	w.Log = s.filterLogEntries(wj.Log)
	w.StatusEntries = wj.StatusEntries
	w.StatusListCounter = wj.StatusListCounter
	w.BaseURL = wj.BaseURL
	w.IssuerURL = wj.IssuerURL

	// Re-hydrate non-serializable fields from Raw
	for i := range w.Credentials {
		if err := w.Credentials[i].Rehydrate(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: rehydrating credential %s: %v\n", w.Credentials[i].ID, err)
		}
	}

	return w, nil
}

// Save persists the wallet state to disk.
func (s *WalletStore) Save(w *Wallet) error {
	if err := s.ensureDir(); err != nil {
		return fmt.Errorf("creating wallet directory: %w", err)
	}

	creds := w.GetCredentials()
	w.mu.RLock()
	issuedAttestations := dedupeIssuedAttestations(w.IssuedAttestations)
	logEntries := s.filterLogEntries(w.Log)
	statusEntries := w.StatusEntries
	statusListCounter := w.StatusListCounter
	baseURL := w.BaseURL
	issuerURL := w.IssuerURL
	w.mu.RUnlock()
	wj := walletJSON{
		Credentials:        creds,
		IssuedAttestations: issuedAttestations,
		Log:                logEntries,
		StatusEntries:      statusEntries,
		StatusListCounter:  statusListCounter,
		BaseURL:            baseURL,
		IssuerURL:          issuerURL,
	}

	data, err := json.MarshalIndent(wj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling wallet.json: %w", err)
	}

	// Write-then-rename so a concurrent writer or a crash never leaves a
	// partially written (or interleaved) wallet.json behind.
	tmp, err := os.CreateTemp(s.Dir, "wallet.json.tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary wallet.json: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("setting wallet.json permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing wallet.json: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing wallet.json: %w", err)
	}
	return os.Rename(tmp.Name(), s.walletPath())
}

// ClearLog removes all persisted wallet activity log entries.
func (s *WalletStore) ClearLog() error {
	w, err := s.LoadOrCreate()
	if err != nil {
		return err
	}
	if err := s.writeLogCleanMarker(time.Now()); err != nil {
		return err
	}
	w.mu.Lock()
	w.Log = nil
	w.mu.Unlock()
	return s.Save(w)
}

func (s *WalletStore) filterLogEntries(entries []LogEntry) []LogEntry {
	cleanedAt := s.loadLogCleanMarker()
	if cleanedAt.IsZero() {
		return append([]LogEntry(nil), entries...)
	}
	filtered := make([]LogEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Time.After(cleanedAt) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func (s *WalletStore) loadLogCleanMarker() time.Time {
	data, err := os.ReadFile(s.logCleanMarkerPath())
	if err != nil {
		return time.Time{}
	}
	cleanedAt, err := time.Parse(time.RFC3339Nano, string(data))
	if err != nil {
		return time.Time{}
	}
	return cleanedAt
}

func (s *WalletStore) writeLogCleanMarker(cleanedAt time.Time) error {
	if err := s.ensureDir(); err != nil {
		return fmt.Errorf("creating wallet directory: %w", err)
	}
	return os.WriteFile(s.logCleanMarkerPath(), []byte(cleanedAt.Format(time.RFC3339Nano)), 0600)
}

// LoadOrCreateKeys loads holder and issuer keys from PEM files, generating them if they don't exist.
func (s *WalletStore) LoadOrCreateKeys() (*ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	if err := s.ensureDir(); err != nil {
		return nil, nil, fmt.Errorf("creating wallet directory: %w", err)
	}

	holderKey, err := s.loadOrGenerateKey(s.holderKeyPath(), "holder")
	if err != nil {
		return nil, nil, err
	}

	issuerKey, err := s.loadOrGenerateKey(s.issuerKeyPath(), "issuer")
	if err != nil {
		return nil, nil, err
	}

	return holderKey, issuerKey, nil
}

// LoadOrCreateSharedCA loads the shared wallet CA from disk or creates it.
func (s *WalletStore) LoadOrCreateSharedCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	if err := os.MkdirAll(s.sharedStateDir(), 0700); err != nil {
		return nil, nil, fmt.Errorf("creating shared wallet state directory: %w", err)
	}

	keyData, keyErr := os.ReadFile(s.sharedCAKeyPath())
	certData, certErr := os.ReadFile(s.sharedCACertPath())
	if keyErr == nil && certErr == nil {
		key, err := parsePEMKey(keyData, "wallet CA")
		if err == nil {
			cert, err := parsePEMCertificate(certData, "wallet CA")
			if err == nil && cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
				return key, cert, nil
			}
		}
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return nil, nil, fmt.Errorf("reading wallet CA key: %w", keyErr)
	}
	if certErr != nil && !os.IsNotExist(certErr) {
		return nil, nil, fmt.Errorf("reading wallet CA certificate: %w", certErr)
	}

	caKey, err := mock.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generating wallet CA key: %w", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generating wallet CA certificate: %w", err)
	}
	if err := saveKeyPEM(s.sharedCAKeyPath(), caKey); err != nil {
		return nil, nil, fmt.Errorf("saving wallet CA key: %w", err)
	}
	if err := saveCertPEM(s.sharedCACertPath(), caCert); err != nil {
		return nil, nil, fmt.Errorf("saving wallet CA certificate: %w", err)
	}
	return caKey, caCert, nil
}

// LoadOrCreateSharedCACertificatePEM returns the shared wallet CA certificate PEM.
func (s *WalletStore) LoadOrCreateSharedCACertificatePEM() ([]byte, error) {
	if _, _, err := s.LoadOrCreateSharedCA(); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(s.sharedCACertPath())
	if err != nil {
		return nil, fmt.Errorf("reading wallet CA certificate: %w", err)
	}
	return certPEM, nil
}

// LoadOrCreateIssuerTLSCertificate loads the issuer HTTPS certificate from disk,
// or generates and persists a new one if none exists or it no longer matches
// the requested host.
func (s *WalletStore) LoadOrCreateIssuerTLSCertificate(serverName string) (tls.Certificate, error) {
	if err := s.ensureDir(); err != nil {
		return tls.Certificate{}, fmt.Errorf("creating wallet directory: %w", err)
	}

	certPEM, keyPEM, err := s.loadIssuerTLSCertificatePEM(serverName)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading issuer TLS certificate: %w", err)
	}
	return cert, nil
}

// LoadOrCreateIssuerTLSCertificateForURL resolves the host from the issuer URL and
// loads or creates a matching issuer HTTPS certificate.
func (s *WalletStore) LoadOrCreateIssuerTLSCertificateForURL(issuerURL string) (tls.Certificate, error) {
	return s.LoadOrCreateIssuerTLSCertificate(parseIssuerHost(issuerURL))
}

// LoadOrCreateIssuerTLSCertificatePEM returns the persisted issuer HTTPS certificate PEM,
// generating it first if needed.
func (s *WalletStore) LoadOrCreateIssuerTLSCertificatePEM(serverName string) ([]byte, error) {
	if err := s.ensureDir(); err != nil {
		return nil, fmt.Errorf("creating wallet directory: %w", err)
	}

	certPEM, _, err := s.loadIssuerTLSCertificatePEM(serverName)
	if err != nil {
		return nil, err
	}
	return certPEM, nil
}

// LoadOrCreateIssuerTLSLeafCertificatePEM returns only the leaf PEM certificate
// for the wallet HTTPS server.
func (s *WalletStore) LoadOrCreateIssuerTLSLeafCertificatePEM(serverName string) ([]byte, error) {
	certPEM, err := s.LoadOrCreateIssuerTLSCertificatePEM(serverName)
	if err != nil {
		return nil, err
	}
	return firstCertificatePEM(certPEM)
}

// LoadOrCreateIssuerTLSCertificatePEMForURL resolves the host from the issuer URL and
// returns the matching persisted issuer HTTPS certificate PEM.
func (s *WalletStore) LoadOrCreateIssuerTLSCertificatePEMForURL(issuerURL string) ([]byte, error) {
	return s.LoadOrCreateIssuerTLSCertificatePEM(parseIssuerHost(issuerURL))
}

// LoadOrCreateIssuerTLSLeafCertificatePEMForURL resolves the host from the issuer URL and
// returns only the leaf PEM certificate for the wallet HTTPS server.
func (s *WalletStore) LoadOrCreateIssuerTLSLeafCertificatePEMForURL(issuerURL string) ([]byte, error) {
	return s.LoadOrCreateIssuerTLSLeafCertificatePEM(parseIssuerHost(issuerURL))
}

func (s *WalletStore) loadIssuerTLSCertificatePEM(serverName string) ([]byte, []byte, error) {
	if serverName == "" {
		serverName = "localhost"
	}
	caKey, caCert, err := s.LoadOrCreateSharedCA()
	if err != nil {
		return nil, nil, err
	}

	certPEM, certErr := os.ReadFile(s.issuerTLSCertPath())
	keyPEM, keyErr := os.ReadFile(s.issuerTLSKeyPath())
	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) {
		certPEM, certErr = os.ReadFile(s.legacyIssuerTLSCertPath())
		keyPEM, keyErr = os.ReadFile(s.legacyIssuerTLSKeyPath())
	}
	if certErr == nil && keyErr == nil {
		if cert, err := tls.X509KeyPair(certPEM, keyPEM); err == nil && issuerTLSCertificateMatches(cert, serverName, caCert) {
			if err := os.WriteFile(s.issuerTLSCertPath(), certPEM, 0644); err != nil {
				return nil, nil, fmt.Errorf("saving wallet TLS certificate: %w", err)
			}
			if err := os.WriteFile(s.issuerTLSKeyPath(), keyPEM, 0600); err != nil {
				return nil, nil, fmt.Errorf("saving wallet TLS key: %w", err)
			}
			return certPEM, keyPEM, nil
		}
	}

	if certErr != nil && !os.IsNotExist(certErr) {
		return nil, nil, fmt.Errorf("reading wallet TLS certificate: %w", certErr)
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return nil, nil, fmt.Errorf("reading wallet TLS key: %w", keyErr)
	}

	certPEM, keyPEM, err = generateIssuerTLSCertificatePEMWithCA(serverName, caKey, caCert)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(s.issuerTLSCertPath(), certPEM, 0644); err != nil {
		return nil, nil, fmt.Errorf("saving wallet TLS certificate: %w", err)
	}
	if err := os.WriteFile(s.issuerTLSKeyPath(), keyPEM, 0600); err != nil {
		return nil, nil, fmt.Errorf("saving wallet TLS key: %w", err)
	}

	return certPEM, keyPEM, nil
}

func issuerTLSCertificateMatches(cert tls.Certificate, serverName string, caCert *x509.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return false
	}
	if leaf.VerifyHostname(serverName) != nil {
		return false
	}
	if caCert == nil {
		return true
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: serverName,
	}
	if _, err := leaf.Verify(opts); err != nil {
		return false
	}
	return true
}

// loadOrGenerateKey loads a PEM key from path, or generates and saves a new one.
func (s *WalletStore) loadOrGenerateKey(path, label string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return parsePEMKey(data, label)
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s key: %w", label, err)
	}

	// Generate new key
	key, err := mock.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", label, err)
	}

	if err := saveKeyPEM(path, key); err != nil {
		return nil, fmt.Errorf("saving %s key: %w", label, err)
	}

	fmt.Fprintf(os.Stderr, "Generated %s key: %s\n", label, path)
	return key, nil
}

// parsePEMKey parses an EC private key from PEM data.
func parsePEMKey(data []byte, label string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s key: no PEM block found", label)
	}

	// Try PKCS#8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
		return nil, fmt.Errorf("%s key: not an EC key", label)
	}

	// Try EC key
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s key: unable to parse PEM: %w", label, err)
	}
	return ecKey, nil
}

func parsePEMCertificate(data []byte, label string) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s certificate: no PEM block found", label)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s certificate: unable to parse PEM: %w", label, err)
	}
	return cert, nil
}

// saveKeyPEM saves an EC private key as a PEM file.
func saveKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func saveCertPEM(path string, cert *x509.Certificate) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644)
}

func firstCertificatePEM(data []byte) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no PEM CERTIFICATE block found")
	}
	return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}), nil
}
