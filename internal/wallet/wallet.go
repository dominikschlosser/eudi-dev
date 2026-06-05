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

// Package wallet implements a stateful testing wallet for OID4VP presentations and OID4VCI issuance flows.
package wallet

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/keys"
	"github.com/dominikschlosser/oid4vc-dev/internal/mdoc"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
)

// SessionTranscriptMode controls how the mDoc session transcript is constructed.
type SessionTranscriptMode string

const (
	// SessionTranscriptISO uses ISO 18013-7 Annex B.4.4 format (EUDI wallet default).
	// Hash inputs are CBOR-encoded [value, mdocGeneratedNonce] arrays, and the
	// handover is wrapped in CBOR Tag 24.
	SessionTranscriptISO SessionTranscriptMode = "iso"

	// SessionTranscriptOID4VP uses the OID4VP Appendix B.2.6 format.
	// Hash inputs are plain string bytes, and the handover is a plain array.
	SessionTranscriptOID4VP SessionTranscriptMode = "oid4vp"
)

// StatusEntry tracks the status list index and current status for a credential.
type StatusEntry struct {
	Index  int `json:"index"`
	Status int `json:"status"` // 0=valid, 1=revoked
}

// NextErrorOverride is a one-shot error override for the next presentation request.
type NextErrorOverride struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Wallet holds credentials, keys, and manages presentation consent flows.
type Wallet struct {
	HolderKey               *ecdsa.PrivateKey
	IssuerKey               *ecdsa.PrivateKey
	CAKey                   *ecdsa.PrivateKey
	CertChain               []*x509.Certificate     // [leaf, CA] certificate chain
	IssuedAttestations      []IssuedAttestationSpec `json:"issued_attestations,omitempty"`
	AutoAccept              bool
	SessionTranscript       SessionTranscriptMode // "oid4vp" (default) or "iso"
	PreferredFormat         string                // "" (no preference), "dc+sd-jwt", or "mso_mdoc"
	RequireEncryptedRequest bool                  // when true, sends encryption keys in wallet_metadata
	RequestEncryptionKey    *ecdsa.PrivateKey     // key for decrypting encrypted request objects
	RequireHAIP             bool                  // when true, enforce HAIP 1.0 compliance checks
	ValidationMode          ValidationMode        `json:"-"`
	Credentials             []StoredCredential
	StatusEntries           map[string]StatusEntry // credential ID → status entry
	StatusListCounter       int                    // next available status list index
	BaseURL                 string                 // base URL for status list endpoint
	IssuerURL               string                 // HTTPS issuer URL for JWT VC issuer metadata/JWKS
	VCIClientID             string                 `json:"-"`
	VCIRedirectURI          string                 `json:"-"`
	Requests                map[string]*ConsentRequest
	TxCode                  string `json:"-"` // one-shot tx_code for OID4VCI token request
	Log                     []LogEntry
	mu                      sync.RWMutex
	logSink                 func(LogEntry)
	nextError               *NextErrorOverride
	subscribers             map[int64]chan *ConsentRequest
	subID                   int64
	errSubscribers          map[int64]chan WalletError
	errSubID                int64
	lastError               *WalletError
	authCodeCallbacks       map[string]chan url.Values
}

// StatusListURL returns the preferred status list URL for generated credentials.
// It prefers the wallet's HTTPS issuer endpoint when available.
func (w *Wallet) StatusListURL() string {
	if w == nil {
		return ""
	}
	if issuer := strings.TrimRight(w.IssuerURL, "/"); issuer != "" {
		return issuer + "/api/statuslist"
	}
	if base := strings.TrimRight(w.BaseURL, "/"); base != "" {
		return base + "/api/statuslist"
	}
	return ""
}

// StatusListIssuer returns the issuer value used in generated status list JWTs.
func (w *Wallet) StatusListIssuer() string {
	if w == nil {
		return ""
	}
	if issuer := strings.TrimRight(w.IssuerURL, "/"); issuer != "" {
		return issuer
	}
	return strings.TrimRight(w.BaseURL, "/")
}

// WalletError is an error event that can be displayed in the UI.
type WalletError struct {
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// StoredCredential is a credential stored in the wallet.
type StoredCredential struct {
	ID          string                             `json:"id"`
	Format      string                             `json:"format"`        // "dc+sd-jwt", "mso_mdoc", or "jwt_vc_json"
	Raw         string                             `json:"raw"`           // original credential string
	Claims      map[string]any                     `json:"claims"`        // decoded claims for display/matching
	VCT         string                             `json:"vct,omitempty"` // SD-JWT vct
	DocType     string                             `json:"doctype,omitempty"`
	Disclosures []sdjwt.Disclosure                 `json:"-"`
	NameSpaces  map[string][]mdoc.IssuerSignedItem `json:"-"`
}

// ConsentRequest represents a pending presentation or issuance consent.
type ConsentRequest struct {
	ID           string                       `json:"id"`
	Type         string                       `json:"type"` // "presentation" or "issuance"
	AuthRequest  *oid4vc.AuthorizationRequest `json:"-"`
	OfferURI     string                       `json:"-"`
	MatchedCreds []CredentialMatch            `json:"matched_credentials"`
	Status       string                       `json:"status"` // "pending", "approved", "denied"
	ResultCh     chan ConsentResult           `json:"-"`
	SubmissionCh chan SubmissionResult        `json:"-"` // result of VP submission after approval
	CreatedAt    time.Time                    `json:"created_at"`
	ClientID     string                       `json:"client_id"`
	OfferConfigs []string                     `json:"offer_configs,omitempty"`
	Nonce        string                       `json:"nonce,omitempty"`
	ResponseURI  string                       `json:"response_uri,omitempty"`
	DCQLQuery    map[string]any               `json:"dcql_query,omitempty"`
}

// CredentialMatch links a credential to a DCQL query credential ID.
type CredentialMatch struct {
	QueryID      string         `json:"query_id"`
	CredentialID string         `json:"credential_id"`
	Format       string         `json:"format"`
	VCT          string         `json:"vct,omitempty"`
	DocType      string         `json:"doctype,omitempty"`
	Claims       map[string]any `json:"claims"`
	SelectedKeys []string       `json:"selected_keys"` // exact claim selectors to disclose
}

// ConsentResult is returned by the consent flow.
type ConsentResult struct {
	Approved       bool
	SelectedClaims map[string][]string // credential ID → claim names
}

// SubmissionResult is the outcome of VP token submission after consent approval.
type SubmissionResult struct {
	RedirectURI string `json:"redirect_uri,omitempty"`
	Error       string `json:"error,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
}

// LogEntry records a wallet action.
type LogEntry struct {
	Time    time.Time      `json:"time"`
	Action  string         `json:"action"`
	Detail  string         `json:"detail"`
	Success bool           `json:"success"`
	Details map[string]any `json:"details,omitempty"`
}

// New creates a new wallet with the given options.
// It generates a CA key and certificate chain (CA → leaf) for realistic x5c chains.
func New(holderKey, issuerKey *ecdsa.PrivateKey, autoAccept bool) *Wallet {
	w := &Wallet{
		HolderKey:         holderKey,
		IssuerKey:         issuerKey,
		AutoAccept:        autoAccept,
		ValidationMode:    ValidationModeDebug,
		Requests:          make(map[string]*ConsentRequest),
		subscribers:       make(map[int64]chan *ConsentRequest),
		authCodeCallbacks: make(map[string]chan url.Values),
	}

	// Generate CA key and certificate chain
	caKey, err := mock.GenerateKey()
	if err != nil {
		log.Printf("[Wallet] Warning: failed to generate CA key: %v", err)
		return w
	}

	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		log.Printf("[Wallet] Warning: failed to generate CA cert: %v", err)
		return w
	}

	leafCert, err := mock.GenerateLeafCert(caKey, caCert, &issuerKey.PublicKey)
	if err != nil {
		log.Printf("[Wallet] Warning: failed to generate leaf cert: %v", err)
		return w
	}

	w.CAKey = caKey
	w.CertChain = []*x509.Certificate{leafCert, caCert}

	return w
}

// SetCertificateAuthority replaces the wallet's certificate chain with one rooted
// in the provided CA, while keeping the existing issuer signing key.
func (w *Wallet) SetCertificateAuthority(caKey *ecdsa.PrivateKey, caCert *x509.Certificate) error {
	if w == nil || w.IssuerKey == nil || caKey == nil || caCert == nil {
		return fmt.Errorf("wallet CA configuration requires issuer key, CA key, and CA certificate")
	}
	leafCert, err := mock.GenerateLeafCert(caKey, caCert, &w.IssuerKey.PublicKey)
	if err != nil {
		return fmt.Errorf("generating issuer leaf certificate: %w", err)
	}
	w.CAKey = caKey
	w.CertChain = []*x509.Certificate{leafCert, caCert}
	return nil
}

// GenerateDefaultCredentials generates SD-JWT and mDoc PID credentials.
// If PID credentials already exist, they are replaced. Optional claimOverrides
// are merged on top of the default PID claims. vct specifies the SD-JWT VCT;
// if empty, mock.DefaultPIDVCT is used.
func (w *Wallet) GenerateDefaultCredentials(claimOverrides map[string]any, vct string) error {
	if vct == "" {
		vct = mock.DefaultPIDVCT
	}
	log.Printf("[Wallet] Generating default PID credentials: vct=%s overrides=%d", vct, len(claimOverrides))
	issuerKey := w.IssuerKey
	issuer := strings.TrimRight(w.IssuerURL, "/")
	if issuer == "" {
		issuer = "https://issuer.example"
	}

	sdClaims := make(map[string]any, len(mock.SDJWTPIDClaims))
	for k, v := range mock.SDJWTPIDClaims {
		sdClaims[k] = v
	}
	for k, v := range claimOverrides {
		sdClaims[k] = v
	}

	mdocClaims := make(map[string]any, len(mock.MDOCPIDClaims))
	for k, v := range mock.MDOCPIDClaims {
		mdocClaims[k] = v
	}
	for k, v := range claimOverrides {
		mdocClaims[k] = v
	}

	// Remove existing PID credentials before generating new ones
	w.removeByType("dc+sd-jwt", vct, "")
	w.removeByType("mso_mdoc", "", "eu.europa.ec.eudi.pid.1")

	// Generate SD-JWT PID
	var holderPubKey *ecdsa.PublicKey
	if w.HolderKey != nil {
		holderPubKey = &w.HolderKey.PublicKey
	}
	pidSpec := applyPIDTrustProfileDefaults(IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: vct})
	pidChain, err := w.SigningCertChainForIssuedAttestation(pidSpec)
	if err != nil {
		return fmt.Errorf("building PID signing certificate chain: %w", err)
	}

	sdConfig := mock.SDJWTConfig{
		Issuer:    issuer,
		VCT:       vct,
		ExpiresIn: 30 * 24 * time.Hour,
		Claims:    sdClaims,
		Key:       issuerKey,
		HolderKey: holderPubKey,
		CertChain: pidChain,
	}

	// Assign status list indices if enabled
	var sdStatusIdx, mdocStatusIdx int
	if w.BaseURL != "" {
		statusListURL := w.StatusListURL()
		sdStatusIdx = w.nextStatusIndex()
		sdConfig.StatusListURI = statusListURL
		sdConfig.StatusListIdx = sdStatusIdx
	}

	sdResult, err := mock.GenerateSDJWT(sdConfig)
	if err != nil {
		return fmt.Errorf("generating SD-JWT PID: %w", err)
	}
	sdCred, err := w.ImportCredential(sdResult)
	if err != nil {
		return fmt.Errorf("importing SD-JWT PID: %w", err)
	}

	// Register status entry for SD-JWT credential
	if w.BaseURL != "" {
		w.registerStatusEntry(sdCred.ID, sdStatusIdx)
	}

	mdocConfig := mock.MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    mdocClaims,
		Key:       issuerKey,
		HolderKey: holderPubKey,
		ExpiresIn: 30 * 24 * time.Hour,
		CertChain: pidChain,
	}

	if w.BaseURL != "" {
		statusListURL := w.StatusListURL()
		mdocStatusIdx = w.nextStatusIndex()
		mdocConfig.StatusListURI = statusListURL
		mdocConfig.StatusListIdx = mdocStatusIdx
	}

	// Generate mDoc PID
	mdocResult, err := mock.GenerateMDOC(mdocConfig)
	if err != nil {
		return fmt.Errorf("generating mDoc PID: %w", err)
	}
	mdocCred, err := w.ImportCredential(mdocResult)
	if err != nil {
		return fmt.Errorf("importing mDoc PID: %w", err)
	}

	w.IssuedAttestations = []IssuedAttestationSpec{
		pidSpec,
		applyPIDTrustProfileDefaults(IssuedAttestationSpec{Format: "mso_mdoc", DocType: "eu.europa.ec.eudi.pid.1"}),
	}

	// Register status entry for mDoc credential
	if w.BaseURL != "" {
		w.registerStatusEntry(mdocCred.ID, mdocStatusIdx)
	}

	return nil
}

// removeByType removes credentials matching the given format and vct/doctype.
func (w *Wallet) removeByType(format, vct, docType string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	filtered := w.Credentials[:0]
	for _, c := range w.Credentials {
		if c.Format == format && (vct == "" || c.VCT == vct) && (docType == "" || c.DocType == docType) {
			continue
		}
		filtered = append(filtered, c)
	}
	w.Credentials = filtered
}

// RemoveCredential removes a credential by ID.
func (w *Wallet) RemoveCredential(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, c := range w.Credentials {
		if c.ID == id {
			w.Credentials = append(w.Credentials[:i], w.Credentials[i+1:]...)
			return true
		}
	}
	return false
}

// RegisterIssuedAttestation records a credential type and its trust/registration
// metadata as something this wallet is configured to issue.
func (w *Wallet) RegisterIssuedAttestation(spec IssuedAttestationSpec) error {
	normalized, err := NormalizeIssuedAttestationSpec(spec, "")
	if err != nil {
		return err
	}
	key := normalized.Format + "|" + normalized.VCT + "|" + normalized.DocType

	w.mu.Lock()
	defer w.mu.Unlock()
	for i, existing := range w.IssuedAttestations {
		existingKey := existing.Format + "|" + existing.VCT + "|" + existing.DocType
		if existingKey == key {
			w.IssuedAttestations[i] = normalized
			return nil
		}
	}
	w.IssuedAttestations = append(w.IssuedAttestations, normalized)
	w.IssuedAttestations = dedupeIssuedAttestations(w.IssuedAttestations)
	return nil
}

// GetCredentials returns a snapshot of all credentials.
func (w *Wallet) GetCredentials() []StoredCredential {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]StoredCredential, len(w.Credentials))
	copy(out, w.Credentials)
	return out
}

// GetCredential returns a credential by ID.
func (w *Wallet) GetCredential(id string) (StoredCredential, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, c := range w.Credentials {
		if c.ID == id {
			return c, true
		}
	}
	return StoredCredential{}, false
}

// SetLogSink sets a callback invoked after each log entry is appended.
func (w *Wallet) SetLogSink(fn func(LogEntry)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logSink = fn
}

// AddLog records a log entry.
func (w *Wallet) AddLog(action, detail string, success bool) {
	w.AddLogDetails(action, detail, success, nil)
}

// AddLogDetails records a log entry with structured verbose details.
func (w *Wallet) AddLogDetails(action, detail string, success bool, details map[string]any) {
	w.appendLogEntry(LogEntry{
		Time:    time.Now(),
		Action:  action,
		Detail:  detail,
		Success: success,
		Details: cloneLogDetails(details),
	})
}

func (w *Wallet) appendLogEntry(entry LogEntry) {
	w.mu.Lock()
	w.Log = append(w.Log, entry)
	sink := w.logSink
	w.mu.Unlock()
	if sink != nil {
		sink(entry)
	}
}

func cloneLogDetails(details map[string]any) map[string]any {
	if len(details) == 0 {
		return nil
	}
	out := make(map[string]any, len(details))
	for key, value := range details {
		out[key] = value
	}
	return out
}

// GetLog returns a snapshot of log entries.
func (w *Wallet) GetLog() []LogEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]LogEntry, len(w.Log))
	copy(out, w.Log)
	return out
}

// LoadKeyFromFile loads a private key from a file path.
func LoadKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	privKey, err := keys.LoadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key must be an EC private key (P-256)")
	}
	return ecKey, nil
}

// CredentialSummary returns a JSON-serializable summary of a credential.
func CredentialSummary(c StoredCredential) map[string]any {
	summary := map[string]any{
		"id":     c.ID,
		"format": c.Format,
		"claims": c.Claims,
	}
	if c.VCT != "" {
		summary["vct"] = c.VCT
	}
	if c.DocType != "" {
		summary["doctype"] = c.DocType
	}
	return summary
}

// MarshalConsentRequest returns a JSON-serializable view of a consent request.
func MarshalConsentRequest(r *ConsentRequest) map[string]any {
	m := map[string]any{
		"id":                  r.ID,
		"type":                r.Type,
		"status":              r.Status,
		"client_id":           r.ClientID,
		"created_at":          r.CreatedAt.Format(time.RFC3339),
		"matched_credentials": r.MatchedCreds,
	}
	if r.Nonce != "" {
		m["nonce"] = r.Nonce
	}
	if r.ResponseURI != "" {
		m["response_uri"] = r.ResponseURI
	}
	if r.DCQLQuery != nil {
		m["dcql_query"] = r.DCQLQuery
	}
	if len(r.OfferConfigs) > 0 {
		m["offer_configs"] = r.OfferConfigs
	}
	return m
}

// CredentialsJSON returns all credentials as JSON bytes.
func (w *Wallet) CredentialsJSON() ([]byte, error) {
	creds := w.GetCredentials()
	summaries := make([]map[string]any, len(creds))
	for i, c := range creds {
		summaries[i] = CredentialSummary(c)
	}
	return json.Marshal(summaries)
}
