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

	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
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
	// ForceClientAttestation sends the wallet attestation on OID4VCI token
	// requests even when the authorization server does not advertise
	// attest_jwt_client_auth. Advertising it is only a SHOULD, so its absence
	// does not prove the issuer will not check one, and this is the operator
	// saying they know it does. Off by default: an attestation reused across
	// issuers is a correlation handle.
	ForceClientAttestation bool
	ValidationMode         ValidationMode `json:"-"`
	Credentials            []StoredCredential
	// DeferredIssuances are credentials an issuer deferred, kept until the
	// wallet manages to collect them.
	DeferredIssuances []DeferredIssuance
	StatusEntries     map[string]StatusEntry // credential ID → status entry
	StatusListCounter int                    // next available status list index
	BaseURL           string                 // base URL for status list endpoint
	IssuerURL         string                 // HTTPS issuer URL for JWT VC issuer metadata/JWKS
	VCIClientID       string                 `json:"-"`
	VCIRedirectURI    string                 `json:"-"`
	TemplatesDir      string                 `json:"-"` // credential template directory; empty selects the default
	TxCode            string                 `json:"-"` // one-shot tx_code for OID4VCI token request
	Log               []LogEntry
	mu                sync.RWMutex
	logSink           func(LogEntry)
	// credentialSink forwards imports to the wallet a clone was made from.
	credentialSink func(StoredCredential)
	runtime        *WalletRuntime
}

// WalletRuntime is the in-memory flow state shared by wallet instances backed
// by the same store directory.
type WalletRuntime struct {
	mu                sync.RWMutex
	requests          map[string]*ConsentRequest
	nextError         *NextErrorOverride
	subscribers       map[int64]chan *ConsentRequest
	subID             int64
	errSubscribers    map[int64]chan WalletError
	errSubID          int64
	stateSubscribers  map[int64]chan struct{}
	stateSubID        int64
	authSubscribers   map[int64]chan string
	authSubID         int64
	lastError         *WalletError
	authCodeCallbacks map[string]chan url.Values
}

func newWalletRuntime() *WalletRuntime {
	return &WalletRuntime{
		requests:          make(map[string]*ConsentRequest),
		subscribers:       make(map[int64]chan *ConsentRequest),
		errSubscribers:    make(map[int64]chan WalletError),
		stateSubscribers:  make(map[int64]chan struct{}),
		authSubscribers:   make(map[int64]chan string),
		authCodeCallbacks: make(map[string]chan url.Values),
	}
}

func (w *Wallet) runtimeState() *WalletRuntime {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.runtime == nil {
		w.runtime = newWalletRuntime()
	}
	return w.runtime
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
	ID      string         `json:"id"`
	Format  string         `json:"format"`        // "dc+sd-jwt", "mso_mdoc", or "jwt_vc_json"
	Raw     string         `json:"raw"`           // original credential string
	Claims  map[string]any `json:"claims"`        // decoded claims for display/matching
	VCT     string         `json:"vct,omitempty"` // SD-JWT vct
	DocType string         `json:"doctype,omitempty"`
	// Protected marks baseline credentials that the UI, the API and the CLI
	// must not delete or revoke. It exists for shared deployments, where a
	// visitor emptying the wallet would break it for everyone. Only direct
	// access to wallet.json can set or clear it.
	Protected bool `json:"protected,omitempty"`
	// Renewal is what re-requesting this credential from its issuer needs,
	// kept only when the issuer handed over a refresh token. Everything here
	// is stored in the clear like the rest of the wallet, which is a
	// development and test store by design (see docs/wallet.md).
	Renewal     *CredentialRenewal                 `json:"renewal,omitempty"`
	Disclosures []sdjwt.Disclosure                 `json:"-"`
	NameSpaces  map[string][]mdoc.IssuerSignedItem `json:"-"`
}

// CredentialRenewal is the issuer context a credential can be re-requested
// with. The flow that obtained the credential is long gone by the time it
// nears expiry, so what that flow knew has to travel with the credential.
type CredentialRenewal struct {
	Issuer             string `json:"issuer"`
	TokenEndpoint      string `json:"token_endpoint"`
	CredentialEndpoint string `json:"credential_endpoint"`
	ConfigurationID    string `json:"credential_configuration_id,omitempty"`
	ClientID           string `json:"client_id,omitempty"`
	RefreshToken       string `json:"refresh_token"`
	UseDPoP            bool   `json:"use_dpop,omitempty"`
	// ClientAuth is how the issuance authenticated this client, when it had
	// to. A refresh is another token request at the same endpoint, held to
	// the same rule.
	ClientAuth *ClientAuthentication `json:"client_auth,omitempty"`
}

// Client authentication methods a token request can be held to.
const (
	ClientAuthAttestation   = "attestation"
	ClientAuthPrivateKeyJWT = "private_key_jwt"
)

// ClientAuthentication is what authenticating to an authorization server
// again needs once the flow that first did it is gone. An issuer that
// required client authentication at issuance requires it on every later token
// request too, a refresh included, and by then nothing is left holding the
// metadata that said so.
type ClientAuthentication struct {
	Method   string `json:"method"`
	ClientID string `json:"client_id,omitempty"`
	// Audience is the authorization server identifier the attestation PoP or
	// the client assertion is addressed to, as the flow resolved it.
	Audience string `json:"audience,omitempty"`
	// ChallengeEndpoint hands out the challenge an attestation PoP carries. A
	// server that requires one rejects a stale challenge, so it is fetched
	// per request rather than stored.
	ChallengeEndpoint string `json:"challenge_endpoint,omitempty"`
}

// CanRenew reports whether a credential carries what re-requesting it needs.
func (c StoredCredential) CanRenew() bool {
	return c.Renewal != nil && c.Renewal.RefreshToken != "" &&
		c.Renewal.TokenEndpoint != "" && c.Renewal.CredentialEndpoint != ""
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
	// OfferDetails describes what the issuer is offering, for the consent UI.
	OfferDetails *IssuanceOfferDetails `json:"offer_details,omitempty"`
	Nonce        string                `json:"nonce,omitempty"`
	ResponseURI  string                `json:"response_uri,omitempty"`
	DCQLQuery    map[string]any        `json:"dcql_query,omitempty"`
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
	// TxCode is the transaction code the user typed for an issuance offer
	// that requires one. It arrives with the approval because the offer is
	// what says a code is needed, and the user only sees that in the dialog.
	TxCode string
}

// SubmissionResult is the outcome of VP token submission after consent
// approval, or of the issuance an approved credential offer started.
type SubmissionResult struct {
	RedirectURI string `json:"redirect_uri,omitempty"`
	Error       string `json:"error,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	// Pending marks an issuance the issuer deferred. The dialog has to tell
	// that apart from a failure: nothing went wrong, the credential simply is
	// not ready, and the wallet keeps collecting it in the background.
	Pending       bool   `json:"pending,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	RetryInterval string `json:"retry_interval,omitempty"`
}

// LogEntry records a wallet action.
type LogEntry struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
	// Success is the pass/fail of the action. Severity carries a third state a
	// bool cannot: a spec violation the wallet noted but did not treat as a
	// failure. An empty Severity means the entry is a plain success or failure
	// read from Success; "warning" marks a violation that only warned.
	Success  bool           `json:"success"`
	Severity string         `json:"severity,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// severityWarning marks a log entry that records a spec violation the wallet
// reported without failing the flow (debug mode, and the demo).
const severityWarning = "warning"

// New creates a new wallet with the given options.
// It generates a CA key and certificate chain (CA → leaf) for realistic x5c chains.
func New(holderKey, issuerKey *ecdsa.PrivateKey, autoAccept bool) *Wallet {
	w := &Wallet{
		HolderKey:      holderKey,
		IssuerKey:      issuerKey,
		AutoAccept:     autoAccept,
		ValidationMode: ValidationModeDebug,
		runtime:        newWalletRuntime(),
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
	// Under the lock because the demo reset renews this while requests are
	// being served. A slice header is not written atomically, so an unguarded
	// swap can hand a reader a length from one chain and a pointer from
	// another. Generating the leaf above stays outside it.
	w.mu.Lock()
	defer w.mu.Unlock()
	w.CAKey = caKey
	w.CertChain = []*x509.Certificate{leafCert, caCert}
	return nil
}

// RefreshSigningCertificate re-issues the wallet's signing leaf from its own
// CA. The CA and the issuer key stay as they are, so the trust anchor and the
// published key do not move.
func (w *Wallet) RefreshSigningCertificate() error {
	if w == nil || w.CAKey == nil || len(w.CertChain) < 2 {
		return nil
	}
	return w.SetCertificateAuthority(w.CAKey, w.CertChain[len(w.CertChain)-1])
}

// SigningCertificateExpiry is when the wallet's signing leaf stops being
// valid, or the zero time when it has no chain.
func (w *Wallet) SigningCertificateExpiry() time.Time {
	if w == nil || len(w.CertChain) == 0 || w.CertChain[0] == nil {
		return time.Time{}
	}
	return w.CertChain[0].NotAfter
}

// signingCertificateRenewBefore is how close to expiry a leaf is re-issued.
// A wallet that runs for months is the normal case for a hosted one, and
// nothing about an expired leaf announces itself: credentials keep being
// issued and quietly stop verifying.
const signingCertificateRenewBefore = 30 * 24 * time.Hour

// RefreshSigningCertificateIfExpiring re-issues the signing leaf when it is
// near its expiry, and reports whether it did.
func (w *Wallet) RefreshSigningCertificateIfExpiring(now time.Time) (bool, error) {
	expiry := w.SigningCertificateExpiry()
	if expiry.IsZero() || now.Add(signingCertificateRenewBefore).Before(expiry) {
		return false, nil
	}
	if err := w.RefreshSigningCertificate(); err != nil {
		return false, err
	}
	return true, nil
}

// GenerateDefaultCredentials generates SD-JWT and mDoc PID credentials from
// the german-pid-sdjwt and german-pid-mdoc credential templates (user
// overrides of those templates in the wallet's template directory apply).
// If PID credentials already exist, they are replaced. Optional claimOverrides
// are merged on top of the template claims. vct specifies the SD-JWT VCT. If
// empty, the template's VCT (mock.DefaultPIDVCT by default) is used.
func (w *Wallet) GenerateDefaultCredentials(claimOverrides map[string]any, vct string) error {
	return w.generateDefaultCredentials(claimOverrides, vct, true)
}

// generateDefaultCredentials generates the default PIDs. dropExisting removes
// any current default PID of the same type first, so a local wallet replaces
// its default rather than keeping two. The demo baseline path passes false: it
// drops its own previous baseline separately and must keep whatever visitors
// issued (see GenerateProtectedDefaults).
func (w *Wallet) generateDefaultCredentials(claimOverrides map[string]any, vct string, dropExisting bool) error {
	sdTpl, err := credtemplate.Load("german-pid-sdjwt", w.TemplatesDir)
	if err != nil {
		return fmt.Errorf("loading german-pid-sdjwt template: %w", err)
	}
	mdocTpl, err := credtemplate.Load("german-pid-mdoc", w.TemplatesDir)
	if err != nil {
		return fmt.Errorf("loading german-pid-mdoc template: %w", err)
	}
	if vct == "" {
		vct = sdTpl.VCT
	}
	if vct == "" {
		vct = mock.DefaultPIDVCT
	}
	mdocDocType := mdocTpl.DocType
	if mdocDocType == "" {
		mdocDocType = "eu.europa.ec.eudi.pid.1"
	}
	mdocNamespace := mdocTpl.Namespace
	if mdocNamespace == "" {
		mdocNamespace = mdocDocType
	}
	log.Printf("[Wallet] Generating default PID credentials: vct=%s overrides=%d", vct, len(claimOverrides))
	issuerKey := w.IssuerKey
	issuer := strings.TrimRight(w.IssuerURL, "/")
	if issuer == "" {
		issuer = "https://issuer.example"
	}

	sdClaims := credtemplate.MergeClaims(sdTpl.Claims, claimOverrides)
	mdocClaims := credtemplate.MergeClaims(mdocTpl.Claims, claimOverrides)

	// A protected one is kept instead of removed, and then there is nothing to
	// regenerate: it is the baseline and must not be duplicated.
	var keptSD, keptMDoc bool
	if dropExisting {
		keptSD = w.removeByType("dc+sd-jwt", vct, "") > 0
		keptMDoc = w.removeByType("mso_mdoc", "", mdocDocType) > 0
		if keptSD || keptMDoc {
			log.Printf("[Wallet] Keeping protected PID credentials: sdjwt=%t mdoc=%t", keptSD, keptMDoc)
		}
	}

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
		Issuer:          issuer,
		VCT:             vct,
		ExpiresIn:       30 * 24 * time.Hour,
		Claims:          sdClaims,
		Key:             issuerKey,
		HolderKey:       holderPubKey,
		CertChain:       pidChain,
		AlwaysDisclosed: sdTpl.AlwaysDisclosed,
	}

	// Assign status list indices when the wallet has a status list URL
	// (derived from the issuer URL or base URL).
	statusListURL := w.StatusListURL()
	var sdStatusIdx, mdocStatusIdx int
	if statusListURL != "" {
		sdStatusIdx = w.nextStatusIndex()
		sdConfig.StatusListURI = statusListURL
		sdConfig.StatusListIdx = sdStatusIdx
	}

	if !keptSD {
		sdResult, err := mock.GenerateSDJWT(sdConfig)
		if err != nil {
			return fmt.Errorf("generating SD-JWT PID: %w", err)
		}
		sdCred, err := w.ImportCredential(sdResult)
		if err != nil {
			return fmt.Errorf("importing SD-JWT PID: %w", err)
		}

		// Register status entry for SD-JWT credential
		if statusListURL != "" {
			w.registerStatusEntry(sdCred.ID, sdStatusIdx)
		}
	}

	mdocConfig := mock.MDOCConfig{
		DocType:   mdocDocType,
		Namespace: mdocNamespace,
		// The German PID keeps its national additions in a second namespace,
		// which claim keys carry as a "namespace:element" prefix.
		NamespaceClaims: splitClaimsByNamespace(mdocClaims, mdocNamespace),
		Key:             issuerKey,
		HolderKey:       holderPubKey,
		ExpiresIn:       30 * 24 * time.Hour,
		CertChain:       pidChain,
	}

	if statusListURL != "" {
		mdocStatusIdx = w.nextStatusIndex()
		mdocConfig.StatusListURI = statusListURL
		mdocConfig.StatusListIdx = mdocStatusIdx
	}

	// Generate mDoc PID
	if !keptMDoc {
		mdocResult, err := mock.GenerateMDOC(mdocConfig)
		if err != nil {
			return fmt.Errorf("generating mDoc PID: %w", err)
		}
		mdocCred, err := w.ImportCredential(mdocResult)
		if err != nil {
			return fmt.Errorf("importing mDoc PID: %w", err)
		}

		// Register status entry for mDoc credential
		if statusListURL != "" {
			w.registerStatusEntry(mdocCred.ID, mdocStatusIdx)
		}
	}

	w.IssuedAttestations = []IssuedAttestationSpec{
		pidSpec,
		applyPIDTrustProfileDefaults(IssuedAttestationSpec{Format: "mso_mdoc", DocType: mdocDocType}),
	}

	return nil
}

// removeByType drops every credential of the given type. Protected
// credentials survive: regenerating the defaults must not be a way around the
// rule that only direct access to the wallet file can remove them. It returns
// how many protected credentials it kept.
func (w *Wallet) removeByType(format, vct, docType string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	var keptProtected int
	filtered := w.Credentials[:0]
	for _, c := range w.Credentials {
		if c.Format == format && (vct == "" || c.VCT == vct) && (docType == "" || c.DocType == docType) {
			if !c.Protected {
				continue
			}
			keptProtected++
		}
		filtered = append(filtered, c)
	}
	w.Credentials = filtered
	return keptProtected
}

// removeProtected drops every credential of the previous baseline.
func (w *Wallet) removeProtected() {
	w.mu.Lock()
	defer w.mu.Unlock()
	kept := w.Credentials[:0]
	for _, c := range w.Credentials {
		if !c.Protected {
			kept = append(kept, c)
		}
	}
	w.Credentials = kept
}

// ClearCredentials removes all stored credentials and returns how many were removed.
func (w *Wallet) ClearCredentials() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	kept := make([]StoredCredential, 0, len(w.Credentials))
	for _, c := range w.Credentials {
		if c.Protected {
			kept = append(kept, c)
		}
	}
	removed := len(w.Credentials) - len(kept)
	w.Credentials = kept
	return removed
}

// RemoveCredential removes a credential by ID. Protected credentials are
// never removed, so no API or CLI path can drop a shared baseline.
func (w *Wallet) RemoveCredential(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, c := range w.Credentials {
		if c.ID == id {
			if c.Protected {
				return false
			}
			w.Credentials = append(w.Credentials[:i], w.Credentials[i+1:]...)
			return true
		}
	}
	return false
}

// IsProtected reports whether the credential is part of a protected baseline.
func (w *Wallet) IsProtected(id string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, c := range w.Credentials {
		if c.ID == id {
			return c.Protected
		}
	}
	return false
}

// GenerateProtectedDefaults generates the default PID credentials and marks
// exactly those as protected. Credentials that were already in the wallet
// keep their current state, so a restart never protects visitor data.
func (w *Wallet) GenerateProtectedDefaults() error {
	// Drop the previous baseline whatever it looked like. Matching it by type
	// only replaces credentials that still carry today's vct and doctype, so a
	// release that changes either (urn:eudi:pid:de:1 to urn:eudi:pid:1, say)
	// would leave the old one behind and the demo would show two.
	w.removeProtected()

	existing := make(map[string]bool)
	for _, c := range w.GetCredentials() {
		existing[c.ID] = true
	}
	// removeProtected above dropped the old baseline; regenerate a fresh one
	// (marked protected below) so it never freezes on an old release's claim
	// set. dropExisting is false: a visitor's own PID of the same type stays.
	if err := w.generateDefaultCredentials(nil, "", false); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if !existing[w.Credentials[i].ID] {
			w.Credentials[i].Protected = true
		}
	}
	return nil
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

// Mode returns the validation mode under the read lock. The conformance
// settings can be changed at runtime on a local wallet (PUT
// /api/config/conformance), and ValidationMode is a string, so an unsynchronized
// read racing that write could tear. Read it through here on any path that can
// run concurrently with the write.
func (w *Wallet) Mode() ValidationMode {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.ValidationMode
}

// ConformanceSettings returns the three runtime-mutable conformance fields
// together under the read lock.
func (w *Wallet) ConformanceSettings() (ValidationMode, bool, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.ValidationMode, w.RequireHAIP, w.RequireEncryptedRequest
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

// AddWarning records a spec violation the wallet noted without failing the
// flow (debug mode, and the demo). It is not a failure, so Success stays true
// and the entry carries the warning severity for the UI to mark distinctly.
func (w *Wallet) AddWarning(action, detail string, details map[string]any) {
	w.appendLogEntry(LogEntry{
		Time:     time.Now(),
		Action:   action,
		Detail:   detail,
		Success:  true,
		Severity: severityWarning,
		Details:  cloneLogDetails(details),
	})
}

// maxLogEntries is how much activity history a wallet keeps. The log is
// persisted with the wallet and re-read at every request boundary, so an
// unbounded one costs disk and a growing parse on each of those reloads, not
// just memory. A thousand entries is the same depth the proxy keeps.
//
// logTrimSlack lets the log run past the cap before it is trimmed, so the
// copy happens once every few hundred entries rather than on every append.
const (
	maxLogEntries = 1000
	logTrimSlack  = 256
)

func (w *Wallet) appendLogEntry(entry LogEntry) {
	w.mu.Lock()
	w.Log = append(w.Log, entry)
	if len(w.Log) >= maxLogEntries+logTrimSlack {
		// Copied into a fresh slice rather than resliced: resliced, the
		// dropped entries stay reachable through the backing array and their
		// details maps are never collected.
		trimmed := make([]LogEntry, maxLogEntries)
		copy(trimmed, w.Log[len(w.Log)-maxLogEntries:])
		w.Log = trimmed
	}
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

// ClearLog removes all activity log entries.
func (w *Wallet) ClearLog() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Log = nil
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
		"raw":    c.Raw,
	}
	if c.VCT != "" {
		summary["vct"] = c.VCT
	}
	if c.DocType != "" {
		summary["doctype"] = c.DocType
	}
	if c.Protected {
		summary["protected"] = true
	}
	// Both backends build their listings from this, so a caller reading the
	// expiry reads the same value whichever one answered.
	if expiry := CredentialExpiry(c); !expiry.IsZero() {
		summary["expires_at"] = expiry.UTC().Format(time.RFC3339)
	}
	// Whether it can be asked for again, not the token that would do it: a
	// listing is printed and logged in places a refresh token should not go.
	if c.CanRenew() {
		summary["can_renew"] = true
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
	if r.OfferDetails != nil {
		m["offer_details"] = r.OfferDetails
	}
	return m
}

// CredentialsJSON returns all credentials as JSON bytes.
func (w *Wallet) CredentialsJSON() ([]byte, error) {
	return w.CredentialsJSONWindow(0, 0)
}

// CredentialsJSONWindow serializes a slice of the stored credentials.
// A limit of 0 means "to the end", and an offset past the end yields an
// empty array rather than an error, so a paging client that lands on a
// stale page simply sees nothing.
func (w *Wallet) CredentialsJSONWindow(offset, limit int) ([]byte, error) {
	creds := w.GetCredentials()
	// Sorted before the window is taken, or paging would slice the stored
	// order and then order each page on its own.
	SortCredentialsNewestFirst(creds)
	if offset > len(creds) {
		offset = len(creds)
	}
	creds = creds[offset:]
	if limit > 0 && limit < len(creds) {
		creds = creds[:limit]
	}
	summaries := make([]map[string]any, len(creds))
	for i, c := range creds {
		summaries[i] = w.CredentialSummaryWithStatus(c)
	}
	return json.Marshal(summaries)
}

// RestoreCredential appends a credential that is already known to have been
// imported, without re-parsing it. It exists for one case: a store reload
// replaced the credential list while an issuance flow was in progress, and
// the credential it produced has to be put back before the wallet is saved.
func (w *Wallet) RestoreCredential(cred StoredCredential) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, existing := range w.Credentials {
		if existing.ID == cred.ID {
			return
		}
	}
	w.Credentials = append(w.Credentials, cred)
}
