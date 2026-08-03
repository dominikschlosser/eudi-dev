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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/internal/statuslist"
)

// Server is the wallet HTTP server.
type Server struct {
	wallet           *Wallet
	port             int
	mux              *http.ServeMux
	onSave           func()
	onConsentRequest func(req *ConsentRequest)
	onUIRequest      func()
	logFunc          func(format string, args ...any)
	httpSrv          *http.Server
	issuerSrv        *http.Server
	issuerTLSCert    *tls.Certificate
	issuerPort       int
	issuerKeyExpiry  time.Time
	parseOpts        oid4vc.ParseOptions
	store            *WalletStore
	storeSyncMu      sync.Mutex
	demo             *demoState
	version          string
	imprintHTML      []byte
	// ShutdownFunc runs after POST /api/shutdown responded. The serve command
	// sets it to deregister the instance and exit; when nil the process exits
	// directly.
	ShutdownFunc func()
}

type presentationRequestOptions struct {
	AutoAccept        bool
	SessionTranscript string
	RequireHAIP       bool
	ValidationMode    string
}

// processBuildID identifies the code this process is running: the SHA-256 of
// the executable, hashed once at startup. Comparing it against the binary on
// disk detects a server that outlived a rebuild.
var processBuildID = sync.OnceValue(func() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
})

// NewServer creates a new wallet HTTP server.
// onSave is called after credential-changing operations (import, delete, issuance).
func NewServer(w *Wallet, port int, onSave func()) *Server {
	processBuildID()
	s := &Server{
		wallet:          w,
		port:            port,
		onSave:          onSave,
		issuerKeyExpiry: time.Now().Add(24 * time.Hour),
	}
	w.SetLogSink(func(LogEntry) {
		s.triggerSave()
	})
	if p := parseIssuerPort(w.IssuerURL); p > 0 {
		s.issuerPort = p
	} else if port > 0 {
		s.issuerPort = port + 1
	}
	s.mux = http.NewServeMux()
	s.setupRoutes()
	// Set up ParseOptions with wallet-aware request_uri fetcher.
	// The logFunc is captured lazily so it works even if SetLogger is called after NewServer.
	s.parseOpts = oid4vc.ParseOptions{
		FetchRequestURI: MakeFetchRequestURI(w, func(format string, args ...any) {
			s.log(format, args...)
		}),
	}
	return s
}

func (s *Server) setupRoutes() {
	// OID4VP Authorization Endpoint
	s.mux.HandleFunc("GET /authorize", s.withFreshStore(s.handleAuthorize))
	s.mux.HandleFunc("POST /authorize", s.withFreshStore(s.handleAuthorize))

	// OID4VCI Credential Offer Endpoint: the web-URL counterpart of the
	// openid-credential-offer:// custom scheme, so issuers can target the
	// wallet's own URL where scheme registration is unavailable
	s.mux.HandleFunc("GET /credential-offer", s.withFreshStore(s.handleCredentialOfferEndpoint))

	// API: feed authorization request URIs
	s.mux.HandleFunc("POST /api/presentations", s.withFreshStore(s.handlePresentationAPI))
	s.mux.HandleFunc("POST /api/dc-api", s.withFreshStore(s.handleBrowserPresentationAPI))

	// API: credential offers
	s.mux.HandleFunc("POST /api/offers", s.withFreshStore(s.handleOfferAPI))
	s.mux.HandleFunc("GET /callback", s.withFreshStore(s.handleAuthorizationCodeCallback))

	// API: build identity, used by the URL handler script to detect stale servers
	s.mux.HandleFunc("GET /api/version", s.handleVersion)

	// API: credential management
	s.mux.HandleFunc("GET /api/credentials", s.withFreshStore(s.handleListCredentials))
	s.mux.HandleFunc("POST /api/credentials", s.withFreshStore(s.handleImportCredential))
	s.mux.HandleFunc("DELETE /api/credentials", s.withFreshStore(s.handleDeleteAllCredentials))
	s.mux.HandleFunc("GET /api/credentials/{id}", s.withFreshStore(s.handleGetCredential))
	s.mux.HandleFunc("DELETE /api/credentials/{id}", s.withFreshStore(s.handleDeleteCredential))

	// API: credential issuance mirroring `issue ... --wallet` and `wallet generate-pid`
	s.mux.HandleFunc("POST /api/issue", s.withFreshStore(s.handleIssueCredential))
	s.mux.HandleFunc("POST /api/generate-pid", s.withFreshStore(s.handleGeneratePID))

	// Credential templates
	s.mux.HandleFunc("GET /api/templates", s.handleListTemplates)
	s.mux.HandleFunc("GET /api/templates/{name}", s.handleGetTemplate)
	s.mux.HandleFunc("PUT /api/templates/{name}", s.handlePutTemplate)
	s.mux.HandleFunc("DELETE /api/templates/{name}", s.handleDeleteTemplate)

	// API: certificate export mirroring `wallet ca-cert` and `wallet tls-cert`
	s.mux.HandleFunc("GET /api/certificates/ca", s.handleCACertificate)
	s.mux.HandleFunc("GET /api/certificates/tls", s.handleTLSCertificate)

	// API: consent requests
	s.mux.HandleFunc("GET /api/requests", s.withFreshStore(s.handleListRequests))
	s.mux.HandleFunc("GET /api/requests/stream", s.withFreshStore(s.handleRequestStream))
	s.mux.HandleFunc("POST /api/requests/{id}/approve", s.withFreshStore(s.handleApproveRequest))
	s.mux.HandleFunc("POST /api/requests/{id}/deny", s.withFreshStore(s.handleDenyRequest))

	// API: trust list
	s.mux.HandleFunc("GET /api/trustlist", s.withFreshStore(s.handleTrustList))
	s.mux.HandleFunc("GET /api/trustlists", s.withFreshStore(s.handleTrustListIndex))
	s.mux.HandleFunc("GET /api/trustlists/{id}", s.withFreshStore(s.handleTrustListByID))
	s.mux.HandleFunc("GET /api/registrar/wrp", s.withFreshStore(s.handleRegistrarWRPList))
	s.mux.HandleFunc("GET /api/registrar/wrp/{identifier}", s.withFreshStore(s.handleRegistrarWRPByIdentifier))

	// API: status list
	s.mux.HandleFunc("GET /api/statuslist", s.withFreshStore(s.handleStatusList))
	s.mux.HandleFunc("GET /api/credentials/{id}/status", s.withFreshStore(s.handleGetCredentialStatus))
	s.mux.HandleFunc("POST /api/credentials/{id}/status", s.withFreshStore(s.handleSetCredentialStatus))

	// SD-JWT VC issuer metadata
	s.mux.HandleFunc("GET /.well-known/jwt-vc-issuer", s.withFreshStore(s.handleJWTVCIssuerMetadata))
	s.mux.HandleFunc("GET /.well-known/openid-credential-issuer", s.withFreshStore(s.handleOpenIDCredentialIssuerMetadata))

	// API: testing overrides
	s.mux.HandleFunc("POST /api/next-error", s.withFreshStore(s.handleSetNextError))
	s.mux.HandleFunc("DELETE /api/next-error", s.withFreshStore(s.handleClearNextError))
	s.mux.HandleFunc("PUT /api/config/preferred-format", s.withFreshStore(s.handleSetPreferredFormat))
	s.mux.HandleFunc("GET /api/config", s.withFreshStore(s.handleGetConfig))
	s.mux.HandleFunc("POST /api/shutdown", s.handleShutdown)

	// API: log
	s.mux.HandleFunc("GET /api/log", s.withFreshStore(s.handleLog))
	s.mux.HandleFunc("DELETE /api/log", s.withFreshStore(s.handleClearLog))

	// API: last error (polled on page load)
	s.mux.HandleFunc("GET /api/error", s.withFreshStore(s.handleLastError))
	s.mux.HandleFunc("DELETE /api/error", s.withFreshStore(s.handleClearLastError))

	// Operator-supplied legal notice (404 until SetImprint is called)
	s.mux.HandleFunc("GET /imprint", s.handleImprint)

	// Static files. Embedded files carry no modtime, so http.FileServer
	// sends no cache validators and browsers may keep stale assets across
	// releases (HTML and JS from different versions). no-cache forces
	// revalidation on every load.
	sub, _ := fs.Sub(staticFiles, "static")
	s.mux.Handle("/", noStaleCache(http.FileServer(http.FS(sub))))
}

func noStaleCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

// SetImprint serves the given pre-rendered imprint page at /imprint and
// makes /api/config advertise it so the UI shows the footer link.
func (s *Server) SetImprint(page []byte) {
	s.imprintHTML = page
}

func (s *Server) handleImprint(w http.ResponseWriter, r *http.Request) {
	if len(s.imprintHTML) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(s.imprintHTML)
}

// ListenAndServe starts the wallet server.
func (s *Server) ListenAndServe() error {
	s.httpSrv = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      s.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := s.startIssuerTLSServer(); err != nil {
		return err
	}
	s.startDemoReset()
	return s.httpSrv.ListenAndServe()
}

// ListenAndServeBackground starts the server on a random port and returns the address.
func (s *Server) ListenAndServeBackground() (string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return "", err
	}
	addr := fmt.Sprintf("http://localhost:%d", ln.Addr().(*net.TCPAddr).Port)
	s.httpSrv = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := s.startIssuerTLSServer(); err != nil {
		if closeErr := ln.Close(); closeErr != nil {
			return "", errors.Join(err, fmt.Errorf("closing listener: %w", closeErr))
		}
		return "", err
	}
	s.startDemoReset()
	go func() { _ = s.httpSrv.Serve(ln) }()
	return addr, nil
}

// SetOnConsentRequest sets a callback invoked when a new consent request is created.
func (s *Server) SetOnConsentRequest(fn func(req *ConsentRequest)) {
	s.onConsentRequest = fn
}

// SetOnUIRequest sets a callback invoked when the interactive wallet UI should be shown.
func (s *Server) SetOnUIRequest(fn func()) {
	s.onUIRequest = fn
}

// SetLogger sets a logging function for verbose terminal output.
func (s *Server) SetLogger(fn func(format string, args ...any)) {
	s.logFunc = fn
}

// SetIssuerTLSCertificate sets the certificate used by the wallet's HTTPS endpoints.
func (s *Server) SetIssuerTLSCertificate(cert tls.Certificate) {
	s.issuerTLSCert = &cert
}

// SetIssuerListenPort overrides the local port of the built-in HTTPS issuer
// listener, which NewServer derives from the wallet's IssuerURL. Pass a
// negative port to disable the listener entirely — used when an external TLS
// terminator serves the issuer origin (IssuerURL equals the base URL), where
// the derived port would otherwise be 443.
func (s *Server) SetIssuerListenPort(port int) {
	s.issuerPort = port
}

// SetStore makes the server reload the wallet store at request boundaries.
// This keeps a long-running interactive server in sync with credentials and
// logs written by other CLI invocations using the same wallet directory.
func (s *Server) SetStore(store *WalletStore) {
	s.storeSyncMu.Lock()
	defer s.storeSyncMu.Unlock()
	s.store = store
}

func (s *Server) log(format string, args ...any) {
	if s.logFunc != nil {
		s.logFunc(format, args...)
	}
}

func (s *Server) triggerUIRequest() {
	if s.onUIRequest != nil {
		s.onUIRequest()
	}
}

func (s *Server) withFreshStore(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.reloadFromStore(); err != nil {
			s.log("  ERROR: reloading wallet store: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "reloading wallet store: " + err.Error()})
			return
		}
		handler(w, r)
	}
}

func (s *Server) reloadFromStore() error {
	s.storeSyncMu.Lock()
	defer s.storeSyncMu.Unlock()

	if s.store == nil {
		return nil
	}

	reloaded, err := s.store.LoadOrCreate()
	if err != nil {
		return err
	}
	s.applyPersistedWalletState(reloaded)
	return nil
}

func (s *Server) applyPersistedWalletState(reloaded *Wallet) {
	if reloaded == nil {
		return
	}

	s.wallet.mu.Lock()
	defer s.wallet.mu.Unlock()

	s.wallet.HolderKey = reloaded.HolderKey
	s.wallet.IssuerKey = reloaded.IssuerKey
	s.wallet.CAKey = reloaded.CAKey
	s.wallet.CertChain = append([]*x509.Certificate(nil), reloaded.CertChain...)
	s.wallet.IssuedAttestations = append([]IssuedAttestationSpec(nil), reloaded.IssuedAttestations...)
	s.wallet.Credentials = append([]StoredCredential(nil), reloaded.Credentials...)
	s.wallet.StatusEntries = cloneStatusEntries(reloaded.StatusEntries)
	s.wallet.StatusListCounter = reloaded.StatusListCounter
	s.wallet.Log = append([]LogEntry(nil), reloaded.Log...)
}

func (s *Server) handleAuthorizationCodeCallback(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	if values.Get("state") == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing state in authorization callback",
		})
		return
	}
	if !s.wallet.CompleteAuthorizationCodeCallback(values) {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "no pending authorization-code flow for callback state",
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "<!doctype html><html><body><p>Wallet authorization completed. You can close this tab.</p></body></html>")
}

func (s *Server) startIssuerTLSServer() error {
	if s.issuerPort <= 0 || s.issuerSrv != nil {
		return nil
	}

	cert := tls.Certificate{}
	if s.issuerTLSCert != nil {
		cert = *s.issuerTLSCert
	} else {
		var err error
		var caCert *x509.Certificate
		if len(s.wallet.CertChain) > 1 {
			caCert = s.wallet.CertChain[len(s.wallet.CertChain)-1]
		}
		cert, err = generateIssuerTLSCertificate(parseIssuerHost(s.wallet.IssuerURL), s.wallet.CAKey, caCert)
		if err != nil {
			return fmt.Errorf("generating issuer TLS certificate: %w", err)
		}
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.issuerPort))
	if err != nil {
		return fmt.Errorf("listening for issuer HTTPS server: %w", err)
	}

	s.issuerSrv = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		tlsListener := tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
		_ = s.issuerSrv.Serve(tlsListener)
	}()

	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() {
	s.stopDemoReset()
	if s.httpSrv != nil {
		s.httpSrv.Close()
	}
	if s.issuerSrv != nil {
		s.issuerSrv.Close()
	}
}

// handleAuthorize processes an OID4VP authorization request from query params or form data.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var authReq *AuthorizationRequestParams
	var err error

	if r.Method == "GET" {
		authReq, err = parseAuthParams(r.URL.Query(), s.parseOpts, s.wallet.ValidationMode)
	} else {
		if parseErr := r.ParseForm(); parseErr != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}
		authReq, err = parseAuthParams(r.Form, s.parseOpts, s.wallet.ValidationMode)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("invalid authorization request: %v", err), http.StatusBadRequest)
		return
	}

	authReq.BrowserRedirect = isBrowserNavigation(r)
	s.handleAuthFlow(w, authReq)
}

// handlePresentationAPI processes a presentation request URI via API.
func (s *Server) handlePresentationAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URI               string `json:"uri"`
		AutoAccept        bool   `json:"auto_accept,omitempty"`
		Interactive       bool   `json:"interactive,omitempty"`
		SessionTranscript string `json:"session_transcript,omitempty"`
		HAIP              bool   `json:"haip,omitempty"`
		Mode              string `json:"mode,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	s.log("Received authorization request")
	// Truncate URI for display
	uriDisplay := format.Truncate(body.URI, 120)
	s.log("  URI: %s", uriDisplay)

	reqServer := s
	if body.AutoAccept || body.SessionTranscript != "" || body.HAIP || body.Mode != "" {
		reqWallet, err := cloneWalletForPresentation(s.wallet, presentationRequestOptions{
			AutoAccept:        body.AutoAccept,
			SessionTranscript: body.SessionTranscript,
			RequireHAIP:       body.HAIP,
			ValidationMode:    body.Mode,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		reqServer = &Server{
			wallet:           reqWallet,
			port:             s.port,
			mux:              s.mux,
			onSave:           s.onSave,
			onConsentRequest: s.onConsentRequest,
			onUIRequest: func() {
				if !body.AutoAccept {
					s.triggerUIRequest()
				}
			},
			logFunc:         s.logFunc,
			httpSrv:         s.httpSrv,
			issuerSrv:       s.issuerSrv,
			issuerTLSCert:   s.issuerTLSCert,
			issuerPort:      s.issuerPort,
			issuerKeyExpiry: s.issuerKeyExpiry,
		}
		reqServer.parseOpts = oid4vc.ParseOptions{
			FetchRequestURI: MakeFetchRequestURI(reqWallet, func(format string, args ...any) {
				reqServer.log(format, args...)
			}),
		}
	}

	parsed, err := ParseAuthorizationRequestWithOptions(body.URI, reqServer.parseOpts)
	if err != nil {
		reqServer.log("  ERROR: %v", err)
		reqServer.wallet.AddLog("presentation", fmt.Sprintf("Failed to parse request: %v", err), false)
		reqServer.wallet.NotifyError(WalletError{
			Message: "Failed to parse authorization request",
			Detail:  err.Error(),
		})
		reqServer.triggerUIRequest()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	reqServer.log("  Client ID:     %s", parsed.ClientID)
	reqServer.log("  Response Mode: %s", parsed.ResponseMode)
	reqServer.log("  Response URI:  %s", parsed.ResponseURI)
	if parsed.State != "" {
		reqServer.log("  State:         %s", parsed.State)
	}
	if parsed.Nonce != "" {
		reqServer.log("  Nonce:         %s", parsed.Nonce)
	}
	if parsed.RequestURIMethod != "" {
		reqServer.log("  Request URI Method: %s", parsed.RequestURIMethod)
	}

	findings, err := ValidateAuthorizationRequest(reqServer.wallet.ValidationMode, &AuthorizationRequestParams{
		ClientID:         parsed.ClientID,
		ResponseType:     parsed.ResponseType,
		ResponseMode:     parsed.ResponseMode,
		Nonce:            parsed.Nonce,
		State:            parsed.State,
		RedirectURI:      parsed.RedirectURI,
		ResponseURI:      parsed.ResponseURI,
		RequestURIMethod: parsed.RequestURIMethod,
		ClientMetadata:   parsed.ClientMetadata,
		DCQLQuery:        parsed.DCQLQuery,
		RequestObject:    parsed.RequestObject,
		RequestPayload:   requestPayload(parsed.RequestObject, parsed.FullJSON),
	})
	if err != nil {
		reqServer.log("  ERROR: %v", err)
		reqServer.wallet.AddLog("presentation", err.Error(), false)
		reqServer.wallet.NotifyError(WalletError{
			Message: "Authorization request validation failed",
			Detail:  err.Error(),
		})
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	for _, finding := range findings {
		reqServer.log("  WARNING: %s", finding)
		reqServer.wallet.AddLog("presentation", fmt.Sprintf("request validation warning: %s", finding), false)
	}

	authReq := &AuthorizationRequestParams{
		ClientID:         parsed.ClientID,
		ResponseType:     parsed.ResponseType,
		ResponseMode:     parsed.ResponseMode,
		Nonce:            parsed.Nonce,
		State:            parsed.State,
		RedirectURI:      parsed.RedirectURI,
		ResponseURI:      parsed.ResponseURI,
		RequestURIMethod: parsed.RequestURIMethod,
		ClientMetadata:   parsed.ClientMetadata,
		DCQLQuery:        parsed.DCQLQuery,
		RequestObject:    parsed.RequestObject,
		RequestPayload:   requestPayload(parsed.RequestObject, parsed.FullJSON),
		Source:           "api",
	}
	if body.Interactive {
		// A scheme dispatch or another submitter acting for a user
		// interaction: keep the consent dialog despite the API channel.
		authReq.Source = "interactive"
	}

	reqServer.handleAuthFlow(w, authReq)
}

func cloneWalletForPresentation(src *Wallet, opts presentationRequestOptions) (*Wallet, error) {
	if src == nil {
		return nil, fmt.Errorf("wallet is not initialized")
	}

	clone := &Wallet{
		HolderKey:               src.HolderKey,
		IssuerKey:               src.IssuerKey,
		CAKey:                   src.CAKey,
		CertChain:               append([]*x509.Certificate(nil), src.CertChain...),
		IssuedAttestations:      append([]IssuedAttestationSpec(nil), src.IssuedAttestations...),
		AutoAccept:              src.AutoAccept,
		SessionTranscript:       src.SessionTranscript,
		PreferredFormat:         src.PreferredFormat,
		RequireEncryptedRequest: src.RequireEncryptedRequest,
		RequestEncryptionKey:    src.RequestEncryptionKey,
		RequireHAIP:             src.RequireHAIP,
		ValidationMode:          src.ValidationMode,
		Credentials:             append([]StoredCredential(nil), src.Credentials...),
		StatusEntries:           cloneStatusEntries(src.StatusEntries),
		StatusListCounter:       src.StatusListCounter,
		BaseURL:                 src.BaseURL,
		IssuerURL:               src.IssuerURL,
		VCIClientID:             src.VCIClientID,
		VCIRedirectURI:          src.VCIRedirectURI,
		Log:                     append([]LogEntry(nil), src.Log...),
		logSink: func(entry LogEntry) {
			src.appendLogEntry(entry)
		},
		runtime: src.runtimeState(),
	}

	if opts.AutoAccept {
		clone.AutoAccept = true
	}
	if opts.SessionTranscript != "" {
		switch SessionTranscriptMode(opts.SessionTranscript) {
		case SessionTranscriptOID4VP, SessionTranscriptISO:
			clone.SessionTranscript = SessionTranscriptMode(opts.SessionTranscript)
		default:
			return nil, fmt.Errorf("invalid session transcript %q", opts.SessionTranscript)
		}
	}
	if opts.RequireHAIP {
		clone.RequireHAIP = true
	}
	if opts.ValidationMode != "" {
		mode, err := ParseValidationMode(opts.ValidationMode)
		if err != nil {
			return nil, err
		}
		clone.ValidationMode = mode
	}

	return clone, nil
}

func cloneStatusEntries(src map[string]StatusEntry) map[string]StatusEntry {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]StatusEntry, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

// handleOfferAPI processes a credential offer URI.
func (s *Server) handleOfferAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URI         string `json:"uri"`
		TxCode      string `json:"tx_code,omitempty"`
		Interactive bool   `json:"interactive,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	s.processOfferURI(w, body.URI, body.TxCode, false, !body.Interactive)
}

// processOfferURI runs the credential offer flow for an offer delivered as a
// URI. With browserRedirect set, a successful import redirects the browser to
// the wallet UI instead of returning JSON. apiInitiated marks programmatic
// submissions, which auto-accept even in interactive mode (the call is the
// caller's consent).
func (s *Server) processOfferURI(w http.ResponseWriter, uri, txCode string, browserRedirect, apiInitiated bool) {
	s.log("Received credential offer")
	uriDisplay := format.Truncate(uri, 120)
	s.log("  URI: %s", uriDisplay)
	offerDetails := map[string]any{"offer_uri": uri}
	addStringDetail(offerDetails, "tx_code", txCode)
	s.wallet.AddLogDetails("issuance", "Received credential offer", true, offerDetails)

	if txCode != "" {
		s.wallet.mu.Lock()
		s.wallet.TxCode = txCode
		s.wallet.mu.Unlock()
	}

	if !s.wallet.AutoAccept && !apiInitiated {
		consentReq, issuerDisplay, err := prepareIssuanceConsentRequest(uri)
		if err != nil {
			s.log("  ERROR: %v", err)
			s.wallet.AddLog("issuance", fmt.Sprintf("Failed: %v", err), false)
			s.wallet.NotifyError(WalletError{
				Message: "Credential offer parsing failed",
				Detail:  err.Error(),
			})
			s.triggerUIRequest()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		s.log("  Mode:          interactive — waiting for consent...")
		s.wallet.CreateConsentRequest(consentReq)
		s.triggerUIRequest()
		if s.onConsentRequest != nil {
			s.onConsentRequest(consentReq)
		}

		if browserRedirect {
			// A browser navigation must not hang while the consent is
			// pending: send the browser to the wallet UI (which shows the
			// request) and import the credential in the background once
			// consent arrives.
			go s.awaitOfferConsent(noopResponseWriter{}, consentReq, issuerDisplay, false)
			redirectBrowser(w, "")
			return
		}
		s.awaitOfferConsent(w, consentReq, issuerDisplay, false)
		return
	}

	s.processOfferDirectly(w, uri, browserRedirect)
}

// awaitOfferConsent waits for the user's decision on an issuance consent
// request and processes the credential offer on approval. The outcome is also
// delivered on the consent request's submission channel for the approve API.
func (s *Server) awaitOfferConsent(w http.ResponseWriter, consentReq *ConsentRequest, issuerDisplay string, browserRedirect bool) {
	select {
	case consent := <-consentReq.ResultCh:
		if !consent.Approved {
			s.log("  Consent:       denied")
			s.wallet.AddLog("issuance", fmt.Sprintf("Denied credential offer from %s", issuerDisplay), false)
			consentReq.SubmissionCh <- SubmissionResult{Error: "user denied issuance", StatusCode: http.StatusForbidden}
			writeJSON(w, http.StatusOK, map[string]any{
				"status":      "denied",
				"error":       "user denied issuance",
				"status_code": http.StatusForbidden,
			})
			return
		}

		s.log("  Consent:       approved")
		result, err := s.wallet.ProcessCredentialOffer(consentReq.OfferURI)
		if err != nil {
			s.log("  ERROR: %v", err)
			s.wallet.AddLog("issuance", fmt.Sprintf("Failed: %v", err), false)
			s.wallet.NotifyError(WalletError{
				Message: "Credential issuance failed",
				Detail:  err.Error(),
			})
			consentReq.SubmissionCh <- SubmissionResult{Error: err.Error(), StatusCode: http.StatusBadRequest}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		s.log("  Received:      %s credential from %s", result.Format, result.Issuer)
		if result.VerificationDetail != "" {
			s.log("  Verification:  %s [%s]", result.VerificationDetail, result.VerificationStatus)
		}
		s.wallet.AddLogDetails("issuance", fmt.Sprintf("Received %s credential from %s", result.Format, result.Issuer), true, map[string]any{
			"offer_uri":            consentReq.OfferURI,
			"credential_id":        result.CredentialID,
			"format":               result.Format,
			"issuer":               result.Issuer,
			"verification_status":  result.VerificationStatus,
			"verification_detail":  result.VerificationDetail,
			"credential_requested": consentReq.OfferConfigs,
		})
		s.triggerSave()
		consentReq.SubmissionCh <- SubmissionResult{StatusCode: http.StatusOK}
		if browserRedirect {
			redirectBrowser(w, "")
		} else {
			writeJSON(w, http.StatusOK, result)
		}
		return
	case <-time.After(5 * time.Minute):
		consentReq.Status = "denied"
		s.wallet.AddLog("issuance", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout", StatusCode: http.StatusRequestTimeout}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
		return
	}
}

// processOfferDirectly runs the credential offer flow without a consent step
// (auto-accept mode).
func (s *Server) processOfferDirectly(w http.ResponseWriter, uri string, browserRedirect bool) {
	result, err := s.wallet.ProcessCredentialOffer(uri)
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("issuance", fmt.Sprintf("Failed: %v", err), false)
		s.wallet.NotifyError(WalletError{
			Message: "Credential issuance failed",
			Detail:  err.Error(),
		})
		if !s.wallet.AutoAccept {
			s.triggerUIRequest()
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.log("  Received:      %s credential from %s", result.Format, result.Issuer)
	if result.VerificationDetail != "" {
		s.log("  Verification:  %s [%s]", result.VerificationDetail, result.VerificationStatus)
	}
	s.wallet.AddLogDetails("issuance", fmt.Sprintf("Received %s credential from %s", result.Format, result.Issuer), true, map[string]any{
		"offer_uri":           uri,
		"credential_id":       result.CredentialID,
		"format":              result.Format,
		"issuer":              result.Issuer,
		"verification_status": result.VerificationStatus,
		"verification_detail": result.VerificationDetail,
	})
	s.triggerSave()
	if browserRedirect {
		redirectBrowser(w, "")
	} else {
		writeJSON(w, http.StatusOK, result)
	}
}

func prepareIssuanceConsentRequest(raw string) (*ConsentRequest, string, error) {
	trimmed := strings.TrimSpace(raw)
	req := &ConsentRequest{
		ID:           newConsentID(),
		Type:         "issuance",
		OfferURI:     trimmed,
		Status:       "pending",
		ResultCh:     make(chan ConsentResult, 1),
		SubmissionCh: make(chan SubmissionResult, 1),
		CreatedAt:    time.Now(),
	}

	offerURI := extractCredentialOfferURI(trimmed)
	if offerURI != "" {
		req.ClientID = credentialOfferIssuerDisplay(offerURI)
		return req, req.ClientID, nil
	}

	reqType, parsed, err := oid4vc.Parse(trimmed)
	if err != nil {
		return nil, "", err
	}
	if reqType != oid4vc.TypeVCI {
		return nil, "", fmt.Errorf("expected VCI credential offer, got VP")
	}
	offer, ok := parsed.(*oid4vc.CredentialOffer)
	if !ok {
		return nil, "", fmt.Errorf("unexpected credential offer type")
	}
	req.ClientID = offer.CredentialIssuer
	req.OfferConfigs = append([]string(nil), offer.CredentialConfigurationIDs...)
	return req, offer.CredentialIssuer, nil
}

func extractCredentialOfferURI(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Query().Get("credential_offer_uri"))
}

func credentialOfferIssuerDisplay(offerURI string) string {
	u, err := url.Parse(strings.TrimSpace(offerURI))
	if err != nil {
		return "credential issuer"
	}
	if issuer := strings.TrimSpace(u.Scheme + "://" + u.Host); issuer != "://" && issuer != "" {
		return issuer
	}
	if host := strings.TrimSpace(u.Host); host != "" {
		return host
	}
	return "credential issuer"
}

// Mount registers an additional handler under the given path prefix (no
// trailing slash), e.g. the embedded credential decoder UI. The prefix is
// stripped before the request reaches the handler. Call before ListenAndServe.
func (s *Server) Mount(prefix string, h http.Handler) {
	s.mux.Handle(prefix+"/", http.StripPrefix(prefix, h))
	// The bare prefix would otherwise fall through to the UI file server.
	s.mux.Handle("GET "+prefix, http.RedirectHandler(prefix+"/", http.StatusMovedPermanently))
}

// Handle registers an extra route on the server mux, e.g. a well-known
// document a mounted handler needs at the server root. Call before
// ListenAndServe.
func (s *Server) Handle(pattern string, h http.Handler) {
	s.mux.Handle(pattern, h)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"build_id": processBuildID(),
		"version":  s.version,
	}
	if s.demo == nil {
		doc["pid"] = os.Getpid()
	}
	writeJSON(w, http.StatusOK, doc)
}

// SetVersion sets the human-readable release version reported by
// /api/version and /api/config. The version lives in the cmd package, so the
// serve command injects it.
func (s *Server) SetVersion(version string) {
	s.version = version
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	data, err := s.wallet.CredentialsJSON()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleImportCredential imports a credential from the request body.
func (s *Server) handleImportCredential(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}

	raw := strings.TrimSpace(string(body))
	if raw == "" {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	imported, err := s.wallet.ImportCredential(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.triggerSave()
	writeJSON(w, http.StatusCreated, CredentialSummary(*imported))
}

// handleDeleteCredential removes a credential by ID.
func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	label := id
	for _, cred := range s.wallet.GetCredentials() {
		if cred.ID == id {
			if cred.VCT != "" {
				label = cred.VCT
			} else if cred.DocType != "" {
				label = cred.DocType
			}
			break
		}
	}
	if !s.wallet.RemoveCredential(id) {
		http.Error(w, "credential not found", http.StatusNotFound)
		return
	}
	s.wallet.AddLog("management", fmt.Sprintf("Deleted credential %s", label), true)
	s.triggerSave()
	w.WriteHeader(http.StatusNoContent)
}

// handleListRequests returns all pending consent requests.
func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	requests := s.wallet.GetPendingRequests()
	items := make([]map[string]any, len(requests))
	for i, req := range requests {
		items[i] = MarshalConsentRequest(req)
	}
	writeJSON(w, http.StatusOK, items)
}

// handleRequestStream provides SSE for new consent requests and error events.
func (s *Server) handleRequestStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	reqCh, reqUnsub := s.wallet.Subscribe()
	defer reqUnsub()
	errCh, errUnsub := s.wallet.SubscribeErrors()
	defer errUnsub()

	for {
		select {
		case req := <-reqCh:
			data, err := json.Marshal(MarshalConsentRequest(req))
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: consent\ndata: %s\n\n", data)
			flusher.Flush()
		case walletErr := <-errCh:
			data, err := json.Marshal(walletErr)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// handleApproveRequest approves a consent request and waits for the submission result.
func (s *Server) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.wallet.ResolveRequest(id, "approved")
	if !ok {
		if req == nil {
			http.Error(w, "request not found", http.StatusNotFound)
		} else {
			http.Error(w, "request already resolved", http.StatusConflict)
		}
		return
	}

	var body struct {
		SelectedClaims map[string][]string `json:"selected_claims"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}

	req.ResultCh <- ConsentResult{
		Approved:       true,
		SelectedClaims: body.SelectedClaims,
	}

	// Wait for the VP submission to complete so we can return the result to the UI
	select {
	case submission := <-req.SubmissionCh:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "approved",
			"redirect_uri": submission.RedirectURI,
			"error":        submission.Error,
			"status_code":  submission.StatusCode,
		})
	case <-time.After(30 * time.Second):
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "approved",
			"error":  "submission timeout",
		})
	}
}

// handleDenyRequest denies a consent request.
func (s *Server) handleDenyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.wallet.ResolveRequest(id, "denied")
	if !ok {
		if req == nil {
			http.Error(w, "request not found", http.StatusNotFound)
		} else {
			http.Error(w, "request already resolved", http.StatusConflict)
		}
		return
	}

	req.ResultCh <- ConsentResult{Approved: false}

	writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
}

// handleLog returns the activity log.
// demoLogLimit caps the activity log served in demo mode: a busy shared
// wallet accumulates entries from every visitor between resets, and the UI
// only needs the recent tail. Local instances stay unbounded.
const demoLogLimit = 50

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	log := s.wallet.GetLog()
	if s.demo != nil && len(log) > demoLogLimit {
		log = log[len(log)-demoLogLimit:]
	}
	writeJSON(w, http.StatusOK, log)
}

// handleClearLog removes all activity log entries.
func (s *Server) handleClearLog(w http.ResponseWriter, r *http.Request) {
	s.wallet.ClearLog()
	s.triggerSave()
	w.WriteHeader(http.StatusNoContent)
}

// handleLastError returns the last error, if any.
func (s *Server) handleLastError(w http.ResponseWriter, r *http.Request) {
	err := s.wallet.PeekLastError()
	if err == nil {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	writeJSON(w, http.StatusOK, err)
}

// handleClearLastError clears the last UI error.
func (s *Server) handleClearLastError(w http.ResponseWriter, r *http.Request) {
	s.wallet.ClearLastError()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

// handleTrustList generates and serves an ETSI trust list JWT from the wallet's issuer key.
func (s *Server) handleTrustList(w http.ResponseWriter, r *http.Request) {
	if len(s.wallet.CertChain) < 2 {
		http.Error(w, "wallet has no CA certificate chain", http.StatusInternalServerError)
		return
	}
	group, ok := FindTrustListGroupForWallet(s.wallet, "", r.URL.Query().Get("vct"), r.URL.Query().Get("doctype"))
	if !ok {
		http.Error(w, "wallet has no matching trust list", http.StatusNotFound)
		return
	}
	jwt, err := GenerateTrustListJWTForWalletGroup(s.wallet, s.wallet.IssuerURL, group, "/api/trustlist")
	if err != nil {
		http.Error(w, fmt.Sprintf("generating trust list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

func (s *Server) handleTrustListIndex(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(strings.TrimSpace(s.wallet.IssuerURL), "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"trust_lists": BuildTrustListIndexEntries(s.wallet, issuer),
	})
}

func (s *Server) handleTrustListByID(w http.ResponseWriter, r *http.Request) {
	if len(s.wallet.CertChain) < 2 {
		http.Error(w, "wallet has no CA certificate chain", http.StatusInternalServerError)
		return
	}
	group, ok := FindTrustListGroupForWallet(s.wallet, r.PathValue("id"), "", "")
	if !ok {
		http.Error(w, "trust list not found", http.StatusNotFound)
		return
	}
	jwt, err := GenerateTrustListJWTForWalletGroup(s.wallet, s.wallet.IssuerURL, group, "/api/trustlists/"+group.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("generating trust list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

func (s *Server) handleJWTVCIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	jwk := buildIssuerSigningJWK(s.wallet, s.issuerKeyExpiry)
	if jwk == nil {
		http.Error(w, "wallet has no issuer signing key", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": issuer,
		"jwks": map[string]any{
			"keys": []any{jwk},
		},
	})
}

func (s *Server) handleOpenIDCredentialIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	if len(s.wallet.CertChain) == 0 {
		http.Error(w, "wallet has no issuer certificate chain", http.StatusInternalServerError)
		return
	}
	jwt, err := signCredentialIssuerMetadataJWT(s.wallet, issuer, s.issuerKeyExpiry)
	if err != nil {
		http.Error(w, fmt.Sprintf("signing issuer metadata: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/openidvci-issuer-metadata+jwt")
	w.Write([]byte(jwt))
}

func (s *Server) handleRegistrarWRPList(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	if s.wallet.CAKey == nil || len(s.wallet.CertChain) == 0 {
		http.Error(w, "wallet has no registrar signing material", http.StatusInternalServerError)
		return
	}
	record := buildRegistrarDataset(s.wallet, issuer)
	if !matchesRegistrarQuery(record, r) {
		recordJWT, err := signRegistrarResponseJWT(s.wallet.CAKey, []*x509.Certificate{s.wallet.CertChain[len(s.wallet.CertChain)-1]}, []RegistrarDataset{})
		if err != nil {
			http.Error(w, fmt.Sprintf("signing registrar response: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(recordJWT))
		return
	}
	recordJWT, err := signRegistrarResponseJWT(s.wallet.CAKey, []*x509.Certificate{s.wallet.CertChain[len(s.wallet.CertChain)-1]}, []RegistrarDataset{record})
	if err != nil {
		http.Error(w, fmt.Sprintf("signing registrar response: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(recordJWT))
}

func (s *Server) handleRegistrarWRPByIdentifier(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	if s.wallet.CAKey == nil || len(s.wallet.CertChain) == 0 {
		http.Error(w, "wallet has no registrar signing material", http.StatusInternalServerError)
		return
	}
	record := buildRegistrarDataset(s.wallet, issuer)
	identifier := strings.TrimSpace(r.PathValue("identifier"))
	if identifier == "" || !recordHasIdentifier(record, identifier) {
		http.Error(w, "wallet relying party not found", http.StatusNotFound)
		return
	}
	recordJWT, err := signRegistrarResponseJWT(s.wallet.CAKey, []*x509.Certificate{s.wallet.CertChain[len(s.wallet.CertChain)-1]}, record)
	if err != nil {
		http.Error(w, fmt.Sprintf("signing registrar response: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(recordJWT))
}

// handleStatusList generates and serves a status list JWT.
func (s *Server) handleStatusList(w http.ResponseWriter, r *http.Request) {
	bitstring := s.wallet.BuildStatusBitstring()
	statusListURI := s.wallet.StatusListURL()
	certChain := s.wallet.CertChain
	if derived, err := s.wallet.DefaultSigningCertChain(); err == nil && len(derived) > 0 {
		certChain = derived
	}
	jwt, err := statuslist.GenerateStatusListJWT(bitstring, s.wallet.IssuerKey, statuslist.StatusListConfig{
		URI:       statusListURI,
		Issuer:    s.wallet.StatusListIssuer(),
		CertChain: certChain,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("generating status list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/statuslist+jwt")
	w.Write([]byte(jwt))
}

// handleGetConfig returns the wallet instance's full introspection document.
// Remote controllers use it to learn everything about an instance: identity
// (pid, port, build), storage locations, URLs, and runtime behavior.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	walletDir := ""
	if store := s.currentStore(); store != nil {
		walletDir = store.Dir
	}
	templatesDir := s.wallet.TemplatesDir
	if templatesDir == "" && walletDir != "" {
		templatesDir = filepath.Join(walletDir, "templates")
	}
	config := map[string]any{
		"port":                      s.port,
		"build_id":                  processBuildID(),
		"version":                   s.version,
		"imprint":                   len(s.imprintHTML) > 0,
		"base_url":                  s.wallet.BaseURL,
		"issuer_url":                s.wallet.IssuerURL,
		"status_list_url":           s.wallet.StatusListURL(),
		"preferred_format":          s.wallet.PreferredFormat,
		"validation_mode":           string(s.wallet.ValidationMode),
		"auto_accept":               s.wallet.AutoAccept,
		"session_transcript":        string(s.wallet.SessionTranscript),
		"require_haip":              s.wallet.RequireHAIP,
		"require_encrypted_request": s.wallet.RequireEncryptedRequest,
		"credential_count":          len(s.wallet.GetCredentials()),
		// False when an external TLS terminator serves the issuer origin: the
		// built-in HTTPS listener is disabled then, and the wallet's
		// self-signed leaf certificate is never presented on the wire.
		"tls_listener": s.issuerPort > 0,
	}
	if demo := s.demoConfig(); demo != nil {
		config["demo"] = demo
	} else {
		// Host paths and the pid identify the process on its machine; they
		// are for local remote-control tooling, not anonymous demo visitors.
		config["pid"] = os.Getpid()
		config["wallet_dir"] = walletDir
		config["templates_dir"] = templatesDir
	}
	writeJSON(w, http.StatusOK, config)
}

// handleShutdown asks the wallet server process to exit. Like the rest of
// the management API it is unauthenticated (testing tool only). The response
// is sent before the process exits.
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	s.log("  Shutdown requested via API")
	writeJSON(w, http.StatusOK, map[string]any{"shutting_down": true, "pid": os.Getpid()})
	go func() {
		time.Sleep(200 * time.Millisecond)
		if s.ShutdownFunc != nil {
			s.ShutdownFunc()
			return
		}
		os.Exit(0)
	}()
}

// handleSetCredentialStatus sets the revocation status for a credential.
func (s *Server) handleSetCredentialStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	entry, ok := s.wallet.SetCredentialStatus(id, body.Status)
	if !ok {
		http.Error(w, "credential has no status entry", http.StatusNotFound)
		return
	}

	verb := fmt.Sprintf("Set status %d on", body.Status)
	switch body.Status {
	case 0:
		verb = "Activated"
	case 1:
		verb = "Revoked"
	}
	s.wallet.AddLog("management", fmt.Sprintf("%s credential %s", verb, id), true)
	s.triggerSave()
	writeJSON(w, http.StatusOK, entry)
}

// handleSetNextError sets a one-shot error override.
func (s *Server) handleSetNextError(w http.ResponseWriter, r *http.Request) {
	var body NextErrorOverride
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	s.wallet.SetNextError(&body)
	writeJSON(w, http.StatusOK, body)
}

// handleClearNextError clears the error override without consuming.
func (s *Server) handleClearNextError(w http.ResponseWriter, r *http.Request) {
	s.wallet.SetNextError(nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleSetPreferredFormat sets the global credential format preference.
func (s *Server) handleSetPreferredFormat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Format string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	s.wallet.mu.Lock()
	s.wallet.PreferredFormat = body.Format
	s.wallet.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"format": body.Format})
}

func mapKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func matchesRegistrarQuery(record RegistrarDataset, r *http.Request) bool {
	q := r.URL.Query()
	if identifier := strings.TrimSpace(q.Get("identifier")); identifier != "" && !recordHasIdentifier(record, identifier) {
		return false
	}
	if entitlement := strings.TrimSpace(q.Get("entitlement")); entitlement != "" {
		match := false
		for _, candidate := range record.Entitlements {
			if candidate == entitlement {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if provides := strings.TrimSpace(q.Get("providesattestation")); provides != "" && !recordProvidesAttestation(record, provides) {
		return false
	}
	return true
}

func recordHasIdentifier(record RegistrarDataset, value string) bool {
	for _, identifier := range record.Identifier {
		if strings.TrimSpace(identifier.Identifier) == value {
			return true
		}
	}
	return false
}

func recordProvidesAttestation(record RegistrarDataset, value string) bool {
	for _, att := range record.ProvidesAttestations {
		switch att.Format {
		case "dc+sd-jwt":
			raw, ok := att.Meta["vct_values"].([]string)
			if ok {
				for _, candidate := range raw {
					if candidate == value {
						return true
					}
				}
			}
			if rawAny, ok := att.Meta["vct_values"].([]any); ok {
				for _, candidate := range rawAny {
					if s, ok := candidate.(string); ok && s == value {
						return true
					}
				}
			}
		case "mso_mdoc":
			if candidate, _ := att.Meta["doctype_value"].(string); candidate == value {
				return true
			}
		}
	}
	return false
}

func (s *Server) triggerSave() {
	if s.onSave != nil {
		s.onSave()
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(data)
}
