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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

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
	parseOpts        oid4vc.ParseOptions
	store            *WalletStore
	storeSyncMu      sync.Mutex
	demo             *demoState
	// deferredIssuanceOwner is the wallet whose deferred credentials the
	// poller collects. Set on the per-request clone a profile override
	// creates, so a deferral recorded there is handed back rather than
	// thrown away with the clone.
	deferredIssuanceOwner *Wallet
	// renewalBackoff holds off retrying a credential whose renewal failed.
	renewalBackoff map[string]time.Time
	renewalMu      sync.Mutex
	// deferredInFlight guards a single deferred issuance from being collected
	// twice at once (the background poller racing an explicit collect, or two
	// collects), which would send two requests and import the credential twice.
	deferredInFlight map[string]bool
	deferredMu       sync.Mutex
	// pendingOffers holds offers paused for an interactive sign-in, so the
	// caller that started one can read how it ended.
	pendingOffers map[string]*pendingOffer
	offerMu       sync.Mutex
	// tlsMu guards issuerTLSCert, which a renewal replaces under a live
	// listener.
	tlsMu       sync.RWMutex
	version     string
	imprintHTML []byte
	// ShutdownFunc runs after POST /api/shutdown responded. The serve command
	// sets it to deregister the instance and exit. When nil the process exits
	// directly.
	ShutdownFunc func()
	// Startup conformance defaults, captured so DELETE /api/config/conformance
	// can restore them after a local wallet's UI changed the runtime settings.
	// Unused in demo mode, where that endpoint is refused.
	defaultValidationMode          ValidationMode
	defaultRequireHAIP             bool
	defaultRequireEncryptedRequest bool
	defaultVCIVersion              VCIVersion
}

// NewServer creates a new wallet HTTP server.
// onSave is called after credential-changing operations (import, delete, issuance).
func NewServer(w *Wallet, port int, onSave func()) *Server {
	processBuildID()
	s := &Server{
		wallet:                         w,
		port:                           port,
		onSave:                         onSave,
		defaultValidationMode:          w.ValidationMode,
		defaultRequireHAIP:             w.RequireHAIP,
		defaultRequireEncryptedRequest: w.RequireEncryptedRequest,
		defaultVCIVersion:              w.VCIFeatureVersion(),
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
	s.mux.HandleFunc("GET /api/offers/{id}", s.handleOfferStatus)
	s.mux.HandleFunc("POST /api/credentials/{id}/refresh", s.withFreshStore(s.handleRefreshCredential))
	s.mux.HandleFunc("GET /callback", s.withFreshStore(s.handleAuthorizationCodeCallback))

	// API: build identity, used by the URL handler script to detect stale servers
	s.mux.HandleFunc("GET /api/version", s.handleVersion)

	// API: credential management
	s.mux.HandleFunc("GET /api/credentials", s.withFreshStore(s.handleListCredentials))
	s.mux.HandleFunc("GET /api/deferred", s.withFreshStore(s.handleListDeferred))
	s.mux.HandleFunc("POST /api/deferred/{id}/collect", s.withFreshStore(s.handleCollectDeferred))
	s.mux.HandleFunc("DELETE /api/deferred/{id}", s.withFreshStore(s.handleAbandonDeferred))
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
	s.mux.HandleFunc("PUT /api/config/auto-accept", s.withFreshStore(s.handleSetAutoAccept))
	s.mux.HandleFunc("PUT /api/config/conformance", s.withFreshStore(s.handleSetConformance))
	s.mux.HandleFunc("DELETE /api/config/conformance", s.withFreshStore(s.handleResetConformance))
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

// ListenAndServe starts the wallet server.
func (s *Server) ListenAndServe() error {
	s.httpSrv = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      s.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: config.SlowRequestTimeout,
		IdleTimeout:  120 * time.Second,
	}
	if err := s.startIssuerTLSServer(); err != nil {
		return err
	}
	s.startDemoReset()
	defer s.StartBackgroundTasks()()
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
		WriteTimeout: config.SlowRequestTimeout,
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
	s.wallet.DeferredIssuances = append([]DeferredIssuance(nil), reloaded.DeferredIssuances...)
	s.wallet.StatusEntries = cloneStatusEntries(reloaded.StatusEntries)
	s.wallet.StatusListCounter = reloaded.StatusListCounter
	s.wallet.Log = append([]LogEntry(nil), reloaded.Log...)
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

func (s *Server) triggerSave() {
	if s.onSave != nil {
		s.onSave()
	}
	// Every save is a state change other open UIs should see immediately.
	s.wallet.NotifyStateChanged()
}

// saveIssuedCredential persists a credential an issuance flow just imported.
// A long-running flow (an authorization code sign-in) is interleaved with
// requests that reload the wallet from disk, and a reload landing between the
// import and the save would drop the credential silently. So it is put back if
// it went missing, under the same lock the reload takes.
func (s *Server) saveIssuedCredential(result *IssuanceResult) {
	if result != nil && result.Imported != nil {
		s.storeSyncMu.Lock()
		if _, ok := s.wallet.GetCredential(result.Imported.ID); !ok {
			s.wallet.RestoreCredential(*result.Imported)
		}
		// The same reload also wipes the status entry the import adopted for a
		// credential on this wallet's own status list, leaving it labelled as
		// externally governed with nothing able to flip its bit. Adoption is
		// idempotent, so it is simply done again here.
		s.wallet.adoptOwnStatusEntry(result.Imported)
		if s.onSave != nil {
			s.onSave()
		}
		s.storeSyncMu.Unlock()
		s.wallet.NotifyStateChanged()
		return
	}
	s.triggerSave()
}

// saveRenewedCredential persists a renewal. The flow holds no lock while it
// talks to the issuer, so a concurrent store reload can put the stale copy
// back before the save, losing the rotated refresh token with it. The
// renewed copy is written back under the same lock the reload takes, like
// saveIssuedCredential.
func (s *Server) saveRenewedCredential(renewed *StoredCredential) {
	if renewed == nil {
		s.triggerSave()
		return
	}
	s.storeSyncMu.Lock()
	s.wallet.PutCredential(*renewed)
	// Re-register the status entry from the renewed credential's own claim
	// (a reload may have wiped or reverted it). A renewal is fresh, so
	// status 0.
	if ref := CredentialStatusRef(*renewed); ref != nil && ref.URI == strings.TrimSpace(s.wallet.StatusListURL()) {
		s.wallet.RegisterStatusEntry(renewed.ID, ref.Idx)
	}
	if s.onSave != nil {
		s.onSave()
	}
	s.storeSyncMu.Unlock()
	s.wallet.NotifyStateChanged()
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(data)
}
