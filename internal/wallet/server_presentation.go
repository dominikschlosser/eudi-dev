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

// The OID4VP endpoints: the authorization endpoint a verifier sends a
// request to, and the API a caller submits one through.

package wallet

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// presentationRequestOptions carries the per-request knobs a presentation flow
// still needs. Conformance (validation mode, HAIP, encrypted requests) is not
// among them: it is process-level wallet state, changed only through the local
// UI, so every request sees the same settings.
type presentationRequestOptions struct {
	AutoAccept        bool
	SessionTranscript string
}

// handleAuthorize processes an OID4VP authorization request from query params or form data.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var authReq *AuthorizationRequestParams
	var err error
	var values map[string][]string

	if r.Method == "GET" {
		values = r.URL.Query()
	} else {
		if parseErr := r.ParseForm(); parseErr != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}
		values = r.Form
	}
	authReq, err = parseAuthParams(values, s.parseOpts, s.wallet.Mode())

	if err != nil {
		// A request that cannot be parsed names a response endpoint the wallet
		// has no reason to trust, so nothing is sent there (RFC 6749 §4.1.2.1,
		// which §8.5 adopts). The caller is told instead.
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
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// A new request makes any earlier failure stale, the same as for an offer.
	s.wallet.ClearLastError()

	s.log("Received authorization request")
	// Truncate URI for display
	uriDisplay := format.Truncate(body.URI, 120)
	s.log("  URI: %s", uriDisplay)

	reqServer := s
	opts := presentationRequestOptions{
		AutoAccept:        body.AutoAccept,
		SessionTranscript: body.SessionTranscript,
	}
	if opts.AutoAccept || opts.SessionTranscript != "" {
		reqWallet, err := cloneWalletForPresentation(s.wallet, opts)
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
			logFunc:       s.logFunc,
			httpSrv:       s.httpSrv,
			issuerSrv:     s.issuerSrv,
			issuerTLSCert: s.issuerTLSCert,
			issuerPort:    s.issuerPort,
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

	authReq := &AuthorizationRequestParams{
		ClientID:         parsed.ClientID,
		ResponseType:     parsed.ResponseType,
		ResponseMode:     parsed.ResponseMode,
		Nonce:            parsed.Nonce,
		State:            parsed.State,
		RedirectURI:      parsed.RedirectURI,
		ResponseURI:      parsed.ResponseURI,
		Scope:            parsed.Scope,
		RequestURIMethod: parsed.RequestURIMethod,
		RequestURI:       parsed.RequestURI,
		ClientMetadata:   parsed.ClientMetadata,
		DCQLQuery:        parsed.DCQLQuery,
		RequestObject:    parsed.RequestObject,
		RequestPayload:   requestPayload(parsed.RequestObject, parsed.FullJSON),
		Source:           "api",
	}

	// Validate here only to answer the API caller with a 400 on a hard failure.
	// The profile-violation warnings are not logged here: handleAuthFlow runs
	// the same validation and logs them, so doing it here too would double every
	// warning for one request.
	vpMode, vpHAIP, _ := reqServer.wallet.ConformanceSettings()
	if _, err := ValidateAuthorizationRequest(vpMode, vpHAIP, authReq); err != nil {
		reqServer.log("  ERROR: %v", err)
		reqServer.wallet.AddLog("presentation", err.Error(), false)
		reqServer.wallet.NotifyError(WalletError{
			Message: "Authorization request validation failed",
			Detail:  err.Error(),
		})
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
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

	// Snapshot the runtime-mutable conformance fields under the lock: a local
	// PUT /api/config/conformance can change them while this copy runs.
	srcMode, srcHAIP, srcEncrypted := src.ConformanceSettings()

	clone := &Wallet{
		HolderKey:               src.HolderKey,
		IssuerKey:               src.IssuerKey,
		CAKey:                   src.CAKey,
		CertChain:               append([]*x509.Certificate(nil), src.CertChain...),
		IssuedAttestations:      append([]IssuedAttestationSpec(nil), src.IssuedAttestations...),
		AutoAccept:              src.AutoAccept,
		SessionTranscript:       src.SessionTranscript,
		PreferredFormat:         src.PreferredFormat,
		RequireEncryptedRequest: srcEncrypted,
		RequestEncryptionKey:    src.RequestEncryptionKey,
		RequireHAIP:             srcHAIP,
		ValidationMode:          srcMode,
		VCIVersion:              src.VCIFeatureVersion(),
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
		// An issuance run on the clone must still land in the real wallet.
		credentialSink: func(cred StoredCredential) {
			src.mu.Lock()
			src.Credentials = append(src.Credentials, cred)
			src.mu.Unlock()
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

func mapKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
