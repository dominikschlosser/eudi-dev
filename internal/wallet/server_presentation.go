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

type presentationRequestOptions struct {
	AutoAccept        bool
	SessionTranscript string
	// RequireHAIP overrides the server's HAIP enforcement for one request.
	// Nil inherits the server setting. A value turns enforcement on or off,
	// so a caller can still be tested against a wallet that enforces HAIP
	// globally (and a HAIP module can raise the bar on one that does not).
	RequireHAIP    *bool
	ValidationMode string
	// RequireEncryptedRequest overrides the server's encrypted-request setting
	// for one request, the same way RequireHAIP does. Nil inherits the server.
	RequireEncryptedRequest *bool
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
	// A verifier link or QR reaches /authorize as a top-level navigation, which
	// carries no header or body. The visitor's conformance override rides along
	// in a cookie instead, so honor it here too, on a per-request clone, and
	// parse with the effective validation mode.
	reqServer := s
	if opts := conformanceOverrideFromRequest(r).applyTo(presentationRequestOptions{}); opts.hasConformanceOverride() {
		reqWallet, cloneErr := cloneWalletForPresentation(s.wallet, opts)
		if cloneErr != nil {
			http.Error(w, fmt.Sprintf("invalid conformance override: %v", cloneErr), http.StatusBadRequest)
			return
		}
		reqServer = s.cloneWithWallet(reqWallet)
	}

	authReq, err = parseAuthParams(values, reqServer.parseOpts, reqServer.wallet.ValidationMode)

	if err != nil {
		// A request that cannot be parsed names a response endpoint the wallet
		// has no reason to trust, so nothing is sent there (RFC 6749 §4.1.2.1,
		// which §8.5 adopts). The caller is told instead.
		http.Error(w, fmt.Sprintf("invalid authorization request: %v", err), http.StatusBadRequest)
		return
	}

	authReq.BrowserRedirect = isBrowserNavigation(r)
	reqServer.handleAuthFlow(w, authReq)
}

// handlePresentationAPI processes a presentation request URI via API.
func (s *Server) handlePresentationAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URI               string `json:"uri"`
		AutoAccept        bool   `json:"auto_accept,omitempty"`
		Interactive       bool   `json:"interactive,omitempty"`
		SessionTranscript string `json:"session_transcript,omitempty"`
		// Pointer so an explicit "haip": false can switch enforcement off on
		// a wallet that requires it. Omitting the field inherits the server.
		HAIP *bool  `json:"haip,omitempty"`
		Mode string `json:"mode,omitempty"`
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
	opts := conformanceOverrideFromRequest(r).applyTo(presentationRequestOptions{
		AutoAccept:        body.AutoAccept,
		SessionTranscript: body.SessionTranscript,
		RequireHAIP:       body.HAIP,
		ValidationMode:    body.Mode,
	})
	if opts.AutoAccept || opts.SessionTranscript != "" || opts.hasConformanceOverride() {
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

	findings, err := ValidateAuthorizationRequest(reqServer.wallet.ValidationMode, reqServer.wallet.RequireHAIP, authReq)
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
	if opts.RequireHAIP != nil {
		clone.RequireHAIP = *opts.RequireHAIP
	}
	if opts.RequireEncryptedRequest != nil {
		clone.RequireEncryptedRequest = *opts.RequireEncryptedRequest
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

// cloneWithWallet returns a Server that runs one request against reqWallet
// (a per-request clone) while sharing everything else with s. The whole flow
// runs on it, so a per-request conformance override reaches validation, the
// direct_post response and any issuer backend calls alike. deferredIssuanceOwner
// points at the real wallet so a deferral recorded during the flow is still
// collected after the clone is gone.
func (s *Server) cloneWithWallet(reqWallet *Wallet) *Server {
	clone := &Server{
		wallet:                reqWallet,
		deferredIssuanceOwner: s.wallet,
		port:                  s.port,
		mux:                   s.mux,
		onSave:                s.onSave,
		onConsentRequest:      s.onConsentRequest,
		onUIRequest:           s.onUIRequest,
		logFunc:               s.logFunc,
		httpSrv:               s.httpSrv,
		issuerSrv:             s.issuerSrv,
		issuerTLSCert:         s.issuerTLSCert,
		issuerPort:            s.issuerPort,
		store:                 s.store,
		demo:                  s.demo,
		version:               s.version,
		imprintHTML:           s.imprintHTML,
	}
	clone.parseOpts = oid4vc.ParseOptions{
		FetchRequestURI: MakeFetchRequestURI(reqWallet, func(format string, args ...any) {
			clone.log(format, args...)
		}),
	}
	return clone
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
