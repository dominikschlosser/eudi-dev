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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// pendingOfferTTL is how long a paused offer stays readable at
// /api/offers/{id}. It outlives the wallet's own five minute wait for the
// authorization callback, so the caller can always read the outcome.
const pendingOfferTTL = 10 * time.Minute

// pendingOffer is an offer whose flow stopped for an interactive sign-in at
// the issuer. The flow keeps running in the background, so this is how the
// caller that started it learns how it ended.
type pendingOffer struct {
	ID        string
	AuthURL   string
	CreatedAt time.Time

	mu     sync.Mutex
	done   bool
	result *IssuanceResult
	err    error
}

func (p *pendingOffer) complete(result *IssuanceResult, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done, p.result, p.err = true, result, err
}

// authorizationRequiredBody is what a caller gets while the user still has to
// sign in, both when the offer is submitted and when its status is polled.
func (p *pendingOffer) authorizationRequiredBody() map[string]any {
	return map[string]any{
		"status":            "authorization_required",
		"authorization_url": p.AuthURL,
		"offer_id":          p.ID,
	}
}

func (p *pendingOffer) outcome() (*IssuanceResult, error, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.result, p.err, p.done
}

// trackPendingOffer makes a paused offer readable at /api/offers/{id} and
// drops entries nobody came back for.
func (s *Server) trackPendingOffer(p *pendingOffer) {
	s.offerMu.Lock()
	defer s.offerMu.Unlock()
	if s.pendingOffers == nil {
		s.pendingOffers = make(map[string]*pendingOffer)
	}
	cutoff := time.Now().Add(-pendingOfferTTL)
	for id, old := range s.pendingOffers {
		if old.CreatedAt.Before(cutoff) {
			delete(s.pendingOffers, id)
		}
	}
	s.pendingOffers[p.ID] = p
}

func (s *Server) lookupPendingOffer(id string) *pendingOffer {
	s.offerMu.Lock()
	defer s.offerMu.Unlock()
	return s.pendingOffers[id]
}

// runOffer processes a credential offer and applies the outcome to the wallet:
// activity log, stored credential, saved store. It returns either that outcome
// or, when the issuer wants the user to sign in first, the pending offer
// carrying the authorization URL.
//
// The flow is not cancelled in that case, it keeps running in the background.
// The user signs in wherever they are, the issuer redirects to /callback, and
// the flow resumes there and finishes the issuance. Nothing here opens a
// browser: the browser that matters belongs to the user, and on a hosted
// wallet it is not on this machine.
func (s *Server) runOffer(uri string, logDetails map[string]any) (*IssuanceResult, *pendingOffer, error) {
	// Subscribing on the caller's behalf is what makes the wallet hand over
	// the URL instead of failing for want of anyone to show it to.
	authCh, unsubscribe := s.wallet.SubscribeAuthorization()
	p := &pendingOffer{ID: newConsentID(), CreatedAt: time.Now()}
	done := make(chan struct{})

	go func() {
		defer unsubscribe()
		result, err := s.wallet.ProcessCredentialOffer(uri)
		s.applyOfferOutcome(uri, result, err, logDetails)
		p.complete(result, err)
		close(done)
	}()

	select {
	case authURL := <-authCh:
		p.AuthURL = authURL
		s.trackPendingOffer(p)
		s.log("  Sign-in:       %s", authURL)
		s.wallet.AddLogDetails("issuance", "Waiting for the user to sign in at the issuer", true, map[string]any{
			"offer_uri":         uri,
			"authorization_url": authURL,
		})
		return nil, p, nil
	case <-done:
		result, err, _ := p.outcome()
		return result, nil, err
	}
}

// applyOfferOutcome records how an offer ended. It runs on the flow's own
// goroutine, so it is the only place that has to run whether the caller is
// still waiting or gave up after an interactive sign-in.
func (s *Server) applyOfferOutcome(uri string, result *IssuanceResult, err error, logDetails map[string]any) {
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("issuance", fmt.Sprintf("Failed: %v", err), false)
		s.wallet.NotifyError(WalletError{
			Message: "Credential issuance failed",
			Detail:  err.Error(),
		})
		return
	}

	if result.Pending {
		s.log("  Deferred:      %s will be collected every %s", result.Issuer, result.RetryInterval)
		// Hand the record to the wallet the poller reads before saving, so a
		// deferral made on a per-request clone is still collected.
		s.pendingIssuanceOwner.AdoptPendingIssuances(s.wallet)
		s.persistWallet()
		return
	}

	s.log("  Received:      %s credential from %s", result.Format, result.Issuer)
	if result.VerificationDetail != "" {
		s.log("  Verification:  %s [%s]", result.VerificationDetail, result.VerificationStatus)
	}
	details := map[string]any{
		"offer_uri":           uri,
		"credential_id":       result.CredentialID,
		"format":              result.Format,
		"issuer":              result.Issuer,
		"verification_status": result.VerificationStatus,
		"verification_detail": result.VerificationDetail,
	}
	for k, v := range logDetails {
		details[k] = v
	}
	s.wallet.AddLogDetails("issuance", fmt.Sprintf("Received %s credential from %s", result.Format, result.Issuer), true, details)
	s.saveIssuedCredential(result)
}

// writeAuthorizationRequired answers a caller whose offer needs a sign-in. A
// browser that navigated here is sent straight to the issuer. Anything else
// gets the URL and the id to follow the flow at.
func (s *Server) writeAuthorizationRequired(w http.ResponseWriter, p *pendingOffer, browserRedirect bool) {
	if browserRedirect {
		redirectBrowser(w, p.AuthURL)
		return
	}
	writeJSON(w, http.StatusAccepted, p.authorizationRequiredBody())
}

// handleOfferStatus reports how an offer that paused for a sign-in ended.
func (s *Server) handleOfferStatus(w http.ResponseWriter, r *http.Request) {
	p := s.lookupPendingOffer(r.PathValue("id"))
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown offer"})
		return
	}
	result, err, done := p.outcome()
	switch {
	case !done:
		writeJSON(w, http.StatusOK, p.authorizationRequiredBody())
	case err != nil:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "failed",
			"error":    err.Error(),
			"offer_id": p.ID,
		})
	case result.Pending:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "deferred",
			"result":   result,
			"offer_id": p.ID,
		})
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "completed",
			"result":   result,
			"offer_id": p.ID,
		})
	}
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
	// The browser came back from the issuer's login. The flow it belongs to
	// is still running server-side and finishes on its own, so send the
	// visitor back to the wallet rather than leaving them on a dead end. The
	// credential shows up there as soon as it lands.
	http.Redirect(w, r, "/?focus=overview", http.StatusSeeOther)
}

// handleOfferAPI processes a credential offer URI.
func (s *Server) handleOfferAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URI         string `json:"uri"`
		TxCode      string `json:"tx_code,omitempty"`
		Interactive bool   `json:"interactive,omitempty"`
		// Same per-request overrides presentations accept: an explicit value
		// turns HAIP enforcement on or off for this offer, an absent one
		// inherits the server setting. Without them an issuer could not be
		// exercised against a wallet configured the other way.
		HAIP *bool  `json:"haip,omitempty"`
		Mode string `json:"mode,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	reqServer := s
	if body.HAIP != nil || body.Mode != "" {
		reqWallet, err := cloneWalletForPresentation(s.wallet, presentationRequestOptions{
			RequireHAIP:    body.HAIP,
			ValidationMode: body.Mode,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// Field by field rather than a struct copy: Server carries a mutex.
		clone := &Server{
			wallet:               reqWallet,
			pendingIssuanceOwner: s.wallet,
			port:                 s.port,
			mux:                  s.mux,
			onSave:               s.onSave,
			onConsentRequest:     s.onConsentRequest,
			onUIRequest:          s.onUIRequest,
			logFunc:              s.logFunc,
			httpSrv:              s.httpSrv,
			issuerSrv:            s.issuerSrv,
			issuerTLSCert:        s.issuerTLSCert,
			issuerPort:           s.issuerPort,
			store:                s.store,
			demo:                 s.demo,
			version:              s.version,
			imprintHTML:          s.imprintHTML,
		}
		clone.parseOpts = oid4vc.ParseOptions{
			FetchRequestURI: MakeFetchRequestURI(reqWallet, func(format string, args ...any) {
				clone.log(format, args...)
			}),
		}
		reqServer = clone
	}

	reqServer.processOfferURI(w, body.URI, body.TxCode, false, !body.Interactive)
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
			redirectBrowser(w, "/?request="+consentReq.ID)
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
		// The offer is what declares a transaction code, so the user only
		// learns one is needed from the dialog. A code typed there arrives
		// with the approval and replaces whatever the request carried.
		if consent.TxCode != "" {
			s.wallet.mu.Lock()
			s.wallet.TxCode = consent.TxCode
			s.wallet.mu.Unlock()
		}
		result, pending, err := s.runOffer(consentReq.OfferURI, map[string]any{
			"credential_requested": consentReq.OfferConfigs,
		})
		if err != nil {
			consentReq.SubmissionCh <- SubmissionResult{Error: err.Error(), StatusCode: http.StatusBadRequest}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if pending != nil {
			// The UI approved the offer and is already navigating to the
			// issuer, having taken the same URL off the event stream.
			consentReq.SubmissionCh <- SubmissionResult{StatusCode: http.StatusAccepted}
			s.writeAuthorizationRequired(w, pending, browserRedirect)
			return
		}

		if result.Pending {
			consentReq.SubmissionCh <- SubmissionResult{Pending: true, TransactionID: result.TransactionID, RetryInterval: result.RetryInterval}
			writeJSON(w, http.StatusAccepted, result)
			return
		}

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
	result, pending, err := s.runOffer(uri, nil)
	if err != nil {
		if !s.wallet.AutoAccept {
			s.triggerUIRequest()
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if pending != nil {
		s.writeAuthorizationRequired(w, pending, browserRedirect)
		return
	}

	if result.Pending {
		if browserRedirect {
			redirectBrowser(w, "")
		} else {
			writeJSON(w, http.StatusAccepted, result)
		}
		return
	}

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

	// The offer is resolved now, by reference as well as by value, so the
	// dialog can say what is being offered. It is fetched again after
	// approval, which the specification allows and real wallets do.
	reqType, parsed, err := oid4vc.Parse(trimmed)
	if err != nil {
		// An offer that cannot be resolved is still worth asking about: name
		// the host rather than failing before the user sees anything.
		if offerURI := extractCredentialOfferURI(trimmed); offerURI != "" {
			req.ClientID = credentialOfferIssuerDisplay(offerURI)
			req.OfferDetails = &IssuanceOfferDetails{
				Issuer:       req.ClientID,
				OfferURI:     offerURI,
				ResolveError: err.Error(),
			}
			return req, req.ClientID, nil
		}
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
	req.OfferDetails = describeCredentialOffer(offer)
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
