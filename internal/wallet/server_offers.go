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
	"fmt"
	"net/http"
	"sync"
	"time"
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
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":            "authorization_required",
		"authorization_url": p.AuthURL,
		"offer_id":          p.ID,
	})
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
		writeJSON(w, http.StatusOK, map[string]any{
			"status":            "authorization_required",
			"authorization_url": p.AuthURL,
			"offer_id":          p.ID,
		})
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
