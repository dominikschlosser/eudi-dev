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
	"errors"
	"fmt"
	"strings"
	"time"
)

// deferredPollerTick is how often the poller looks for work, not how often it
// asks an issuer. Each pending issuance carries its own interval.
const deferredPollerTick = time.Second

// StartDeferredPoller collects deferred credentials in the background, each on
// the interval its issuer asked for. Pending issuances are persisted, so a
// restarted wallet picks up where it left off. The returned function stops it.
func (s *Server) StartDeferredPoller() func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(deferredPollerTick)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				s.collectDueDeferredCredentials(time.Now())
			}
		}
	}()
	return func() { close(done) }
}

// collectDueDeferredCredentials makes one attempt for every pending issuance
// whose next attempt is due.
func (s *Server) collectDueDeferredCredentials(now time.Time) {
	for _, pending := range s.wallet.PendingIssuanceList() {
		if pending.NextAttemptAt.After(now) {
			continue
		}
		if pending.Expired(now) {
			s.abandonDeferred(pending, fmt.Sprintf("the issuer did not produce it within %s", pendingIssuanceMaxAge))
			continue
		}
		s.attemptDeferredCollection(pending)
	}
}

// DeferredAttempt is the outcome of one deferred credential request, so a
// caller that asked for it can be told what happened.
type DeferredAttempt struct {
	// Collected is set when the credential arrived and was imported.
	Collected  bool              `json:"collected"`
	Credential *StoredCredential `json:"credential,omitempty"`
	// Pending is set when the issuer is still working on it.
	Pending       bool      `json:"pending,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
	Interval      string    `json:"interval,omitempty"`
	// Abandoned is set when the record was dropped for good.
	Abandoned bool   `json:"abandoned,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// attemptDeferredCollection makes one deferred credential request. The
// credential is imported when it arrives, the attempt is rescheduled while the
// issuer still wants more time, and the record is dropped when the issuer says
// something that will not improve by asking again.
func (s *Server) attemptDeferredCollection(pending PendingIssuance) DeferredAttempt {
	proofKeys, err := pending.ProofKeys()
	if err != nil {
		return s.abandonDeferred(pending, fmt.Sprintf("its proof keys could not be read back: %v", err))
	}
	var dpopKey *ecdsa.PrivateKey
	if pending.UseDPoP {
		dpopKey = s.wallet.HolderKey
	}

	// One request per turn: the schedule lives here, so the request must not
	// wait on its own or two things would be pacing the same issuer.
	nonce := ""
	credResp, err := deferredCredentialAttempt(
		pending.DeferredEndpoint, pending.AccessToken, pending.AuthScheme,
		pending.TransactionID, dpopKey, s.wallet.HolderKey, &nonce)

	if err != nil {
		return s.handleDeferredAttemptError(pending, err)
	}

	credential, err := selectHolderBoundCredential(credResp, proofKeys)
	if err != nil {
		return s.abandonDeferred(pending, fmt.Sprintf("the issuer answered without a usable credential: %v", err))
	}
	imported, err := s.wallet.ImportCredential(credential)
	if err != nil {
		return s.abandonDeferred(pending, fmt.Sprintf("the credential could not be imported: %v", err))
	}

	s.wallet.RemovePendingIssuance(pending.ID)
	details := credentialImportLogDetails(imported, credential)
	details["issuer"] = pending.Issuer
	details["transaction_id"] = pending.TransactionID
	details["deferred"] = true
	s.wallet.addProtocolLog("issuance", "credential_imported",
		fmt.Sprintf("Collected deferred credential %s from %s", imported.ID, pending.Issuer), true, details)
	s.log("  Collected:     deferred %s credential from %s", imported.Format, pending.Issuer)

	s.saveIssuedCredential(&IssuanceResult{Imported: imported})
	s.wallet.NotifyStateChanged()
	return DeferredAttempt{Collected: true, Credential: imported}
}

// handleDeferredAttemptError decides what a failed attempt means. Being told
// to wait longer reschedules. Anything else ends it, because a rejected token
// or an unknown transaction will not recover on a timer.
func (s *Server) handleDeferredAttemptError(pending PendingIssuance, err error) DeferredAttempt {
	var stillPending stillPendingError
	if errors.As(err, &stillPending) {
		return s.rescheduleDeferred(pending, stillPending.interval, "")
	}
	if isRetryableDeferredError(err) {
		return s.rescheduleDeferred(pending, pending.Interval(), err.Error())
	}
	return s.abandonDeferred(pending, err.Error())
}

// isRetryableDeferredError reports whether an error is worth another attempt.
// A network hiccup or a server-side fault is; a refused token or an unknown
// transaction is not.
func isRetryableDeferredError(err error) bool {
	message := err.Error()
	for _, fatal := range []string{
		"invalid_token", "invalid_grant", "invalid_transaction_id",
		"invalid_request", "invalid_client", "expired",
	} {
		if strings.Contains(message, fatal) {
			return false
		}
	}
	return true
}

func (s *Server) rescheduleDeferred(pending PendingIssuance, interval time.Duration, lastErr string) DeferredAttempt {
	next := time.Now().Add(interval)
	s.wallet.UpdatePendingIssuance(pending.ID, func(p *PendingIssuance) {
		p.Attempts++
		p.NextAttemptAt = next
		p.LastError = lastErr
		if seconds := int(interval / time.Second); seconds >= 1 {
			p.IntervalSeconds = seconds
		}
	})
	s.persistWallet()
	return DeferredAttempt{
		Pending:       true,
		NextAttemptAt: next,
		Interval:      interval.String(),
		Reason:        lastErr,
	}
}

func (s *Server) abandonDeferred(pending PendingIssuance, reason string) DeferredAttempt {
	s.wallet.RemovePendingIssuance(pending.ID)
	s.wallet.addProtocolLog("issuance", "issuance_deferred_abandoned",
		fmt.Sprintf("Gave up on the deferred credential from %s: %s", pending.Issuer, reason), false, map[string]any{
			"issuer":         pending.Issuer,
			"transaction_id": pending.TransactionID,
			"attempts":       pending.Attempts,
			"reason":         reason,
		})
	s.log("  Deferred:      gave up on %s from %s (%s)", pending.TransactionID, pending.Issuer, reason)
	s.wallet.NotifyError(WalletError{
		Message: "Deferred credential was not issued",
		Detail:  fmt.Sprintf("%s: %s", pending.Issuer, reason),
	})
	s.persistWallet()
	s.wallet.NotifyStateChanged()
	return DeferredAttempt{Abandoned: true, Reason: reason}
}

// CollectDeferredNow asks the issuer for a deferred credential right away,
// ahead of its next scheduled attempt.
func (s *Server) CollectDeferredNow(id string) (DeferredAttempt, bool) {
	for _, pending := range s.wallet.PendingIssuanceList() {
		if pending.ID == id {
			return s.attemptDeferredCollection(pending), true
		}
	}
	return DeferredAttempt{}, false
}

// AbandonDeferredNow drops a deferred issuance on request. The transaction
// stays valid at the issuer, the wallet just stops asking for it.
func (s *Server) AbandonDeferredNow(id string) (PendingIssuance, bool) {
	for _, pending := range s.wallet.PendingIssuanceList() {
		if pending.ID != id {
			continue
		}
		s.wallet.RemovePendingIssuance(pending.ID)
		s.wallet.addProtocolLog("issuance", "issuance_deferred_abandoned",
			fmt.Sprintf("Stopped collecting the deferred credential from %s", pending.Issuer), true, map[string]any{
				"issuer":         pending.Issuer,
				"transaction_id": pending.TransactionID,
				"attempts":       pending.Attempts,
				"reason":         "abandoned on request",
			})
		s.log("  Deferred:      stopped collecting %s from %s", pending.TransactionID, pending.Issuer)
		s.persistWallet()
		s.wallet.NotifyStateChanged()
		return pending, true
	}
	return PendingIssuance{}, false
}

// persistWallet saves the wallet, so a pending issuance and its schedule
// survive a restart.
func (s *Server) persistWallet() {
	if s.onSave != nil {
		s.onSave()
	}
}
