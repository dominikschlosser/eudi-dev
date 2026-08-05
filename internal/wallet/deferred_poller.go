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
	"net/url"
	"strings"
	"time"
)

// backgroundTask is one job the wallet does on its own, without a caller
// waiting for it: collecting a deferred credential, renewing a certificate.
type backgroundTask struct {
	// name appears in the log when the task fails, so a wallet that stops
	// doing something says which something.
	name string
	// every is how often the task is worth considering. The task itself
	// decides whether there is anything to do.
	every time.Duration
	// run reports whether the task got its work done. A task that fails is
	// tried again on the next tick rather than waiting out its interval,
	// because the usual cause is something transient.
	run func(now time.Time) error
}

// backgroundTick is how often the loop wakes. It is the resolution of every
// task's schedule, not a rate: a task due hourly is considered once an hour.
const backgroundTick = time.Second

func (s *Server) backgroundTasks() []backgroundTask {
	return []backgroundTask{
		{name: "deferred credentials", every: backgroundTick, run: s.collectDueDeferredCredentials},
		{name: "credential renewal", every: renewalCheckInterval, run: s.renewExpiringCredentials},
		{name: "signing certificate", every: certificateCheckInterval, run: s.renewSigningCertificate},
	}
}

// StartBackgroundTasks runs the wallet's own work on one loop and returns a
// function that stops it.
//
// One loop rather than a goroutine per job: they all reduce to "is anything
// due", they all touch the same wallet, and a single place to look is what
// makes it possible to say what the wallet does when nobody is asking. Each
// task carries its own interval instead of throttling itself inside its body,
// which is how the certificate check used to hide its schedule.
func (s *Server) StartBackgroundTasks() func() {
	done := make(chan struct{})
	tasks := s.backgroundTasks()
	state := make([]taskState, len(tasks))

	go func() {
		ticker := time.NewTicker(backgroundTick)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				for i := range tasks {
					if state[i].abandoned {
						continue
					}
					// A failed task is due again immediately: the interval
					// paces successful work, not recovery.
					if state[i].failures == 0 && !state[i].lastRun.IsZero() &&
						now.Sub(state[i].lastRun) < tasks[i].every {
						continue
					}
					state[i].lastRun = now
					if err := s.runBackgroundTask(tasks[i], now); err != nil {
						state[i].failures++
						s.log("  ERROR: the %s task failed (attempt %d of %d): %v",
							tasks[i].name, state[i].failures, maxTaskFailures, err)
						if state[i].failures >= maxTaskFailures {
							state[i].abandoned = true
							s.log("  ERROR: giving up on the %s task after %d failures; restart the wallet to run it again",
								tasks[i].name, state[i].failures)
						}
						continue
					}
					state[i].failures = 0
				}
			}
		}
	}()
	return func() { close(done) }
}

// taskState is one task's schedule and failure history.
type taskState struct {
	lastRun  time.Time
	failures int
	// abandoned marks a task that failed too often to keep trying. The others
	// carry on: one broken job must not take the rest of the wallet's own work
	// with it.
	abandoned bool
}

// maxTaskFailures bounds retrying. A task that has failed this many times in a
// row is not going to start working on the next tick, and repeating it forever
// buries the reason in a log nobody reads to the end.
const maxTaskFailures = 5

// runBackgroundTask isolates one run. A panic in one task must not take the
// loop down with it: the wallet would go on serving requests while quietly
// doing none of its own work, which is the failure that is hardest to notice.
func (s *Server) runBackgroundTask(task backgroundTask, now time.Time) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return task.run(now)
}

// certificateCheckInterval is how often the signing certificate is checked
// against its expiry. Leaves last a year, so this only has to be often enough
// that a wallet left running notices before the day arrives.
const certificateCheckInterval = time.Hour

// renewSigningCertificate re-issues the signing leaf as it approaches
// expiry. A hosted wallet runs for months and nobody watches its certificate:
// an expired leaf keeps issuing credentials that quietly stop verifying.
func (s *Server) renewSigningCertificate(now time.Time) error {
	s.renewIssuerTLSCertificateIfNeeded(now)
	renewed, err := s.wallet.RefreshSigningCertificateIfExpiring(now)
	if err != nil {
		return fmt.Errorf("re-issuing the signing certificate: %w", err)
	}
	if renewed {
		s.log("  Renewed:       signing certificate, now valid until %s",
			s.wallet.SigningCertificateExpiry().Format(time.DateOnly))
		s.persistWallet()
	}
	return nil
}

// collectDueDeferredCredentials makes one attempt for every pending issuance
// whose next attempt is due.
func (s *Server) collectDueDeferredCredentials(now time.Time) error {
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
	// Each record carries its own schedule and its own give-up rule, so a
	// credential the issuer will not hand over is not a failure of the sweep.
	return nil
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

	// The access token was minted for the credential request and outlives it
	// by minutes, while the issuer may ask the wallet back in an hour. Mint a
	// new one before spending the attempt on a request the issuer will refuse.
	if pending.AccessTokenExpired(time.Now()) && pending.CanRefresh() {
		refreshed, err := s.refreshDeferredAccessToken(pending, dpopKey)
		if err != nil {
			return s.abandonDeferred(pending, fmt.Sprintf("its access token expired and could not be renewed: %v", err))
		}
		pending = refreshed
	}

	// One request per turn: the schedule lives here, so the request must not
	// wait on its own or two things would be pacing the same issuer.
	nonce := ""
	credResp, err := deferredCredentialAttempt(
		pending.DeferredEndpoint, pending.AccessToken, pending.AuthScheme,
		pending.TransactionID, dpopKey, s.wallet.HolderKey, &nonce)

	// An issuer that refuses the authorization may simply have expired the
	// token earlier than it said. One renewal and one retry is worth it before
	// giving up on a credential the wallet is owed.
	if err != nil && isAuthorizationRejected(err) && pending.CanRefresh() {
		refreshed, refreshErr := s.refreshDeferredAccessToken(pending, dpopKey)
		if refreshErr == nil {
			pending = refreshed
			nonce = ""
			credResp, err = deferredCredentialAttempt(
				pending.DeferredEndpoint, pending.AccessToken, pending.AuthScheme,
				pending.TransactionID, dpopKey, s.wallet.HolderKey, &nonce)
		}
	}

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
// A network hiccup or a server-side fault is. A refused token or an unknown
// transaction is not.
//
// A rejected authorization is the case a long deferral runs into: the access
// token was minted for the credential request and expires in minutes, while
// the issuer may ask the wallet back in an hour. Asking again with the same
// dead token cannot succeed, so it is not worth another 24 hours of hourly
// requests. The wallet cannot yet mint a new one, which is what refresh token
// support will add.
// isAuthorizationRejected reports whether the issuer refused the credentials
// the request carried, rather than the request itself.
func isAuthorizationRejected(err error) bool {
	message := err.Error()
	return strings.Contains(message, "HTTP 401") ||
		strings.Contains(message, "HTTP 403") ||
		strings.Contains(message, "invalid_token")
}

func isRetryableDeferredError(err error) bool {
	message := err.Error()
	for _, fatal := range []string{
		"invalid_token", "invalid_grant", "invalid_transaction_id",
		"invalid_request", "invalid_client", "expired",
		"HTTP 401", "HTTP 403",
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

// refreshDeferredAccessToken exchanges the stored refresh token for a new
// access token and records it, so the next collection uses an authorization
// the issuer still accepts.
func (s *Server) refreshDeferredAccessToken(pending PendingIssuance, dpopKey *ecdsa.PrivateKey) (PendingIssuance, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", pending.RefreshToken)
	if pending.ClientID != "" {
		form.Set("client_id", pending.ClientID)
	}

	nonce := ""
	resp, err := postFormWithDPoP(pending.TokenEndpoint, form, dpopKey, "", &nonce, nil)
	if err != nil {
		return pending, err
	}
	accessToken, _ := resp["access_token"].(string)
	if accessToken == "" {
		return pending, fmt.Errorf("the token response carried no access_token")
	}

	updated := pending
	updated.AccessToken = accessToken
	if scheme := accessTokenScheme(resp, pending.UseDPoP); scheme != "" {
		updated.AuthScheme = scheme
	}
	// An issuer may rotate the refresh token, and reusing a rotated one fails.
	if rotated, _ := resp["refresh_token"].(string); rotated != "" {
		updated.RefreshToken = rotated
	}
	updated.AccessTokenExpiresAt = time.Time{}
	if seconds, ok := resp["expires_in"].(float64); ok && seconds > 0 {
		updated.AccessTokenExpiresAt = time.Now().Add(time.Duration(seconds) * time.Second)
	}

	s.wallet.UpdatePendingIssuance(updated.ID, func(p *PendingIssuance) {
		p.AccessToken = updated.AccessToken
		p.AuthScheme = updated.AuthScheme
		p.RefreshToken = updated.RefreshToken
		p.AccessTokenExpiresAt = updated.AccessTokenExpiresAt
	})
	s.persistWallet()
	s.log("  Renewed:       access token for the deferred credential from %s", pending.Issuer)
	return updated, nil
}
