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

type backgroundTask struct {
	name string
	// every sets how often the loop considers the task. The task decides
	// whether work is due.
	every time.Duration
	// run reports whether the task got its work done. A failed task runs
	// again on the next tick.
	run func(now time.Time) error
}

const backgroundTick = time.Second

func (s *Server) backgroundTasks() []backgroundTask {
	return []backgroundTask{
		{name: "deferred credentials", every: backgroundTick, run: s.collectDueDeferredCredentials},
		{name: "credential renewal", every: renewalCheckInterval, run: s.renewExpiringCredentials},
		{name: "signing certificate", every: certificateCheckInterval, run: s.renewSigningCertificate},
	}
}

// syncDemoRegistrations keeps the demo issuer and verifier of a public demo
// registered for the wallet's templates and catalogue. Visitors can't change
// them. A local wallet registers them once and leaves them to the user.
func (s *Server) syncDemoRegistrations() error {
	if s.demo == nil {
		return nil
	}
	var err error
	s.saveMutation(func() bool {
		var changed bool
		changed, err = s.wallet.EnsureDemoRegistrations()
		return changed
	})
	return err
}

// registerDemoParties registers the demo issuer and verifier at startup. A
// local wallet keeps a registration that is already there, with the user's
// changes.
func (s *Server) registerDemoParties() error {
	if s.demo != nil {
		return s.syncDemoRegistrations()
	}
	var err error
	s.saveMutation(func() bool {
		var changed bool
		changed, err = s.wallet.RegisterMissingDemoParties()
		return changed
	})
	return err
}

func (s *Server) StartBackgroundTasks() func() {
	if err := s.registerDemoParties(); err != nil {
		s.log("  WARNING: registering the demo issuer and verifier: %v", err)
	}
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
					// A failed task is due again at once. The interval paces
					// only successful runs.
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
							s.log("  ERROR: giving up on the %s task after %d failures (restart the wallet to run it again)",
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

type taskState struct {
	lastRun  time.Time
	failures int
	// abandoned marks a task that failed too often to keep trying. The others
	// carry on.
	abandoned bool
}

const maxTaskFailures = 5

// runBackgroundTask isolates one run so a panic in one task does not take the
// loop down.
func (s *Server) runBackgroundTask(task backgroundTask, now time.Time) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return task.run(now)
}

const certificateCheckInterval = time.Hour

func (s *Server) renewSigningCertificate(now time.Time) error {
	s.renewIssuerTLSCertificateIfNeeded(now)
	var renewed bool
	var err error
	s.saveMutation(func() bool {
		renewed, err = s.wallet.RefreshSigningCertificateIfExpiring(now)
		return err == nil && renewed
	})
	if err != nil {
		return fmt.Errorf("re-issuing the signing certificate: %w", err)
	}
	if renewed {
		s.log("  Renewed:       signing certificate, now valid until %s",
			s.wallet.SigningCertificateExpiry().Format(time.DateOnly))
	}
	return nil
}

func (s *Server) collectDueDeferredCredentials(now time.Time) error {
	for _, pending := range s.wallet.DeferredIssuanceList() {
		if pending.NextAttemptAt.After(now) {
			continue
		}
		if pending.Expired(now) {
			s.abandonDeferred(pending, fmt.Sprintf("the issuer did not produce it within %s", deferredIssuanceMaxAge))
			continue
		}
		s.attemptDeferredCollection(pending)
	}
	// Each record keeps its own retry schedule, so one refusal does not fail
	// the sweep.
	return nil
}

type DeferredAttempt struct {
	Collected     bool              `json:"collected"`
	Credential    *StoredCredential `json:"credential,omitempty"`
	Pending       bool              `json:"pending,omitempty"`
	NextAttemptAt time.Time         `json:"next_attempt_at,omitempty"`
	Interval      string            `json:"interval,omitempty"`
	Abandoned     bool              `json:"abandoned,omitempty"`
	Reason        string            `json:"reason,omitempty"`
}

// attemptDeferredCollection imports a completed credential, reschedules a
// pending one and removes the record after a final error.
func (s *Server) attemptDeferredCollection(pending DeferredIssuance) DeferredAttempt {
	if !s.beginDeferredCollection(pending.ID) {
		// Another collection for this record is already running. A second one
		// would ask the issuer twice and import the credential twice.
		return DeferredAttempt{Pending: true, Reason: "a collection for this credential is already in progress"}
	}
	defer s.endDeferredCollection(pending.ID)

	proofKeys, err := pending.ProofKeys()
	if err != nil {
		return s.abandonDeferred(pending, fmt.Sprintf("its proof keys could not be read back: %v", err))
	}
	var dpopKey *ecdsa.PrivateKey
	if pending.UseDPoP {
		dpopKey = s.wallet.HolderKeyPair()
	}

	// Collection can outlast the original access token.
	if pending.AccessTokenExpired(time.Now()) && pending.CanRefresh() {
		refreshed, err := s.refreshDeferredAccessToken(pending, dpopKey)
		if err != nil {
			return s.abandonDeferred(pending, fmt.Sprintf("its access token expired and could not be renewed: %v", err))
		}
		pending = refreshed
	}

	// §9.1 applies the encryption rules of the Credential Request to the
	// Deferred Credential Request. The original flow is gone by now, so the
	// metadata is fetched again. Strict mode retries later when it can't use
	// the metadata. Debug mode sends the request unencrypted and says so.
	//
	// The validation mode is read once. This runs on the poller goroutine and
	// can race a PUT /api/config/conformance.
	mode := s.wallet.Mode()
	metadata, metadataErr := fetchIssuerMetadata(s.wallet.HTTPClient(), pending.Issuer, s.wallet.metadataPolicy(mode, nil))
	if metadataErr != nil {
		if mode == ValidationModeStrict {
			return s.rescheduleDeferred(pending, pending.Interval(), fmt.Sprintf("the issuer metadata can't be used: %v", metadataErr))
		}
		s.wallet.addProtocolWarning("issuance", "deferred_metadata_unavailable", fmt.Sprintf("The issuer metadata of %s can't be used, so the deferred credential request goes unencrypted: %v", pending.Issuer, metadataErr), map[string]any{"issuer": pending.Issuer})
		metadata = nil
	}
	responseEncryption, err := buildCredentialResponseEncryptionRequest(mode, metadata, s.wallet.HolderKeyPair())
	if err != nil {
		return s.rescheduleDeferred(pending, pending.Interval(), err.Error())
	}

	// Each call sends one request without waiting. The poller schedules retries.
	nonce := ""
	credResp, err := s.wallet.deferredCredentialAttempt(
		mode, metadata,
		pending.DeferredEndpoint, pending.AccessToken, pending.AuthScheme,
		pending.TransactionID, responseEncryption, dpopKey, s.wallet.HolderKeyPair(), &nonce)

	// An issuer that refuses the authorization may have expired the token
	// earlier than it said. The wallet renews the token and retries once.
	if err != nil && isAuthorizationRejected(err) && pending.CanRefresh() {
		refreshed, refreshErr := s.refreshDeferredAccessToken(pending, dpopKey)
		if refreshErr == nil {
			pending = refreshed
			nonce = ""
			credResp, err = s.wallet.deferredCredentialAttempt(
				mode, metadata,
				pending.DeferredEndpoint, pending.AccessToken, pending.AuthScheme,
				pending.TransactionID, responseEncryption, dpopKey, s.wallet.HolderKeyPair(), &nonce)
		}
	}

	if err != nil {
		return s.handleDeferredAttemptError(pending, err)
	}

	credential, err := selectPrimaryCredential(credResp, proofKeys)
	if err != nil {
		return s.abandonDeferred(pending, fmt.Sprintf("the issuer answered without a usable credential: %v", err))
	}
	if _, err := s.wallet.checkReceivedCredentials(credResp, pending.Issuer); err != nil {
		return s.abandonDeferred(pending, err.Error())
	}
	imported, err := s.wallet.importPrimaryCredential(credential, proofKeys)
	if err != nil {
		return s.abandonDeferred(pending, fmt.Sprintf("the credential could not be imported: %v", err))
	}
	// The record carries the display resolved at offer time. When that was
	// empty, the display comes from the metadata fetched for this collection.
	display := pending.Display
	if display == nil && metadata != nil {
		display = s.wallet.resolveCredentialDisplay(metadata, pending.ConfigurationID)
	}
	s.wallet.rememberDisplay(imported, display)
	stored := s.wallet.storeBatchSiblings(imported, credResp, proofKeys, display)

	s.wallet.RemoveDeferredIssuance(pending.ID)
	details := credentialImportLogDetails(imported, credential)
	details["issuer"] = pending.Issuer
	details["transaction_id"] = pending.TransactionID
	details["deferred"] = true
	s.wallet.addProtocolLog("issuance", "credential_imported",
		fmt.Sprintf("Collected deferred credential %s from %s", imported.ID, pending.Issuer), true, details, credentialImportLogPayload(stored))
	s.log("  Collected:     deferred %s credential from %s", imported.Format, pending.Issuer)

	// §9.2 lets the Deferred Credential Response carry a notification_id of
	// its own, defined in §8.3.
	s.wallet.notifyCredentialAccepted(metadata, credResp, pending.AccessToken, pending.AuthScheme, dpopKey, &nonce)

	s.saveIssuance(&IssuanceResult{Imported: imported})
	s.wallet.NotifyStateChanged()
	return DeferredAttempt{Collected: true, Credential: imported}
}

// handleDeferredAttemptError reschedules a pending record or a transient
// error. Other errors end collection.
func (s *Server) handleDeferredAttemptError(pending DeferredIssuance, err error) DeferredAttempt {
	var stillPending stillPendingError
	if errors.As(err, &stillPending) {
		return s.rescheduleDeferred(pending, stillPending.interval, "")
	}
	if isRetryableDeferredError(err) {
		return s.rescheduleDeferred(pending, pending.Interval(), err.Error())
	}
	return s.abandonDeferred(pending, err.Error())
}

func isAuthorizationRejected(err error) bool {
	message := err.Error()
	return strings.Contains(message, "HTTP 401") ||
		strings.Contains(message, "HTTP 403") ||
		strings.Contains(message, "invalid_token")
}

// isRetryableDeferredError reports whether collection retries after err.
// Rejected authorization, unknown transactions and expiry are final.
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

func (s *Server) rescheduleDeferred(pending DeferredIssuance, interval time.Duration, lastErr string) DeferredAttempt {
	next := time.Now().Add(interval)
	s.saveMutation(func() bool {
		s.wallet.UpdateDeferredIssuance(pending.ID, func(p *DeferredIssuance) {
			p.Attempts++
			p.NextAttemptAt = next
			p.LastError = lastErr
			if seconds := int(interval / time.Second); seconds >= 1 {
				p.IntervalSeconds = seconds
			}
		})
		return true
	})
	return DeferredAttempt{
		Pending:       true,
		NextAttemptAt: next,
		Interval:      interval.String(),
		Reason:        lastErr,
	}
}

func (s *Server) abandonDeferred(pending DeferredIssuance, reason string) DeferredAttempt {
	s.saveMutation(func() bool {
		s.wallet.RemoveDeferredIssuance(pending.ID)
		s.wallet.addProtocolLog("issuance", "issuance_deferred_abandoned",
			fmt.Sprintf("Gave up on the deferred credential from %s: %s", pending.Issuer, reason), false, map[string]any{
				"issuer":         pending.Issuer,
				"transaction_id": pending.TransactionID,
				"attempts":       pending.Attempts,
				"reason":         reason,
			})
		return true
	})
	s.log("  Deferred:      gave up on %s from %s (%s)", pending.TransactionID, pending.Issuer, reason)
	s.wallet.NotifyError(WalletError{
		Message: "Deferred credential was not issued",
		Detail:  fmt.Sprintf("%s: %s", pending.Issuer, reason),
	})
	return DeferredAttempt{Abandoned: true, Reason: reason}
}

// beginDeferredCollection claims the record before collecting, so concurrent
// polls cannot import it twice.
func (s *Server) beginDeferredCollection(id string) bool {
	s.deferredMu.Lock()
	defer s.deferredMu.Unlock()
	if s.deferredInFlight == nil {
		s.deferredInFlight = make(map[string]bool)
	}
	if s.deferredInFlight[id] {
		return false
	}
	s.deferredInFlight[id] = true
	return true
}

func (s *Server) endDeferredCollection(id string) {
	s.deferredMu.Lock()
	defer s.deferredMu.Unlock()
	delete(s.deferredInFlight, id)
}

func (s *Server) CollectDeferredNow(id string) (DeferredAttempt, bool) {
	for _, pending := range s.wallet.DeferredIssuanceList() {
		if pending.ID == id {
			return s.attemptDeferredCollection(pending), true
		}
	}
	return DeferredAttempt{}, false
}

// AbandonDeferredNow stops polling. The transaction stays valid at the issuer.
func (s *Server) AbandonDeferredNow(id string) (DeferredIssuance, bool) {
	for _, pending := range s.wallet.DeferredIssuanceList() {
		if pending.ID != id {
			continue
		}
		s.saveMutation(func() bool {
			s.wallet.RemoveDeferredIssuance(pending.ID)
			s.wallet.addProtocolLog("issuance", "issuance_deferred_abandoned",
				fmt.Sprintf("Stopped collecting the deferred credential from %s", pending.Issuer), true, map[string]any{
					"issuer":         pending.Issuer,
					"transaction_id": pending.TransactionID,
					"attempts":       pending.Attempts,
					"reason":         "abandoned on request",
				})
			return true
		})
		s.log("  Deferred:      stopped collecting %s from %s", pending.TransactionID, pending.Issuer)
		return pending, true
	}
	return DeferredIssuance{}, false
}

func (s *Server) refreshDeferredAccessToken(pending DeferredIssuance, dpopKey *ecdsa.PrivateKey) (DeferredIssuance, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", pending.RefreshToken)
	if pending.ClientID != "" {
		form.Set("client_id", pending.ClientID)
	}
	// The issuer that required client authentication for the first token
	// requires it for this one too.
	if err := applyClientAuthentication(form, pending.ClientAuth, s.wallet.HolderKeyPair()); err != nil {
		return pending, err
	}

	nonce := ""
	resp, err := postFormWithDPoP(s.wallet.HTTPClient(), pending.TokenEndpoint, form, dpopKey, "", &nonce, s.wallet.attestorFor(pending.ClientAuth))
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

	// A rotated refresh token replaces the old one for good, so it is saved
	// under the reload lock.
	s.saveMutation(func() bool {
		s.wallet.UpdateDeferredIssuance(updated.ID, func(p *DeferredIssuance) {
			p.AccessToken = updated.AccessToken
			p.AuthScheme = updated.AuthScheme
			p.RefreshToken = updated.RefreshToken
			p.AccessTokenExpiresAt = updated.AccessTokenExpiresAt
		})
		return true
	})
	s.log("  Renewed:       access token for the deferred credential from %s", pending.Issuer)
	return updated, nil
}
