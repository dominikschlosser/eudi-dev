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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// deferredCollectionIssuer serves only a deferred credential endpoint, which
// stays pending for pendingRounds polls and then hands over the credential.
func deferredCollectionIssuer(t *testing.T, credRaw string, pendingRounds, intervalSeconds int) (*httptest.Server, func() int) {
	t.Helper()
	var mu sync.Mutex
	polls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		polls++
		current := polls
		mu.Unlock()

		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["transaction_id"] != "test-transaction" {
			rw.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_transaction_id"})
			return
		}
		if current <= pendingRounds {
			// §9.2: "If the Credential Issuer still requires more time, the
			// Deferred Credential Response MUST use the interval and
			// transaction_id parameters [...] and it MUST respond with the HTTP
			// status code 202".
			rw.WriteHeader(http.StatusAccepted)
			json.NewEncoder(rw).Encode(map[string]any{
				"transaction_id": "test-transaction",
				"interval":       intervalSeconds,
			})
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})
	}))

	return srv, func() int {
		mu.Lock()
		defer mu.Unlock()
		return polls
	}
}

func pendingFor(t *testing.T, w *Wallet, endpoint string, intervalSeconds int) *DeferredIssuance {
	t.Helper()
	pending, err := newDeferredIssuance(deferredContext{
		issuer:           "https://issuer.example",
		configID:         "test-config",
		format:           "dc+sd-jwt",
		deferredEndpoint: endpoint,
		accessToken:      "test-access-token",
		authScheme:       "Bearer",
		proofKeys:        []*ecdsa.PrivateKey{w.HolderKey},
	}, "test-transaction", time.Duration(intervalSeconds)*time.Second)
	if err != nil {
		t.Fatalf("newDeferredIssuance: %v", err)
	}
	return pending
}

func TestCollectDeferredNow_SkipsWhenCollectionInFlight(t *testing.T) {
	w := generateTestWallet(t)
	server := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, "https://issuer.example/deferred", 1)
	w.AddDeferredIssuance(pending)

	// Stand in for a collection already running for this record.
	if !server.beginDeferredCollection(pending.ID) {
		t.Fatal("expected to acquire the in-flight guard")
	}
	defer server.endDeferredCollection(pending.ID)

	attempt, ok := server.CollectDeferredNow(pending.ID)
	if !ok {
		t.Fatal("CollectDeferredNow should still find the record")
	}
	if !attempt.Pending {
		t.Fatalf("a collect that races an in-flight one should be skipped as pending, got %+v", attempt)
	}
	// The bogus issuer URL is never contacted, so nothing is imported.
	if got := len(w.GetCredentials()); got != 0 {
		t.Fatalf("no credential should be imported while a collection is in flight, got %d", got)
	}
}

func TestDeferredCollectionInFlightGuard(t *testing.T) {
	s := &Server{}
	if !s.beginDeferredCollection("id-1") {
		t.Fatal("first begin should win")
	}
	if s.beginDeferredCollection("id-1") {
		t.Fatal("second begin for the same id must not win while in flight")
	}
	if !s.beginDeferredCollection("id-2") {
		t.Fatal("a different id should be independent")
	}
	s.endDeferredCollection("id-1")
	if !s.beginDeferredCollection("id-1") {
		t.Fatal("after release the id can be collected again")
	}
}

// TestDeferredPoller_CollectsWhenReady covers the whole point of the poller:
// a credential the issuer was not ready to hand over lands in the wallet
// later, without anyone asking again.
func TestDeferredPoller_CollectsWhenReady(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)
	srv, polls := deferredCollectionIssuer(t, credRaw, 1, 1)
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	saves := 0
	server := NewServer(w, 0, func() { saves++ })
	pending := pendingFor(t, w, srv.URL, 1)
	pending.NextAttemptAt = time.Now().Add(-time.Second) // due now
	w.AddDeferredIssuance(pending)

	// First sweep: the issuer is still working, so the record stays and is
	// rescheduled rather than dropped.
	server.collectDueDeferredCredentials(time.Now())
	if got := len(w.DeferredIssuanceList()); got != 1 {
		t.Fatalf("after a pending answer the wallet holds %d records, want 1", got)
	}
	if got := len(w.GetCredentials()); got != 0 {
		t.Fatalf("wallet holds %d credentials, want none yet", got)
	}
	rescheduled := w.DeferredIssuanceList()[0]
	if rescheduled.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", rescheduled.Attempts)
	}
	if !rescheduled.NextAttemptAt.After(time.Now()) {
		t.Error("next attempt should have been pushed into the future")
	}

	// Not due yet: nothing happens, and the issuer is left alone.
	server.collectDueDeferredCredentials(time.Now())
	if got := polls(); got != 1 {
		t.Errorf("issuer polled %d times, want 1 while the wait is not over", got)
	}

	// Due again: the credential arrives and the record is gone.
	server.collectDueDeferredCredentials(time.Now().Add(2 * time.Second))
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d pending records, want 0", got)
	}
	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("wallet holds %d credentials, want the collected one", len(creds))
	}
	if saves == 0 {
		t.Error("collecting a deferred credential should persist the wallet")
	}
	assertWalletLogEvent(t, w.GetLog(), "credential_imported")
}

// TestDeferredPoller_NotifiesAfterCollecting covers the acknowledgement a
// collected deferred credential owes its issuer. OpenID4VCI 1.0 §8.3 lets the
// Deferred Credential Response carry a notification_id of its own, so the
// wallet reports the credential it just stored the same way it does for one
// handed over immediately.
func TestDeferredPoller_NotifiesAfterCollecting(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	var mu sync.Mutex
	var notified []string
	var issuerURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-credential-issuer":
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     issuerURL,
				"notification_endpoint": issuerURL + "/notification",
			})
		case "/deferred":
			json.NewEncoder(rw).Encode(map[string]any{
				"credentials":     []any{map[string]any{"credential": credRaw}},
				"notification_id": "deferred-notification",
			})
		case "/notification":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			notified = append(notified, fmt.Sprintf("%v/%v", body["notification_id"], body["event"]))
			mu.Unlock()
			rw.WriteHeader(http.StatusNoContent)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	issuerURL = srv.URL

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, srv.URL+"/deferred", 1)
	pending.Issuer = issuerURL
	pending.NextAttemptAt = time.Now().Add(-time.Second)
	w.AddDeferredIssuance(pending)

	server.collectDueDeferredCredentials(time.Now())

	if got := len(w.GetCredentials()); got != 1 {
		t.Fatalf("wallet holds %d credentials, want the collected one", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(notified) != 1 {
		t.Fatalf("notification endpoint called %d times, want 1", len(notified))
	}
	if notified[0] != "deferred-notification/credential_accepted" {
		t.Errorf("notification = %q, want deferred-notification/credential_accepted", notified[0])
	}
}

// TestDeferredPoller_GivesUpOnFatalAnswers covers answers that will not get
// better by asking again: the record has to go, with a reason, rather than
// hammering the issuer on a timer forever.
func TestDeferredPoller_GivesUpOnFatalAnswers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		error string
	}{
		{"rejected token", "invalid_token"},
		{"unknown transaction", "invalid_transaction_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{"error": tc.error})
			}))
			defer srv.Close()

			oldClient := httpClient
			httpClient = srv.Client()
			defer func() { httpClient = oldClient }()

			server := NewServer(w, 0, func() {})
			pending := pendingFor(t, w, srv.URL, 1)
			pending.NextAttemptAt = time.Now().Add(-time.Second)
			w.AddDeferredIssuance(pending)

			server.collectDueDeferredCredentials(time.Now())
			if got := len(w.DeferredIssuanceList()); got != 0 {
				t.Errorf("wallet still holds %d pending records, want it dropped", got)
			}
			assertWalletLogEvent(t, w.GetLog(), "issuance_deferred_abandoned")
		})
	}
}

// TestDeferredPoller_DropsExpiredRecords covers a deferral the wallet has
// carried for longer than it is worth.
func TestDeferredPoller_DropsExpiredRecords(t *testing.T) {
	w := generateTestWallet(t)
	polled := false
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		polled = true
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, srv.URL, 1)
	pending.CreatedAt = time.Now().Add(-2 * deferredIssuanceMaxAge)
	pending.NextAttemptAt = time.Now().Add(-time.Second)
	w.AddDeferredIssuance(pending)

	server.collectDueDeferredCredentials(time.Now())
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d expired records, want 0", got)
	}
	if polled {
		t.Error("an expired record should be dropped without troubling the issuer")
	}
}

// TestDeferredIssuance_SurvivesAStoreRoundTrip covers the persistence a long
// deferral depends on: a wallet that restarts has to be able to finish
// collecting, which means the ticket and the keys it was bound to come back.
func TestDeferredIssuance_SurvivesAStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	pending := pendingFor(t, w, "https://issuer.example/deferred", 42)
	w.AddDeferredIssuance(pending)
	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}
	restored := reloaded.DeferredIssuanceList()
	if len(restored) != 1 {
		t.Fatalf("reloaded wallet holds %d pending issuances, want 1", len(restored))
	}
	if restored[0].TransactionID != "test-transaction" {
		t.Errorf("transaction_id = %q, want it preserved", restored[0].TransactionID)
	}
	if restored[0].Interval() != 42*time.Second {
		t.Errorf("interval = %s, want the issuer's 42s", restored[0].Interval())
	}
	keys, err := restored[0].ProofKeys()
	if err != nil {
		t.Fatalf("ProofKeys after reload: %v", err)
	}
	if len(keys) != 1 || !keys[0].PublicKey.Equal(&w.HolderKey.PublicKey) {
		t.Error("the proof key did not survive the round trip")
	}
}

// TestIsRetryableDeferredError covers which answers are worth another attempt.
func TestIsRetryableDeferredError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"network trouble", errString("connection refused"), true},
		{"server fault", errString("HTTP 503: upstream unavailable"), true},
		{"rejected token", errString(`HTTP 401: {"error":"invalid_token"}`), false},
		{"unknown transaction", errString(`HTTP 400: {"error":"invalid_transaction_id"}`), false},
		{"expired grant", errString(`HTTP 400: {"error":"invalid_grant","error_description":"expired"}`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableDeferredError(tc.err); got != tc.retry {
				t.Errorf("isRetryableDeferredError = %v, want %v", got, tc.retry)
			}
		})
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// TestCollectDeferredNow covers asking an issuer straight away instead of
// waiting for the next scheduled attempt, and what the caller is told.
func TestCollectDeferredNow(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)
	srv, polls := deferredCollectionIssuer(t, credRaw, 1, 30)
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, srv.URL, 30)
	// Far in the future: the poller would not touch this for half a minute.
	pending.NextAttemptAt = time.Now().Add(30 * time.Second)
	w.AddDeferredIssuance(pending)

	// First check: the issuer is still working, so the caller is told so.
	attempt, ok := server.CollectDeferredNow(pending.ID)
	if !ok {
		t.Fatal("CollectDeferredNow did not find the pending issuance")
	}
	if !attempt.Pending || attempt.Collected {
		t.Fatalf("attempt = %+v, want it reported as still pending", attempt)
	}
	if attempt.Interval != "30s" {
		t.Errorf("interval = %q, want the issuer's 30s", attempt.Interval)
	}
	if polls() != 1 {
		t.Errorf("issuer polled %d times, want 1", polls())
	}

	// Second check: ready now, so the credential arrives without the schedule
	// having come round.
	attempt, ok = server.CollectDeferredNow(pending.ID)
	if !ok {
		t.Fatal("CollectDeferredNow did not find the pending issuance on the second try")
	}
	if !attempt.Collected {
		t.Fatalf("attempt = %+v, want the credential collected", attempt)
	}
	if attempt.Credential == nil || attempt.Credential.ID == "" {
		t.Error("a collected attempt should name the credential it imported")
	}
	if got := len(w.GetCredentials()); got != 1 {
		t.Errorf("wallet holds %d credentials, want the collected one", got)
	}
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d pending records, want 0", got)
	}

	if _, ok := server.CollectDeferredNow("no-such-id"); ok {
		t.Error("an unknown id should not report a result")
	}
}

// TestAbandonDeferredNow covers dropping a deferred issuance on request: the
// wallet stops asking, and does not go near the issuer to do it.
func TestAbandonDeferredNow(t *testing.T) {
	w := generateTestWallet(t)
	polled := false
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		polled = true
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	saves := 0
	server := NewServer(w, 0, func() { saves++ })
	pending := pendingFor(t, w, srv.URL, 10)
	w.AddDeferredIssuance(pending)

	dropped, ok := server.AbandonDeferredNow(pending.ID)
	if !ok {
		t.Fatal("AbandonDeferredNow did not find the pending issuance")
	}
	if dropped.TransactionID != "test-transaction" {
		t.Errorf("dropped transaction = %q, want it reported back", dropped.TransactionID)
	}
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d pending records, want 0", got)
	}
	if polled {
		t.Error("abandoning is the wallet's own decision and must not contact the issuer")
	}
	if saves == 0 {
		t.Error("abandoning should persist the wallet")
	}
	assertWalletLogEvent(t, w.GetLog(), "issuance_deferred_abandoned")

	if _, ok := server.AbandonDeferredNow(pending.ID); ok {
		t.Error("abandoning the same id twice should report nothing to drop")
	}
}

// The poller only collects if something starts its goroutine. Every other test
// here calls the sweep directly, which passes whether or not the server ever
// runs it, so this one checks that the server does.
func TestDeferredPollerRunsFromTheServer(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)
	srv, polls := deferredCollectionIssuer(t, credRaw, 0, 1)
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, nil)
	pending := pendingFor(t, w, srv.URL, 1)
	pending.NextAttemptAt = time.Now().Add(-time.Second)
	w.AddDeferredIssuance(pending)

	stop := server.StartBackgroundTasks()
	defer stop()

	deadline := time.Now().Add(5 * time.Second)
	for len(w.GetCredentials()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	if got := len(w.GetCredentials()); got != 1 {
		t.Fatalf("the running poller collected %d credentials after %d polls, want 1", got, polls())
	}
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d pending records, want 0", got)
	}
}

// A credential offer names configurations, not credential types, so a deferred
// row takes its credential type from the issuer's metadata rather than
// carrying the configuration id until the credential arrives.
func TestDeferredIssuanceRecordsTheCredentialType(t *testing.T) {
	metadata := map[string]any{
		"credential_configurations_supported": map[string]any{
			"eudi-pid-sd-jwt-bdr-key-attestations": map[string]any{
				"format": "dc+sd-jwt",
				"vct":    "urn:eudi:pid:1",
			},
			"pid-mdoc": map[string]any{
				"format":  "mso_mdoc",
				"doctype": "eu.europa.ec.eudi.pid.1",
			},
		},
	}

	vct, docType := credentialTypeForConfiguration(metadata, "eudi-pid-sd-jwt-bdr-key-attestations")
	if vct != "urn:eudi:pid:1" || docType != "" {
		t.Errorf("sd-jwt configuration resolved to vct=%q doctype=%q", vct, docType)
	}

	vct, docType = credentialTypeForConfiguration(metadata, "pid-mdoc")
	if vct != "" || docType != "eu.europa.ec.eudi.pid.1" {
		t.Errorf("mdoc configuration resolved to vct=%q doctype=%q", vct, docType)
	}

	// An issuer that declares nothing leaves the row on its configuration id.
	if vct, docType = credentialTypeForConfiguration(metadata, "unknown"); vct != "" || docType != "" {
		t.Errorf("unknown configuration resolved to vct=%q doctype=%q, want empty", vct, docType)
	}
	if vct, docType = credentialTypeForConfiguration(nil, "any"); vct != "" || docType != "" {
		t.Errorf("missing metadata resolved to vct=%q doctype=%q, want empty", vct, docType)
	}
}

// A long deferral outlives its access token: the token is issued for the
// credential request and expires in minutes, while the issuer may ask the
// wallet back in an hour. Repeating the request with a dead token cannot
// succeed, so it must not be retried hourly until the 24 hour cap.
func TestDeferredGivesUpOnARejectedToken(t *testing.T) {
	for _, status := range []string{"HTTP 401", "HTTP 403"} {
		if isRetryableDeferredError(fmt.Errorf("deferred credential request: %s: ", status)) {
			t.Errorf("%s is treated as retryable, so the wallet keeps asking with a token the issuer already refused", status)
		}
	}
	// A server-side fault is still worth another attempt.
	for _, status := range []string{"HTTP 500", "HTTP 502", "connection refused"} {
		if !isRetryableDeferredError(fmt.Errorf("deferred credential request: %s", status)) {
			t.Errorf("%s should stay retryable", status)
		}
	}
}

// A deferral outlives its access token, so the collection has to obtain a new
// one. Without this the wallet asks with an authorization the issuer already
// expired and the credential it is owed never arrives.
func TestDeferredCollectionRefreshesAnExpiredToken(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	var refreshes, refusedWithOldToken int
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "refresh-1" {
				rw.WriteHeader(http.StatusBadRequest)
				return
			}
			refreshes++
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "fresh-token", "token_type": "Bearer", "expires_in": 300,
			})
		case strings.HasSuffix(r.URL.Path, "/deferred"):
			// The issuer only honours the renewed token.
			if r.Header.Get("Authorization") != "Bearer fresh-token" {
				refusedWithOldToken++
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, nil)
	pending := pendingFor(t, w, srvURL+"/deferred", 1)
	pending.NextAttemptAt = time.Now().Add(-time.Second)
	pending.AccessToken = "stale-token"
	pending.AuthScheme = "Bearer"
	pending.RefreshToken = "refresh-1"
	pending.TokenEndpoint = srvURL + "/token"
	pending.AccessTokenExpiresAt = time.Now().Add(-time.Minute) // already expired
	w.AddDeferredIssuance(pending)

	server.collectDueDeferredCredentials(time.Now())

	if refreshes != 1 {
		t.Errorf("the wallet refreshed %d times, want exactly one renewal", refreshes)
	}
	if refusedWithOldToken != 0 {
		t.Errorf("the wallet spent %d attempts on the expired token before renewing it", refusedWithOldToken)
	}
	if got := len(w.GetCredentials()); got != 1 {
		t.Fatalf("wallet holds %d credentials, want the collected one", got)
	}
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d pending records, want 0", got)
	}
}

// One task failing must not stop the others. A loop that dies leaves the
// wallet serving requests while quietly doing none of its own work, which is
// the failure hardest to notice from outside.
func TestBackgroundTaskPanicDoesNotStopTheLoop(t *testing.T) {
	w := generateTestWallet(t)
	server := NewServer(w, 0, nil)

	var logged []string
	server.SetLogger(func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	})

	ran := 0
	err := server.runBackgroundTask(backgroundTask{name: "explodes", every: time.Second, run: func(time.Time) error {
		panic("boom")
	}}, time.Now())
	if err == nil {
		t.Error("a panicking task reported success")
	}
	if err != nil && !strings.Contains(err.Error(), "boom") {
		t.Errorf("the panic value is missing from the error: %v", err)
	}
	if err := server.runBackgroundTask(backgroundTask{name: "works", every: time.Second, run: func(time.Time) error {
		ran++
		return nil
	}}, time.Now()); err != nil {
		t.Errorf("a healthy task after a panicking one failed: %v", err)
	}
	if ran != 1 {
		t.Error("a task after a panicking one did not run")
	}
	_ = logged
}

// The loop runs off the request path, so a slow task never delays a caller.
func TestBackgroundTasksRunOffTheRequestPath(t *testing.T) {
	w := generateTestWallet(t)
	server := NewServer(w, 0, nil)

	blocked := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = server.runBackgroundTask(backgroundTask{name: "slow", every: time.Second, run: func(time.Time) error {
			close(blocked)
			<-release
			return nil
		}}, time.Now())
	}()
	<-blocked
	defer close(release)

	// A request is served while that task is still in flight.
	rec := httptest.NewRecorder()
	server.handleListCredentials(rec, httptest.NewRequest(http.MethodGet, "/api/credentials", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("serving a request during a background task returned %d", rec.Code)
	}
}

// A failing task is retried on the next tick rather than waiting out its
// interval, and dropped once it has clearly stopped working. Retrying forever
// buries the reason, and giving up silently loses the work.
func TestFailingBackgroundTaskIsRetriedThenAbandoned(t *testing.T) {
	w := generateTestWallet(t)
	server := NewServer(w, 0, nil)
	var logged []string
	server.SetLogger(func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	})

	attempts := 0
	failing := backgroundTask{name: "always fails", every: time.Hour, run: func(time.Time) error {
		attempts++
		return fmt.Errorf("nope")
	}}

	// Drive the same schedule the loop uses, so the retry rule is what is
	// under test rather than the ticker.
	state := taskState{}
	now := time.Now()
	for range maxTaskFailures + 3 {
		if state.abandoned {
			continue
		}
		if state.failures == 0 && !state.lastRun.IsZero() && now.Sub(state.lastRun) < failing.every {
			continue
		}
		state.lastRun = now
		if err := server.runBackgroundTask(failing, now); err != nil {
			state.failures++
			if state.failures >= maxTaskFailures {
				state.abandoned = true
			}
		}
		now = now.Add(backgroundTick)
	}

	if attempts != maxTaskFailures {
		t.Errorf("the task ran %d times, want %d: an hourly task that fails must retry on the next tick and stop at the limit", attempts, maxTaskFailures)
	}
	if !state.abandoned {
		t.Error("the task was never abandoned, so it would retry forever")
	}
	_ = logged
}
