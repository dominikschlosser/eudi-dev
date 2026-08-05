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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// deferringIssuer serves a pre-authorized offer whose credential endpoint
// answers with a transaction_id, then holds the deferred endpoint pending for
// pendingRounds polls before releasing the credential. pendingStyle picks how
// "not ready" is expressed: OID4VCI 1.0 §9.3 uses the issuance_pending error,
// while some issuers echo the transaction_id back in a success-shaped body.
func deferringIssuer(t *testing.T, w *Wallet, pendingRounds int, pendingStyle string, intervalSeconds int) (*httptest.Server, string, func() int) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string
	var mu sync.Mutex
	polls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":            serverURL,
				"credential_endpoint":          serverURL + "/credential",
				"deferred_credential_endpoint": serverURL + "/deferred",
				"token_endpoint":               serverURL + "/token",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential"},
				},
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token", "token_type": "Bearer", "c_nonce": "test-c-nonce",
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			// The issuer takes the request but is not ready to answer with a
			// credential, so it hands back the ticket to collect it with.
			json.NewEncoder(rw).Encode(map[string]any{
				"transaction_id": "test-transaction",
				"interval":       intervalSeconds,
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/deferred"):
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
				if pendingStyle == "issuance_pending" {
					rw.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(rw).Encode(map[string]any{
						"error":    "issuance_pending",
						"interval": intervalSeconds,
					})
					return
				}
				json.NewEncoder(rw).Encode(map[string]any{
					"transaction_id": "test-transaction",
					"interval":       intervalSeconds,
				})
				return
			}
			json.NewEncoder(rw).Encode(map[string]any{"credential": credRaw})

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	serverURL = srv.URL

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "test-pre-auth-code",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	return srv, offerURI, func() int {
		mu.Lock()
		defer mu.Unlock()
		return polls
	}
}

// TestProcessCredentialOffer_DeferredWithoutEndpoint covers an issuer that
// defers without publishing anywhere to collect the credential from.
func TestProcessCredentialOffer_DeferredWithoutEndpoint(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)
	var serverURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			// No deferred_credential_endpoint.
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"token_endpoint":      serverURL + "/token",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential"},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "t", "token_type": "Bearer", "c_nonce": "n",
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			json.NewEncoder(rw).Encode(map[string]any{"transaction_id": "test-transaction"})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL
	_ = credRaw

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "c",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	_, err := w.ProcessCredentialOffer(offerURI)
	if err == nil || !strings.Contains(err.Error(), "deferred_credential_endpoint") {
		t.Fatalf("error = %v, want it to name the missing deferred_credential_endpoint", err)
	}
}

// TestDeferredIssuancePending covers reading the pending state and the wait
// the issuer asks for out of a deferred credential response.
func TestDeferredIssuancePending(t *testing.T) {
	for _, tc := range []struct {
		name         string
		out          map[string]any
		wantPending  bool
		wantInterval time.Duration
	}{
		{
			name:        "spec error with an interval",
			out:         map[string]any{"error": "issuance_pending", "interval": float64(7)},
			wantPending: true, wantInterval: 7 * time.Second,
		},
		{
			name:        "spec error without an interval falls back",
			out:         map[string]any{"error": "issuance_pending"},
			wantPending: true, wantInterval: deferredPollInterval,
		},
		{
			name:        "echoed transaction_id with no credential",
			out:         map[string]any{"transaction_id": "t", "interval": float64(3)},
			wantPending: true, wantInterval: 3 * time.Second,
		},
		{
			name:        "transaction_id alongside a credential is not pending",
			out:         map[string]any{"transaction_id": "t", "credential": "abc"},
			wantPending: false,
		},
		{
			name:        "a credential is not pending",
			out:         map[string]any{"credential": "abc"},
			wantPending: false,
		},
		{
			name:        "another error is not pending",
			out:         map[string]any{"error": "invalid_token"},
			wantPending: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pending, interval := deferredIssuancePending(tc.out)
			if pending != tc.wantPending {
				t.Fatalf("pending = %v, want %v", pending, tc.wantPending)
			}
			if pending && interval != tc.wantInterval {
				t.Errorf("interval = %s, want %s", interval, tc.wantInterval)
			}
		})
	}
}

// TestProcessCredentialOffer_DeferredIsRecordedNotWaitedOut covers the shape
// of a deferral: the flow returns straight away with the ticket, so whoever
// started it is not held for the issuer's interval.
func TestProcessCredentialOffer_DeferredIsRecordedNotWaitedOut(t *testing.T) {
	w := generateTestWallet(t)
	// Pending for far longer than any caller would wait, and the deferred
	// endpoint must not be touched during the offer flow at all.
	srv, offerURI, polls := deferringIssuer(t, w, 1000, "issuance_pending", 3600)
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	started := time.Now()
	result, err := w.ProcessCredentialOffer(offerURI)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if !result.Pending {
		t.Fatalf("result = %+v, want it reported as pending", result)
	}
	if result.TransactionID == "" {
		t.Error("a pending result should carry the transaction id")
	}
	if elapsed > 5*time.Second {
		t.Errorf("the flow took %s, want it to return without waiting out the deferral", elapsed)
	}
	if got := polls(); got != 0 {
		t.Errorf("deferred endpoint was called %d times during the offer flow, want 0", got)
	}
	if got := len(w.PendingIssuanceList()); got != 1 {
		t.Fatalf("wallet holds %d pending issuances, want 1", got)
	}
	if w.PendingIssuanceList()[0].Interval() != time.Hour {
		t.Errorf("interval = %s, want the issuer's 1h", w.PendingIssuanceList()[0].Interval())
	}
}

// A credential can only be re-requested from an issuer that handed over a
// refresh token, and the flow that obtained it is gone by the time it nears
// expiry, so what that flow knew has to travel with the credential.
func TestIssuanceRemembersHowToRenew(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	w.Credentials = append(w.Credentials, StoredCredential{ID: "cred-1", Format: "dc+sd-jwt", Raw: credRaw})

	w.rememberRenewal("cred-1", "refresh-1", CredentialRenewal{
		Issuer: "https://issuer.example", TokenEndpoint: "https://issuer.example/token",
		CredentialEndpoint: "https://issuer.example/credential", ConfigurationID: "cfg", UseDPoP: true,
	})
	stored, _ := w.GetCredential("cred-1")
	if !stored.CanRenew() {
		t.Fatalf("the credential cannot be renewed: %+v", stored.Renewal)
	}
	if stored.Renewal.RefreshToken != "refresh-1" {
		t.Errorf("refresh token = %q", stored.Renewal.RefreshToken)
	}

	// An issuer that gave no refresh token leaves nothing behind: there is no
	// way to ask again, and a half-filled block would look like there is.
	w.Credentials = append(w.Credentials, StoredCredential{ID: "cred-2", Format: "dc+sd-jwt", Raw: credRaw})
	w.rememberRenewal("cred-2", "", CredentialRenewal{
		Issuer: "https://issuer.example", TokenEndpoint: "https://issuer.example/token",
		CredentialEndpoint: "https://issuer.example/credential",
	})
	if stored, _ := w.GetCredential("cred-2"); stored.CanRenew() || stored.Renewal != nil {
		t.Error("a credential without a refresh token was recorded as renewable")
	}
}
