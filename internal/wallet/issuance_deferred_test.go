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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// deferringIssuer serves a pre-authorized offer whose credential endpoint
// answers with a transaction_id, then holds the deferred endpoint pending for
// pendingRounds polls before releasing the credential. Not ready is expressed
// the way OpenID4VCI 1.0 §9.2 defines it: HTTP 202 with the transaction_id and
// the interval, and no credentials.
func deferringIssuer(t *testing.T, w *Wallet, pendingRounds int, intervalSeconds int) (*httptest.Server, string, func() int) {
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
				rw.WriteHeader(http.StatusAccepted)
				json.NewEncoder(rw).Encode(map[string]any{
					"transaction_id": "test-transaction",
					"interval":       intervalSeconds,
				})
				return
			}
			json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})

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
			name:        "the transaction handed back with an interval",
			out:         map[string]any{"transaction_id": "t", "interval": float64(3)},
			wantPending: true, wantInterval: 3 * time.Second,
		},
		{
			name:        "the transaction handed back without an interval falls back",
			out:         map[string]any{"transaction_id": "t"},
			wantPending: true, wantInterval: deferredPollInterval,
		},
		{
			name:        "transaction_id alongside a credential is not pending",
			out:         map[string]any{"transaction_id": "t", "credentials": []any{map[string]any{"credential": "abc"}}},
			wantPending: false,
		},
		{
			name:        "a credential is not pending",
			out:         map[string]any{"credentials": []any{map[string]any{"credential": "abc"}}},
			wantPending: false,
		},
		{
			name:        "an error is not pending",
			out:         map[string]any{"error": "invalid_token"},
			wantPending: false,
		},
		{
			name:        "the draft-era issuance_pending error is not a pending signal",
			out:         map[string]any{"error": "issuance_pending", "interval": float64(7)},
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
	srv, offerURI, polls := deferringIssuer(t, w, 1000, 3600)
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
	if got := len(w.DeferredIssuanceList()); got != 1 {
		t.Fatalf("wallet holds %d pending issuances, want 1", got)
	}
	if w.DeferredIssuanceList()[0].Interval() != time.Hour {
		t.Errorf("interval = %s, want the issuer's 1h", w.DeferredIssuanceList()[0].Interval())
	}
}

// TestProcessCredentialOffer_DeferredWithBatchAdvertised reproduces the Animo
// playground: the issuer advertises batch_credential_issuance (so the wallet
// sends several proofs) and then defers, answering the credential endpoint with
// a transaction_id and no credentials. The deferral must still be recorded.
func TestProcessCredentialOffer_DeferredWithBatchAdvertised(t *testing.T) {
	w := generateTestWallet(t)
	var serverURL string
	credEndpointCalls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":            serverURL,
				"credential_endpoint":          serverURL + "/credential",
				"deferred_credential_endpoint": serverURL + "/deferred",
				"token_endpoint":               serverURL + "/token",
				// Animo advertises this, which makes the wallet request a batch.
				"batch_credential_issuance": map[string]any{"batch_size": 10},
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt", "vct": "urn:test:credential",
						// The Animo config requires key attestations, which routes
						// proof building through the attestation path.
						"proof_types_supported": map[string]any{
							"jwt": map[string]any{
								"proof_signing_alg_values_supported": []any{"ES256"},
								"key_attestations_required": map[string]any{
									"key_storage":         []any{"iso_18045_high"},
									"user_authentication": []any{"iso_18045_high"},
								},
							},
						},
					},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token", "token_type": "Bearer", "c_nonce": "test-c-nonce",
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			credEndpointCalls++
			rw.WriteHeader(http.StatusAccepted)
			json.NewEncoder(rw).Encode(map[string]any{
				"transaction_id": "test-transaction",
				"interval":       3600,
				"c_nonce":        "test-c-nonce",
			})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
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

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if !result.Pending {
		t.Fatalf("result = %+v, want it recorded as a pending deferred issuance", result)
	}
	if got := len(w.DeferredIssuanceList()); got != 1 {
		t.Fatalf("wallet holds %d pending issuances, want 1", got)
	}
	if credEndpointCalls != 1 {
		t.Errorf("credential endpoint called %d times, want 1", credEndpointCalls)
	}
}

// TestProcessCredentialOffer_FailureIsLogged covers the activity log naming why
// issuance did not finish, rather than the flow stopping silently after the last
// step that happened to succeed (the credential response).
func TestProcessCredentialOffer_FailureIsLogged(t *testing.T) {
	w := generateTestWallet(t)
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"token_endpoint":      serverURL + "/token",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential"},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(rw).Encode(map[string]any{"access_token": "t", "token_type": "Bearer", "c_nonce": "n"})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			// A response with neither a credential nor a transaction_id, so the
			// flow cannot finish after the credential response.
			json.NewEncoder(rw).Encode(map[string]any{"unexpected": "shape"})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{"pre-authorized_code": "c"},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	if _, err := w.ProcessCredentialOffer(offerURI); err == nil {
		t.Fatal("expected the offer to fail")
	}
	found := false
	for _, e := range w.GetLog() {
		if !e.Success && strings.Contains(e.Detail, "did not finish") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a failed activity log entry naming that issuance did not finish")
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

// §9.1 holds a Deferred Credential Request to the same encryption as the one
// that started the issuance: "The Client MAY encrypt the request when
// encryption_required is false and MUST do so when encryption_required is
// true", and it "MUST [provide its encryption parameters] when
// encryption_required is true. Note that this object will be used for
// encrypting the response, regardless of what was sent in the initial
// Credential Request. If it is not included encryption will not be performed."
// A plaintext poll at an issuer that requires encryption never collects the
// credential.
func TestDeferredCredentialRequestIsEncryptedWhenTheIssuerRequiresIt(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubJWK := mock.PublicKeyJWKMap(&issuerKey.PublicKey)

	var serverURL string
	var contentType string
	var deferredRequest map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":            serverURL,
				"credential_endpoint":          serverURL + "/credential",
				"deferred_credential_endpoint": serverURL + "/deferred",
				"credential_request_encryption": map[string]any{
					"jwks": map[string]any{"keys": []any{map[string]any{
						"kty": pubJWK["kty"], "crv": pubJWK["crv"],
						"x": pubJWK["x"], "y": pubJWK["y"],
						"kid": "issuer-enc-key", "use": "enc", "alg": "ECDH-ES",
					}}},
					"enc_values_supported": []any{"A256GCM"},
					"encryption_required":  true,
				},
				"credential_response_encryption": map[string]any{
					"alg_values_supported": []any{"ECDH-ES"},
					"enc_values_supported": []any{"A128GCM"},
					"encryption_required":  true,
				},
			})

		case strings.HasSuffix(r.URL.Path, "/deferred"):
			contentType = r.Header.Get("Content-Type")
			body, _ := io.ReadAll(r.Body)
			decrypted, err := DecryptCompactJWE(strings.TrimSpace(string(body)), issuerKey)
			if err != nil {
				rw.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(rw).Encode(map[string]any{"error": "invalid_encryption_parameters"})
				return
			}
			_ = json.Unmarshal([]byte(decrypted), &deferredRequest)
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credentials": []any{map[string]any{"credential": credRaw}},
			})

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, func() {})
	pending, err := newDeferredIssuance(deferredContext{
		issuer:           srv.URL,
		configID:         "test-config",
		format:           "dc+sd-jwt",
		deferredEndpoint: srv.URL + "/deferred",
		accessToken:      "test-access-token",
		authScheme:       "Bearer",
		proofKeys:        []*ecdsa.PrivateKey{w.HolderKey},
	}, "test-transaction", time.Second)
	if err != nil {
		t.Fatalf("newDeferredIssuance: %v", err)
	}
	w.AddDeferredIssuance(pending)

	attempt := server.attemptDeferredCollection(*pending)
	if !attempt.Collected {
		t.Fatalf("the deferred credential was not collected: %+v", attempt)
	}
	if contentType != "application/jwt" {
		t.Errorf("Content-Type = %q, want application/jwt: the request must be encrypted", contentType)
	}
	if deferredRequest["transaction_id"] != "test-transaction" {
		t.Errorf("decrypted transaction_id = %v", deferredRequest["transaction_id"])
	}
	if _, present := deferredRequest["credential_response_encryption"]; !present {
		t.Errorf("the deferred request carries no credential_response_encryption: %v", deferredRequest)
	}
}

// A deferral recorded during an offer must survive the per-request store
// reload that demo mode runs on every HTTP request. The poller reads the
// server's own wallet, so if a reload overwrote its deferred issuances from a
// disk copy written before the deferral was recorded, a busy demo would wipe
// the record moments after it was made and never collect the credential.
func TestReloadKeepsUnpersistedDeferral(t *testing.T) {
	srv := newTestServer(t, true)
	store := NewWalletStore(t.TempDir())
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("initializing store: %v", err)
	}
	srv.SetStore(store)

	srv.wallet.AddDeferredIssuance(&DeferredIssuance{
		ID:            "pending-1",
		TransactionID: "tx-1",
		Issuer:        "https://issuer.test.example",
		NextAttemptAt: time.Now().Add(time.Minute),
	})

	if err := srv.reloadFromStore(); err != nil {
		t.Fatalf("reloadFromStore: %v", err)
	}

	deferrals := srv.wallet.DeferredIssuanceList()
	if len(deferrals) != 1 || deferrals[0].ID != "pending-1" {
		t.Fatalf("a per-request reload wiped the just-recorded deferral: %+v", deferrals)
	}
}
