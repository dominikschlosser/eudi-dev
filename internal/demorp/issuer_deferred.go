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

// Deferred issuance (OpenID4VCI 1.0 §9): the credential endpoint accepts the
// request and returns a transaction id, and the credential is handed over at
// the deferred credential endpoint once it is ready.

package demorp

import (
	"crypto/ecdsa"
	"net/http"
	"time"
)

const (
	// deferredReadyDelay is how long the demo holds a deferred credential before
	// it is ready, long enough for a wallet to show the "awaiting issuance" state
	// and short enough not to make the demo wait.
	deferredReadyDelay = 5 * time.Second
	// deferredPollSeconds is the interval the demo tells a polling wallet to
	// wait between attempts.
	deferredPollSeconds = 2
)

// deferredTicket is an issuance the credential endpoint accepted but has not
// handed over yet. The proof keys and the grant are held so the same credential
// batch can be signed once it is ready.
type deferredTicket struct {
	holderKeys []*ecdsa.PublicKey
	granted    ticketGrant
	token      string
	readyAt    time.Time
	expires    time.Time
}

// deferIssuance stores a pending issuance and returns the transaction id a
// wallet polls the deferred endpoint with.
func (d *DemoRP) deferIssuance(holderKeys []*ecdsa.PublicKey, granted ticketGrant, token string) string {
	txID := randToken()
	now := time.Now()
	d.mu.Lock()
	d.deferred[txID] = &deferredTicket{
		holderKeys: holderKeys,
		granted:    granted,
		token:      token,
		readyAt:    now.Add(deferredReadyDelay),
		expires:    now.Add(entryTTL),
	}
	d.mu.Unlock()
	return txID
}

// handleDeferredCredential is the Deferred Credential Endpoint of §9.2. It
// answers with a transaction_id and an interval while the credential is not
// ready, and with the credentials array once it is.
func (d *DemoRP) handleDeferredCredential(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	token, ok := accessToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	var req struct {
		TransactionID string `json:"transaction_id"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_credential_request", err.Error()))
		return
	}

	d.mu.Lock()
	pending, known := d.deferred[req.TransactionID]
	if known && time.Now().After(pending.expires) {
		delete(d.deferred, req.TransactionID)
		known = false
	}
	d.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_transaction_id", "unknown or expired transaction id"))
		return
	}
	// The deferred request carries the same access token as the one that
	// started the issuance, so a different token cannot collect the credential.
	if pending.token != token {
		writeJSON(w, http.StatusUnauthorized, oauthError("invalid_token", "the access token does not match this transaction"))
		return
	}
	if pending.granted.jkt != "" {
		presented, err := d.verifyDPoPProof(r, d.issuerID()+"/deferred_credential", token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, oauthError("invalid_dpop_proof", err.Error()))
			return
		}
		if presented != pending.granted.jkt {
			writeJSON(w, http.StatusUnauthorized, oauthError("invalid_token", "the access token is bound to a different DPoP key"))
			return
		}
	}

	if time.Now().Before(pending.readyAt) {
		// §9.2: still working, a 202 with the transaction id and an interval.
		writeJSON(w, http.StatusAccepted, map[string]any{
			"transaction_id": req.TransactionID,
			"interval":       deferredPollSeconds,
		})
		return
	}

	// Claim the transaction before signing, so two polls that arrive at once
	// issue the batch once, not twice.
	d.mu.Lock()
	_, stillPending := d.deferred[req.TransactionID]
	delete(d.deferred, req.TransactionID)
	d.mu.Unlock()
	if !stillPending {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_transaction_id", "the credential was already collected"))
		return
	}
	credentials, err := d.signBatch(pending.holderKeys, pending.granted)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, oauthError("server_error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": credentials})
}
