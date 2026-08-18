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

// Pending consent requests and the event stream the UI follows them on.

package wallet

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/config"
)

// handleListRequests returns all pending consent requests.
func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.wallet.PendingRequestDocs())
}

// streamWriteTimeout bounds one write to an event stream. It outlasts the
// keepalive, so a reading client never hits it, while a client that stopped
// reading stops holding a goroutine and its subscriptions.
var streamWriteTimeout = 2 * time.Minute

// sseKeepaliveInterval is how often an otherwise idle event stream sends a
// comment line. A variable so tests do not have to wait for it.
var sseKeepaliveInterval = 25 * time.Second

// handleRequestStream provides SSE for new consent requests and error events.
func (s *Server) handleRequestStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// A stream outlives the server's write timeout by definition, and that
	// deadline covers the whole response: left in place it ends the stream
	// mid-session, and a consent request arriving before the UI reconnects
	// is one no tab is told about. It is pushed forward before every write
	// rather than removed, so a client that stops reading still releases the
	// handler and its subscriptions instead of holding them indefinitely.
	rc := http.NewResponseController(w)
	extendDeadline := func() {
		if err := rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout)); err != nil {
			s.log("  WARNING: event stream write deadline not extended, the stream ends with the server's write timeout: %v", err)
		}
	}
	extendDeadline()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// No Access-Control-Allow-Origin: this stream carries consent requests
	// with the claims a verifier asked for, and the only browser client is
	// the wallet's own UI, which is same-origin. A wildcard let any page the
	// user happened to visit subscribe to it. Non-browser clients (the CLI,
	// the conformance runner) do not enforce CORS and are unaffected.
	flusher.Flush()

	reqCh, reqUnsub := s.wallet.Subscribe()
	defer reqUnsub()
	errCh, errUnsub := s.wallet.SubscribeErrors()
	defer errUnsub()
	stateCh, stateUnsub := s.wallet.SubscribeState()
	defer stateUnsub()
	authCh, authUnsub := s.wallet.SubscribeAuthorization()
	defer authUnsub()

	// An idle stream sends nothing for minutes at a time, and proxies drop
	// idle connections. The client reconnects, so nothing breaks, but each
	// reconnect is another request. A comment line keeps the connection up.
	keepalive := time.NewTicker(sseKeepaliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case <-keepalive.C:
			extendDeadline()
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case req := <-reqCh:
			data, err := json.Marshal(s.wallet.RequestDoc(req))
			if err != nil {
				continue
			}
			extendDeadline()
			fmt.Fprintf(w, "event: consent\ndata: %s\n\n", data)
			flusher.Flush()
		case walletErr := <-errCh:
			data, err := json.Marshal(walletErr)
			if err != nil {
				continue
			}
			extendDeadline()
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
			flusher.Flush()
		case <-stateCh:
			extendDeadline()
			fmt.Fprintf(w, "event: state\ndata: {}\n\n")
			flusher.Flush()
		case authURL := <-authCh:
			// An issuance is waiting for the user to authenticate at the
			// issuer. The UI navigates there and comes back through
			// /callback, which resumes the flow already in progress.
			data, err := json.Marshal(map[string]string{"url": authURL})
			if err != nil {
				continue
			}
			extendDeadline()
			fmt.Fprintf(w, "event: authorize\ndata: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// handleApproveRequest approves a consent request and waits for the submission result.
func (s *Server) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body struct {
		SelectedClaims map[string][]string `json:"selected_claims"`
		TxCode         string              `json:"tx_code"`
		// Picks and SetChoices are the credential selection made in the
		// dialog's Edit view, referencing the request's credential_options.
		Picks      map[string]string `json:"picks"`
		SetChoices []int             `json:"set_choices"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}

	// Checked against the pending request before it is resolved, so a bad
	// selection leaves the dialog open instead of consuming the consent.
	if pending, ok := s.wallet.GetRequest(id); ok {
		if err := ValidateConsentSelection(pending.CredentialOptions, body.Picks, body.SetChoices); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	req, ok := s.wallet.ResolveRequest(id, "approved")
	if !ok {
		if req == nil {
			http.Error(w, "request not found", http.StatusNotFound)
		} else {
			http.Error(w, "request already resolved", http.StatusConflict)
		}
		return
	}

	req.ResultCh <- ConsentResult{
		Approved:       true,
		SelectedClaims: body.SelectedClaims,
		TxCode:         strings.TrimSpace(body.TxCode),
		Picks:          body.Picks,
		SetChoices:     body.SetChoices,
	}

	// Wait for the VP submission to complete so we can return the result to the UI
	select {
	case submission := <-req.SubmissionCh:
		out := map[string]any{
			"status":       "approved",
			"redirect_uri": submission.RedirectURI,
			"error":        submission.Error,
			"status_code":  submission.StatusCode,
		}
		if submission.Pending {
			// The issuer deferred the credential. Saying "approved" with no
			// error would read as issued, so the outcome is named.
			out["status"] = "pending"
			out["pending"] = true
			out["transaction_id"] = submission.TransactionID
			out["retry_interval"] = submission.RetryInterval
		}
		writeJSON(w, http.StatusOK, out)
	case <-time.After(config.SlowRequestTimeout):
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "approved",
			"error":  "submission timeout",
		})
	}
}

// handleDenyRequest denies a consent request.
func (s *Server) handleDenyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.wallet.ResolveRequest(id, "denied")
	if !ok {
		if req == nil {
			http.Error(w, "request not found", http.StatusNotFound)
		} else {
			http.Error(w, "request already resolved", http.StatusConflict)
		}
		return
	}

	req.ResultCh <- ConsentResult{Approved: false}

	writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
}
