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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/config"
)

// handleListRequests returns the pending consent requests this caller may see.
func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Vary", "Cookie, "+OwnerHeader)
	writeJSON(w, http.StatusOK, s.wallet.PendingRequestDocsFor(callerOwners(r), namedRequest(r)))
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

	// The server's write timeout covers the whole response and would end the
	// stream mid-session. The deadline is pushed forward before every write
	// rather than removed, so a client that stops reading still releases the
	// handler and its subscriptions.
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
	// No Access-Control-Allow-Origin: this stream carries the claims a
	// verifier asked for, and the only browser client is the wallet's own
	// same-origin UI. A wildcard would let any page the user visits subscribe.
	// Non-browser clients do not enforce CORS.
	flusher.Flush()

	owners := callerOwners(r)

	reqCh, reqUnsub := s.wallet.Subscribe()
	defer reqUnsub()
	errCh, errUnsub := s.wallet.SubscribeErrors()
	defer errUnsub()
	stateCh, stateUnsub := s.wallet.SubscribeState()
	defer stateUnsub()
	authCh, authUnsub := s.wallet.SubscribeAuthorization()
	defer authUnsub()

	// Proxies drop idle connections and each reconnect is another request, so
	// a comment line keeps the connection up.
	keepalive := time.NewTicker(sseKeepaliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case <-keepalive.C:
			extendDeadline()
			if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case req := <-reqCh:
			// A request belongs to the browser that started it. Another
			// visitor's stream carries neither the event nor the claims the
			// verifier asked for.
			if !ownsRequest(owners, req, "") {
				continue
			}
			data, err := json.Marshal(s.wallet.RequestDocFor(req, owners))
			if err != nil {
				continue
			}
			extendDeadline()
			if _, err := fmt.Fprintf(w, "event: consent\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case walletErr := <-errCh:
			// A failure belongs to the flow that raised it, so it reaches the
			// browser that started that flow. One with no owner came from a
			// client that named no browser, and is everyone's to see.
			if walletErr.Owner != "" && !ownedBy(owners, walletErr.Owner) {
				continue
			}
			data, err := json.Marshal(walletErr)
			if err != nil {
				continue
			}
			extendDeadline()
			// Not "error": an EventSource dispatches a named event of that
			// type at itself, where it would also run the handler for a lost
			// connection and tear the stream down on every reported error.
			if _, err := fmt.Fprintf(w, "event: wallet-error\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case <-stateCh:
			extendDeadline()
			if _, err := fmt.Fprintf(w, "event: state\ndata: {}\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case prompt := <-authCh:
			// The sign-in navigates a tab to the issuer, so it goes to the
			// browser whose issuance it is and to no other.
			if !ownedBy(owners, prompt.Owner) {
				continue
			}
			// An issuance is waiting for the user to authenticate at the
			// issuer. The UI navigates there and comes back through
			// /callback, which resumes the flow already in progress.
			data, err := json.Marshal(map[string]string{"url": prompt.URL})
			if err != nil {
				continue
			}
			extendDeadline()
			if _, err := fmt.Fprintf(w, "event: authorize\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// allowSlowResponse pushes this response's write deadline past a wait longer
// than config.SlowRequestTimeout. Without it the answer is written to a
// connection Go already closed, and a URL handler takes the dropped connection
// for a failure and dispatches the same offer again.
func (s *Server) allowSlowResponse(w http.ResponseWriter, wait time.Duration) {
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(wait + config.SlowRequestTimeout))
	// A browser redirected on its way in leaves the flow running against a
	// writer that carries no deadline, so there is none to miss either.
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.log("  WARNING: write deadline not extended, a slow answer may not reach the caller: %v", err)
	}
}

// refusalReason says why a request can no longer be answered. A request that
// ran out of time was not answered by anybody, and saying it was sends the
// user looking for the tab that did it.
func refusalReason(status string) string {
	if status == statusExpired {
		return "This request timed out before it was answered"
	}
	return "This request was already answered"
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
		if !ownsRequest(callerOwners(r), pending, namedRequest(r)) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
			return
		}
		if err := ValidateConsentSelection(pending.CredentialOptions, body.Picks, body.SetChoices); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	req, ok := s.wallet.ResolveRequest(id, "approved")
	if !ok {
		if req == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
		} else {
			writeJSON(w, http.StatusConflict, map[string]string{"error": refusalReason(req.Status)})
		}
		return
	}

	req.ResultCh <- ConsentResult{
		Approved:       true,
		Owner:          requestOwner(r),
		SelectedClaims: body.SelectedClaims,
		TxCode:         strings.TrimSpace(body.TxCode),
		Picks:          body.Picks,
		SetChoices:     body.SetChoices,
	}

	// Wait for the submission so the UI gets its result.
	s.allowSlowResponse(w, config.SlowRequestTimeout)
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
	if pending, ok := s.wallet.GetRequest(id); ok && !ownsRequest(callerOwners(r), pending, namedRequest(r)) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
		return
	}
	req, ok := s.wallet.ResolveRequest(id, "denied")
	if !ok {
		if req == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
		} else {
			writeJSON(w, http.StatusConflict, map[string]string{"error": refusalReason(req.Status)})
		}
		return
	}

	req.ResultCh <- ConsentResult{Approved: false}

	writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
}
