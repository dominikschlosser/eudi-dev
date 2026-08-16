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

package demorp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Interactive Authorization (OpenID4VCI 1.1 §6): this issuer asks for a PID
// before it issues a ticket, and does it at the Authorization Challenge
// Endpoint rather than by sending the user to a browser. It acts as the
// Verifier of that presentation itself.
const (
	interactionTypePresentation = "urn:openid:dcp:ia:openid4vp_presentation"

	// challengePath is where the endpoint is mounted under the issuer.
	challengePath = "/authorize-challenge"
)

// interactiveSession is one Authorization Challenge conversation: what the
// wallet asked for in its initial request, and the presentation this issuer
// asked for in return.
type interactiveSession struct {
	id            string
	clientID      string
	scope         string
	codeChallenge string
	issuerState   string
	request       *requestState
	expires       time.Time
}

// challengeEndpoint is the URL wallets are told to use, and the value every
// presentation made through it is bound to.
func (d *DemoRP) challengeEndpoint() string {
	return d.issuerID() + challengePath
}

// handleAuthorizationChallenge is the Authorization Challenge Endpoint of
// §6.1. The first request is answered with the presentation this issuer
// requires (§6.2.1.1), and the request carrying that presentation is answered
// with an authorization code.
func (d *DemoRP) handleAuthorizationChallenge(w http.ResponseWriter, r *http.Request) {
	// The endpoint is DPoP-bound and client-authenticated like the token
	// endpoint: §6.1 notes a Wallet Attestation "has to be included in this
	// request" where the server requires one.
	jkt, err := d.verifyDPoPProof(r, d.challengeEndpoint(), "")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", err.Error()))
		return
	}
	clientID := r.PostFormValue("client_id")
	if _, authErr := d.authenticateClient(r, clientID, jkt); authErr != nil {
		writeJSON(w, http.StatusUnauthorized, oauthError(authErr.code, authErr.description))
		return
	}

	if session := strings.TrimSpace(r.PostFormValue("auth_session")); session != "" {
		d.continueInteractiveAuthorization(w, r, session, clientID)
		return
	}
	d.startInteractiveAuthorization(w, r, clientID)
}

// startInteractiveAuthorization answers an Initial Request (§6.1.1) with the
// Interaction Required Response of §6.2.1.
func (d *DemoRP) startInteractiveAuthorization(w http.ResponseWriter, r *http.Request, clientID string) {
	if got := r.PostFormValue("response_type"); got != "code" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", fmt.Sprintf("response_type must be code, got %q", got)))
		return
	}
	if clientID == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "client_id is required"))
		return
	}
	// §6.2.2: the wallet offered no interaction type this server can finish
	// the authorization with.
	if !offersInteractionType(r.PostFormValue("interaction_types_supported"), interactionTypePresentation) {
		writeJSON(w, http.StatusBadRequest, oauthError("missing_interaction_type",
			"interaction_types_supported in the request is missing the required interaction type '"+interactionTypePresentation+"'"))
		return
	}
	codeChallenge := r.PostFormValue("code_challenge")
	if codeChallenge == "" || r.PostFormValue("code_challenge_method") != "S256" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "code_challenge with code_challenge_method S256 is required"))
		return
	}

	request := d.newInteractivePIDRequest()
	session := &interactiveSession{
		id:            randToken(),
		clientID:      clientID,
		scope:         r.PostFormValue("scope"),
		codeChallenge: codeChallenge,
		issuerState:   r.PostFormValue("issuer_state"),
		request:       request,
		expires:       time.Now().Add(entryTTL),
	}

	d.mu.Lock()
	d.pruneLocked()
	if len(d.interactive) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open authorization sessions, try again later"})
		return
	}
	d.interactive[session.id] = session
	d.requests[request.id] = request
	d.mu.Unlock()

	log.Printf("[Demo issuer] interactive authorization: asking %s for a PID before issuing", clientID)
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":                     "insufficient_authorization",
		"interaction_type_required": interactionTypePresentation,
		"auth_session":              session.id,
		"openid4vp_request":         d.interactivePresentationRequest(request),
	})
}

// continueInteractiveAuthorization reads the presentation out of an
// Intermediate Request (§6.1.2), verifies it, and issues the authorization
// code that the token endpoint then exchanges.
func (d *DemoRP) continueInteractiveAuthorization(w http.ResponseWriter, r *http.Request, sessionID, clientID string) {
	d.mu.Lock()
	session, known := d.interactive[sessionID]
	if known && time.Now().After(session.expires) {
		delete(d.interactive, sessionID)
		known = false
	}
	d.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "unknown or expired auth_session"))
		return
	}
	if clientID != "" && clientID != session.clientID {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "client_id does not match the authorization session"))
		return
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(r.PostFormValue("openid4vp_response")), &response); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "openid4vp_response is not a JSON object: "+err.Error()))
		return
	}
	// §6.2.1.1 lets the wallet answer with the Authorization Error Response
	// instead of a presentation, which is how it says it cannot satisfy the
	// request.
	if refusal, _ := response["error"].(string); refusal != "" {
		detail, _ := response["error_description"].(string)
		d.finishRequest(session.request, nil, nil, fmt.Errorf("the wallet refused: %s", strings.TrimSpace(refusal+" "+detail)))
		writeJSON(w, http.StatusBadRequest, oauthError("access_denied", "the wallet did not present a credential: "+refusal))
		return
	}

	vpToken, err := json.Marshal(response["vp_token"])
	if err != nil || response["vp_token"] == nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "openid4vp_response carried no vp_token"))
		return
	}

	// The same verification an OpenID4VP response gets, which includes the
	// nonce this session handed out: §6.2.1.4 requires the presentation to be
	// bound to the authorization session, and the nonce is what binds it.
	claims, checks, verifyErr := d.verifyPresentation(session.request, string(vpToken))
	d.finishRequest(session.request, claims, checks, verifyErr)
	if verifyErr != nil {
		log.Printf("[Demo issuer] interactive authorization: presentation refused: %v", verifyErr)
		writeJSON(w, http.StatusBadRequest, oauthError("access_denied", "the presentation could not be verified: "+verifyErr.Error()))
		return
	}

	code := randToken()
	granted := &authRequestState{
		clientID:      session.clientID,
		scope:         session.scope,
		codeChallenge: session.codeChallenge,
		issuerState:   session.issuerState,
		code:          code,
		subject:       presentedHolder(claims),
		holderClaims:  claims,
		expires:       time.Now().Add(entryTTL),
	}
	d.mu.Lock()
	d.codes[code] = granted
	delete(d.interactive, sessionID)
	d.mu.Unlock()

	log.Printf("[Demo issuer] interactive authorization: presentation verified, issuing an authorization code to %s", session.clientID)
	writeJSON(w, http.StatusOK, map[string]any{"authorization_code": code})
}

// newInteractivePIDRequest builds the presentation this issuer asks for: a PID
// in either format, bound to the Authorization Challenge Endpoint.
func (d *DemoRP) newInteractivePIDRequest() *requestState {
	return &requestState{
		id:                  randToken(),
		queryID:             "pid",
		mdocQueryID:         "pid_mdoc",
		vct:                 PIDVCT,
		docType:             PIDDocType,
		want:                []string{"given_name", "family_name"},
		wantMDOC:            []string{"given_name", "family_name"},
		nonce:               randToken(),
		clientID:            d.issuerID(),
		interactiveEndpoint: d.challengeEndpoint(),
		status:              "pending",
		expires:             time.Now().Add(entryTTL),
	}
}

// interactivePresentationRequest is the openid4vp_request of §6.2.1.1: an
// OpenID4VP Authorization Request shaped as the Digital Credentials API takes
// one, with the response mode that sends the answer back here.
//
// It is sent unsigned, which is the form the draft's own example uses. The
// binding does not depend on a signature: the wallet checks expected_origins
// against the endpoint it called, and the presentation it signs names that
// endpoint (§6.2.1.5).
func (d *DemoRP) interactivePresentationRequest(req *requestState) map[string]any {
	return map[string]any{
		"response_type":    "vp_token",
		"response_mode":    "ia_post",
		"nonce":            req.nonce,
		"expected_origins": []string{originOf(d.challengeEndpoint())},
		"dcql_query": map[string]any{
			"credentials": []map[string]any{
				{
					"id":     req.queryID,
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []string{req.vct}},
					"claims": claimPaths(req.want),
				},
				{
					"id":     req.mdocQueryID,
					"format": "mso_mdoc",
					"meta":   map[string]any{"doctype_value": req.docType},
					"claims": namespacedClaimPaths(req.docType, req.wantMDOC),
				},
			},
			// Either format satisfies the request, so a wallet holding one of
			// them is not asked for both.
			"credential_sets": []map[string]any{{
				"options": [][]string{{req.queryID}, {req.mdocQueryID}},
			}},
		},
	}
}

func claimPaths(names []string) []map[string]any {
	paths := make([]map[string]any, 0, len(names))
	for _, name := range names {
		paths = append(paths, map[string]any{"path": []string{name}})
	}
	return paths
}

func namespacedClaimPaths(namespace string, names []string) []map[string]any {
	paths := make([]map[string]any, 0, len(names))
	for _, name := range names {
		paths = append(paths, map[string]any{"path": []string{namespace, name}})
	}
	return paths
}

// offersInteractionType reports whether a comma-separated
// interaction_types_supported names the given type (§6.1.1).
func offersInteractionType(list, want string) bool {
	for _, entry := range strings.Split(list, ",") {
		if strings.TrimSpace(entry) == want {
			return true
		}
	}
	return false
}

// presentedHolder names the person the presented PID identifies, so the
// credential this issues carries the holder who authorized it rather than the
// demo account no one signed in as.
func presentedHolder(claims map[string]any) string {
	given, _ := claims["given_name"].(string)
	family, _ := claims["family_name"].(string)
	if name := strings.TrimSpace(given + " " + family); name != "" {
		return name
	}
	return demoAccountUsername
}
