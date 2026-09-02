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
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// Interactive Authorization (OpenID4VCI 1.1 §6) replaces the browser redirect
// of the authorization code grant with a conversation at the Authorization
// Challenge Endpoint.
const (
	// interactionTypePresentation is the OpenID4VP presentation interaction of
	// §6.2.1.1.
	interactionTypePresentation = "urn:openid:dcp:ia:openid4vp_presentation"

	// interactionTypeAuthViaWeb is the browser interaction of §6.2.1.2: the
	// server hands over a request_uri, the wallet sends the user's browser to
	// the authorization endpoint with it (RFC 9126 §4), and the redirect back
	// carries the code or an auth_session to continue with.
	interactionTypeAuthViaWeb = "urn:openid:dcp:ia:auth_via_web"

	// errorInsufficientAuthorization is what an Interaction Required Response
	// carries (§6.2.1). The member is error: the draft's prose says error_code
	// once, but its examples, first-party-apps §5.2.2 and RFC 6749 §5.2 agree
	// on error.
	errorInsufficientAuthorization = "insufficient_authorization"

	// errorRedirectToWeb is the authorization server saying this exchange
	// cannot be finished with the wallet and belongs in a browser (Section
	// 5.2.2.1.1 of the first-party-apps specification).
	errorRedirectToWeb = "redirect_to_web"
)

// redirectToWebError carries a redirect_to_web response back to the caller,
// which owns the redirect flow this falls back to. requestURI is the pushed
// request the server offered, empty when it offered none and the wallet starts
// its own authorization request instead.
type redirectToWebError struct {
	requestURI string
}

func (e *redirectToWebError) Error() string {
	return "the authorization server asked for the authorization to continue in a browser (redirect_to_web)"
}

func isRedirectToWeb(err error) bool {
	var target *redirectToWebError
	return errors.As(err, &target)
}

func redirectToWebRequestURI(err error) string {
	var target *redirectToWebError
	if errors.As(err, &target) {
		return target.requestURI
	}
	return ""
}

// noteRedirectToWeb records the handover to the browser, and refuses it where
// this wallet has nothing to hand over to: the redirect flow needs a redirect
// URI it can be called back at, which interactive authorization did not.
func (w *Wallet) noteRedirectToWeb(endpoint, redirectURI, authorizationEndpoint string) error {
	if redirectURI == "" {
		return fmt.Errorf("the authorization server asked for a browser sign-in (redirect_to_web), which needs a redirect URI: run the wallet with --vci-redirect-uri")
	}
	if authorizationEndpoint == "" {
		return fmt.Errorf("the authorization server asked for a browser sign-in (redirect_to_web) but published no authorization_endpoint")
	}
	w.addProtocolLog("issuance", "interactive_authorization_redirect_to_web",
		"Authorization server sent the sign-in to a browser", true, map[string]any{
			"authorization_challenge_endpoint": endpoint,
			"authorization_endpoint":           authorizationEndpoint,
		})
	return nil
}

// maxInteractiveAuthorizationRounds bounds the conversation, so a server that
// keeps asking for interactions is eventually walked away from.
const maxInteractiveAuthorizationRounds = 8

// interactiveAuthorizationConsentTimeout matches the OpenID4VP endpoint's
// consent timeout.
const interactiveAuthorizationConsentTimeout = 5 * time.Minute

// interactiveAuthorizationEndpoint reads the Authorization Challenge Endpoint
// out of authorization server metadata.
func interactiveAuthorizationEndpoint(oauthMeta map[string]any) string {
	endpoint, _ := oauthMeta["authorization_challenge_endpoint"].(string)
	return strings.TrimSpace(endpoint)
}

// interactionTypesSupported is what the wallet advertises in the initial
// request (§6.1.1). Only what it can carry out is listed: §6.2.1 makes a
// wallet abort on a type it does not support. The browser interaction needs a
// redirect URI and an authorization endpoint, so it is offered only where both
// exist.
func (w *Wallet) interactionTypesSupported(setup authorizationCodeSetup) []string {
	types := []string{interactionTypePresentation}
	if setup.redirectURI != "" && setup.authorizationEndpoint != "" {
		types = append(types, interactionTypeAuthViaWeb)
	}
	return types
}

// obtainInteractiveAuthorizationCode runs the Authorization Challenge
// conversation of §6.1 and §6.2 and returns the authorization code. viaWeb
// reports that the code came through the auth_via_web browser redirect rather
// than from the challenge endpoint, in which case the token request has to
// repeat the redirect URI (RFC 6749 §4.1.3).
func (w *Wallet) obtainInteractiveAuthorizationCode(endpoint string, setup authorizationCodeSetup, offer *oid4vc.CredentialOffer) (code string, viaWeb bool, err error) {
	form := w.initialAuthorizationChallengeForm(setup, offer)
	if err := applyClientAuthentication(form, setup.clientAuth, w.HolderKey); err != nil {
		return "", false, err
	}

	var authSession string
	for round := 1; round <= maxInteractiveAuthorizationRounds; round++ {
		response, err := w.postAuthorizationChallenge(endpoint, form, setup)
		if err != nil {
			return "", false, err
		}

		// §5.3.1 of the first-party-apps specification: "Every response
		// defined by this specification may include a new auth_session value.
		// Clients MUST NOT assume that auth_session values are static."
		if session := jsonutil.GetString(response, "auth_session"); session != "" {
			authSession = session
		}

		code, err := w.authorizationChallengeCode(response)
		if err != nil {
			return "", false, err
		}
		if code != "" {
			return code, false, nil
		}

		errorCode := jsonutil.GetString(response, "error")
		if errorCode == errorRedirectToWeb {
			return "", false, &redirectToWebError{requestURI: jsonutil.GetString(response, "request_uri")}
		}
		if errorCode != errorInsufficientAuthorization {
			return "", false, authorizationChallengeError(response)
		}
		// §6.2.1 makes auth_session REQUIRED here. Without it the next
		// request would start a new conversation.
		if authSession == "" {
			return "", false, fmt.Errorf("authorization server asked for an interaction without an auth_session (OpenID4VCI 1.1 §6.2.1)")
		}

		outcome, err := w.runAuthorizationInteraction(endpoint, response, setup)
		if err != nil {
			return "", false, err
		}
		// The browser interaction can finish the authorization on its own:
		// the redirect back to the wallet carries the code (§6.2.1.2).
		if outcome.code != "" {
			return outcome.code, true, nil
		}
		if outcome.authSession != "" {
			authSession = outcome.authSession
		}

		next := outcome.form
		if next == nil {
			next = url.Values{}
		}
		next.Set("auth_session", authSession)
		if setup.clientID != "" {
			next.Set("client_id", setup.clientID)
		}
		if err := applyClientAuthentication(next, setup.clientAuth, w.HolderKey); err != nil {
			return "", false, err
		}
		form = next
	}

	return "", false, fmt.Errorf("interactive authorization did not finish after %d rounds", maxInteractiveAuthorizationRounds)
}

// interactionOutcome is what one performed interaction produced: the
// parameters answering it in the next Intermediate Request (§6.1.2), or, for
// the browser interaction, what the redirect back to the wallet carried
// (§6.2.1.2): the authorization code, or an auth_session that replaces the
// current one and continues the conversation.
type interactionOutcome struct {
	form        url.Values
	code        string
	authSession string
}

// initialAuthorizationChallengeForm builds the Initial Request of §6.1.1.
func (w *Wallet) initialAuthorizationChallengeForm(setup authorizationCodeSetup, offer *oid4vc.CredentialOffer) url.Values {
	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", setup.clientID)
	form.Set("scope", setup.scope)
	// Carried so a server that answers redirect_to_web can put it in the
	// authorization request it hands back. The redirect flow's callback is
	// matched by it.
	form.Set("state", setup.state)
	form.Set("code_challenge", setup.codeChallenge)
	form.Set("code_challenge_method", "S256")
	form.Set("interaction_types_supported", strings.Join(w.interactionTypesSupported(setup), ","))
	// A redirect URI is sent only where one was configured. It is what
	// auth_via_web comes back to.
	if setup.redirectURI != "" {
		form.Set("redirect_uri", setup.redirectURI)
	}
	if offer != nil && offer.Grants.IssuerState != "" {
		form.Set("issuer_state", offer.Grants.IssuerState)
	}
	return form
}

// postAuthorizationChallenge sends one request to the Authorization Challenge
// Endpoint and returns the JSON document it answered with. The body decides
// rather than the status: an Interaction Required Response (§6.2.1) is a 403
// carrying the request the wallet has to answer.
func (w *Wallet) postAuthorizationChallenge(endpoint string, form url.Values, setup authorizationCodeSetup) (map[string]any, error) {
	w.addProtocolLog("issuance", "authorization_challenge_request",
		fmt.Sprintf("Authorization challenge request to %s", endpoint), true,
		formRequestLogDetails(endpoint, "authorization_challenge", form))

	body := []byte(form.Encode())
	respBody, status, reqErr := doDPoPRequest("POST", endpoint, "application/x-www-form-urlencoded", "", body,
		"", "", setup.dpopKey, &setup.nonces.authzServer, w.attestorFor(setup.clientAuth))

	var response map[string]any
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &response); err != nil {
			response = nil
		}
	}
	if response == nil {
		err := reqErr
		if err == nil {
			err = fmt.Errorf("authorization challenge response was not JSON")
		}
		w.addProtocolLog("issuance", "authorization_challenge_response",
			fmt.Sprintf("Authorization challenge response from %s", endpoint), false,
			responseMapLogDetails(endpoint, "authorization_challenge", nil, err))
		return nil, fmt.Errorf("authorization challenge request: %w", err)
	}

	details := responseMapLogDetails(endpoint, "authorization_challenge", response, nil)
	details["status_code"] = status
	// An Interaction Required Response carries an error member and a 403. It
	// is recorded as a successful step.
	errorCode := jsonutil.GetString(response, "error")
	w.addProtocolLog("issuance", "authorization_challenge_response",
		fmt.Sprintf("Authorization challenge response from %s", endpoint),
		errorCode == "" || errorCode == errorInsufficientAuthorization, details)
	return response, nil
}

// authorizationChallengeCode reads the Authorization Code Response of
// first-party-apps §5.2.1, which carries the code in authorization_code.
func (w *Wallet) authorizationChallengeCode(response map[string]any) (string, error) {
	if code := jsonutil.GetString(response, "authorization_code"); code != "" {
		return code, nil
	}
	// A server answering with the redirect flow's parameter name has finished
	// the authorization and named it wrongly.
	if code := jsonutil.GetString(response, "code"); code != "" {
		if err := w.reportServerDeviation("authorization challenge response carried the authorization code in \"code\". Section 5.2.1 of the OAuth 2.0 for First-Party Applications specification names it \"authorization_code\""); err != nil {
			return "", err
		}
		return code, nil
	}
	return "", nil
}

// authorizationChallengeError renders an Authorization Challenge Error
// Response (§6.2.2) as an error.
func authorizationChallengeError(response map[string]any) error {
	code := jsonutil.GetString(response, "error")
	if code == "" {
		return fmt.Errorf("authorization challenge response carried neither an authorization code nor an error")
	}
	if description := jsonutil.GetString(response, "error_description"); description != "" {
		return fmt.Errorf("authorization challenge failed: %s: %s", code, description)
	}
	return fmt.Errorf("authorization challenge failed: %s", code)
}

// runAuthorizationInteraction performs the interaction the server asked for.
func (w *Wallet) runAuthorizationInteraction(endpoint string, response map[string]any, setup authorizationCodeSetup) (*interactionOutcome, error) {
	interaction := jsonutil.GetString(response, "interaction_type_required")
	switch interaction {
	case interactionTypePresentation:
		form, err := w.runPresentationInteraction(endpoint, response, setup)
		if err != nil {
			return nil, err
		}
		return &interactionOutcome{form: form}, nil
	case interactionTypeAuthViaWeb:
		if setup.redirectURI == "" || setup.authorizationEndpoint == "" {
			// The wallet did not advertise this type (§6.2.1).
			return nil, fmt.Errorf("authorization server asked for the %s interaction, which this wallet did not advertise (it needs a redirect URI and an authorization endpoint)", interactionTypeAuthViaWeb)
		}
		return w.runAuthViaWebInteraction(response, setup)
	case "":
		return nil, fmt.Errorf("authorization server asked for an interaction without naming its type (OpenID4VCI 1.1 §6.2.1 makes interaction_type_required REQUIRED)")
	default:
		// §6.2.1: "If a Wallet receives an interaction_type_required value
		// that it does not support, it MUST abort the issuance process."
		return nil, fmt.Errorf("authorization server asked for the unsupported interaction type %q", interaction)
	}
}

// runAuthViaWebInteraction performs the browser interaction of §6.2.1.2. The
// server's response carries a request_uri, which "the Wallet MUST use ... to
// build an Authorization Request as defined in Section 4 of RFC9126". The
// wallet hands that URL to the user's browser and waits for the redirect
// back, which carries the authorization code when the authorization is
// complete, or an auth_session when further steps remain at the challenge
// endpoint.
func (w *Wallet) runAuthViaWebInteraction(response map[string]any, setup authorizationCodeSetup) (*interactionOutcome, error) {
	requestURI := strings.TrimSpace(jsonutil.GetString(response, "request_uri"))
	if requestURI == "" {
		return nil, fmt.Errorf("authorization server asked for the %s interaction without a request_uri (OpenID4VCI 1.1 §6.2.1.2)", interactionTypeAuthViaWeb)
	}

	w.addProtocolLog("issuance", "interactive_authorization_auth_via_web",
		"Authorization server asked for a browser sign-in (auth_via_web)", true, map[string]any{
			"authorization_endpoint": setup.authorizationEndpoint,
			"request_uri":            requestURI,
		})

	values, err := runAuthorizationCodeRequest(w, setup.authorizationEndpoint, setup.clientID, requestURI, nil, setup.redirectURI, setup.state, setup.issuer, setup.owner, setup.issRequired)
	if err != nil {
		return nil, err
	}
	if errorCode := values.Get("error"); errorCode != "" {
		if description := values.Get("error_description"); description != "" {
			return nil, fmt.Errorf("the browser sign-in failed: %s: %s", errorCode, description)
		}
		return nil, fmt.Errorf("the browser sign-in failed: %s", errorCode)
	}
	if code := values.Get("code"); code != "" {
		return &interactionOutcome{code: code}, nil
	}
	if session := values.Get("auth_session"); session != "" {
		return &interactionOutcome{form: url.Values{}, authSession: session}, nil
	}
	return nil, fmt.Errorf("the redirect back from the browser sign-in carried neither a code nor an auth_session (OpenID4VCI 1.1 §6.2.1.2)")
}

// runPresentationInteraction answers a Require Presentation response
// (§6.2.1.1), where the authorization server acts as the Verifier.
func (w *Wallet) runPresentationInteraction(endpoint string, response map[string]any, setup authorizationCodeSetup) (url.Values, error) {
	request, ok := response["openid4vp_request"].(map[string]any)
	if !ok || len(request) == 0 {
		return nil, fmt.Errorf("authorization server asked for a presentation without an openid4vp_request (OpenID4VCI 1.1 §6.2.1.1)")
	}

	authReq, err := w.parseInteractiveAuthorizationRequest(request, endpoint)
	if err != nil {
		return nil, err
	}
	w.addPresentationRequestLogEntry(authReq)

	params := PresentationParams{
		Nonce:                            authReq.Nonce,
		ClientID:                         authReq.ClientID,
		ResponseMode:                     authReq.ResponseMode,
		ClientMetadata:                   authReq.ClientMetadata,
		RequestObject:                    authReq.RequestObject,
		InteractiveAuthorizationEndpoint: endpoint,
	}

	matches, credentialOptions := w.EvaluateDCQLWithOptions(authReq.DCQLQuery)
	if len(matches) == 0 {
		// §6.2.1.1: openid4vp_response "in the case of an error instead
		// encodes the Authorization Error Response parameters", which tells
		// the server why nothing was presented.
		return w.interactionErrorResponse(params, "access_denied", "no credential in this wallet satisfies the request")
	}

	matches, approved, err := w.awaitInteractivePresentationConsent(endpoint, authReq, matches, credentialOptions, setup.presentationConsented, setup.owner)
	if err != nil {
		return nil, err
	}
	if !approved {
		w.AddLog("issuance", "Denied the presentation the issuer asked for", false)
		return w.interactionErrorResponse(params, "access_denied", "user denied the presentation")
	}

	vpResult, err := w.CreateVPTokenMap(matches, params)
	if err != nil {
		return nil, fmt.Errorf("creating the presentation for interactive authorization: %w", err)
	}
	// auth_session correlates the exchange, not state.
	envelope, err := w.BuildAuthorizationResponse(vpResult, "", authReq.State, params)
	if err != nil {
		return nil, fmt.Errorf("building the presentation response for interactive authorization: %w", err)
	}

	encoded, err := encodeInteractiveAuthorizationResponse(envelope)
	if err != nil {
		return nil, err
	}

	w.AddLogDetails("issuance", fmt.Sprintf("Presented %d credential(s) to satisfy interactive authorization", len(matches)), true, map[string]any{
		"event":                            "interactive_authorization_presentation",
		"authorization_challenge_endpoint": endpoint,
		"response_mode":                    params.ResponseMode,
		"query_ids":                        vpResult.QueryIDs(),
	})

	form := url.Values{}
	form.Set("openid4vp_response", encoded)
	return form, nil
}

// interactionErrorResponse answers the interaction with an OpenID4VP error
// instead of a presentation, leaving the server to decide what to do.
func (w *Wallet) interactionErrorResponse(params PresentationParams, errorCode, description string) (url.Values, error) {
	envelope, err := w.BuildAuthorizationErrorResponse(errorCode, description, "", params)
	if err != nil {
		return nil, fmt.Errorf("building the error response for interactive authorization: %w", err)
	}
	encoded, err := encodeInteractiveAuthorizationResponse(envelope)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("openid4vp_response", encoded)
	return form, nil
}

// encodeInteractiveAuthorizationResponse renders an authorization response as
// the openid4vp_response parameter of §6.2.1.1: the response parameters as a
// JSON object, or the JWE under response when encrypted.
func encodeInteractiveAuthorizationResponse(envelope *AuthorizationResponseEnvelope) (string, error) {
	if envelope == nil {
		return "", fmt.Errorf("no authorization response to send")
	}
	payload := envelope.Plain
	if envelope.ResponseJWT != "" {
		payload = map[string]any{"response": envelope.ResponseJWT}
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("authorization response for response_mode %q was empty", envelope.ResponseMode)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encoding openid4vp_response: %w", err)
	}
	return string(encoded), nil
}

// parseInteractiveAuthorizationRequest reads the openid4vp_request of
// §6.2.1.1, whose contents are "the same as for requests passed to the Digital
// Credentials API": a signed Request Object under request, or the parameters
// themselves.
func (w *Wallet) parseInteractiveAuthorizationRequest(request map[string]any, endpoint string) (*AuthorizationRequestParams, error) {
	opts := oid4vc.ParseOptions{
		FetchRequestURI: MakeFetchRequestURI(w, func(format string, args ...any) {
			log.Printf("[VCI] "+format, args...)
		}),
	}

	raw := jsonutil.GetString(request, "request")
	signed := raw != ""
	if !signed {
		encoded, err := json.Marshal(request)
		if err != nil {
			return nil, fmt.Errorf("encoding openid4vp_request: %w", err)
		}
		raw = string(encoded)
	}

	parsed, err := ParseAuthorizationRequestWithOptions(raw, opts)
	if err != nil {
		return nil, fmt.Errorf("parsing openid4vp_request: %w", err)
	}

	params := &AuthorizationRequestParams{
		ClientID:         parsed.ClientID,
		ResponseType:     parsed.ResponseType,
		ResponseMode:     parsed.ResponseMode,
		Nonce:            parsed.Nonce,
		State:            parsed.State,
		RedirectURI:      parsed.RedirectURI,
		ResponseURI:      parsed.ResponseURI,
		Scope:            parsed.Scope,
		RequestURIMethod: parsed.RequestURIMethod,
		RequestURI:       parsed.RequestURI,
		ClientMetadata:   parsed.ClientMetadata,
		DCQLQuery:        parsed.DCQLQuery,
		RequestObject:    parsed.RequestObject,
		RequestPayload:   requestPayload(parsed.RequestObject, parsed.FullJSON),
		Source:           "interactive_authorization",
	}

	// §6.2.1.1: "The response_mode MUST be either ia_post for unencrypted
	// responses or ia_post.jwt for encrypted responses."
	if !isInteractiveAuthorizationResponseMode(params.ResponseMode) {
		return nil, fmt.Errorf("openid4vp_request has response_mode %q, which OpenID4VCI 1.1 §6.2.1.1 does not allow here (ia_post or ia_post.jwt)", params.ResponseMode)
	}

	if err := checkInteractiveAuthorizationOrigins(params.RequestPayload, endpoint); err != nil {
		return nil, err
	}

	findings, err := ValidateAuthorizationRequest(w.Mode(), w.RequireHAIP, params)
	if err != nil {
		return nil, fmt.Errorf("openid4vp_request: %w", err)
	}
	w.warnFindings("issuance", specCitedSummary("The issuer's openid4vp_request", findings), findings)
	w.warnUndefinedRequestParameters("issuance", params)

	return params, nil
}

// checkInteractiveAuthorizationOrigins enforces §6.2.1.1: "If expected_origins
// is present, it MUST contain only the derived Origin of the Authorization
// Challenge Endpoint." It is what detects a request forwarded from another
// authorization server (§6.2.1.5).
//
// Unlike the Digital Credentials API, it is checked on unsigned requests too:
// no platform reports a true origin here.
func checkInteractiveAuthorizationOrigins(payload map[string]any, endpoint string) error {
	if payload == nil {
		return nil
	}
	values := jsonutil.GetArray(payload, "expected_origins")
	if len(values) == 0 {
		return nil
	}
	origin := derivedOrigin(endpoint)
	if origin == "" {
		return fmt.Errorf("cannot derive the origin of the authorization challenge endpoint %q", endpoint)
	}
	for _, value := range values {
		if candidate, ok := value.(string); !ok || strings.TrimSpace(candidate) != origin {
			return fmt.Errorf("openid4vp_request expected_origins must contain only the origin of the authorization challenge endpoint (%s), got %v", origin, values)
		}
	}
	return nil
}

// derivedOrigin is the origin of a URL as RFC 6454 §4 derives it: scheme, host
// and port. §6.2.1.1: "the derived Origin from
// https://example.com/authorize-challenge is https://example.com".
func derivedOrigin(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// awaitInteractivePresentationConsent asks the user to approve the
// presentation the issuer made a condition of issuance. It is asked separately
// from the issuance consent: agreeing to receive a credential is not agreeing
// to disclose one.
func (w *Wallet) awaitInteractivePresentationConsent(endpoint string, authReq *AuthorizationRequestParams, matches []CredentialMatch, credentialOptions *ConsentCredentialOptions, consented bool, owner string) ([]CredentialMatch, bool, error) {
	if w.AutoAccept || consented {
		return matches, true, nil
	}

	// An unsigned request carries no client_id (Appendix A.2), so the party to
	// name is the endpoint this presentation is bound to.
	asking := authReq.ClientID
	if asking == "" {
		asking = derivedOrigin(endpoint)
	}
	consentReq := &ConsentRequest{
		ID: newConsentID(),
		// Its own type: this presentation belongs to an issuance one visitor
		// started, so a shared wallet must not show it to everybody.
		Type:         ConsentTypeIssuancePresentation,
		Owner:        owner,
		MatchedCreds: matches,
		Status:       "pending",
		ResultCh:     make(chan ConsentResult, 1),
		SubmissionCh: make(chan SubmissionResult, 1),
		CreatedAt:    time.Now(),
		ClientID:     asking,
		Nonce:        authReq.Nonce,
		DCQLQuery:    authReq.DCQLQuery,
		Purposes:     w.consentPurposes("issuance", authReq),

		CredentialOptions: credentialOptions,
	}
	consentReq.applyClientAuth(authReq)
	w.CreateConsentRequest(consentReq)

	handle := func(result ConsentResult) ([]CredentialMatch, bool, error) {
		if result.Approved {
			matches = ApplyConsentSelection(consentReq.CredentialOptions, matches, result)
			if result.SelectedClaims != nil {
				for i, match := range matches {
					if selected, ok := result.SelectedClaims[match.CredentialID]; ok {
						matches[i].SelectedKeys = selected
						cred, _ := w.GetCredential(match.CredentialID)
						matches[i].Claims = filterClaims(cred, selected)
					}
				}
			}
		}
		// The approve endpoint waits for this before answering the UI.
		consentReq.SubmissionCh <- SubmissionResult{StatusCode: 200}
		return matches, result.Approved, nil
	}

	select {
	case result := <-consentReq.ResultCh:
		return handle(result)
	case <-time.After(interactiveAuthorizationConsentTimeout):
		// The timer races an arriving decision, and the request's status is
		// the referee: a decision that already resolved the request is
		// honored, only a request still pending times out.
		if _, ok := w.ResolveRequest(consentReq.ID, statusExpired); !ok {
			return handle(<-consentReq.ResultCh)
		}
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout"}
		return matches, false, fmt.Errorf("no answer to the presentation the issuer asked for")
	}
}

// addPresentationRequestLogEntry records the request under the issuance it
// belongs to.
func (w *Wallet) addPresentationRequestLogEntry(authReq *AuthorizationRequestParams) {
	details := presentationRequestLogDetails(authReq)
	details["direction"] = "inbound"
	details["source"] = "interactive_authorization"
	w.addProtocolLog("issuance", "interactive_authorization_presentation_request",
		"Issuer asked for a presentation before issuing", true, details)
}
