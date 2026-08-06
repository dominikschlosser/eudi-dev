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
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"

	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// Authorization Error Response codes. invalid_request and access_denied are
// the OAuth 2.0 codes OpenID4VP 1.0 §8.5 clarifies for this protocol; the
// other three are codes §8.5 adds and Appendix E.3 registers in the IANA
// "OAuth Extensions Error" registry.
const (
	errorCodeInvalidRequest          = "invalid_request"
	errorCodeAccessDenied            = "access_denied"
	errorCodeVPFormatsNotSupported   = "vp_formats_not_supported"
	errorCodeInvalidRequestURIMethod = "invalid_request_uri_method"
	errorCodeInvalidTransactionData  = "invalid_transaction_data"
)

// authorizationError is a refusal that already knows which OpenID4VP 1.0 §8.5
// error code the Verifier should be told. Refusals that carry no code are
// reported as invalid_request.
type authorizationError struct {
	Code string
	Err  error
}

func (e *authorizationError) Error() string { return e.Err.Error() }
func (e *authorizationError) Unwrap() error { return e.Err }

// authorizationErrorCode returns the §8.5 error code err asks for, defaulting
// to invalid_request: §8.5 lists the malformed-request cases under that code,
// and a request the wallet could not make sense of is one of them.
func authorizationErrorCode(err error) string {
	var authErr *authorizationError
	if errors.As(err, &authErr) && authErr.Code != "" {
		return authErr.Code
	}
	return errorCodeInvalidRequest
}

// walletPresentationFormats are the Credential Formats this wallet can put in
// a VP Token. A query naming only formats outside this set can never match.
var walletPresentationFormats = map[string]bool{
	"dc+sd-jwt":   true,
	"mso_mdoc":    true,
	"jwt_vc_json": true,
}

// unsatisfiableQueryError picks the §8.5 error code for a DCQL query no stored
// credential matched, and the description that goes with it.
//
// §8.5 defines access_denied for "The Wallet did not have the requested
// Credentials to satisfy the Authorization Request" and vp_formats_not_supported
// for "The Wallet does not support any of the formats requested by the
// Verifier". The query decides which is true: when every Credential Query names
// a Credential Format the wallet cannot present, the holdings never came into
// it and the format is the reason.
func unsatisfiableQueryError(query map[string]any) (string, string) {
	credQueries, _ := query["credentials"].([]any)
	unsupported := map[string]bool{}
	for _, item := range credQueries {
		cq, ok := item.(map[string]any)
		if !ok {
			continue
		}
		requested, _ := cq["format"].(string)
		if requested == "" || walletPresentationFormats[requested] {
			return errorCodeAccessDenied, "no stored credential satisfies the requested query"
		}
		unsupported[requested] = true
	}
	if len(unsupported) == 0 {
		return errorCodeAccessDenied, "no stored credential satisfies the requested query"
	}
	formats := make([]string, 0, len(unsupported))
	for format := range unsupported {
		formats = append(formats, format)
	}
	sort.Strings(formats)
	return errorCodeVPFormatsNotSupported, "unsupported credential format(s): " + strings.Join(formats, ", ")
}

// refusalCodeForRequest maps a rejected request to its OpenID4VP 1.0 §8.5
// error code. A code the error already carries wins; otherwise the request
// itself is inspected for the two cases §8.5 singles out by parameter.
func refusalCodeForRequest(authReq *AuthorizationRequestParams, err error) string {
	if code := authorizationErrorCode(err); code != errorCodeInvalidRequest {
		return code
	}
	if authReq == nil {
		return errorCodeInvalidRequest
	}
	// §8.5 invalid_request_uri_method: "The value of the request_uri_method
	// request parameter is neither get nor post (case-sensitive)."
	switch authReq.RequestURIMethod {
	case "", "get", "post":
	default:
		return errorCodeInvalidRequestURIMethod
	}
	// §8.5 invalid_transaction_data covers a transaction_data object that
	// "contains an unknown or unsupported transaction data type value". This
	// wallet supports no transaction data type at all, so any object in the
	// structure is of an unsupported type.
	if payloadHasKey(authReq.RequestPayload, "transaction_data") {
		return errorCodeInvalidTransactionData
	}
	return errorCodeInvalidRequest
}

func newConsentID() string {
	return uuid.New().String()
}

// isBrowserNavigation reports whether the request looks like a top-level
// browser navigation rather than an API call.
func isBrowserNavigation(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}

// redirectBrowser sends the browser to the verifier's redirect_uri, or to the
// wallet UI when the verifier did not provide one.
func redirectBrowser(w http.ResponseWriter, redirectURI string) {
	if redirectURI == "" {
		redirectURI = "/"
	}
	w.Header().Set("Location", redirectURI)
	w.WriteHeader(http.StatusSeeOther)
}

// AuthorizationRequestParams holds the extracted fields from an authorization request.
type AuthorizationRequestParams struct {
	ClientID         string
	ResponseType     string
	ResponseMode     string
	Nonce            string
	State            string
	RequestOrigin    string
	RedirectURI      string
	ResponseURI      string
	Scope            string
	RequestURIMethod string
	// RequestURI is where the request object was fetched from, empty when it
	// was not delivered by reference.
	RequestURI     string
	ClientMetadata map[string]any
	DCQLQuery      map[string]any
	RequestObject  *oid4vc.RequestObjectJWT
	RequestPayload map[string]any
	Source         string
	// UnsignedDCAPI marks a request that arrived unsigned over the Digital
	// Credentials API (OpenID4VP 1.0 Appendix A.3.1).
	//
	// Such a request carries no client_id: "The client_id parameter MUST be
	// omitted in unsigned requests defined in Appendix A.3.1. The Wallet MUST
	// ignore any client_id parameter that is present in an unsigned request"
	// (Appendix A.2). What identifies the caller is the origin the platform
	// reports, which no web page can forge, so the flag records what the
	// absent client_id cannot.
	UnsignedDCAPI bool
	// BrowserRedirect is set when the request came from a browser navigation
	// (GET with an HTML Accept header): after submission the browser is
	// redirected to the verifier's redirect_uri instead of receiving JSON.
	BrowserRedirect bool
}

type preparedPresentation struct {
	ResponseURI string
	Params      PresentationParams
	VPResult    *VPTokenMapResult
	IDToken     string
}

// handleAuthFlow is the core OID4VP flow handler.
func (s *Server) handleAuthFlow(w http.ResponseWriter, authReq *AuthorizationRequestParams) {
	source := authReq.Source
	if source == "" {
		source = "authorize"
	}
	authReq.Source = source
	s.addPresentationRequestLog(authReq, source)

	// Check one-shot error override
	if override := s.wallet.ConsumeNextError(); override != nil {
		s.log("  Next-error override consumed: %s", override.Error)
		s.wallet.AddLog("presentation", fmt.Sprintf("Returned error override: %s", override.Error), false)
		s.submitAuthorizationError(w, authReq, "error", override.Error, override.ErrorDescription)
		return
	}

	findings, err := ValidateAuthorizationRequest(s.wallet.ValidationMode, authReq)
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("presentation", err.Error(), false)
		s.wallet.NotifyError(WalletError{
			Message: "Authorization request validation failed",
			Detail:  err.Error(),
		})
		s.triggerUIRequest()
		errorCode := refusalCodeForRequest(authReq, err)
		s.reportRefusalToVerifier(authReq, errorCode, err.Error())
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             errorCode,
			"error_description": err.Error(),
		})
		return
	}
	for _, finding := range findings {
		s.log("  WARNING: %s", finding)
		s.wallet.AddLog("presentation", fmt.Sprintf("request validation warning: %s", finding), false)
	}

	// HAIP 1.0 compliance check
	if s.wallet.RequireHAIP {
		if violations := ValidateHAIPCompliance(authReq, authReq.RequestObject); len(violations) > 0 {
			for _, v := range violations {
				s.log("  HAIP VIOLATION: %s", v)
			}
			s.wallet.AddLog("presentation", fmt.Sprintf("HAIP violations: %v", violations), false)
			s.wallet.NotifyError(WalletError{
				Message: "HAIP 1.0 compliance check failed",
				Detail:  strings.Join(violations, "; "),
			})
			s.triggerUIRequest()
			// A profile violation is a request the wallet will not act on, so
			// §8.5's invalid_request is what the verifier is owed.
			description := "HAIP 1.0 compliance check failed: " + strings.Join(violations, "; ")
			s.reportRefusalToVerifier(authReq, errorCodeInvalidRequest, description)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":             errorCodeInvalidRequest,
				"error_description": description,
			})
			return
		}
	}

	// Log DCQL query
	if authReq.DCQLQuery != nil {
		if dcqlJSON, err := json.Marshal(authReq.DCQLQuery); err == nil {
			s.log("  DCQL Query:    %s", string(dcqlJSON))
		}
	}

	requiresVP := ResponseTypeRequiresVP(authReq.ResponseType)

	// Evaluate DCQL query
	var matches []CredentialMatch
	if authReq.DCQLQuery != nil && requiresVP {
		matches = s.wallet.EvaluateDCQL(authReq.DCQLQuery)
	}

	s.log("  Matched:       %d credential(s)", len(matches))
	for _, m := range matches {
		s.log("    - %s %s (%s), disclosing %d claims", m.Format, credTypeLabel(m), m.CredentialID[:8], len(m.SelectedKeys))
	}

	if requiresVP && len(matches) == 0 {
		s.log("  Result:        no matching credentials")
		s.wallet.AddLog("presentation", fmt.Sprintf("No matching credentials for %s", authReq.ClientID), false)
		s.wallet.NotifyError(WalletError{
			Message: "No matching credentials",
			Detail:  fmt.Sprintf("Verifier %s requested credentials but none matched the query", authReq.ClientID),
		})
		s.triggerUIRequest()
		// §8.5 access_denied: "The Wallet did not have the requested
		// Credentials to satisfy the Authorization Request."
		errorCode, description := unsatisfiableQueryError(authReq.DCQLQuery)
		s.reportRefusalToVerifier(authReq, errorCode, description)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":            "no_match",
			"error":             "no matching credentials found",
			"error_code":        errorCode,
			"error_description": description,
		})
		return
	}

	// Auto-accept mode skips consent. API submissions auto-accept even in
	// interactive mode: the programmatic call is the caller's consent.
	// Interactive channels (web invocation URLs, scheme dispatches) keep
	// the consent dialog.
	if s.wallet.AutoAccept || authReq.Source == "api" {
		s.log("  Mode:          auto-accept")
		s.autoAcceptPresentation(w, authReq, matches)
		return
	}

	// Interactive mode: create consent request and wait
	s.log("  Mode:          interactive — waiting for consent...")
	consentReq := &ConsentRequest{
		ID:           newConsentID(),
		Type:         "presentation",
		MatchedCreds: matches,
		Status:       "pending",
		ResultCh:     make(chan ConsentResult, 1),
		SubmissionCh: make(chan SubmissionResult, 1),
		CreatedAt:    time.Now(),
		ClientID:     authReq.ClientID,
		Nonce:        authReq.Nonce,
		ResponseURI:  authReq.ResponseURI,
		DCQLQuery:    authReq.DCQLQuery,
	}

	s.wallet.CreateConsentRequest(consentReq)
	s.triggerUIRequest()

	if s.onConsentRequest != nil {
		s.onConsentRequest(consentReq)
	}

	if authReq.BrowserRedirect {
		// A browser navigation must not hang while the consent is pending:
		// send the browser to the wallet UI (which shows the request) and
		// finish the flow in the background once consent arrives. The UI
		// navigates onward via the approve response's redirect_uri.
		go s.awaitPresentationConsent(noopResponseWriter{}, authReq, matches, consentReq)
		redirectBrowser(w, "/?request="+consentReq.ID)
		return
	}
	s.awaitPresentationConsent(w, authReq, matches, consentReq)
}

// awaitPresentationConsent waits for the user's decision on a presentation
// consent request and submits the presentation (or an error response) to the
// verifier. The submission result is also delivered on the consent request's
// submission channel for the approve API.
func (s *Server) awaitPresentationConsent(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch, consentReq *ConsentRequest) {
	select {
	case result := <-consentReq.ResultCh:
		if !result.Approved {
			s.log("  Consent:       denied")
			s.wallet.AddLog("presentation", fmt.Sprintf("Denied presentation to %s", authReq.ClientID), false)
			submission := s.submitAuthorizationError(w, authReq, "denied", "access_denied", "User denied presentation")
			consentReq.SubmissionCh <- submission
			return
		}

		s.log("  Consent:       approved")

		// Apply user's claim selections if provided
		if result.SelectedClaims != nil {
			for i, m := range matches {
				if selectedKeys, ok := result.SelectedClaims[m.CredentialID]; ok {
					matches[i].SelectedKeys = selectedKeys
					cred, _ := s.wallet.GetCredential(m.CredentialID)
					matches[i].Claims = filterClaims(cred, selectedKeys)
					s.log("    - %s: disclosing %v", m.CredentialID[:8], selectedKeys)
				}
			}
		}

		s.submitPresentationWithNotify(w, authReq, matches, consentReq.SubmissionCh)

	case <-time.After(5 * time.Minute):
		consentReq.Status = "denied"
		s.wallet.AddLog("presentation", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout"}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
	}
}

// noopResponseWriter discards the response of a consent flow that has been
// detached from its originating HTTP request (browser navigations are
// redirected to the wallet UI instead of blocking until consent).
type noopResponseWriter struct{}

func (noopResponseWriter) Header() http.Header         { return http.Header{} }
func (noopResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (noopResponseWriter) WriteHeader(int)             {}

// autoAcceptPresentation handles auto-accept mode.
func (s *Server) autoAcceptPresentation(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch) {
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	dim.Println("───────────────────────────────────────")
	yellow.Printf("  Verifier: %s\n", authReq.ClientID)
	for _, m := range matches {
		fmt.Printf("  Credential: %s (%s)\n", m.Format, credTypeLabel(m))
		fmt.Printf("  Disclosing: %v\n", m.SelectedKeys)
	}

	s.submitPresentation(w, authReq, matches)
	green.Printf("  Auto-accepted\n")
	dim.Println("───────────────────────────────────────")
}

// submitPresentationWithNotify creates VP tokens, submits them, and notifies via the submission channel.
func (s *Server) submitPresentationWithNotify(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch, submissionCh chan SubmissionResult) {
	result := s.submitPresentation(w, authReq, matches)
	if submissionCh != nil {
		submissionCh <- result
	}
}

func (s *Server) preparePresentation(authReq *AuthorizationRequestParams, matches []CredentialMatch) (*preparedPresentation, error) {
	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}

	params := PresentationParams{
		Nonce:          authReq.Nonce,
		ClientID:       authReq.ClientID,
		RequestOrigin:  authReq.RequestOrigin,
		ResponseURI:    responseURI,
		RedirectURI:    authReq.RedirectURI,
		ResponseMode:   authReq.ResponseMode,
		ClientMetadata: authReq.ClientMetadata,
		RequestObject:  authReq.RequestObject,
	}

	prepared := &preparedPresentation{
		ResponseURI: responseURI,
		Params:      params,
	}

	if ResponseTypeContains(authReq.ResponseType, "vp_token") || authReq.ResponseType == "" {
		vpResult, err := s.wallet.CreateVPTokenMap(matches, params)
		if err != nil {
			return nil, fmt.Errorf("creating VP token map: %w", err)
		}
		prepared.VPResult = vpResult
	}

	if ResponseTypeContains(authReq.ResponseType, "id_token") {
		// The audience is what identifies the recipient, and over the Digital
		// Credentials API that is the origin the platform reported rather
		// than a client_id the request need not carry (OID4VP 1.0 §5.9.3:
		// "the audience of the Credential Presentation is always the origin
		// value prefixed by origin:").
		idToken, err := s.wallet.CreateSelfIssuedIDToken(authReq.Nonce, presentationAudience(authReq))
		if err != nil {
			return nil, fmt.Errorf("creating id_token: %w", err)
		}
		prepared.IDToken = idToken
	}

	return prepared, nil
}

func (s *Server) buildBrowserPresentationResult(authReq *AuthorizationRequestParams, protocol string, matches []CredentialMatch) (*BrowserAPIResult, *preparedPresentation, error) {
	prepared, err := s.preparePresentation(authReq, matches)
	if err != nil {
		return nil, nil, err
	}
	response, err := s.wallet.BuildAuthorizationResponse(prepared.VPResult, prepared.IDToken, authReq.State, prepared.Params)
	if err != nil {
		return nil, nil, err
	}
	result, err := BuildBrowserAPIResult(protocol, response)
	if err != nil {
		return nil, nil, err
	}
	return result, prepared, nil
}

func (s *Server) buildBrowserAuthorizationErrorResult(authReq *AuthorizationRequestParams, protocol, errorCode, errorDescription string) (*BrowserAPIResult, error) {
	params := PresentationParams{
		Nonce:          authReq.Nonce,
		ClientID:       authReq.ClientID,
		RequestOrigin:  authReq.RequestOrigin,
		ResponseURI:    authReq.ResponseURI,
		RedirectURI:    authReq.RedirectURI,
		ResponseMode:   authReq.ResponseMode,
		ClientMetadata: authReq.ClientMetadata,
		RequestObject:  authReq.RequestObject,
	}
	response, err := s.wallet.BuildAuthorizationErrorResponse(errorCode, errorDescription, authReq.State, params)
	if err != nil {
		return nil, err
	}
	return BuildBrowserAPIResult(protocol, response)
}

// canDeliverAuthorizationError reports whether an Authorization Error Response
// has anywhere to go.
//
// A Digital Credentials API Response Mode hands its response back through the
// API call rather than to a URL (Appendix A.4: "Protocol error responses are
// returned as an object within the data property"), and a request carrying
// neither response_uri nor redirect_uri named no destination at all.
func canDeliverAuthorizationError(authReq *AuthorizationRequestParams) bool {
	if authReq == nil || isDCAPIResponseMode(authReq.ResponseMode) {
		return false
	}
	return authReq.ResponseURI != "" || authReq.RedirectURI != ""
}

// deliverAuthorizationError returns an OpenID4VP 1.0 §8.5 Authorization Error
// Response to the verifier over the Response Mode of the request.
//
// §5.6: "Both successful and error responses SHOULD be returned using the
// supplied Response Mode, or if none is supplied, using the default Response
// Mode." A verifier that hears nothing is left waiting on its Response URI
// until it times out, with no way to tell a refusal from a broken wallet.
func (s *Server) deliverAuthorizationError(authReq *AuthorizationRequestParams, errorCode, errorDescription string) (*DirectPostResult, error) {
	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}

	s.log("  Submitting authorization error to %s", responseURI)
	if authReq.State != "" {
		s.log("  State:         %s", authReq.State)
	}

	params := PresentationParams{
		Nonce:          authReq.Nonce,
		ClientID:       authReq.ClientID,
		RequestOrigin:  authReq.RequestOrigin,
		ResponseURI:    responseURI,
		RedirectURI:    authReq.RedirectURI,
		ResponseMode:   authReq.ResponseMode,
		ClientMetadata: authReq.ClientMetadata,
		RequestObject:  authReq.RequestObject,
	}

	errorDetails := presentationRequestLogDetails(authReq)
	addStringDetail(errorDetails, "submission_uri", responseURI)
	errorDetails["direction"] = "outbound"
	errorDetails["error"] = errorCode
	addStringDetail(errorDetails, "error_description", errorDescription)
	if authReq.Source != "" {
		errorDetails["source"] = authReq.Source
	}
	s.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Sending authorization error to %s", authReq.ClientID), true, errorDetails)

	result, err := s.wallet.SubmitAuthorizationError(errorCode, errorDescription, authReq.State, responseURI, params)
	if err != nil {
		s.log("  ERROR: Error submission failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Error submission failed: %v", err), false)
		return nil, err
	}

	s.log("  Response:      HTTP %d", result.StatusCode)
	if result.RedirectURI != "" {
		s.log("  Redirect:      %s", result.RedirectURI)
	}

	s.wallet.addProtocolLog("presentation", "verifier_response", fmt.Sprintf("Verifier result from %s: %s", authReq.ClientID, FormatDirectPostResult(result)), result.StatusCode < 400, verifierResponseLogDetails(authReq, &preparedPresentation{ResponseURI: responseURI}, result))

	return result, nil
}

// reportRefusalToVerifier tells the verifier why the wallet is not answering
// its request. The local HTTP caller gets its own answer separately; this is
// the copy §5.6 owes the verifier, so a refusal the wallet decided on its own
// (a malformed request, a profile violation, nothing to present) ends the
// verifier's wait instead of hanging it. A delivery failure is logged and
// swallowed: the wallet's refusal stands either way.
func (s *Server) reportRefusalToVerifier(authReq *AuthorizationRequestParams, errorCode, errorDescription string) {
	if !canDeliverAuthorizationError(authReq) {
		return
	}
	_, _ = s.deliverAuthorizationError(authReq, errorCode, errorDescription)
}

// submitAuthorizationError submits an authorization error response to the
// verifier and answers the local caller with the outcome.
func (s *Server) submitAuthorizationError(w http.ResponseWriter, authReq *AuthorizationRequestParams, status, errorCode, errorDescription string) SubmissionResult {
	result, err := s.deliverAuthorizationError(authReq, errorCode, errorDescription)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
	}

	if authReq.BrowserRedirect {
		redirectBrowser(w, result.RedirectURI)
	} else {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":            status,
			"error":             errorCode,
			"error_description": errorDescription,
			"response":          result,
		})
	}

	return SubmissionResult{
		RedirectURI: result.RedirectURI,
		StatusCode:  result.StatusCode,
		Error: func() string {
			if result.StatusCode >= 400 {
				return result.Body
			}
			return ""
		}(),
	}
}

// submitPresentation creates VP tokens and submits them to the verifier.
func (s *Server) submitPresentation(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch) SubmissionResult {
	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}

	s.log("  Submitting VP token to %s", responseURI)
	if authReq.State != "" {
		s.log("  State:         %s", authReq.State)
	}

	prepared, err := s.preparePresentation(authReq, matches)
	if err != nil {
		s.log("  ERROR: Presentation preparation failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Presentation preparation failed: %v", err), false)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
	}
	if prepared.VPResult != nil {
		s.log("  VP tokens:     %d created", len(prepared.VPResult.TokenMap))
	}
	if prepared.IDToken != "" {
		s.log("  id_token:      created (SIOPv2)")
	}

	s.wallet.addProtocolLog("presentation", "presentation_response", fmt.Sprintf("Sending presentation response to %s", authReq.ClientID), true, presentationResponseLogDetails(authReq, s.wallet, matches, prepared))

	result, err := s.wallet.SubmitPresentation(prepared.VPResult, prepared.IDToken, authReq.State, responseURI, prepared.Params)
	if err != nil {
		s.log("  ERROR: Submission failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Submission failed: %v", err), false)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
	}

	s.log("  Response:      HTTP %d", result.StatusCode)
	if result.RedirectURI != "" {
		s.log("  Redirect:      %s", result.RedirectURI)
	}
	if result.StatusCode >= 400 {
		s.log("  ERROR:         %s", result.Body)
	}

	s.wallet.addProtocolLog("presentation", "verifier_response", fmt.Sprintf("Verifier result from %s: %s", authReq.ClientID, FormatDirectPostResult(result)), result.StatusCode < 400, verifierResponseLogDetails(authReq, prepared, result))

	if authReq.BrowserRedirect {
		redirectBrowser(w, result.RedirectURI)
	} else {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "submitted",
			"response": result,
			"vp_token_keys": func() []string {
				if prepared.VPResult == nil {
					return nil
				}
				return prepared.VPResult.QueryIDs()
			}(),
		})
	}

	return SubmissionResult{
		RedirectURI: result.RedirectURI,
		StatusCode:  result.StatusCode,
		Error: func() string {
			if result.StatusCode >= 400 {
				return result.Body
			}
			return ""
		}(),
	}
}

// parseAuthParams extracts authorization request params from URL values.
func parseAuthParams(values map[string][]string, opts oid4vc.ParseOptions, mode ValidationMode) (*AuthorizationRequestParams, error) {
	get := func(key string) string {
		if vs, ok := values[key]; ok && len(vs) > 0 {
			return vs[0]
		}
		return ""
	}

	params := &AuthorizationRequestParams{
		ClientID:         get("client_id"),
		ResponseType:     get("response_type"),
		ResponseMode:     get("response_mode"),
		Nonce:            get("nonce"),
		State:            get("state"),
		RedirectURI:      get("redirect_uri"),
		ResponseURI:      get("response_uri"),
		RequestURIMethod: get("request_uri_method"),
	}

	if cm := get("client_metadata"); cm != "" {
		var clientMetadata map[string]any
		if err := json.Unmarshal([]byte(cm), &clientMetadata); err != nil {
			return nil, fmt.Errorf("parsing client_metadata: %w", err)
		}
		params.ClientMetadata = clientMetadata
	}

	if td := get("transaction_data"); td != "" {
		if mode == ValidationModeStrict {
			// §8.5 invalid_transaction_data applies when an object in the
			// transaction_data structure "contains an unknown or unsupported
			// transaction data type value". This wallet supports no type, so
			// every object in it is of an unsupported type.
			return nil, &authorizationError{
				Code: errorCodeInvalidTransactionData,
				Err:  fmt.Errorf("transaction_data is not supported by this wallet"),
			}
		}
		log.Printf("[Wallet] WARNING: request contains transaction_data which is not processed (OID4VP §7.2)")
	}
	if method := get("request_uri_method"); method != "" && get("request_uri") == "" {
		return nil, fmt.Errorf("request_uri_method requires request_uri")
	}
	if method := get("request_uri_method"); method != "" && method != "get" && method != "post" {
		// §8.5 invalid_request_uri_method: "The value of the
		// request_uri_method request parameter is neither get nor post
		// (case-sensitive)."
		return nil, &authorizationError{
			Code: errorCodeInvalidRequestURIMethod,
			Err:  fmt.Errorf("unsupported request_uri_method %q", method),
		}
	}

	// Parse dcql_query if present
	if dq := get("dcql_query"); dq != "" {
		var query map[string]any
		if err := json.Unmarshal([]byte(dq), &query); err != nil {
			return nil, fmt.Errorf("parsing dcql_query: %w", err)
		}
		params.DCQLQuery = query
	}

	// If request_uri is present, build a synthetic openid4vp:// URI with all
	// params so the parser can handle request_uri_method and fetch the JWT.
	if requestURI := get("request_uri"); requestURI != "" {
		syntheticParams := url.Values{}
		for k, vs := range values {
			if len(vs) > 0 {
				syntheticParams.Set(k, vs[0])
			}
		}
		syntheticURI := "openid4vp://authorize?" + syntheticParams.Encode()

		parsed, err := ParseAuthorizationRequestWithOptions(syntheticURI, opts)
		if err != nil {
			return nil, fmt.Errorf("parsing request_uri %q: %w", requestURI, err)
		}
		params.ClientID = parsed.ClientID
		params.ResponseType = parsed.ResponseType
		params.Nonce = parsed.Nonce
		params.State = parsed.State
		params.ResponseURI = parsed.ResponseURI
		params.RedirectURI = parsed.RedirectURI
		params.ResponseMode = parsed.ResponseMode
		params.RequestURIMethod = parsed.RequestURIMethod
		params.RequestURI = parsed.RequestURI
		params.ClientMetadata = parsed.ClientMetadata
		params.DCQLQuery = parsed.DCQLQuery
		params.RequestObject = parsed.RequestObject
		params.RequestPayload = requestPayload(parsed.RequestObject, nil)
	}

	// If request (JWT) is present, parse it
	if requestJWT := get("request"); requestJWT != "" {
		parsed, err := ParseAuthorizationRequestWithOptions(requestJWT, opts)
		if err != nil {
			return nil, fmt.Errorf("parsing request JWT: %w", err)
		}
		params.ClientID = parsed.ClientID
		params.ResponseType = parsed.ResponseType
		params.Nonce = parsed.Nonce
		params.State = parsed.State
		params.ResponseURI = parsed.ResponseURI
		params.RedirectURI = parsed.RedirectURI
		params.ResponseMode = parsed.ResponseMode
		params.RequestURIMethod = parsed.RequestURIMethod
		params.ClientMetadata = parsed.ClientMetadata
		params.DCQLQuery = parsed.DCQLQuery
		params.RequestObject = parsed.RequestObject
		params.RequestPayload = requestPayload(parsed.RequestObject, nil)
	}

	if params.ClientID == "" {
		return nil, fmt.Errorf("missing client_id")
	}

	return params, nil
}

// authorizationErrorTarget rebuilds just enough of a request the wallet failed
// to parse to still return an Authorization Error Response for it. §5.6 wants
// the error returned over the supplied Response Mode, and the parameters that
// decide where it goes (response_mode, response_uri, redirect_uri, state) are
// readable even when the request as a whole is not. A request delivered by
// reference may carry none of them, in which case there is no destination and
// nothing is sent.
func authorizationErrorTarget(values map[string][]string) *AuthorizationRequestParams {
	get := func(key string) string {
		if vs, ok := values[key]; ok && len(vs) > 0 {
			return vs[0]
		}
		return ""
	}
	return &AuthorizationRequestParams{
		ClientID:         get("client_id"),
		ResponseMode:     get("response_mode"),
		State:            get("state"),
		Nonce:            get("nonce"),
		RedirectURI:      get("redirect_uri"),
		ResponseURI:      get("response_uri"),
		RequestURIMethod: get("request_uri_method"),
	}
}

func requestPayload(reqObj *oid4vc.RequestObjectJWT, fallback map[string]any) map[string]any {
	return RequestPayload(reqObj, fallback)
}

func credTypeLabel(m CredentialMatch) string {
	if m.VCT != "" {
		return m.VCT
	}
	if m.DocType != "" {
		return m.DocType
	}
	return m.Format
}
