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
	"net/http"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
)

// Returns the result that navigator.credentials.get() would deliver to the requesting
// page.
func (s *Server) handleBrowserPresentationAPI(w http.ResponseWriter, r *http.Request) {
	var body BrowserAPIRequestEnvelope
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	requestOrigin := strings.TrimSpace(r.Header.Get("Origin"))
	protocol, authReq, err := ParseBrowserAPIRequest(body, s.parseOpts, requestOrigin)
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Failed to parse browser request: %v", err), false)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.log("Received Browser API authorization request")
	s.log("  Protocol:      %s", protocol)
	s.log("  Client ID:     %s", authReq.ClientID)
	s.log("  Response Mode: %s", authReq.ResponseMode)
	authReq.Source = "browser_api"
	if authReq.Nonce != "" {
		s.log("  Nonce:         %s", authReq.Nonce)
	}
	if requestOrigin != "" {
		s.log("  Origin:        %s", requestOrigin)
	}
	s.addPresentationRequestLog(authReq, "browser_api")

	s.wallet.PrepareARFChecks(authReq)
	findings, err := ValidateAuthorizationRequest(s.wallet.Conformance(), authReq)
	var refusal *ARFRefusal
	if errors.As(err, &refusal) {
		s.log("  REFUSED: %v", err)
		s.wallet.AddLog("presentation", err.Error(), false)
		s.wallet.NotifyError(WalletError{Owner: requestOwner(r), Message: "The request does not meet the ARF registration rules", Detail: err.Error()})
		s.triggerUIRequest("")
		// OpenID4VP 1.0 Appendix A returns a protocol error inside the
		// fulfilled API result.
		s.writeBrowserAuthorizationError(w, authReq, protocol, errorCodeAccessDenied, "The request does not meet the ARF registration rules: "+strings.Join(refusal.Findings, ", "), http.StatusOK)
		return
	}
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("presentation", err.Error(), false)
		s.wallet.NotifyError(WalletError{
			Owner:   requestOwner(r),
			Message: "Authorization request validation failed",
			Detail:  err.Error(),
		})
		// Invalid requests receive an API error. OpenID4VP 1.0 §8.5 follows RFC 6749
		// §4.1.2.1, which reports the error to the user without redirecting to an
		// invalid destination.
		s.triggerUIRequest("")
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             refusalCodeForRequest(authReq, err),
			"error_description": err.Error(),
		})
		return
	}
	// The override answers only a valid request. RFC 6749 §4.1.2.1, which
	// OpenID4VP 1.0 §8.5 applies, sends no error to an invalid client.
	if override := s.wallet.ConsumeNextError(); override != nil {
		s.log("  Next-error override consumed: %s", override.Error)
		result, buildErr := s.buildBrowserAuthorizationErrorResult(authReq, protocol, override.Error, override.ErrorDescription)
		if buildErr != nil {
			s.log("  ERROR: Browser error response failed: %v", buildErr)
			s.wallet.AddLog("presentation", fmt.Sprintf("Browser error response failed: %v", buildErr), false)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": buildErr.Error()})
			return
		}
		errorDetails := presentationRequestLogDetails(authReq)
		errorDetails["direction"] = "outbound"
		errorDetails["source"] = "browser_api"
		errorDetails["error"] = override.Error
		addStringDetail(errorDetails, "error_description", override.ErrorDescription)
		s.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Returned Browser API error to %s", authReq.ClientID), true, errorDetails)
		writeJSON(w, http.StatusOK, result)
		return
	}
	for _, finding := range findings {
		s.log("  WARNING: %s", finding)
	}
	authReq.Findings = findings
	s.wallet.warnFindings("presentation", specCitedSummary("The request", findings), findings)
	s.wallet.warnUndefinedRequestParameters("presentation", authReq)

	if authReq.DCQLQuery != nil {
		if dcqlJSON, err := json.Marshal(authReq.DCQLQuery); err == nil {
			s.log("  DCQL Query:    %s", string(dcqlJSON))
		}
	}

	requiresVP := ResponseTypeRequiresVP(authReq.ResponseType)

	var matches []CredentialMatch
	var credentialOptions *ConsentCredentialOptions
	if authReq.DCQLQuery != nil && requiresVP {
		var err error
		if matches, credentialOptions, err = s.wallet.EvaluateDCQLWithOptions(authReq.DCQLQuery); err != nil {
			s.refuseQuery(w, requestOwner(r), err, func(code, description string) {
				s.writeBrowserAuthorizationError(w, authReq, protocol, code, description, http.StatusOK)
			})
			return
		}
	}

	s.log("  Matched:       %d credential(s)", len(matches))
	for _, m := range matches {
		s.log("    - %s %s (%s), disclosing %d claims", m.Format, credTypeLabel(m), shortID(m.CredentialID), len(m.SelectedKeys))
	}

	// Debug mode lets the user answer with a credential that does not match.
	if requiresVP && len(matches) == 0 && credentialOptions != nil && !s.autoAccepts(authReq) {
		s.log("  Result:        no matching credentials, debug mode offers the others")
	} else if requiresVP && len(matches) == 0 {
		errorCode, description := s.reportNoMatch(authReq, requestOwner(r))
		s.writeBrowserAuthorizationError(w, authReq, protocol, errorCode, description, http.StatusOK)
		return
	}

	if s.autoAccepts(authReq) {
		s.writeBrowserPresentationResult(w, authReq, protocol, matches)
		return
	}

	s.log("  Mode:          interactive (waiting for consent)")
	consentReq := newPresentationConsent("presentation", requestOwner(r), authReq.ClientID, authReq, matches, credentialOptions)
	s.wallet.CreateConsentRequest(consentReq)
	s.triggerUIRequest(consentReq.ID)
	if s.onConsentRequest != nil {
		s.onConsentRequest(consentReq)
	}

	s.allowSlowResponse(w, config.ConsentTimeout)
	result, answered := s.wallet.awaitConsent(consentReq, config.ConsentTimeout)
	switch {
	case !answered:
		s.wallet.AddLog("presentation", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout"}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
	case !result.Approved:
		s.log("  Consent:       denied")
		browserResult, buildErr := s.buildBrowserAuthorizationErrorResult(authReq, protocol, "access_denied", "User denied presentation")
		if buildErr != nil {
			s.log("  ERROR: Browser error response failed: %v", buildErr)
			s.wallet.AddLog("presentation", fmt.Sprintf("Browser error response failed: %v", buildErr), false)
			consentReq.SubmissionCh <- SubmissionResult{Error: buildErr.Error()}
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": buildErr.Error()})
			return
		}
		denialDetails := presentationRequestLogDetails(authReq)
		denialDetails["direction"] = "outbound"
		denialDetails["source"] = "browser_api"
		denialDetails["error"] = "access_denied"
		denialDetails["browser_api_result"] = browserResult
		s.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Returned Browser API denial to %s", authReq.ClientID), true, denialDetails)
		consentReq.SubmissionCh <- SubmissionResult{StatusCode: http.StatusOK, Error: "access_denied"}
		writeJSON(w, http.StatusOK, browserResult)
	default:
		consentReq.SubmissionCh <- s.writeBrowserPresentationResult(w, authReq, protocol, s.wallet.consentedMatches(consentReq, matches, result))
	}
}

// OpenID4VP 1.0 Appendix A.4 fulfills the DC API promise even for protocol errors.
// Building an encrypted error response can still fail if dc_api.jwt has no usable key.
func (s *Server) writeBrowserAuthorizationError(w http.ResponseWriter, authReq *AuthorizationRequestParams, protocol, errorCode, errorDescription string, fallbackStatus int) {
	result, err := s.buildBrowserAuthorizationErrorResult(authReq, protocol, errorCode, errorDescription)
	if err != nil {
		s.log("  ERROR: Browser error response failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Browser error response failed: %v", err), false)
		writeJSON(w, fallbackStatus, map[string]any{
			"error":             errorCode,
			"error_description": errorDescription,
		})
		return
	}

	details := presentationRequestLogDetails(authReq)
	details["direction"] = "outbound"
	details["source"] = "browser_api"
	details["error"] = errorCode
	addStringDetail(details, "error_description", errorDescription)
	details["browser_api_result"] = result
	s.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Returned Browser API error to %s", authReq.ClientID), true, details)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) writeBrowserPresentationResult(w http.ResponseWriter, authReq *AuthorizationRequestParams, protocol string, matches []CredentialMatch) SubmissionResult {
	result, prepared, err := s.buildBrowserPresentationResult(authReq, protocol, matches)
	if err != nil {
		s.log("  ERROR: Browser API presentation failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Browser API presentation failed: %v", err), false)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
	}

	if prepared.VPResult != nil {
		s.log("  VP tokens:     %d created", prepared.VPResult.PresentationCount())
	}
	if prepared.IDToken != "" {
		s.log("  id_token:      created (SIOPv2)")
	}

	details := presentationResponseLogDetails(authReq, s.wallet, matches, prepared)
	details["status_code"] = http.StatusOK
	details["browser_api_result"] = result
	payload := PresentationLogPayload(prepared.Response)
	if payload.Encrypted {
		payload.Wire = result
	} else {
		payload.Body = result
	}
	s.wallet.addProtocolLog("presentation", "presentation_response", fmt.Sprintf("Returned Browser API presentation to %s", authReq.ClientID), true, details, payload)
	writeJSON(w, http.StatusOK, result)
	return SubmissionResult{StatusCode: http.StatusOK}
}
