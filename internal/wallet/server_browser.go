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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

// handleBrowserPresentationAPI executes an OpenID4VP Browser API request and
// returns the browser-facing result object that navigator.credentials.get()
// would yield to the RP page.
func (s *Server) handleBrowserPresentationAPI(w http.ResponseWriter, r *http.Request) {
	var body BrowserAPIRequestEnvelope
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	reqServer := s
	if r.Header.Get("X-OID4VC-Dev-HAIP") == "true" || r.Header.Get("X-OID4VC-Dev-Mode") != "" {
		reqWallet, err := cloneWalletForPresentation(s.wallet, presentationRequestOptions{
			RequireHAIP:    r.Header.Get("X-OID4VC-Dev-HAIP") == "true",
			ValidationMode: r.Header.Get("X-OID4VC-Dev-Mode"),
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		reqServer = &Server{
			wallet:           reqWallet,
			port:             s.port,
			mux:              s.mux,
			onSave:           s.onSave,
			onConsentRequest: s.onConsentRequest,
			onUIRequest:      s.onUIRequest,
			logFunc:          s.logFunc,
			httpSrv:          s.httpSrv,
			issuerSrv:        s.issuerSrv,
			issuerTLSCert:    s.issuerTLSCert,
			issuerPort:       s.issuerPort,
			issuerKeyExpiry:  s.issuerKeyExpiry,
		}
		reqServer.parseOpts = oid4vc.ParseOptions{
			FetchRequestURI: MakeFetchRequestURI(reqWallet, func(format string, args ...any) {
				reqServer.log(format, args...)
			}),
		}
	}

	requestOrigin := strings.TrimSpace(r.Header.Get("Origin"))
	protocol, authReq, err := ParseBrowserAPIRequest(body, reqServer.parseOpts, requestOrigin)
	if err != nil {
		reqServer.log("  ERROR: %v", err)
		reqServer.wallet.AddLog("presentation", fmt.Sprintf("Failed to parse browser request: %v", err), false)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	reqServer.log("Received Browser API authorization request")
	reqServer.log("  Protocol:      %s", protocol)
	reqServer.log("  Client ID:     %s", authReq.ClientID)
	reqServer.log("  Response Mode: %s", authReq.ResponseMode)
	authReq.Source = "browser_api"
	if authReq.Nonce != "" {
		reqServer.log("  Nonce:         %s", authReq.Nonce)
	}
	if requestOrigin != "" {
		reqServer.log("  Origin:        %s", requestOrigin)
	}
	reqServer.addPresentationRequestLog(authReq, "browser_api")

	if override := reqServer.wallet.ConsumeNextError(); override != nil {
		reqServer.log("  Next-error override consumed: %s", override.Error)
		result, buildErr := reqServer.buildBrowserAuthorizationErrorResult(authReq, protocol, override.Error, override.ErrorDescription)
		if buildErr != nil {
			reqServer.log("  ERROR: Browser error response failed: %v", buildErr)
			reqServer.wallet.AddLog("presentation", fmt.Sprintf("Browser error response failed: %v", buildErr), false)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": buildErr.Error()})
			return
		}
		errorDetails := presentationRequestLogDetails(authReq)
		errorDetails["direction"] = "outbound"
		errorDetails["source"] = "browser_api"
		errorDetails["error"] = override.Error
		addStringDetail(errorDetails, "error_description", override.ErrorDescription)
		reqServer.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Returned Browser API error to %s", authReq.ClientID), true, errorDetails)
		writeJSON(w, http.StatusOK, result)
		return
	}

	findings, err := ValidateAuthorizationRequest(reqServer.wallet.ValidationMode, authReq)
	if err != nil {
		reqServer.log("  ERROR: %v", err)
		reqServer.wallet.AddLog("presentation", err.Error(), false)
		reqServer.wallet.NotifyError(WalletError{
			Message: "Authorization request validation failed",
			Detail:  err.Error(),
		})
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	for _, finding := range findings {
		reqServer.log("  WARNING: %s", finding)
		reqServer.wallet.AddLog("presentation", fmt.Sprintf("request validation warning: %s", finding), false)
	}

	if reqServer.wallet.RequireHAIP {
		if violations := ValidateHAIPCompliance(authReq, authReq.RequestObject); len(violations) > 0 {
			for _, v := range violations {
				reqServer.log("  HAIP VIOLATION: %s", v)
			}
			reqServer.wallet.AddLog("presentation", fmt.Sprintf("HAIP violations: %v", violations), false)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_request",
				"error_description": "HAIP 1.0 compliance check failed: " + strings.Join(violations, "; "),
			})
			return
		}
	}

	if authReq.DCQLQuery != nil {
		if dcqlJSON, err := json.Marshal(authReq.DCQLQuery); err == nil {
			reqServer.log("  DCQL Query:    %s", string(dcqlJSON))
		}
	}

	requiresVP := ResponseTypeRequiresVP(authReq.ResponseType)

	var matches []CredentialMatch
	if authReq.DCQLQuery != nil && requiresVP {
		matches = reqServer.wallet.EvaluateDCQL(authReq.DCQLQuery)
	}

	reqServer.log("  Matched:       %d credential(s)", len(matches))
	for _, m := range matches {
		reqServer.log("    - %s %s (%s), disclosing %d claims", m.Format, credTypeLabel(m), m.CredentialID[:8], len(m.SelectedKeys))
	}

	if requiresVP && len(matches) == 0 {
		reqServer.log("  Result:        no matching credentials")
		reqServer.wallet.AddLog("presentation", fmt.Sprintf("No matching credentials for %s", authReq.ClientID), false)
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "no_match",
			"error":  "no matching credentials found",
		})
		return
	}

	if reqServer.wallet.AutoAccept {
		reqServer.writeBrowserPresentationResult(w, authReq, protocol, matches)
		return
	}

	reqServer.log("  Mode:          interactive — waiting for consent...")
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

	reqServer.wallet.CreateConsentRequest(consentReq)
	reqServer.triggerUIRequest()
	if reqServer.onConsentRequest != nil {
		reqServer.onConsentRequest(consentReq)
	}

	select {
	case result := <-consentReq.ResultCh:
		if !result.Approved {
			reqServer.log("  Consent:       denied")
			browserResult, buildErr := reqServer.buildBrowserAuthorizationErrorResult(authReq, protocol, "access_denied", "User denied presentation")
			if buildErr != nil {
				reqServer.log("  ERROR: Browser error response failed: %v", buildErr)
				reqServer.wallet.AddLog("presentation", fmt.Sprintf("Browser error response failed: %v", buildErr), false)
				consentReq.SubmissionCh <- SubmissionResult{Error: buildErr.Error()}
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": buildErr.Error()})
				return
			}
			denialDetails := presentationRequestLogDetails(authReq)
			denialDetails["direction"] = "outbound"
			denialDetails["source"] = "browser_api"
			denialDetails["error"] = "access_denied"
			denialDetails["browser_api_result"] = browserResult
			reqServer.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Returned Browser API denial to %s", authReq.ClientID), true, denialDetails)
			consentReq.SubmissionCh <- SubmissionResult{StatusCode: http.StatusOK, Error: "access_denied"}
			writeJSON(w, http.StatusOK, browserResult)
			return
		}

		if result.SelectedClaims != nil {
			for i, m := range matches {
				if selectedKeys, ok := result.SelectedClaims[m.CredentialID]; ok {
					matches[i].SelectedKeys = selectedKeys
					cred, _ := reqServer.wallet.GetCredential(m.CredentialID)
					matches[i].Claims = filterClaims(cred, selectedKeys)
					reqServer.log("    - %s: disclosing %v", m.CredentialID[:8], selectedKeys)
				}
			}
		}

		submission := reqServer.writeBrowserPresentationResult(w, authReq, protocol, matches)
		consentReq.SubmissionCh <- submission
	case <-time.After(5 * time.Minute):
		consentReq.Status = "denied"
		reqServer.wallet.AddLog("presentation", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout"}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
	}
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
		s.log("  VP tokens:     %d created", len(prepared.VPResult.TokenMap))
	}
	if prepared.IDToken != "" {
		s.log("  id_token:      created (SIOPv2)")
	}

	details := presentationResponseLogDetails(authReq, s.wallet, matches, prepared)
	details["status_code"] = http.StatusOK
	details["browser_api_result"] = result
	s.wallet.addProtocolLog("presentation", "presentation_response", fmt.Sprintf("Returned Browser API presentation to %s", authReq.ClientID), true, details)
	writeJSON(w, http.StatusOK, result)
	return SubmissionResult{StatusCode: http.StatusOK}
}
