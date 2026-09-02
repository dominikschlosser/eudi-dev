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
	"fmt"

	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

func (s *Server) addPresentationRequestLog(authReq *AuthorizationRequestParams, source string) {
	clientID := authReq.ClientID
	if clientID == "" {
		clientID = "unknown verifier"
	}
	details := presentationRequestLogDetails(authReq)
	details["event"] = "presentation_request"
	details["direction"] = "inbound"
	if source != "" {
		details["source"] = source
	}
	s.wallet.AddLogDetails("presentation", fmt.Sprintf("Received presentation request from %s", clientID), true, details)
}

func (w *Wallet) addProtocolLog(action, event, detail string, success bool, details map[string]any) {
	w.AddLogDetails(action, detail, success, protocolLogDetails(event, details))
}

// addProtocolWarning records a spec violation the wallet noted without failing
// the flow.
func (w *Wallet) addProtocolWarning(action, event, detail string, details map[string]any) {
	w.AddWarning(action, detail, protocolLogDetails(event, details))
}

func protocolLogDetails(event string, details map[string]any) map[string]any {
	if details == nil {
		details = map[string]any{}
	} else {
		clone := make(map[string]any, len(details)+1)
		for key, value := range details {
			clone[key] = value
		}
		details = clone
	}
	details["event"] = event
	return details
}

func presentationRequestLogDetails(authReq *AuthorizationRequestParams) map[string]any {
	details := map[string]any{}
	addStringDetail(details, "client_id", authReq.ClientID)
	addStringDetail(details, "response_type", authReq.ResponseType)
	addStringDetail(details, "response_mode", authReq.ResponseMode)
	addStringDetail(details, "response_uri", authReq.ResponseURI)
	addStringDetail(details, "redirect_uri", authReq.RedirectURI)
	addStringDetail(details, "state", authReq.State)
	addStringDetail(details, "nonce", authReq.Nonce)
	addStringDetail(details, "request_uri_method", authReq.RequestURIMethod)
	addStringDetail(details, "request_origin", authReq.RequestOrigin)
	if authReq.ClientMetadata != nil {
		details["client_metadata"] = authReq.ClientMetadata
	}
	if authReq.DCQLQuery != nil {
		details["dcql_query"] = authReq.DCQLQuery
	}
	if authReq.RequestPayload != nil {
		details["request_object"] = authReq.RequestPayload
	}
	return details
}

// RequestPayload returns the parsed request object payload when available,
// otherwise the fallback authorization request payload.
func RequestPayload(reqObj *oid4vc.RequestObjectJWT, fallback map[string]any) map[string]any {
	if reqObj != nil && reqObj.Payload != nil {
		return reqObj.Payload
	}
	return fallback
}

// PresentationSubmissionLogDetails returns the structured detail payload used by
// verbose wallet logs for successful presentation submissions.
func PresentationSubmissionLogDetails(authReq *AuthorizationRequestParams, w *Wallet, matches []CredentialMatch, vpResult *VPTokenMapResult, idToken string, result *DirectPostResult) map[string]any {
	details := presentationRequestLogDetails(authReq)
	if result != nil {
		details["status_code"] = result.StatusCode
		addStringDetail(details, "redirect_uri", result.RedirectURI)
		addStringDetail(details, "response_body", result.Body)
	}
	if vpResult != nil {
		details["vp_token"] = vpResult.VPToken()
	}
	if idToken != "" {
		details["id_token"] = idToken
	}
	if authReq.State != "" {
		details["state"] = authReq.State
	}
	if sent := sentCredentialLogDetails(matches); len(sent) > 0 {
		details["sent_credentials"] = sent
	}
	if presented := presentedCredentialLogDetails(w, matches, vpResult); len(presented) > 0 {
		details["presented_credentials"] = presented
	}
	return details
}

func presentationResponseLogDetails(authReq *AuthorizationRequestParams, w *Wallet, matches []CredentialMatch, prepared *preparedPresentation) map[string]any {
	var vpResult *VPTokenMapResult
	var idToken string
	var submissionURI string
	if prepared != nil {
		vpResult = prepared.VPResult
		idToken = prepared.IDToken
		submissionURI = prepared.ResponseURI
	}
	return PresentationResponseLogDetails(authReq, w, matches, vpResult, idToken, submissionURI)
}

// PresentationResponseLogDetails returns only the wallet's outbound
// authorization response details. Request-only material such as DCQL,
// request objects, client metadata, and nonce stays on presentation_request.
func PresentationResponseLogDetails(authReq *AuthorizationRequestParams, w *Wallet, matches []CredentialMatch, vpResult *VPTokenMapResult, idToken, submissionURI string) map[string]any {
	details := map[string]any{
		"direction": "outbound",
	}
	addStringDetail(details, "submission_uri", submissionURI)
	addStringDetail(details, "state", authReq.State)
	if authReq.Source != "" {
		details["source"] = authReq.Source
	}
	if vpResult != nil {
		details["vp_token"] = vpResult.VPToken()
	}
	if idToken != "" {
		details["id_token"] = idToken
	}
	if sent := sentCredentialLogDetails(matches); len(sent) > 0 {
		details["sent_credentials"] = sent
	}
	if presented := presentedCredentialLogDetails(w, matches, vpResult); len(presented) > 0 {
		details["presented_credentials"] = presented
	}
	return details
}

func verifierResponseLogDetails(authReq *AuthorizationRequestParams, prepared *preparedPresentation, result *DirectPostResult) map[string]any {
	details := map[string]any{
		"direction": "inbound",
	}
	addStringDetail(details, "client_id", authReq.ClientID)
	addStringDetail(details, "response_mode", authReq.ResponseMode)
	addStringDetail(details, "state", authReq.State)
	if prepared != nil {
		addStringDetail(details, "submission_uri", prepared.ResponseURI)
	}
	if authReq.Source != "" {
		details["source"] = authReq.Source
	}
	if result != nil {
		details["status_code"] = result.StatusCode
		addStringDetail(details, "redirect_uri", result.RedirectURI)
		addStringDetail(details, "response_body", result.Body)
	}
	return details
}

func credentialImportLogDetails(cred *StoredCredential, raw string) map[string]any {
	if cred == nil {
		return map[string]any{}
	}
	details := map[string]any{
		"credential": CredentialSummary(*cred),
	}
	addStringDetail(details, "credential_id", cred.ID)
	addStringDetail(details, "format", cred.Format)
	addStringDetail(details, "vct", cred.VCT)
	addStringDetail(details, "doc_type", cred.DocType)
	addStringDetail(details, "raw_credential", raw)
	return details
}

func sentCredentialLogDetails(matches []CredentialMatch) []map[string]any {
	if len(matches) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(matches))
	for _, match := range matches {
		item := map[string]any{
			"id":        match.CredentialID,
			"query_id":  match.QueryID,
			"format":    match.Format,
			"disclosed": append([]string(nil), match.SelectedKeys...),
		}
		addStringDetail(item, "vct", match.VCT)
		addStringDetail(item, "doc_type", match.DocType)
		out = append(out, item)
	}
	return out
}

func presentedCredentialLogDetails(w *Wallet, matches []CredentialMatch, vpResult *VPTokenMapResult) []map[string]any {
	if len(matches) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(matches))
	for _, match := range matches {
		item := map[string]any{
			"id":        match.CredentialID,
			"query_id":  match.QueryID,
			"format":    match.Format,
			"disclosed": append([]string(nil), match.SelectedKeys...),
		}
		addStringDetail(item, "vct", match.VCT)
		addStringDetail(item, "doc_type", match.DocType)
		if len(match.Claims) > 0 {
			item["claims"] = match.Claims
		}
		if w != nil {
			if cred, ok := w.GetCredential(match.CredentialID); ok {
				item["credential"] = CredentialSummary(cred)
				addStringDetail(item, "raw_credential", cred.Raw)
			}
		}
		if vpResult != nil {
			addStringDetail(item, "presentation", vpResult.TokenMap[match.QueryID])
		}
		out = append(out, item)
	}
	return out
}

func addStringDetail(details map[string]any, key string, value string) {
	if value != "" {
		details[key] = value
	}
}
