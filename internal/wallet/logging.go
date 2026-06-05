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

import "fmt"

func (s *Server) addPresentationRequestLog(authReq *AuthorizationRequestParams, source string) {
	clientID := authReq.ClientID
	if clientID == "" {
		clientID = "unknown verifier"
	}
	details := presentationRequestLogDetails(authReq)
	if source != "" {
		details["source"] = source
	}
	s.wallet.AddLogDetails("presentation", fmt.Sprintf("Received presentation request from %s", clientID), true, details)
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

func presentationSubmissionLogDetails(authReq *AuthorizationRequestParams, matches []CredentialMatch, prepared *preparedPresentation, result *DirectPostResult) map[string]any {
	details := presentationRequestLogDetails(authReq)
	if prepared != nil {
		addStringDetail(details, "submission_uri", prepared.ResponseURI)
	}
	if result != nil {
		details["status_code"] = result.StatusCode
		addStringDetail(details, "redirect_uri", result.RedirectURI)
		addStringDetail(details, "response_body", result.Body)
	}
	if prepared != nil && prepared.VPResult != nil {
		details["vp_token"] = prepared.VPResult.VPToken()
	}
	if prepared != nil && prepared.IDToken != "" {
		details["id_token"] = prepared.IDToken
	}
	if authReq.State != "" {
		details["state"] = authReq.State
	}
	if sent := sentCredentialLogDetails(matches); len(sent) > 0 {
		details["sent_credentials"] = sent
	}
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

func addStringDetail(details map[string]any, key string, value string) {
	if value != "" {
		details[key] = value
	}
}
