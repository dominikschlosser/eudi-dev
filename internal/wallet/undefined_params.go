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
	"sort"
	"strings"
)

// definedRequestParameters are the Authorization Request parameters OID4VP
// 1.0 defines or reuses (§5.1, §5.2, §5.10, §8.2, Appendix A.2, RFC 6749,
// JAR).
var definedRequestParameters = map[string]bool{
	"client_id":          true,
	"response_type":      true,
	"response_mode":      true,
	"response_uri":       true,
	"redirect_uri":       true,
	"nonce":              true,
	"state":              true,
	"scope":              true,
	"request":            true,
	"request_uri":        true,
	"request_uri_method": true,
	"dcql_query":         true,
	"client_metadata":    true,
	"transaction_data":   true,
	"verifier_info":      true,
	"expected_origins":   true,
	"wallet_nonce":       true,
}

// definedRequestObjectMembers adds what a signed request object may also
// carry (RFC 7519 registered claims, used by JAR).
var definedRequestObjectMembers = func() map[string]bool {
	merged := map[string]bool{
		"iss": true,
		"sub": true,
		"aud": true,
		"exp": true,
		"nbf": true,
		"iat": true,
		"jti": true,
	}
	for name := range definedRequestParameters {
		merged[name] = true
	}
	return merged
}()

// undefinedRequestParameterFindings lists request parameters the specs do
// not define. RFC 6749 §3.1 has unrecognized parameters ignored, so these
// stay warnings in every mode and never fail a strict flow.
func undefinedRequestParameterFindings(params *AuthorizationRequestParams) []string {
	if params == nil {
		return nil
	}
	undefined := map[string]bool{}
	if params.RequestObject != nil && params.RequestObject.Payload != nil {
		// The outer query parameters are still checked below: they are the
		// place testers put stray fields, even though a signed request only
		// uses its object's members (OID4VP 1.0 §5.10.1).
		for name := range params.RequestObject.Payload {
			if !definedRequestObjectMembers[name] {
				undefined[name] = true
			}
		}
	} else if params.RequestPayload != nil {
		for name := range params.RequestPayload {
			if !definedRequestParameters[name] {
				undefined[name] = true
			}
		}
	}
	for name := range params.FullParams {
		if !definedRequestParameters[name] {
			undefined[name] = true
		}
	}

	names := make([]string, 0, len(undefined))
	for name := range undefined {
		names = append(names, name)
	}
	sort.Strings(names)

	findings := make([]string, 0, len(names))
	for _, name := range names {
		findings = append(findings, fmt.Sprintf("The request parameter %q is not defined in OID4VP 1.0 and is ignored", name))
	}
	return findings
}

// warnUndefinedRequestParameters records the undefined-parameter findings of
// a presentation request.
func (w *Wallet) warnUndefinedRequestParameters(scope string, params *AuthorizationRequestParams) {
	w.warnFindings(scope, "The request contains parameters OID4VP 1.0 does not define", undefinedRequestParameterFindings(params))
}

// undefinedResponseMembers lists fields of an accepted response that OID4VP
// 1.0 §8.2 does not define (redirect_uri is its only one). A non-2xx answer
// is an OAuth error response with its own members, not a §8.2 body.
func undefinedResponseMembers(result *DirectPostResult) []string {
	if result == nil || result.StatusCode < 200 || result.StatusCode >= 300 {
		return nil
	}
	var respJSON map[string]any
	if json.Unmarshal([]byte(result.Body), &respJSON) != nil {
		return nil
	}
	var members []string
	for member := range respJSON {
		if member != "redirect_uri" {
			members = append(members, member)
		}
	}
	sort.Strings(members)
	return members
}

func (w *Wallet) warnUndefinedResponseMembers(result *DirectPostResult) {
	members := undefinedResponseMembers(result)
	if len(members) == 0 {
		return
	}
	w.AddWarning("presentation", fmt.Sprintf(
		"The verifier's response contains fields OID4VP 1.0 §8.2 does not define: %s. They are ignored.",
		strings.Join(members, ", ")), nil)
}
