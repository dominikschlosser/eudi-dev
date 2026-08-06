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
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// ValidateAuthorizationRequest evaluates request syntax, verifier metadata, and
// request-object checks for the full authorization request the wallet received.
func ValidateAuthorizationRequest(mode ValidationMode, params *AuthorizationRequestParams) ([]string, error) {
	if err := validateAuthorizationRequestSyntax(params); err != nil {
		return nil, fmt.Errorf("authorization request validation failed: %w", err)
	}

	var reqPayload map[string]any
	if params != nil && params.RequestObject != nil {
		reqPayload = params.RequestObject.Payload
	}
	if reqPayload == nil && params != nil {
		reqPayload = params.RequestPayload
	}
	var outerClientMetadata map[string]any
	if params != nil {
		outerClientMetadata = params.ClientMetadata
	}
	if err := ValidateClientMetadata(ResolveClientMetadata(reqPayload, outerClientMetadata)); err != nil {
		return nil, fmt.Errorf("authorization request validation failed: %w", err)
	}

	responseURI := ""
	clientID := ""
	requestOrigin := ""
	var reqObj *oid4vc.RequestObjectJWT
	if params != nil {
		responseURI = params.ResponseURI
		if responseURI == "" {
			responseURI = params.RedirectURI
		}
		clientID = params.ClientID
		requestOrigin = params.RequestOrigin
		reqObj = params.RequestObject
	}
	return validatePresentationRequestCore(mode, clientID, reqObj, responseURI, requestOrigin, params, reqPayload)
}

// ValidatePresentationRequest evaluates client_id, request-object metadata, and signature checks.
// In debug mode findings are returned as warnings. In strict mode any finding is fatal.
func ValidatePresentationRequest(mode ValidationMode, clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string) ([]string, error) {
	return validatePresentationRequestCore(mode, clientID, reqObj, responseURI, "", nil, nil)
}

func validatePresentationRequestCore(mode ValidationMode, clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string, requestOrigin string, params *AuthorizationRequestParams, payload map[string]any) ([]string, error) {
	var findings []string

	if finding := VerifyClientID(clientID, reqObj, responseURI, requestOrigin); finding != "" {
		findings = append(findings, finding)
	}
	if finding := ValidateRequestObject(clientID, reqObj); finding != "" {
		findings = append(findings, finding)
	}
	if finding := VerifyRequestObjectSignature(reqObj); finding != "" {
		findings = append(findings, finding)
	}
	findings = append(findings, authorizationFindings(params, payload)...)

	if mode == ValidationModeStrict && len(findings) > 0 {
		return nil, fmt.Errorf("authorization request validation failed: %s", strings.Join(findings, "; "))
	}

	return findings, nil
}

// authorizationFindings collects what an authorization request gets wrong
// against OpenID4VP 1.0.
//
// Findings are gathered in every mode. What the mode decides is what happens
// to them: strict stops the flow, debug reports them and carries on so a
// developer can watch the rest of the exchange. Collecting them only in strict
// mode meant a debug run said nothing at all about a malformed request, which
// is the run where saying something matters most.
func authorizationFindings(params *AuthorizationRequestParams, payload map[string]any) []string {
	if params == nil {
		return nil
	}

	var findings []string
	if !hasKnownClientIDPrefix(params.ClientID) {
		findings = append(findings, fmt.Sprintf("client_id uses an unsupported prefix: %q", params.ClientID))
	}
	// §5.2 marks nonce REQUIRED. It is what binds the presentation to this
	// request, so a missing one is not a formality.
	if requestRequiresNonce(params.ResponseType) && params.Nonce == "" {
		findings = append(findings, "nonce is required")
	}
	// §8.2: "When the response_uri parameter is present, the redirect_uri
	// Authorization Request parameter MUST NOT be present."
	if responseModeUsesDirectPost(params.ResponseMode) && params.RedirectURI != "" {
		findings = append(findings, fmt.Sprintf("redirect_uri must not be used with response_mode %q", params.ResponseMode))
	}
	// §5.1: "Either a dcql_query or a scope parameter representing a DCQL
	// Query MUST be present in the Authorization Request, but not both."
	if ResponseTypeRequiresVP(params.ResponseType) {
		hasDCQL := params.DCQLQuery != nil
		hasScope := strings.TrimSpace(params.Scope) != ""
		switch {
		case hasDCQL && hasScope:
			findings = append(findings, "dcql_query and scope must not both be present")
		case !hasDCQL && !hasScope:
			findings = append(findings, "a vp_token request must carry either dcql_query or scope")
		}
	}
	// §5: "Wallets that do not support this parameter MUST reject requests
	// that contain it." Answering without transaction_data_hashes instead
	// produces a presentation the Verifier has to refuse, for a reason it
	// cannot see.
	if payloadHasKey(payload, "transaction_data") {
		findings = append(findings, "transaction_data is not supported by this wallet")
	}
	// Appendix A.2: for a signed Digital Credentials API request
	// expected_origins is REQUIRED, and "If the Origin does not match any of
	// the entries in expected_origins, the Wallet MUST return an error."
	if !params.UnsignedDCAPI && isDCAPIResponseMode(params.ResponseMode) && params.RequestOrigin != "" {
		if !originAllowedByExpectedOrigins(payload, params.RequestOrigin) {
			findings = append(findings, fmt.Sprintf(
				"expected_origins must include the caller origin %q", params.RequestOrigin))
		}
	}
	return findings
}

func requestRequiresNonce(responseType string) bool {
	return responseType == "" || ResponseTypeRequiresVP(responseType) || ResponseTypeContains(responseType, "id_token")
}

func responseModeUsesDirectPost(responseMode string) bool {
	return responseMode == "direct_post" || responseMode == "direct_post.jwt"
}

// hasKnownClientIDPrefix reports whether a Client Identifier is one this
// wallet can make sense of.
//
// OID4VP 1.0 §5.9.2: "If a : character is not present in the Client
// Identifier, the Wallet MUST treat the Client Identifier as referencing a
// pre-registered client." So a bare identifier is legal rather than
// prefix-less, and only an unrecognised prefix is worth reporting.
func hasKnownClientIDPrefix(clientID string) bool {
	if !strings.Contains(clientID, ":") {
		return true
	}
	for _, prefix := range []string{
		"x509_san_dns:",
		"x509_hash:",
		"redirect_uri:",
		"verifier_attestation:",
		"decentralized_identifier:",
	} {
		if strings.HasPrefix(clientID, prefix) {
			return true
		}
	}
	return false
}

func payloadHasKey(payload map[string]any, key string) bool {
	if payload == nil {
		return false
	}
	_, ok := payload[key]
	return ok
}

func validateAuthorizationRequestSyntax(params *AuthorizationRequestParams) error {
	if params == nil {
		return fmt.Errorf("authorization request is missing")
	}
	// An unsigned request over the Digital Credentials API is the one shape
	// that carries no client_id. OID4VP 1.0 Appendix A.2: "The client_id
	// parameter MUST be omitted in unsigned requests defined in Appendix
	// A.3.1." Demanding one there refuses the only kind of caller that
	// endpoint has.
	if params.ClientID == "" && !params.UnsignedDCAPI {
		return fmt.Errorf("missing client_id")
	}
	if err := validateResponseType(params.ResponseType); err != nil {
		return err
	}
	if err := validateResponseMode(params.ResponseMode, params.ResponseURI, params.RedirectURI); err != nil {
		return err
	}
	if err := validateRequestURIMethod(params.RequestURIMethod); err != nil {
		return err
	}
	if err := validateAbsoluteURI("response_uri", params.ResponseURI); err != nil {
		return err
	}
	if err := validateAbsoluteURI("redirect_uri", params.RedirectURI); err != nil {
		return err
	}
	return nil
}

func validateRequestURIMethod(method string) error {
	switch method {
	case "", "get", "post":
		return nil
	default:
		return fmt.Errorf("unsupported request_uri_method %q", method)
	}
}

func validateResponseType(responseType string) error {
	if responseType == "" {
		return nil
	}
	seen := map[string]bool{}
	for _, part := range strings.Fields(responseType) {
		switch part {
		case "vp_token", "id_token":
			if seen[part] {
				return fmt.Errorf("response_type %q contains duplicate %q", responseType, part)
			}
			seen[part] = true
		default:
			return fmt.Errorf("unsupported response_type value %q", part)
		}
	}
	return nil
}

func validateResponseMode(responseMode, responseURI, redirectURI string) error {
	switch responseMode {
	case "", "direct_post", "direct_post.jwt":
		if responseMode != "" && responseURI == "" {
			return fmt.Errorf("response_mode %q requires response_uri", responseMode)
		}
	case "dc_api", "dc_api.jwt":
		return nil
	case "fragment":
		if redirectURI == "" {
			return fmt.Errorf("response_mode %q requires redirect_uri", responseMode)
		}
	default:
		return fmt.Errorf("unsupported response_mode %q", responseMode)
	}
	return nil
}

// validateAbsoluteURI checks a URI the wallet will send a browser to. "Absolute"
// alone is not enough: url.Parse reports javascript: and data: as absolute, and
// a verifier that answers a presentation with
// {"redirect_uri":"javascript:..."} would then get script execution on the
// wallet's own origin. Only http and https can be navigated to safely.
func validateAbsoluteURI(field, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return fmt.Errorf("%s must be an absolute URI", field)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("%s must use http or https, got scheme %q", field, u.Scheme)
	}
}
