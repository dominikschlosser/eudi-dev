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

	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
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
// In debug mode findings are returned as warnings; in strict mode any finding is fatal.
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
	findings = append(findings, strictAuthorizationFindings(mode, params, payload)...)

	if mode == ValidationModeStrict && len(findings) > 0 {
		return nil, fmt.Errorf("authorization request validation failed: %s", strings.Join(findings, "; "))
	}

	return findings, nil
}

func strictAuthorizationFindings(mode ValidationMode, params *AuthorizationRequestParams, payload map[string]any) []string {
	if mode != ValidationModeStrict || params == nil {
		return nil
	}

	var findings []string
	if !hasKnownClientIDPrefix(params.ClientID) {
		findings = append(findings, fmt.Sprintf("client_id uses unsupported prefix or no prefix: %q", params.ClientID))
	}
	if requestRequiresNonce(params.ResponseType) && params.Nonce == "" {
		findings = append(findings, "nonce is required in strict mode")
	}
	if responseModeUsesDirectPost(params.ResponseMode) && params.RedirectURI != "" {
		findings = append(findings, fmt.Sprintf("redirect_uri must not be used with response_mode %q", params.ResponseMode))
	}
	if payloadHasKey(payload, "transaction_data") {
		findings = append(findings, "transaction_data is not supported by this wallet")
	}
	return findings
}

func requestRequiresNonce(responseType string) bool {
	return responseType == "" || ResponseTypeRequiresVP(responseType) || ResponseTypeContains(responseType, "id_token")
}

func responseModeUsesDirectPost(responseMode string) bool {
	return responseMode == "direct_post" || responseMode == "direct_post.jwt"
}

func hasKnownClientIDPrefix(clientID string) bool {
	for _, prefix := range []string{
		"x509_san_dns:",
		"x509_hash:",
		"web-origin:",
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
	if params.ClientID == "" {
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

func validateAbsoluteURI(field, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return fmt.Errorf("%s must be an absolute URI", field)
	}
	return nil
}
