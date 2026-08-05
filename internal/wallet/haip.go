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
	"net/netip"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// ValidateHAIPCompliance checks an authorization request against HAIP 1.0 requirements.
// Returns a list of violation messages. Empty list means compliant.
//
// HAIP requires:
//   - response_mode MUST be an encrypted mode: direct_post.jwt or dc_api.jwt
//   - client_id MUST use an allowed HAIP scheme
//   - Signed Request Objects (JAR) MUST be used except for web-origin Browser API requests
//   - DCQL query MUST be used (not presentation_definition)
//   - Request Object alg MUST be ES256 when a Request Object is present
func ValidateHAIPCompliance(params *AuthorizationRequestParams, reqObj *oid4vc.RequestObjectJWT) []string {
	var violations []string
	if params == nil {
		return []string{"HAIP: authorization request is missing"}
	}
	var payload map[string]any
	if reqObj != nil {
		payload = reqObj.Payload
	}
	if payload == nil && params != nil {
		payload = params.RequestPayload
	}

	// Encrypted response modes are required.
	if params.ResponseMode != "direct_post.jwt" && params.ResponseMode != "dc_api.jwt" {
		violations = append(violations, fmt.Sprintf(
			"HAIP: response_mode MUST be 'direct_post.jwt' or 'dc_api.jwt', got %q", params.ResponseMode))
	}

	// Current HAIP wallet profiles use x509-bound or web-origin client identifiers.
	if !strings.HasPrefix(params.ClientID, "x509_hash:") &&
		!strings.HasPrefix(params.ClientID, "x509_san_dns:") &&
		!strings.HasPrefix(params.ClientID, "web-origin:") {
		violations = append(violations, fmt.Sprintf(
			"HAIP: client_id MUST use 'x509_hash:', 'x509_san_dns:', or 'web-origin:' scheme, got %q", params.ClientID))
	}

	// Browser API web-origin requests may be unsigned. Other HAIP requests require JAR.
	requiresJAR := !(params.ResponseMode == "dc_api.jwt" && strings.HasPrefix(params.ClientID, "web-origin:"))
	if requiresJAR && (reqObj == nil || reqObj.Header == nil) {
		violations = append(violations, "HAIP: signed Request Object (JAR) MUST be used")
	}

	// §5.2.4: DCQL query MUST be used
	if params.DCQLQuery == nil {
		violations = append(violations, "HAIP: DCQL query MUST be used (not presentation_definition)")
	}

	// §7: ES256 MUST be supported. Request object alg MUST be ES256
	if reqObj != nil && reqObj.Header != nil {
		alg := jsonutil.GetString(reqObj.Header, "alg")
		if alg != "" && alg != "ES256" {
			violations = append(violations, fmt.Sprintf(
				"HAIP: Request Object algorithm MUST be ES256, got %q", alg))
		}
	}

	if params.ResponseMode == "dc_api.jwt" && params.RequestOrigin != "" {
		unsignedWebOrigin := reqObj == nil && strings.HasPrefix(params.ClientID, "web-origin:")
		if (!unsignedWebOrigin || expectedOriginsProvided(payload)) &&
			!originAllowedByExpectedOrigins(payload, params.RequestOrigin) {
			violations = append(violations, fmt.Sprintf(
				"HAIP: expected_origins MUST include caller origin %q", params.RequestOrigin))
		}
	}

	return violations
}

func expectedOriginsProvided(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	_, ok := payload["expected_origins"]
	return ok
}

func originAllowedByExpectedOrigins(payload map[string]any, origin string) bool {
	if payload == nil {
		return false
	}
	values := jsonutil.GetArray(payload, "expected_origins")
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if text, ok := value.(string); ok && text == origin {
			return true
		}
	}
	return false
}

// ValidateHAIPIssuanceCompliance checks a credential offer and the issuer's
// metadata against the HAIP 1.0 profile of OpenID4VCI. It returns violation
// messages. An empty list means compliant.
//
// HAIP 1.0 §4 requires an issuer to *support* the authorization code flow. It
// does not require an issuer to use it for every credential, and it says
// nothing about the pre-authorized code flow, so an offer that uses that flow
// is conformant. §4 also scopes pushed authorization requests to "when using
// the Authorization Endpoint".
//
// The checks therefore follow the flow the offer actually drives, because
// that is what a wallet can assess from an offer in front of it:
//
//   - always: the credential issuer MUST be an https origin
//   - authorization code offers: the authorization server MUST support the
//     flow, require pushed authorization requests, support PKCE with S256,
//     support DPoP, and authenticate the client
//
// A pre-authorized code offer never reaches the authorization endpoint, so
// holding it to those endpoint requirements would be stricter than the
// profile.
func ValidateHAIPIssuanceCompliance(offer *oid4vc.CredentialOffer, oauthMeta map[string]any) []string {
	var violations []string
	if offer == nil {
		return []string{"HAIP: credential offer is missing"}
	}

	if issuer := strings.TrimSpace(offer.CredentialIssuer); issuer != "" && !secureIssuerOrigin(issuer) {
		violations = append(violations, fmt.Sprintf("HAIP: the credential issuer must be an https URL, got %q", issuer))
	}

	if !usesAuthorizationEndpoint(offer) {
		return violations
	}

	if oauthMeta == nil {
		return append(violations, "HAIP: the authorization server metadata could not be read")
	}
	if !supportsAuthorizationCodeFlow(oauthMeta) {
		violations = append(violations, "HAIP: the authorization server must support the authorization code flow")
	}
	if required, _ := oauthMeta["require_pushed_authorization_requests"].(bool); !required {
		violations = append(violations, "HAIP: the authorization server must require pushed authorization requests")
	}
	if !metadataListContains(oauthMeta, "code_challenge_methods_supported", "S256") {
		violations = append(violations, "HAIP: the authorization server must support PKCE with S256")
	}
	if !supportsDPoP(oauthMeta) {
		violations = append(violations, "HAIP: the authorization server must support DPoP")
	}
	if method := detectTokenEndpointAuthMethod(oauthMeta); method != "attest_jwt_client_auth" && method != "private_key_jwt" {
		violations = append(violations, "HAIP: the authorization server must authenticate the client with attest_jwt_client_auth or private_key_jwt")
	}

	return violations
}

// usesAuthorizationEndpoint reports whether redeeming this offer goes through
// the authorization endpoint. An offer carrying only a pre-authorized code
// goes straight to the token endpoint.
func usesAuthorizationEndpoint(offer *oid4vc.CredentialOffer) bool {
	if offer.Grants.AuthorizationCode != "" || offer.Grants.IssuerState != "" {
		return true
	}
	return offer.Grants.PreAuthorizedCode == ""
}

// supportsAuthorizationCodeFlow reports whether the authorization server
// advertises the flow HAIP 1.0 §4 requires it to support. Metadata that
// omits grant_types_supported defaults to authorization_code per RFC 8414,
// so an authorization endpoint alone is enough to satisfy it.
func supportsAuthorizationCodeFlow(oauthMeta map[string]any) bool {
	if _, declared := oauthMeta["grant_types_supported"]; declared {
		return metadataListContains(oauthMeta, "grant_types_supported", "authorization_code")
	}
	endpoint, _ := oauthMeta["authorization_endpoint"].(string)
	return strings.TrimSpace(endpoint) != ""
}

// secureIssuerOrigin reports whether an issuer URL is acceptable transport.
// https always is. Plain http is allowed only on loopback, the way OAuth
// treats a local development host, so a demo instance on localhost is not
// rejected for being local.
func secureIssuerOrigin(issuer string) bool {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// metadataListContains reports whether a metadata array holds the value.
func metadataListContains(meta map[string]any, key, want string) bool {
	values, ok := meta[key].([]any)
	if !ok {
		return false
	}
	for _, raw := range values {
		if s, _ := raw.(string); s == want {
			return true
		}
	}
	return false
}
