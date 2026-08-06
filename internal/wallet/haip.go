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

	// §5.1: "For signed requests, the Verifier MUST use, and the Wallet MUST
	// accept the Client Identifier Prefix x509_hash". That is the only prefix
	// the profile names. x509_san_dns appears nowhere in it, so accepting one
	// would pass a request the profile does not allow.
	//
	// Unsigned requests are the exception, and only over the Digital
	// Credentials API: §5.2 requires a wallet to support "unsigned, signed,
	// and multi-signed requests", noting that unsigned ones "depend on the
	// origin information provided by the platform". It leaves the mechanics to
	// Appendix A of OID4VP, which identifies that caller by the web origin.
	// So the prefix is not named in the profile, it is inherited from what the
	// profile points at.
	unsignedBrowserRequest := reqObj == nil && params.ResponseMode == "dc_api.jwt"
	if unsignedBrowserRequest {
		if !strings.HasPrefix(params.ClientID, "web-origin:") {
			violations = append(violations, fmt.Sprintf(
				"HAIP: an unsigned Digital Credentials API request must be identified by 'web-origin:', got %q", params.ClientID))
		}
	} else if !strings.HasPrefix(params.ClientID, "x509_hash:") {
		violations = append(violations, fmt.Sprintf(
			"HAIP: a signed request MUST use the 'x509_hash:' Client Identifier Prefix, got %q", params.ClientID))
	}

	// Browser API web-origin requests may be unsigned. Other HAIP requests require JAR.
	requiresJAR := !(params.ResponseMode == "dc_api.jwt" && strings.HasPrefix(params.ClientID, "web-origin:"))
	if requiresJAR && (reqObj == nil || reqObj.Header == nil) {
		violations = append(violations, "HAIP: signed Request Object (JAR) MUST be used")
	}
	// §5.1 does not stop at requiring JAR: "Signed Authorization Requests MUST
	// be used by utilizing JWT-Secured Authorization Request (JAR) [RFC9101]
	// with the request_uri parameter". A request object handed over inline
	// satisfies the first half and not the second, so the delivery is checked
	// as well as the signature. Requests over the Digital Credentials API do
	// not go through a request_uri at all and are left out.
	if requiresJAR && reqObj != nil && params.ResponseMode != "dc_api.jwt" && params.RequestURI == "" {
		violations = append(violations, "HAIP: the signed Request Object MUST be delivered through the request_uri parameter")
	}

	// §5.2.4: DCQL query MUST be used
	if params.DCQLQuery == nil {
		violations = append(violations, "HAIP: DCQL query MUST be used (not presentation_definition)")
	}

	// §7 puts ES256 as the floor a wallet must be able to validate a signed
	// presentation request with, and this wallet advertises exactly that in
	// its wallet_metadata: request_object_signing_alg_values_supported is
	// ["ES256"]. A verifier signing with anything else has therefore ignored
	// what the wallet told it, and its request would not be verifiable by a
	// wallet that implements the profile and nothing more. The profile lets
	// an ecosystem mandate further suites, so this is enforcement of the
	// baseline rather than a claim that no other algorithm exists.
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
//     flow, offer pushed authorization requests, support PKCE with S256,
//     and support DPoP
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
	// What is checkable is that the server offers PAR at all. Neither profile
	// asks it to advertise require_pushed_authorization_requests: HAIP 1.0 §4
	// scopes PAR to "when using the Authorization Endpoint" and defers to
	// FAPI 2.0, which puts the obligation on behaviour ("shall reject
	// authorization requests sent without RFC 9126") rather than on metadata.
	// The flag is optional in RFC 9126 and absent from conformant servers,
	// the EUDI reference issuer among them, so requiring it reported a
	// violation that no specification supports. The behavioural half is not
	// observable from metadata and does not need to be: this wallet sends the
	// authorization request through PAR or not at all.
	if _, ok := oauthMeta["pushed_authorization_request_endpoint"].(string); !ok {
		violations = append(violations, "HAIP: the authorization server must support pushed authorization requests")
	}
	// PKCE and DPoP are behavioural requirements, and neither profile obliges
	// a server to advertise them: code_challenge_methods_supported is
	// optional in RFC 8414 and dpop_signing_alg_values_supported in RFC 9449.
	// So absence is judged the same way absent client authentication already
	// is below, as no evidence either way, while a list that is present and
	// says the server cannot do what the profile requires is a violation the
	// wallet can stand behind.
	if _, declared := oauthMeta["code_challenge_methods_supported"]; declared &&
		!metadataListContains(oauthMeta, "code_challenge_methods_supported", "S256") {
		violations = append(violations, "HAIP: the authorization server advertises PKCE without S256")
	}
	// ES256 specifically: this wallet signs DPoP proofs with its holder key,
	// and §7 requires every party to support that algorithm at a minimum, so
	// a server that lists DPoP algorithms without it contradicts the profile
	// and could not accept a proof from any conformant wallet either.
	if _, declared := oauthMeta["dpop_signing_alg_values_supported"]; declared &&
		!metadataListContains(oauthMeta, "dpop_signing_alg_values_supported", "ES256") {
		violations = append(violations, "HAIP: the authorization server advertises DPoP without ES256")
	}
	// Client authentication is deliberately not checked here. HAIP 1.0 §4.4.1
	// requires the issuer to require it, but nothing requires the issuer to
	// advertise it: draft-ietf-oauth-attestation-based-client-auth §10.1 makes
	// that a SHOULD. Absent metadata is therefore no evidence of a violation,
	// and the wallet finds out by authenticating, which under HAIP it always
	// does.

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
