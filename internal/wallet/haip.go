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
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/validate"
)

// ValidateHAIPCompliance checks an authorization request against HAIP 1.0 and
// returns the violations, empty when the request conforms. Every finding is a
// MUST in the profile. The validation mode decides what a violation does.
func ValidateHAIPCompliance(params *AuthorizationRequestParams, reqObj *oid4vc.RequestObjectJWT) []string {
	var violations []string
	if params == nil {
		return []string{"HAIP 1.0: authorization request is missing"}
	}
	// §5.2: "The Wallet MUST support unsigned, signed, and multi-signed
	// requests as defined in Appendices A.3.1 and A.3.2 of [OIDF.OID4VP]." An
	// unsigned request carries no client_id, so the platform-reported origin
	// identifies the caller instead.
	unsigned := params.UnsignedDCAPI || (reqObj == nil && isDCAPIResponseMode(params.ResponseMode))

	// A presentation made during Interactive Authorization (OpenID4VCI 1.1
	// §6.2.1.1) is a step inside an issuance flow, whose response mode,
	// delivery and binding that specification fixes itself. HAIP 1.0 profiles
	// the two channels a Verifier sends an Authorization Request over, so its
	// channel rules do not apply here. What it asks of the query still does.
	interactive := isInteractiveAuthorizationResponseMode(params.ResponseMode)

	// §5: "The Response type MUST be vp_token."
	if params.ResponseType != "vp_token" {
		violations = append(violations, fmt.Sprintf(
			"HAIP 1.0 §5: response_type MUST be 'vp_token', got %q", params.ResponseType))
	}

	// §5.1: "Response encryption MUST be used by utilizing response mode
	// direct_post.jwt." §5.2: "The Verifier MUST use the Response Mode
	// dc_api.jwt." Those are the only two the profile permits.
	if !interactive && params.ResponseMode != "direct_post.jwt" && params.ResponseMode != "dc_api.jwt" {
		violations = append(violations, fmt.Sprintf(
			"HAIP 1.0 §5.1/§5.2: response_mode MUST be 'direct_post.jwt' or 'dc_api.jwt', got %q", params.ResponseMode))
	}

	if !unsigned && !interactive {
		// §5: "For signed requests, the Verifier MUST use, and the Wallet
		// MUST accept the Client Identifier Prefix x509_hash."
		if !strings.HasPrefix(params.ClientID, "x509_hash:") {
			violations = append(violations, fmt.Sprintf(
				"HAIP 1.0 §5: a signed request MUST use the 'x509_hash:' Client Identifier Prefix, got %q", params.ClientID))
		}
		if reqObj == nil || reqObj.Header == nil {
			violations = append(violations, "HAIP 1.0 §5.1: signed Request Object (JAR) MUST be used")
		}
		// §5.1 asks for more than a signature: "Signed Authorization Requests
		// MUST be used by utilizing JWT-Secured Authorization Request (JAR)
		// [RFC9101] with the request_uri parameter." A request object handed
		// over inline meets the first half only. The Digital Credentials API
		// has no request_uri.
		if reqObj != nil && !isDCAPIResponseMode(params.ResponseMode) && params.RequestURI == "" {
			violations = append(violations, "HAIP 1.0 §5.1: the signed Request Object MUST be delivered through the request_uri parameter")
		}
		violations = append(violations, haipSignedRequestViolations(reqObj)...)
	}

	// §5: "The DCQL query and response MUST be used as defined in Section 6
	// of [OIDF.OID4VP]."
	if params.DCQLQuery == nil {
		violations = append(violations, "HAIP 1.0 §5: DCQL query MUST be used (not presentation_definition)")
	}
	violations = append(violations, haipCredentialFormatViolations(params.DCQLQuery)...)

	if !interactive {
		violations = append(violations, haipClientMetadataViolations(params.ClientMetadata)...)
		violations = append(violations, haipEncryptionKeyViolations(params.RequestObject, params.ClientMetadata)...)
	}

	return violations
}

// haipEncryptionKeyViolations checks §5's requirement that the response is
// encrypted with ECDH-ES to the Verifier's key on the P-256 curve.
// findEncryptionJWK returns the key the response path uses (EC is preferred
// over RSA).
func haipEncryptionKeyViolations(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) []string {
	jwk := findEncryptionJWK(reqObj, clientMetadata)
	if jwk == nil {
		return nil
	}
	if kty, _ := jwk["kty"].(string); kty != "" && kty != "EC" {
		return []string{fmt.Sprintf("HAIP 1.0 §5: response encryption key MUST be an EC key on P-256 (ECDH-ES), got kty %q", kty)}
	}
	if crv, ok := jwk["crv"].(string); ok && crv != "P-256" {
		return []string{fmt.Sprintf("HAIP 1.0 §5: response encryption key MUST be on the P-256 curve, got %q", crv)}
	}
	return nil
}

// isDCAPIResponseMode reports whether a response mode belongs to the Digital
// Credentials API.
func isDCAPIResponseMode(mode string) bool {
	return mode == "dc_api" || mode == "dc_api.jwt"
}

// haipSignedRequestViolations checks the certificates a signed request
// carries.
func haipSignedRequestViolations(reqObj *oid4vc.RequestObjectJWT) []string {
	if reqObj == nil || reqObj.Header == nil {
		return nil
	}
	var violations []string

	// §5: "The X.509 certificate of the trust anchor MUST NOT be included in
	// the x5c JOSE header of the signed request. The X.509 certificate
	// signing the request MUST NOT be self-signed."
	//
	// Which certificate is the anchor depends on what the checking party
	// trusts, and this wallet holds no such list, so the finding reports the
	// visible fact: a self-signed certificate.
	certs, _ := extractCertChain(reqObj)
	if len(certs) > 0 {
		leaf := certs[0]
		if validate.SelfSignedCertificate(leaf) {
			violations = append(violations, "HAIP 1.0 §5: the certificate signing the request MUST NOT be self-signed")
		}
		for i, cert := range certs[1:] {
			if validate.SelfSignedCertificate(cert) {
				violations = append(violations, fmt.Sprintf(
					"HAIP 1.0 §5: the x5c header of the signed request carries a self-signed certificate at position %d (subject %q), where the certificate of the trust anchor MUST NOT be included",
					i+2, cert.Subject.String()))
				break
			}
		}
	}

	return violations
}

// haipCredentialFormatViolations checks the credential formats a DCQL query
// asks for. §5.3.1: "The Credential Format identifier MUST be mso_mdoc."
// §5.3.2: "The Credential Format identifier MUST be dc+sd-jwt." The profile
// covers those two and no others.
func haipCredentialFormatViolations(query map[string]any) []string {
	credentials, _ := query["credentials"].([]any)
	var violations []string
	for _, entry := range credentials {
		credential, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		format := jsonutil.GetString(credential, "format")
		if format != "mso_mdoc" && format != "dc+sd-jwt" {
			violations = append(violations, fmt.Sprintf(
				"HAIP 1.0 §5.3.1/§5.3.2: credential format MUST be 'mso_mdoc' or 'dc+sd-jwt', got %q", format))
		}
	}
	return violations
}

// haipClientMetadataViolations checks what §5 requires a Verifier to publish
// about response encryption.
func haipClientMetadataViolations(metadata map[string]any) []string {
	if metadata == nil {
		return nil
	}
	var violations []string

	// §5: "Verifiers MUST list both A128GCM and A256GCM in
	// encrypted_response_enc_values_supported in their client metadata."
	values, _ := metadata["encrypted_response_enc_values_supported"].([]any)
	listed := make(map[string]bool, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			listed[text] = true
		}
	}
	if !listed["A128GCM"] || !listed["A256GCM"] {
		violations = append(violations,
			"HAIP 1.0 §5: client metadata MUST list both 'A128GCM' and 'A256GCM' in encrypted_response_enc_values_supported")
	}

	return violations
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
// metadata against the HAIP 1.0 profile of OpenID4VCI.
//
// The checks follow the flow the offer drives. §4 requires an issuer to
// support the authorization code flow but says nothing about the
// pre-authorized one, and scopes PAR to "when using the Authorization
// Endpoint":
//
//   - always: the credential issuer MUST be an https origin
//   - authorization code offers: the authorization server MUST support the
//     flow, offer pushed authorization requests, support PKCE with S256,
//     and support DPoP
func ValidateHAIPIssuanceCompliance(offer *oid4vc.CredentialOffer, oauthMeta map[string]any) []string {
	var violations []string
	if offer == nil {
		return []string{"HAIP 1.0: credential offer is missing"}
	}

	// OID4VCI 1.0 §12.2.1: "The Credential Issuer Identifier MUST be a case
	// sensitive URL using the https scheme".
	if issuer := strings.TrimSpace(offer.CredentialIssuer); issuer != "" && !secureIssuerOrigin(issuer) {
		violations = append(violations, fmt.Sprintf("OID4VCI 1.0 §12.2.1: the credential issuer must be an https URL, got %q", issuer))
	}

	if !usesAuthorizationEndpoint(offer) {
		return violations
	}

	if oauthMeta == nil {
		return append(violations, "HAIP 1.0 §4: the authorization server metadata could not be read")
	}
	if !supportsAuthorizationCodeFlow(oauthMeta) {
		violations = append(violations, "HAIP 1.0 §4: the authorization server must support the authorization code flow")
	}
	// Pushed authorization requests belong to the authorization endpoint,
	// which an Interactive Authorization exchange never reaches (the request
	// goes to the Authorization Challenge Endpoint, and §4 scopes PAR to "when
	// using the Authorization Endpoint").
	//
	// Only the endpoint's presence is checkable: require_pushed_authorization_requests
	// is optional in RFC 9126, and FAPI 2.0 puts the obligation on behaviour.
	_, hasPAR := oauthMeta["pushed_authorization_request_endpoint"].(string)
	if !hasPAR && interactiveAuthorizationEndpoint(oauthMeta) == "" {
		violations = append(violations, "HAIP 1.0 §4: the authorization server must support pushed authorization requests")
	}
	// PKCE and DPoP are behavioural requirements that no profile obliges a
	// server to advertise (both metadata fields are optional), so absence is
	// no evidence. A list that is present and lacks them is a violation.
	if _, declared := oauthMeta["code_challenge_methods_supported"]; declared &&
		!metadataListContains(oauthMeta, "code_challenge_methods_supported", "S256") {
		violations = append(violations, "HAIP 1.0 §4: the authorization server advertises PKCE without S256")
	}
	// ES256 specifically: §7 requires every party to support it at a minimum,
	// and this wallet signs DPoP proofs with it.
	if _, declared := oauthMeta["dpop_signing_alg_values_supported"]; declared &&
		!metadataListContains(oauthMeta, "dpop_signing_alg_values_supported", "ES256") {
		violations = append(violations, "HAIP 1.0 §7: the authorization server advertises DPoP without ES256")
	}
	// Client authentication is not checked: §4.4.1 requires the
	// issuer to require it, but advertising it is only a SHOULD (§10.1 of the
	// attestation draft). The wallet finds out by authenticating.

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
	// Undeclared, so it is read off the endpoints that can issue a code: the
	// authorization endpoint, or the Authorization Challenge Endpoint that
	// replaces it under Interactive Authorization, where the grant is still
	// authorization_code.
	if interactiveAuthorizationEndpoint(oauthMeta) != "" {
		return true
	}
	endpoint, _ := oauthMeta["authorization_endpoint"].(string)
	return strings.TrimSpace(endpoint) != ""
}

// secureIssuerOrigin reports whether an issuer URL is acceptable transport.
// https always is. Plain http is allowed only on loopback, the way OAuth
// treats a local development host.
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

// haipCredentialViolations holds a received credential to §6.1.1. A credential
// in another format, or one this wallet cannot parse, is left to the checks
// that own it: the section is the IETF SD-JWT VC profile.
func (w *Wallet) haipCredentialViolations(raw string) []string {
	token, err := sdjwt.ParseLenient(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	return validate.HAIPCredentialFindings(token.Header, token.Payload)
}
