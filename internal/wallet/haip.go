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
	"crypto/x509"
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
// MUST in the profile; what a violation does is the validation mode's call.
func ValidateHAIPCompliance(params *AuthorizationRequestParams, reqObj *oid4vc.RequestObjectJWT) []string {
	var violations []string
	if params == nil {
		return []string{"HAIP: authorization request is missing"}
	}
	var payload map[string]any
	if reqObj != nil {
		payload = reqObj.Payload
	}
	if payload == nil {
		payload = params.RequestPayload
	}

	// §5.2: "The Wallet MUST support unsigned, signed, and multi-signed
	// requests as defined in Appendices A.3.1 and A.3.2 of [OIDF.OID4VP]." An
	// unsigned request carries no client_id, so the platform-reported origin
	// identifies the caller instead.
	unsigned := params.UnsignedDCAPI || (reqObj == nil && isDCAPIResponseMode(params.ResponseMode))

	// HAIP 1.0 profiles the two channels a Verifier sends an Authorization
	// Request over, and a presentation made during Interactive Authorization
	// (OpenID4VCI 1.1 §6.2.1.1) is neither: it is a step inside an issuance
	// flow, whose response mode, delivery and binding the newer specification
	// fixes itself. Holding it to the profile's channel rules reports
	// violations no specification supports, and in strict mode would stop the
	// wallet using the feature at all. What the profile asks of the query
	// still applies.
	interactive := isInteractiveAuthorizationResponseMode(params.ResponseMode)

	// §5: "The Response type MUST be vp_token."
	if params.ResponseType != "vp_token" {
		violations = append(violations, fmt.Sprintf(
			"HAIP: response_type MUST be 'vp_token', got %q", params.ResponseType))
	}

	// §5.1: "Response encryption MUST be used by utilizing response mode
	// direct_post.jwt." §5.2: "The Verifier MUST use the Response Mode
	// dc_api.jwt." Those are the only two the profile permits.
	if !interactive && params.ResponseMode != "direct_post.jwt" && params.ResponseMode != "dc_api.jwt" {
		violations = append(violations, fmt.Sprintf(
			"HAIP: response_mode MUST be 'direct_post.jwt' or 'dc_api.jwt', got %q", params.ResponseMode))
	}

	if !unsigned && !interactive {
		// §5: "For signed requests, the Verifier MUST use, and the Wallet
		// MUST accept the Client Identifier Prefix x509_hash." It is the only
		// prefix the profile names, so anything else is a request the profile
		// does not allow.
		if !strings.HasPrefix(params.ClientID, "x509_hash:") {
			violations = append(violations, fmt.Sprintf(
				"HAIP: a signed request MUST use the 'x509_hash:' Client Identifier Prefix, got %q", params.ClientID))
		}
		if reqObj == nil || reqObj.Header == nil {
			violations = append(violations, "HAIP: signed Request Object (JAR) MUST be used")
		}
		// §5.1 asks for more than a signature: "Signed Authorization Requests
		// MUST be used by utilizing JWT-Secured Authorization Request (JAR)
		// [RFC9101] with the request_uri parameter." A request object handed
		// over inline meets the first half only. The Digital Credentials API
		// has no request_uri and is left out.
		if reqObj != nil && !isDCAPIResponseMode(params.ResponseMode) && params.RequestURI == "" {
			violations = append(violations, "HAIP: the signed Request Object MUST be delivered through the request_uri parameter")
		}
		violations = append(violations, haipSignedRequestViolations(params, reqObj)...)
	}

	// §5: "The DCQL query and response MUST be used as defined in Section 6
	// of [OIDF.OID4VP]."
	if params.DCQLQuery == nil {
		violations = append(violations, "HAIP: DCQL query MUST be used (not presentation_definition)")
	}
	violations = append(violations, haipCredentialFormatViolations(params.DCQLQuery)...)

	// OID4VP 1.0 Appendix A.2, which §5.2 incorporates: expected_origins is
	// "REQUIRED when signed requests defined in Appendix A.3.2 are used with
	// the Digital Credentials API", and for unsigned ones "a Wallet MUST
	// ignore this parameter if it is present".
	if !unsigned && isDCAPIResponseMode(params.ResponseMode) && params.RequestOrigin != "" {
		if !originAllowedByExpectedOrigins(payload, params.RequestOrigin) {
			violations = append(violations, fmt.Sprintf(
				"HAIP: expected_origins MUST include caller origin %q", params.RequestOrigin))
		}
	}

	if !interactive {
		violations = append(violations, haipClientMetadataViolations(params.ClientMetadata)...)
	}

	return violations
}

// isDCAPIResponseMode reports whether a response mode belongs to the Digital
// Credentials API.
func isDCAPIResponseMode(mode string) bool {
	return mode == "dc_api" || mode == "dc_api.jwt"
}

// haipSignedRequestViolations checks what the profile requires of the request
// signature. The x509_hash prefix value hashes the signing certificate, and
// OID4VP §5.9.3 obliges the wallet to "validate the signature and the trust
// chain of the X.509 leaf certificate".
func haipSignedRequestViolations(params *AuthorizationRequestParams, reqObj *oid4vc.RequestObjectJWT) []string {
	if reqObj == nil || reqObj.Header == nil {
		return nil
	}
	var violations []string

	if finding := VerifyRequestObjectSignature(params.ClientID, reqObj); finding != "" {
		violations = append(violations, "HAIP: "+finding)
	}
	if strings.HasPrefix(params.ClientID, "x509_hash:") {
		if finding := verifyX509Hash(params.ClientID, reqObj); finding != "" {
			violations = append(violations, "HAIP: "+finding)
		}
	}

	// §5: "The X.509 certificate of the trust anchor MUST NOT be included in
	// the x5c JOSE header of the signed request. The X.509 certificate
	// signing the request MUST NOT be self-signed."
	//
	// Which certificate is the anchor depends on what the checking party was
	// configured to trust, and this wallet holds no such list. So the finding
	// reports what is visible, a self-signed certificate, rather than claiming
	// the anchor was included.
	certs, _ := extractCertChain(reqObj)
	if len(certs) > 0 {
		leaf := certs[0]
		if isSelfSignedCert(leaf) {
			violations = append(violations, "HAIP: the certificate signing the request MUST NOT be self-signed")
		}
		for i, cert := range certs[1:] {
			if isSelfSignedCert(cert) {
				violations = append(violations, fmt.Sprintf(
					"HAIP: the x5c header of the signed request carries a self-signed certificate at position %d (subject %q), and §5 says the certificate of the trust anchor MUST NOT be included there",
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
				"HAIP: credential format MUST be 'mso_mdoc' or 'dc+sd-jwt', got %q", format))
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
			"HAIP: client metadata MUST list both 'A128GCM' and 'A256GCM' in encrypted_response_enc_values_supported")
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
	// Pushed authorization requests belong to the authorization endpoint, which
	// an Interactive Authorization exchange never reaches: the request goes to
	// the Authorization Challenge Endpoint instead, and §4 scopes PAR to "when
	// using the Authorization Endpoint". The grant is still authorization_code,
	// so the check above still applies.
	//
	// Only the endpoint's presence is checkable. Neither profile asks a server
	// to advertise require_pushed_authorization_requests: FAPI 2.0 puts the
	// obligation on behaviour, and the flag is optional in RFC 9126 and absent
	// from conformant servers such as the EUDI reference issuer.
	_, hasPAR := oauthMeta["pushed_authorization_request_endpoint"].(string)
	if !hasPAR && interactiveAuthorizationEndpoint(oauthMeta) == "" {
		violations = append(violations, "HAIP: the authorization server must support pushed authorization requests")
	}
	// PKCE and DPoP are behavioural requirements that no profile obliges a
	// server to advertise (both metadata fields are optional), so absence is
	// no evidence. A list that is present and lacks them is a violation.
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
	// Client authentication is deliberately not checked: §4.4.1 requires the
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

// isSelfSignedCert reports whether a certificate is its own issuer, which is
// what a trust anchor looks like inside a chain that must not carry one.
func isSelfSignedCert(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// haipCredentialIssuerViolations reads the pieces validate.HAIPIssuerBinding
// compares out of a received credential. A credential in another format, or
// one this wallet cannot parse, is left to the checks that own it.
func (w *Wallet) haipCredentialIssuerViolations(raw string) []string {
	token, err := sdjwt.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	chain, err := validate.X5CCertificates(token.Header)
	if err != nil || len(chain) == 0 {
		return nil
	}
	iss, _ := token.Payload["iss"].(string)
	return validate.HAIPIssuerBinding(iss, chain)
}
