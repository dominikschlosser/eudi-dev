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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// VerifyRequestObjectSignature verifies the Request Object JWS using the leaf x5c certificate.
// If an x5c chain is present, it also verifies that the supplied chain is internally consistent.
func VerifyRequestObjectSignature(reqObj *oid4vc.RequestObjectJWT) string {
	if reqObj == nil {
		return ""
	}
	if reqObj.Raw == "" {
		return "Request Object signature cannot be verified because the raw JWT is unavailable"
	}
	if reqObj.Header == nil {
		return "Request Object has no header"
	}

	alg := jsonutil.GetString(reqObj.Header, "alg")
	if alg == "" {
		return fmt.Sprintf("Request Object has unsupported signing algorithm %q", alg)
	}
	if alg == "none" {
		return ""
	}

	certs, warning := extractCertChain(reqObj)
	if warning != "" {
		return warning
	}
	if warning := verifySuppliedX5CChain(certs); warning != "" {
		return warning
	}

	if strings.Count(reqObj.Raw, ".") != 2 {
		return "Request Object is not a compact JWS"
	}
	if _, err := jws.Verify(reqObj.Raw, certs[0].PublicKey); err != nil {
		return fmt.Sprintf("Request Object signature verification failed: %v", err)
	}

	return ""
}

// VerifyClientID validates the client_id prefix against the request object and
// response URI per OID4VP 1.0 Client Identifier Prefixes.
// Returns a warning string if there's a mismatch, or "" if OK / not applicable.
func VerifyClientID(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string, requestOrigin string) string {
	switch {
	case strings.HasPrefix(clientID, "x509_san_dns:"):
		return verifyX509SAN(clientID, "x509_san_dns:", "dns", reqObj)
	case strings.HasPrefix(clientID, "x509_hash:"):
		return verifyX509Hash(clientID, reqObj)
	case strings.HasPrefix(clientID, "origin:"):
		// OID4VP 1.0 §5.9.3 reserves this prefix: "The Wallet MUST NOT accept
		// this Client Identifier Prefix in requests." It names the audience a
		// Digital Credentials API presentation is bound to, which the wallet
		// derives from the origin the platform reports. Accepting it in a
		// request would let a verifier on one channel ask for a presentation
		// audienced to another.
		return "origin: is a reserved Client Identifier Prefix and MUST NOT be accepted in a request"
	case strings.HasPrefix(clientID, "openid_federation:"):
		// §5.9.3 defers to OpenID Federation for this prefix, and its
		// processing rules are not implemented here. Accepting it without
		// resolving the trust chain would assert a verification that never
		// happened.
		return "openid_federation: client_id is not supported by this wallet"
	case strings.HasPrefix(clientID, "redirect_uri:"):
		return verifyRedirectURI(clientID, reqObj, responseURI)
	case strings.HasPrefix(clientID, "verifier_attestation:"):
		return verifyVerifierAttestation(clientID, reqObj)
	case strings.HasPrefix(clientID, "decentralized_identifier:"):
		return verifyDecentralizedIdentifier(clientID, reqObj)
	default:
		return ""
	}
}

// verifyX509SAN checks that the leaf certificate SAN contains the expected DNS name.
func verifyX509SAN(clientID, prefix, scheme string, reqObj *oid4vc.RequestObjectJWT) string {
	expected := strings.TrimPrefix(clientID, prefix)

	cert, warning := extractLeafCert(reqObj)
	if warning != "" {
		return warning
	}

	switch scheme {
	case "dns":
		for _, name := range cert.DNSNames {
			if name == expected {
				return ""
			}
		}
		return fmt.Sprintf("client_id expects DNS SAN %q but leaf certificate has DNSNames=%v", expected, cert.DNSNames)
	}

	return ""
}

// verifyX509Hash checks that SHA-256(leaf cert DER) matches the hash in client_id.
func verifyX509Hash(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	expectedHash := strings.TrimPrefix(clientID, "x509_hash:")

	expectedBytes, err := format.DecodeBase64URL(expectedHash)
	if err != nil {
		return fmt.Sprintf("x509_hash: client_id value is not valid base64url: %v", err)
	}

	cert, warning := extractLeafCert(reqObj)
	if warning != "" {
		return warning
	}

	actualHash := sha256.Sum256(cert.Raw)
	if string(expectedBytes) != string(actualHash[:]) {
		return "x509_hash: SHA-256 of leaf certificate does not match client_id hash"
	}

	return ""
}

// verifyRedirectURI checks that the redirect_uri: prefix value matches the
// response URI and that no signed request object is used.
func verifyRedirectURI(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string) string {
	expected := strings.TrimPrefix(clientID, "redirect_uri:")

	if reqObj != nil && reqObj.Header != nil && jsonutil.GetString(reqObj.Header, "alg") != "none" {
		return "redirect_uri: prefix MUST NOT use signed request objects (OID4VP 1.0)"
	}

	if responseURI != "" && expected != responseURI {
		return fmt.Sprintf("redirect_uri: prefix value %q does not match response_uri %q", expected, responseURI)
	}

	return ""
}

// verifyVerifierAttestation validates the verifier_attestation: prefix per OID4VP 1.0.
// The request object MUST contain a "jwt" header with a Verifier Attestation JWT.
// The Verifier Attestation JWT must be a valid JWT (3 dot-separated parts) and
// its payload must contain a "sub" claim matching the client_id value after the prefix.
func verifyVerifierAttestation(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	if reqObj == nil || reqObj.Header == nil {
		return "verifier_attestation: requires a signed Request Object"
	}

	jwtStr := jsonutil.GetString(reqObj.Header, "jwt")
	if jwtStr == "" {
		return "verifier_attestation: Request Object must contain 'jwt' header with Verifier Attestation JWT"
	}

	// Basic JWT structure check (3 dot-separated parts)
	parts := strings.SplitN(jwtStr, ".", 4)
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return "verifier_attestation: 'jwt' header value is not a valid JWT (expected 3 dot-separated parts)"
	}

	// Parse the attestation JWT payload to check the sub claim
	_, payload, _, err := format.ParseJWTParts(jwtStr)
	if err != nil {
		return fmt.Sprintf("verifier_attestation: failed to parse Verifier Attestation JWT: %v", err)
	}

	expected := strings.TrimPrefix(clientID, "verifier_attestation:")
	sub, _ := payload["sub"].(string)
	if sub != "" && sub != expected {
		return fmt.Sprintf("verifier_attestation: Attestation JWT sub %q does not match client_id value %q", sub, expected)
	}

	return ""
}

// verifyDecentralizedIdentifier validates the decentralized_identifier: prefix per OID4VP 1.0.
// The value must be a valid DID (did:method:identifier format) and a signed Request Object must be present.
// Note: Full DID resolution is not implemented. Only format validation is performed.
func verifyDecentralizedIdentifier(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	did := strings.TrimPrefix(clientID, "decentralized_identifier:")

	// Validate DID format: must have at least 3 colon-separated parts (did:method:id)
	didParts := strings.SplitN(did, ":", 3)
	if len(didParts) < 3 || didParts[0] != "did" || didParts[1] == "" || didParts[2] == "" {
		return fmt.Sprintf("decentralized_identifier: value %q is not a valid DID (expected did:method:identifier)", did)
	}

	if reqObj == nil || reqObj.Header == nil {
		return "decentralized_identifier: requires a signed Request Object"
	}

	// Check that the request object's kid header references the DID
	kid := jsonutil.GetString(reqObj.Header, "kid")
	if kid != "" && !strings.HasPrefix(kid, did) {
		return fmt.Sprintf("decentralized_identifier: Request Object kid %q does not reference DID %q", kid, did)
	}

	return ""
}

// extractLeafCert extracts and parses the leaf certificate from the request
// object's x5c header. Returns a warning if extraction fails.
func extractLeafCert(reqObj *oid4vc.RequestObjectJWT) (*x509.Certificate, string) {
	if reqObj == nil || reqObj.Header == nil {
		return nil, "client_id uses x509 scheme but request object has no x5c header"
	}

	x5cArr := jsonutil.GetArray(reqObj.Header, "x5c")
	if len(x5cArr) == 0 {
		return nil, "client_id uses x509 scheme but x5c header is empty or missing"
	}

	leafB64, ok := x5cArr[0].(string)
	if !ok {
		return nil, "client_id uses x509 scheme but x5c[0] is not a string"
	}

	der, err := format.DecodeBase64Std(leafB64)
	if err != nil {
		return nil, fmt.Sprintf("client_id uses x509 scheme but failed to decode x5c[0]: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Sprintf("client_id uses x509 scheme but failed to parse leaf certificate: %v", err)
	}

	return cert, ""
}

func extractCertChain(reqObj *oid4vc.RequestObjectJWT) ([]*x509.Certificate, string) {
	if reqObj == nil || reqObj.Header == nil {
		return nil, "Request Object signature verification requires an x5c header"
	}

	x5cArr := jsonutil.GetArray(reqObj.Header, "x5c")
	if len(x5cArr) == 0 {
		return nil, "Request Object signature verification requires an x5c header"
	}

	certs := make([]*x509.Certificate, 0, len(x5cArr))
	for i, entry := range x5cArr {
		b64, ok := entry.(string)
		if !ok {
			return nil, fmt.Sprintf("Request Object x5c[%d] is not a string", i)
		}
		der, err := format.DecodeBase64Std(b64)
		if err != nil {
			return nil, fmt.Sprintf("failed to decode Request Object x5c[%d]: %v", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Sprintf("failed to parse Request Object x5c[%d]: %v", i, err)
		}
		certs = append(certs, cert)
	}

	return certs, ""
}

// prefixRequiresSigning returns true if the client_id prefix requires a signed
// Request Object per OID4VP 1.0.
func prefixRequiresSigning(clientID string) bool {
	prefixes := []string{"x509_san_dns:", "x509_hash:", "decentralized_identifier:", "verifier_attestation:"}
	for _, p := range prefixes {
		if strings.HasPrefix(clientID, p) {
			return true
		}
	}
	return false
}

// ValidateRequestObject checks that the Request Object's typ header is
// "oauth-authz-req+jwt" per OID4VP 1.0 / RFC 9101.
// Also warns if the client_id prefix requires signing but no Request Object is present.
func ValidateRequestObject(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	if reqObj == nil {
		if prefixRequiresSigning(clientID) {
			return "client_id prefix requires a signed Request Object but none was provided"
		}
		return ""
	}

	if reqObj.Header == nil {
		return "Request Object has no header"
	}

	alg := jsonutil.GetString(reqObj.Header, "alg")
	typ := jsonutil.GetString(reqObj.Header, "typ")

	// An unsigned ("alg": "none") Request Object satisfies none of the prefixes
	// that OID4VP 1.0 requires to be signed. Catch it here, where the client_id
	// is in scope: VerifyRequestObjectSignature has nothing to verify for
	// alg=none, and without this a forged unsigned request against a
	// signing-required prefix would raise no finding at all (and so pass strict
	// mode). redirect_uri:, which is allowed to be unsigned, is not in the set.
	if alg == "none" && prefixRequiresSigning(clientID) {
		return "client_id prefix requires a signed Request Object but the Request Object is unsigned (alg \"none\")"
	}

	if typ == "" {
		if alg == "none" {
			return ""
		}
		return "Request Object missing 'typ' header (OID4VP 1.0 requires typ: oauth-authz-req+jwt)"
	}
	if typ != "oauth-authz-req+jwt" {
		return fmt.Sprintf("Request Object has typ %q but OID4VP 1.0 requires 'oauth-authz-req+jwt'", typ)
	}

	// Verify that the alg header matches the key type in the x5c certificate.
	if warning := verifyAlgMatchesCert(reqObj); warning != "" {
		return warning
	}

	return ""
}

// verifyAlgMatchesCert checks that the JWT "alg" header is compatible with the
// public key type in the x5c leaf certificate. Returns a warning on mismatch,
// or "" if OK or if x5c is not present.
func verifyAlgMatchesCert(reqObj *oid4vc.RequestObjectJWT) string {
	alg := jsonutil.GetString(reqObj.Header, "alg")
	if alg == "" {
		return ""
	}

	// Only check when x5c is present.
	cert, warning := extractLeafCert(reqObj)
	if warning != "" {
		// No x5c. Nothing to cross-check.
		return ""
	}

	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(alg, "ES") {
			return fmt.Sprintf("Request Object alg %q is not compatible with EC key in x5c certificate", alg)
		}
	case *rsa.PublicKey:
		if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS") {
			return fmt.Sprintf("Request Object alg %q is not compatible with RSA key in x5c certificate", alg)
		}
	}

	return ""
}

func verifySuppliedX5CChain(certs []*x509.Certificate) string {
	if len(certs) < 2 {
		return ""
	}

	roots := x509.NewCertPool()
	roots.AddCert(certs[len(certs)-1])

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1 : len(certs)-1] {
		intermediates.AddCert(cert)
	}

	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Sprintf("Request Object x5c chain is not internally consistent: %v", err)
	}

	return ""
}
