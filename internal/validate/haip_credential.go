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

package validate

import (
	"crypto/x509"
	"fmt"

	"github.com/dominikschlosser/eudi-dev/internal/keys"
)

// NonStatusListFormat describes a status claim that does not use the IETF Token
// Status List (status.status_list), so a caller can tell it apart from a
// credential that carries no status at all. It returns "" when the status claim
// is absent or is a status_list, and catches a W3C StatusList2021Entry. HAIP 1.0
// §6.1 requires the status_list form, so a caller under that profile treats a
// non-empty result as a finding.
func NonStatusListFormat(claims map[string]any) string {
	status, ok := claims["status"].(map[string]any)
	if !ok {
		return ""
	}
	if _, ietf := status["status_list"].(map[string]any); ietf {
		return ""
	}
	if typ, _ := status["type"].(string); typ != "" {
		return fmt.Sprintf("the status claim uses %q, not a Token Status List (status.status_list)", typ)
	}
	return "the status claim is not a Token Status List (status.status_list)"
}

// HAIPCredentialFindings holds a credential's issuer key to §6.1.1: the
// certificate chain that signed it, and whether it is named by a DID, which
// this profile has no way to resolve. Both are read from the credential
// itself, so the caller does not have to know which header carries what.
func HAIPCredentialFindings(header, payload map[string]any) []string {
	var findings []string
	kid, _ := header["kid"].(string)
	iss, _ := payload["iss"].(string)
	if did := keys.DIDReference(kid, iss); did != "" {
		findings = append(findings, fmt.Sprintf(
			"HAIP 1.0 §6.1.1: the credential names its issuer key by the DID %s, where the issuer's signing certificate and its trust chain travel in the x5c header instead", did))
	}
	// HAIP 1.0 §6.1: "The status claim, if present, MUST contain status_list as
	// defined in [I-D.ietf-oauth-status-list]." A W3C StatusList2021Entry does
	// not, so it is a finding under the profile (a plain claim, so it sits in
	// the payload rather than behind a disclosure).
	if nonStandard := NonStatusListFormat(payload); nonStandard != "" {
		findings = append(findings, fmt.Sprintf("HAIP 1.0 §6.1: %s", nonStandard))
	}

	chain, _ := X5CCertificates(header)
	return append(findings, HAIPCredentialChain(chain)...)
}

// HAIPCredentialChain checks what HAIP 1.0 §6.1.1 asks of an issued SD-JWT VC:
// "The SD-JWT VC MUST contain the credential issuer's signing certificate
// along with a trust chain in the x5c JOSE header parameter as described in
// section 3.5 of [I-D.ietf-oauth-sd-jwt-vc]. The X.509 certificate of the
// trust anchor MUST NOT be included in the x5c JOSE header of the SD-JWT VC.
// The X.509 certificate signing the request MUST NOT be self-signed."
//
// The issuer of a credential carrying x5c is the subject of the end-entity
// certificate, which is why SD-JWT VC makes iss optional there. Only SD-JWT
// VCs are in scope: §6.1.1 is the IETF SD-JWT VC profile, and an mdoc carries
// its issuer certificate elsewhere.
func HAIPCredentialChain(chain []*x509.Certificate) []string {
	if len(chain) == 0 {
		return []string{"HAIP 1.0 §6.1.1: the credential carries no x5c header, which must hold the issuer's signing certificate and its trust chain"}
	}

	var violations []string
	if SelfSignedCertificate(chain[0]) {
		violations = append(violations, "HAIP 1.0 §6.1.1: the certificate signing the credential MUST NOT be self-signed")
	}
	// Which certificate is the anchor depends on what the checking party was
	// configured to trust, and this wallet holds no such list. So the finding
	// reports what is visible, a self-signed certificate, rather than claiming
	// the anchor was included.
	for i, cert := range chain[1:] {
		if SelfSignedCertificate(cert) {
			violations = append(violations, fmt.Sprintf(
				"HAIP 1.0 §6.1.1: the credential's x5c header carries a self-signed certificate at position %d (subject %q), where the certificate of the trust anchor MUST NOT be included",
				i+2, cert.Subject.String()))
			break
		}
	}
	return violations
}

// SelfSignedCertificate reports whether a certificate is its own issuer, which
// is what a trust anchor looks like inside a chain that must not carry one.
func SelfSignedCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	// CheckSignature verifies the certificate against its own key. CheckSignatureFrom
	// enforces CA constraints first and rejects a non-CA certificate before it ever
	// checks the signature, so it misses a self-signed end-entity leaf, which is
	// exactly what HAIP §6.1.1 targets.
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}
