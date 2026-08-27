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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/validate"
)

// registrationCertificateTyp is the typ of an EUDI wallet-relying-party
// registration certificate (ETSI TS 119 475), the attestation this wallet
// reads a verifier's registered purpose from. It travels in a verifier_info
// entry whose format is "registration_cert" (ETSI TS 119 472-2), but the typ
// is what identifies the JWT, so entries are selected by it alone.
const registrationCertificateTyp = "rc-wrp+jwt"

// verifierInfoPurposes reads the purposes a verifier registered out of the
// registration certificates in a request's verifier_info (OpenID4VP 1.0
// §5.1: attestations that "support authorization decisions, inform Wallet
// policy enforcement, or enrich the End-User consent dialog"). The purpose of
// the data request is what the consent dialog needs.
//
// A certificate is recognized by its rc-wrp+jwt typ. Its sub is the
// registered legal entity, not the request's client_id, so the only check is
// the signature against the embedded x5c leaf. A signature that fails or
// cannot be checked (no readable x5c) leaves a finding and the purpose is
// not shown. The chain is not anchored to a trust list, like every other x5c
// this wallet checks (see SECURITY.md). Other formats and JWT types are
// skipped.
func verifierInfoPurposes(payload map[string]any) (purposes []string, findings []string) {
	certs, findings := verifiedRegistrationCertificates(payload)
	for _, cert := range certs {
		for _, purpose := range purposeStrings(cert["purpose"]) {
			if !containsPurpose(purposes, purpose) {
				purposes = append(purposes, purpose)
			}
		}
	}
	return purposes, findings
}

// verifiedRegistrationCertificates decodes the rc-wrp+jwt registration
// certificates in a request's verifier_info and returns the claims of the ones
// whose signature verifies against their own x5c leaf. Findings name the
// entries that could not be used. The chain is not anchored to a trust list,
// like every other x5c this wallet checks (see SECURITY.md).
func verifiedRegistrationCertificates(payload map[string]any) (certs []map[string]any, findings []string) {
	for _, entry := range verifierInfoEntries(payload) {
		data, _ := entry["data"].(string)
		if strings.Count(data, ".") != 2 {
			continue
		}
		header, claims, err := decodeCompactJWT(data)
		if err != nil {
			continue
		}
		if typ, _ := header["typ"].(string); typ != registrationCertificateTyp {
			continue
		}
		key, err := validate.ExtractX5CLeafKey(header)
		if err != nil || key == nil {
			findings = append(findings, "the registration certificate carries no readable x5c certificate, so its signature cannot be checked and its purpose is not shown")
			continue
		}
		if _, err := jws.Verify(data, key); err != nil {
			findings = append(findings, fmt.Sprintf("the registration certificate signature does not verify with its x5c leaf, so its purpose is not shown: %v", err))
			continue
		}
		certs = append(certs, claims)
	}
	return certs, findings
}

// consentPurposes reads the verifier's registered purposes for the consent
// dialog and warns about the registration certificate. A request sent as plain
// parameters has no payload document, so its verifier_info survives only as the
// raw parameter. A signed request's outer parameters stay ignored (OID4VP 1.0
// §5.10.1).
//
// The registration certificate is an ARF requirement (RPRC_19), so its absence
// and its content are checked against ETSI TS 119 475 and the ARF. These are
// always warnings, in every mode. Validation mode is OpenID4VP and HAIP strict.
// The ARF rules are not part of it.
func (w *Wallet) consentPurposes(scope string, authReq *AuthorizationRequestParams) []string {
	if authReq == nil {
		return nil
	}
	payload := authReq.RequestPayload
	if payload == nil && authReq.RequestObject == nil && strings.TrimSpace(authReq.VerifierInfo) != "" {
		payload = map[string]any{"verifier_info": authReq.VerifierInfo}
	}

	certs, findings := verifiedRegistrationCertificates(payload)
	if len(certs) == 0 {
		findings = append(findings, "the request carries no relying party registration certificate (verifier_info with an rc-wrp+jwt), which ARF RPRC_19 requires in every presentation request")
	}

	var purposes []string
	for _, cert := range certs {
		findings = append(findings, registrationCertificateContentFindings(cert)...)
		findings = append(findings, overAskingFindings(cert, authReq.DCQLQuery)...)
		for _, purpose := range purposeStrings(cert["purpose"]) {
			if !containsPurpose(purposes, purpose) {
				purposes = append(purposes, purpose)
			}
		}
	}
	w.warnFindings(scope, "The relying party registration certificate does not follow the ARF and ETSI TS 119 475", findings)
	return purposes
}

// registrationCertificateContentFindings checks a verified WRPRC against the
// mandatory content of ETSI TS 119 475 V1.2.1 §5.2.4 and the ARF (Topic 44).
// Each missing member is a warning naming the rule.
func registrationCertificateContentFindings(cert map[string]any) []string {
	var findings []string
	miss := func(field, rule string) {
		findings = append(findings, fmt.Sprintf("the registration certificate has no %s, which %s requires", field, rule))
	}
	if stringClaim(cert["name"]) == "" {
		miss("name (trade name)", "ARF RPRC_06")
	}
	if stringClaim(cert["sub"]) == "" {
		miss("sub (relying party identifier)", "ARF RPRC_07")
	}
	if stringClaim(cert["privacy_policy"]) == "" {
		miss("privacy_policy", "ETSI TS 119 475 §5.2.4")
	}
	if len(purposeStrings(cert["srv_description"])) == 0 {
		miss("srv_description", "ETSI TS 119 475 §5.2.4")
	}
	if !nonEmptyList(cert["entitlements"]) {
		miss("entitlements (at least one)", "ETSI TS 119 475 GEN-5.2.4-03")
	}
	if !hasContact(cert["support_uri"]) {
		miss("support_uri (data deletion contact)", "ARF RPRC_11")
	}
	if !hasSupervisoryAuthority(cert["supervisory_authority"]) {
		miss("supervisory_authority contact", "ARF RPRC_12")
	}
	if !nonEmptyList(cert["credentials"]) {
		miss("credentials (the registered attestations and attributes)", "ETSI TS 119 475 GEN-5.2.4-06")
	}
	return append(findings, registrationValidityFindings(cert)...)
}

// registrationValidityFindings checks the certificate's validity window: iat is
// required, and exp (when present) must be in the future and no more than 12
// months after iat (ETSI TS 119 475 GEN-5.2.4-08, ARF RPRC_17).
func registrationValidityFindings(cert map[string]any) []string {
	var findings []string
	iat, hasIat := numberClaim(cert["iat"])
	if !hasIat {
		findings = append(findings, "the registration certificate has no iat, which ETSI TS 119 475 §5.2.4 requires")
	}
	exp, hasExp := numberClaim(cert["exp"])
	if !hasExp {
		return findings
	}
	expTime := time.Unix(int64(exp), 0)
	if expTime.Before(time.Now()) {
		findings = append(findings, "the registration certificate has expired (ARF RPRC_17)")
	}
	if hasIat && expTime.After(time.Unix(int64(iat), 0).AddDate(1, 0, 0)) {
		findings = append(findings, "the registration certificate is valid for more than 12 months (ETSI TS 119 475 GEN-5.2.4-08)")
	}
	return findings
}

// overAskingFindings is the ARF RPRC_21 over-asking check: every claim the
// request asks for has to be among the attributes the registration certificate
// registered in its credentials. A credential type the certificate does not
// register at all is one finding for the whole query, and a registered type
// asked for an attribute it did not register is one finding per attribute.
func overAskingFindings(cert map[string]any, dcql map[string]any) []string {
	registered := registeredCredentials(cert)
	if len(registered) == 0 {
		// The absent credentials list is already a content finding, and without
		// it there is nothing to check the request against.
		return nil
	}
	var findings []string
	overAsk := func(what string) {
		findings = append(findings, fmt.Sprintf("the request asks for %s, which the registration certificate does not register (ARF RPRC_21 over-asking)", what))
	}
	for _, cq := range listOfMaps(dcql["credentials"]) {
		format, _ := cq["format"].(string)
		types := credentialTypes(cq["meta"])
		if !registersCredential(registered, format, types) {
			overAsk(credentialTypeName(format, types))
			continue
		}
		for _, claim := range listOfMaps(cq["claims"]) {
			path := toAnyList(claim["path"])
			if len(path) == 0 {
				continue
			}
			if !registeredCovers(registered, format, types, path) {
				overAsk(describeClaim(format, types, path))
			}
		}
	}
	return findings
}

// registersCredential reports whether the certificate registers a credential of
// this format and type at all, regardless of which attributes it names.
func registersCredential(registered []registeredCredential, format string, types []string) bool {
	for _, rc := range registered {
		if rc.matches(format, types) {
			return true
		}
	}
	return false
}

// registeredCredential is one entry of a WRPRC credentials array: the format
// and type it registers, and the claim paths the relying party may request. An
// entry with no claim list registers the credential without restricting its
// attributes (ETSI TS 119 475 §5.2.4 Table 9).
type registeredCredential struct {
	format          string
	types           []string
	paths           [][]any
	anyClaimAllowed bool
}

// matches reports whether this registered credential covers the format and type
// a request asks for. An empty format or type on either side is not a mismatch.
func (rc registeredCredential) matches(format string, types []string) bool {
	if format != "" && rc.format != "" && rc.format != format {
		return false
	}
	return typesOverlap(types, rc.types)
}

func registeredCredentials(cert map[string]any) []registeredCredential {
	var out []registeredCredential
	for _, entry := range listOfMaps(cert["credentials"]) {
		format, _ := entry["format"].(string)
		rc := registeredCredential{format: format, types: credentialTypes(entry["meta"])}
		claims := listOfMaps(entry["claim"])
		if len(claims) == 0 {
			// ETSI TS 119 475 §5.2.4 Table 9 leaves a credential with no claim
			// list as declaring no specific attributes. That is read as the
			// relying party being registered for the credential without an
			// attribute restriction, so the over-asking check does not flag it.
			rc.anyClaimAllowed = true
		}
		for _, claim := range claims {
			if path := toAnyList(claim["path"]); len(path) > 0 {
				rc.paths = append(rc.paths, path)
			}
		}
		out = append(out, rc)
	}
	return out
}

func registeredCovers(registered []registeredCredential, format string, types []string, path []any) bool {
	for _, rc := range registered {
		if !rc.matches(format, types) {
			continue
		}
		if rc.anyClaimAllowed {
			return true
		}
		for _, registeredPath := range rc.paths {
			if pathPrefix(registeredPath, path) {
				return true
			}
		}
	}
	return false
}

// typesOverlap reports whether two credential type lists share a value. An
// empty list on either side matches, so a request or a registration that names
// no type is not treated as a mismatch.
func typesOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// pathPrefix reports whether registered is a prefix of requested, so a
// registered parent path (address) covers a requested child (address,
// street_address).
func pathPrefix(registered, requested []any) bool {
	if len(registered) > len(requested) {
		return false
	}
	for i := range registered {
		if fmt.Sprint(registered[i]) != fmt.Sprint(requested[i]) {
			return false
		}
	}
	return true
}

// credentialTypes reads the type identifiers out of a DCQL or WRPRC meta
// object: vct_values for SD-JWT VC, doctype_value for mdoc.
func credentialTypes(meta any) []string {
	m, ok := meta.(map[string]any)
	if !ok {
		return nil
	}
	var types []string
	for _, v := range toAnyList(m["vct_values"]) {
		if s, ok := v.(string); ok {
			types = append(types, s)
		}
	}
	if s, ok := m["doctype_value"].(string); ok && s != "" {
		types = append(types, s)
	}
	return types
}

func describeClaim(format string, types []string, path []any) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = fmt.Sprint(p)
	}
	claim := strings.Join(parts, ".")
	label := credentialTypeName(format, types)
	if label == "" {
		return claim
	}
	return fmt.Sprintf("%s of %s", claim, label)
}

// credentialTypeName names a credential by its first registered type, or its
// format when no type is given.
func credentialTypeName(format string, types []string) string {
	if len(types) > 0 {
		return types[0]
	}
	return format
}

func stringClaim(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func numberClaim(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func nonEmptyList(v any) bool {
	list, ok := v.([]any)
	return ok && len(list) > 0
}

// hasContact accepts a single URL or address string or a non-empty list of
// them, since ETSI TS 119 475 allows one or more.
func hasContact(v any) bool {
	if stringClaim(v) != "" {
		return true
	}
	return nonEmptyList(v)
}

func hasSupervisoryAuthority(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	return stringClaim(m["email"]) != "" || stringClaim(m["phone"]) != "" || stringClaim(m["uri"]) != ""
}

func listOfMaps(v any) []map[string]any {
	list, _ := v.([]any)
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func toAnyList(v any) []any {
	list, _ := v.([]any)
	return list
}

// SignRegistrationCertificateJWT signs a relying-party registration
// certificate (typ rc-wrp+jwt) with the given key, carrying the signer's leaf
// certificate in x5c. The demo verifier and issuer present one so the wallet
// they run beside has a purpose to show.
func SignRegistrationCertificateJWT(claims map[string]any, signingKey *ecdsa.PrivateKey, signerCerts []*x509.Certificate) (string, error) {
	header := map[string]any{
		"alg": "ES256",
		"typ": registrationCertificateTyp,
	}
	if x5c := buildJWSX5C(signerCerts); len(x5c) > 0 {
		header["x5c"] = x5c
	}
	return signJSONWebSignature(claims, signingKey, header)
}

// verifierInfoEntries reads the verifier_info array out of a request payload.
// Over plain request parameters the array arrives JSON-encoded in a string.
func verifierInfoEntries(payload map[string]any) []map[string]any {
	if payload == nil {
		return nil
	}
	raw := payload["verifier_info"]
	if encoded, ok := raw.(string); ok && encoded != "" {
		var decoded any
		if err := json.Unmarshal([]byte(encoded), &decoded); err == nil {
			raw = decoded
		}
	}
	list, _ := raw.([]any)
	entries := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if entry, ok := item.(map[string]any); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

// purposeStrings renders a purpose claim: one or more localized entries
// ({lang, value} in the certificate profile, {lang, content} in the TS5 data
// model it is gathered from), where English is preferred and the first entry
// stands in without it. A plain string is taken as it is.
func purposeStrings(raw any) []string {
	switch value := raw.(type) {
	case string:
		if v := strings.TrimSpace(value); v != "" {
			return []string{v}
		}
	case []any:
		var plain []string
		var first, english string
		for _, item := range value {
			switch entry := item.(type) {
			case string:
				if v := strings.TrimSpace(entry); v != "" {
					plain = append(plain, v)
				}
			case map[string]any:
				text, _ := entry["value"].(string)
				if text == "" {
					text, _ = entry["content"].(string)
				}
				text = strings.TrimSpace(text)
				if text == "" {
					continue
				}
				if first == "" {
					first = text
				}
				if lang, _ := entry["lang"].(string); strings.HasPrefix(strings.ToLower(lang), "en") && english == "" {
					english = text
				}
			}
		}
		if english != "" {
			return append(plain, english)
		}
		if first != "" {
			return append(plain, first)
		}
		return plain
	}
	return nil
}

func containsPurpose(purposes []string, purpose string) bool {
	for _, p := range purposes {
		if p == purpose {
			return true
		}
	}
	return false
}

// decodeCompactJWT decodes the header and payload of a compact JWT without
// verifying it. Verification, where possible, is the caller's step.
func decodeCompactJWT(compact string) (header, payload map[string]any, err error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("not a compact JWT")
	}
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("parsing JWT payload: %w", err)
	}
	return header, payload, nil
}
