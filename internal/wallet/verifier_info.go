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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/validate"
)

// ETSI TS 119 475 identifies registration certificates by rc-wrp+jwt. Select by this
// typ even though the verifier_info format is registration_cert (ETSI TS 119 472-2).

// Read registered purposes from verifier_info for the consent dialog (OpenID4VP 1.0
// §5.1). Only rc-wrp+jwt certificates whose signature verifies against their own x5c
// leaf contribute purposes. Their sub identifies a legal entity and may differ from
// client_id.
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

// Verify signatures against each certificate's own x5c leaf. This does not establish
// trust in the signer. See SECURITY.md.
func verifiedRegistrationCertificates(payload map[string]any) (certs []map[string]any, findings []string) {
	registrations, findings := verifiedRegistrations(payload)
	for _, r := range registrations {
		certs = append(certs, r.claims)
	}
	return certs, findings
}

type verifiedRegistration struct {
	claims map[string]any
	chain  []*x509.Certificate
}

func verifiedRegistrations(payload map[string]any) (registrations []verifiedRegistration, findings []string) {
	registrations, problems := verifyRegistrationEntries(infoEntries(payload, "verifier_info"))
	for _, problem := range problems {
		findings = append(findings, "The registration certificate "+problem+", so its purpose is not shown")
	}
	return registrations, findings
}

// verifyRegistrationEntries verifies the rc-wrp+jwt entries of a verifier_info
// or issuer_info array against their own x5c leaf. Each problem completes the
// sentence "The registration certificate ...".
func verifyRegistrationEntries(entries []map[string]any) (registrations []verifiedRegistration, problems []string) {
	for _, entry := range entries {
		data, _ := entry["data"].(string)
		if strings.Count(data, ".") != 2 {
			continue
		}
		header, claims, err := decodeCompactJWT(data)
		if err != nil {
			continue
		}
		if typ, _ := header["typ"].(string); typ != registrar.RegistrationCertificateTyp {
			continue
		}
		key, err := validate.ExtractX5CLeafKey(header)
		if err != nil || key == nil {
			problems = append(problems, "has no readable x5c certificate")
			continue
		}
		if _, err := jws.Verify(data, key); err != nil {
			problems = append(problems, fmt.Sprintf("signature does not verify with its x5c leaf (%v)", err))
			continue
		}
		registrations = append(registrations, verifiedRegistration{claims: claims, chain: x5cChain(header)})
	}
	return registrations, problems
}

// x5cChain parses a JOSE x5c header, leaf first. It skips entries that do not
// parse.
func x5cChain(header map[string]any) []*x509.Certificate {
	entries, _ := header["x5c"].([]any)
	var chain []*x509.Certificate
	for _, entry := range entries {
		encoded, _ := entry.(string)
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		if cert, err := x509.ParseCertificate(der); err == nil {
			chain = append(chain, cert)
		}
	}
	return chain
}

// verifyToAnchor verifies the leaf of chain to one of roots, with the rest of
// chain as intermediates.
func verifyToAnchor(chain []*x509.Certificate, roots *x509.CertPool) error {
	if len(chain) == 0 {
		return errors.New("no certificate")
	}
	if roots == nil {
		return errors.New("no trusted CA")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// Unsigned requests carry verifier_info as a parameter. Signed requests use only the
// Request Object (OID4VP 1.0 §5.10.1).
func requestVerifierInfo(authReq *AuthorizationRequestParams) map[string]any {
	payload := authReq.RequestPayload
	if payload == nil && authReq.RequestObject == nil && strings.TrimSpace(authReq.FullParams["verifier_info"]) != "" {
		payload = map[string]any{"verifier_info": authReq.FullParams["verifier_info"]}
	}
	return payload
}

// registrationStatusFindings checks a registration certificate against its
// registrar's status list (ARF §6.6.3.3 step 4). An unreadable status is a
// finding too, because then the wallet can't tell whether the certificate is
// revoked.
func registrationStatusFindings(cert map[string]any, client *http.Client) []string {
	return registrationStatusFindingsFor(cert, client, "ARF RPRC_17")
}

func registrationStatusFindingsFor(cert map[string]any, client *http.Client, rule string) []string {
	ref := statuslist.ExtractStatusRef(cert)
	if ref == nil {
		return nil
	}
	name := firstNonEmpty(stringClaim(cert["name"]), stringClaim(cert["sub"]), "the relying party")
	result, err := statuslist.CheckWithOptions(ref, statuslist.CheckOptions{HTTPClient: client})
	if err != nil {
		return []string{fmt.Sprintf("%s: the status of the registration certificate of %s cannot be checked: %v", rule, name, err)}
	}
	if !result.IsValid {
		return []string{fmt.Sprintf("%s: the registrar revoked the registration certificate of %s (status %s at index %d of %s)", rule, name, result.StatusName, ref.Idx, ref.URI)}
	}
	return nil
}

// consentRegistration returns the purposes and privacy policy links the consent
// dialog shows (ARF RPA_10).
func consentRegistration(authReq *AuthorizationRequestParams) (purposes, privacyPolicies []string) {
	if authReq == nil {
		return nil, nil
	}
	certs, _ := verifiedRegistrationCertificates(requestVerifierInfo(authReq))
	for _, cert := range certs {
		for _, purpose := range purposeStrings(cert["purpose"]) {
			if !containsPurpose(purposes, purpose) {
				purposes = append(purposes, purpose)
			}
		}
		if policy := stringClaim(cert["privacy_policy"]); registrar.IsWebURL(policy) && !containsPurpose(privacyPolicies, policy) {
			privacyPolicies = append(privacyPolicies, policy)
		}
	}
	return purposes, privacyPolicies
}

// ARFFindings checks how a request authenticates its relying party against
// the ARF and ETSI TS 119 475. --arf runs them. The ARF leaves refusing to the
// Wallet Provider (RPA_06a, RPRC_17, RPRC_21), and strict mode refuses.
func ARFFindings(authReq *AuthorizationRequestParams) []string {
	if authReq == nil {
		return nil
	}
	registrations, findings := verifiedRegistrations(requestVerifierInfo(authReq))
	if len(registrations) == 0 {
		findings = append(findings, "ARF RPRC_19: the request has no registration certificate in verifier_info (typ rc-wrp+jwt)")
	}
	accessChain := requestAccessChain(authReq)
	if len(accessChain) == 0 {
		findings = append(findings, "ARF RPA_03: the request is not signed with a relying party access certificate in x5c")
	} else if err := verifyToAnchor(accessChain, authReq.RelyingPartyCAs); err != nil {
		findings = append(findings, fmt.Sprintf("ARF RPA_04: the access certificate %q does not chain to a trusted access certificate authority: %v", accessChain[0].Subject.String(), err))
	}
	var registered []any
	for _, r := range registrations {
		cert := r.claims
		name := firstNonEmpty(stringClaim(cert["name"]), stringClaim(cert["sub"]), "the relying party")
		findings = append(findings, registrationCertificateContentFindings(cert)...)
		registered = append(registered, toAnyList(cert["credentials"])...)
		if len(accessChain) > 0 {
			findings = append(findings, registrationBindingFindings(cert, accessChain[0])...)
		}
		if err := verifyToAnchor(r.chain, authReq.RegistrarCAs); err != nil {
			findings = append(findings, fmt.Sprintf("ARF RPRC_02a: the registration certificate of %s does not chain to a trusted registrar: %v", name, err))
		}
		findings = append(findings, registrationStatusFindings(cert, authReq.StatusClient)...)
	}
	// A request may carry one certificate per intended use. Together they
	// define what it may request.
	if len(registrations) > 0 {
		findings = append(findings, overAskingFindings(map[string]any{"credentials": registered}, authReq.DCQLQuery)...)
	}
	return findings
}

// requestAccessChain returns the request object's x5c chain, leaf first, if the
// leaf key verifies the signature. A chain whose leaf didn't sign the request
// proves nothing about the relying party.
func requestAccessChain(authReq *AuthorizationRequestParams) []*x509.Certificate {
	reqObj := authReq.RequestObject
	if reqObj == nil || stringClaim(reqObj.Header["alg"]) == "none" || strings.Count(reqObj.Raw, ".") != 2 {
		return nil
	}
	chain := x5cChain(reqObj.Header)
	if len(chain) == 0 {
		return nil
	}
	if _, err := jws.Verify(reqObj.Raw, chain[0].PublicKey); err != nil {
		return nil
	}
	return chain
}

// ARF RPRC_17a links a registration certificate to the access certificate of
// the request through the relying party identifier. An intermediary's
// certificate carries it in act.sub (ETSI TS 119 475 GEN-5.2.4-09). Neither
// certificate has a service identifier, so only the relying party is compared
// (TS 119 475 V1.2.1).
func registrationBindingFindings(cert map[string]any, access *x509.Certificate) []string {
	return registrationBindingFindingsFor(cert, access, "ARF RPRC_17a")
}

func registrationBindingFindingsFor(cert map[string]any, access *x509.Certificate, rule string) []string {
	identifier := stringClaim(cert["sub"])
	if act, ok := cert["act"].(map[string]any); ok && stringClaim(act["sub"]) != "" {
		identifier = stringClaim(act["sub"])
	}
	accessIdentifier := organizationIdentifier(access)
	if identifier != "" && identifier == accessIdentifier {
		return nil
	}
	return []string{fmt.Sprintf("%s: the registration certificate identifies %q, but the access certificate's organizationIdentifier is %q", rule, identifier, accessIdentifier)}
}

func organizationIdentifier(cert *x509.Certificate) string {
	for _, attribute := range cert.Subject.Names {
		if attribute.Type.String() == "2.5.4.97" {
			value, _ := attribute.Value.(string)
			return value
		}
	}
	return ""
}

// Check required content from ETSI TS 119 475 V1.2.1 §5.2.4 and ARF Topic 44. Missing
// fields produce warnings.
func registrationCertificateContentFindings(cert map[string]any) []string {
	var findings []string
	miss := func(field, rule string) {
		findings = append(findings, fmt.Sprintf("%s: the registration certificate has no %s", rule, field))
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
	if statuslist.ExtractStatusRef(cert) == nil {
		miss("status (its entry in the registrar's status list), so the wallet cannot check revocation", "ETSI TS 119 475 V1.2.1 Table 7")
	}
	return append(findings, registrationValidityFindings(cert)...)
}

// ETSI TS 119 475 GEN-5.2.4-08 and ARF RPRC_17 require iat. If exp is present, it must
// be in the future and within 12 months of iat.
func registrationValidityFindings(cert map[string]any) []string {
	return registrationValidityFindingsFor(cert, "ARF RPRC_17")
}

func registrationValidityFindingsFor(cert map[string]any, rule string) []string {
	var findings []string
	iat, hasIat := numberClaim(cert["iat"])
	if !hasIat {
		findings = append(findings, "ETSI TS 119 475 §5.2.4: the registration certificate has no iat")
	}
	exp, hasExp := numberClaim(cert["exp"])
	if !hasExp {
		return findings
	}
	expTime := time.Unix(int64(exp), 0)
	if expTime.Before(time.Now()) {
		findings = append(findings, rule+": the registration certificate has expired")
	}
	if hasIat && expTime.After(time.Unix(int64(iat), 0).AddDate(1, 0, 0)) {
		findings = append(findings, "ETSI TS 119 475 GEN-5.2.4-08: the registration certificate is valid for more than 12 months")
	}
	return findings
}

// ARF RPRC_21 requires requested claims to be registered. Report one finding for an
// unregistered credential type, or one per unregistered attribute of a registered
// type.
func overAskingFindings(cert map[string]any, dcql map[string]any) []string {
	registered := registeredCredentials(cert)
	if len(registered) == 0 {
		// A missing credentials list already has a content finding and provides
		// nothing to compare.
		return nil
	}
	var findings []string
	overAsk := func(what string) {
		findings = append(findings, fmt.Sprintf("ARF RPRC_21: the request asks for %s, which the registration certificate does not register (over-asking)", what))
	}
	for _, cq := range listOfMaps(dcql["credentials"]) {
		format, _ := cq["format"].(string)
		types := registrar.CredentialTypes(cq["meta"])
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

func registersCredential(registered []registeredCredential, format string, types []string) bool {
	for _, rc := range registered {
		if rc.matches(format, types) {
			return true
		}
	}
	return false
}

// An entry without a claim list declares no attributes (ETSI TS 119 475 V1.2.1
// Annex B.2.9), so ARF RPRC_21 counts every requested claim as over-asking.
type registeredCredential struct {
	format string
	types  []string
	paths  [][]any
}

// An omitted format or type on either side does not restrict matching.
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
		rc := registeredCredential{format: format, types: registrar.CredentialTypes(entry["meta"])}
		for _, claim := range listOfMaps(entry["claim"]) {
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
		for _, registeredPath := range rc.paths {
			if pathPrefix(registeredPath, path) {
				return true
			}
		}
	}
	return false
}

// An empty type list does not restrict matching.
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

// Registering a parent path such as address also covers children such as
// address.street_address.
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

// ETSI TS 119 475 permits one or more contact addresses.
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

// toAnyList also takes []string, which in-memory records hold before a JSON
// round trip.
func toAnyList(v any) []any {
	if strs, ok := v.([]string); ok {
		list := make([]any, len(strs))
		for i, s := range strs {
			list[i] = s
		}
		return list
	}
	list, _ := v.([]any)
	return list
}

// infoEntries reads a verifier_info or issuer_info array. Plain request
// parameters carry verifier_info as a JSON string. issuer_info has the
// structure of verifier_info (ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-03).
func infoEntries(payload map[string]any, name string) []map[string]any {
	if payload == nil {
		return nil
	}
	raw := payload[name]
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

// Prefer English, then the first available translation. Certificate entries use value.
// The TS5 data model uses content. Plain strings pass through unchanged.
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

// Decoding does not verify the signature. The caller must verify it where possible.
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
