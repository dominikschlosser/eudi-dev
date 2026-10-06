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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RegistrationCertificateRequest selects the intended use to certify. ETSI TS
// 119 475 §5.2 has one certificate per intended use, and TS05 v1.5 §2 stores
// intended uses with the relying party.
type RegistrationCertificateRequest struct {
	Identifier            string `json:"identifier"`
	ServiceIdentifier     string `json:"serviceIdentifier,omitempty"`
	IntendedUseIdentifier string `json:"intendedUseIdentifier"`
	// Validity is a Go duration of at most 12 months (TS 119 475 GEN-5.2.4-08).
	Validity string `json:"validity,omitempty"`
}

// RegistrationCertificateContent is what a registration certificate says about
// the relying party (ETSI TS 119 475 V1.2.1 §5.2.4).
type RegistrationCertificateContent struct {
	// Name is the trade name the wallet shows (ARF RPRC_06).
	Name    string
	Purpose []MultiLangString
	// Identifier is the registered legal entity identifier (sub, ARF RPRC_07).
	// TS 119 475 §5.1.1 links it to the organizationIdentifier of the access
	// certificate.
	Identifier                string
	LegalName                 string
	Country                   string
	Description               []MultiLangString
	Entitlements              []string
	RegistryURI               string
	PrivacyPolicy             string
	SupportURI                string
	SupervisoryAuthorityEmail string
	SupervisoryAuthorityURI   string
	Validity                  string
	// StatusIndex is the certificate's entry in the registrar's status list.
	// Zero is the entry of the wallet's own certificates.
	StatusIndex int
	// StatusListURI defaults to the status list under base.
	StatusListURI string
}

// RegistrationCertificateResult carries the signed certificate and the
// verifier_info value that presents it (OpenID4VP 1.0 §5.1).
type RegistrationCertificateResult struct {
	RegistrationCertificate string `json:"registrationCertificate"`
	// VerifierInfo is the JSON array as a string, ready for a request parameter or
	// a configuration field.
	VerifierInfo string `json:"verifierInfo"`
}

// errRegistrarSigning marks a failure of the wallet's own signer (HTTP 500).
var errRegistrarSigning = errors.New("registrar signer")

const (
	defaultRegistrationValidity = 6 * 30 * 24 * time.Hour
	maxRegistrationValidity     = 365 * 24 * time.Hour
)

// IssueRegistrationCertificate signs a registration certificate for a
// registered intended use with the wallet's registrar key.
func (w *Wallet) IssueRegistrationCertificate(req RegistrationCertificateRequest) (*RegistrationCertificateResult, error) {
	rp, ok := w.RelyingParty(req.Identifier)
	if !ok {
		return nil, fmt.Errorf("%w: %s", errRelyingPartyNotFound, req.Identifier)
	}
	service, use, ok := findIntendedUse(rp, req.ServiceIdentifier, req.IntendedUseIdentifier)
	if !ok {
		return nil, fmt.Errorf("%w: no intended use %q", errRelyingPartyNotFound, req.IntendedUseIdentifier)
	}
	content := registrationContent(rp, service, use)
	content.Validity = req.Validity
	credentials := make([]map[string]any, 0, len(use.Credentials))
	for _, c := range use.Credentials {
		credentials = append(credentials, map[string]any{"format": c.Format, "meta": c.Meta, "claims": c.Claims})
	}
	validity, err := registrationValidity(req.Validity)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	content.StatusListURI = w.RegistrationStatusListURL()
	content.StatusIndex, err = w.allocateRegistrationStatus(rp, use.IntendedUseIdentifier, now.Add(validity))
	if err != nil {
		return nil, err
	}
	signed, err := w.signRegistrationCertificate(content, credentials, now)
	if err != nil {
		w.releaseRegistrationStatus(content.StatusIndex)
		return nil, err
	}
	w.replaceRegistrationStatus(content.Identifier, use.IntendedUseIdentifier, content.StatusIndex)
	return &RegistrationCertificateResult{RegistrationCertificate: signed, VerifierInfo: VerifierInfoValue(signed)}, nil
}

// registrationContent returns what a certificate for the intended use contains,
// apart from the credentials.
func registrationContent(rp WalletRelyingParty, service WalletRelyingPartyService, use IntendedUse) RegistrationCertificateContent {
	return RegistrationCertificateContent{
		Name:                      service.ServiceTradeName,
		Purpose:                   use.Purpose,
		Identifier:                rp.Identifier[0].Identifier,
		LegalName:                 rp.LegalPerson.LegalName[0],
		Country:                   rp.Country,
		Description:               service.SrvDescription,
		Entitlements:              service.Entitlements,
		RegistryURI:               rp.RegistryURI,
		PrivacyPolicy:             use.PrivacyPolicy[0].PolicyURI,
		SupportURI:                firstNonEmpty(service.SupportURI...),
		SupervisoryAuthorityEmail: firstNonEmpty(rp.SupervisoryAuthority.Email...),
		SupervisoryAuthorityURI:   firstNonEmpty(rp.SupervisoryAuthority.FormURI...),
	}
}

func (w *Wallet) signRegistrationCertificate(content RegistrationCertificateContent, credentials []map[string]any, now time.Time) (string, error) {
	claims, err := RegistrationCertificateClaimsFor(w.RegistrarBase(), content, nil, credentials, now)
	if err != nil {
		return "", err
	}
	key, chain, err := w.RegistrarSigningMaterial()
	if err != nil {
		return "", fmt.Errorf("%w: loading the key: %w", errRegistrarSigning, err)
	}
	signed, err := SignRegistrationCertificateJWT(claims, key, chain)
	if err != nil {
		return "", fmt.Errorf("%w: signing the registration certificate: %w", errRegistrarSigning, err)
	}
	return signed, nil
}

// RegistrarBase is the base URL of the registrar's default contact URLs and
// registry URIs.
func (w *Wallet) RegistrarBase() string {
	return firstNonEmpty(strings.TrimRight(w.IssuerURL, "/"), strings.TrimRight(w.BaseURL, "/"), "https://issuer.example")
}

// VerifierInfoValue wraps a registration certificate in a verifier_info array
// (OpenID4VP 1.0 §5.1, format registration_cert).
func VerifierInfoValue(registrationCertificate string) string {
	encoded, _ := json.Marshal([]map[string]any{{"format": "registration_cert", "data": registrationCertificate}})
	return string(encoded)
}

// RegistrationCertificateClaimsFor builds the payload of ETSI TS 119 475 V1.2.1
// §5.2.4. If the content has no identifier, legal name or country, they come
// from the access certificate. base is the base URL of the default contact
// URLs.
func RegistrationCertificateClaimsFor(base string, req RegistrationCertificateContent, accessCertificate *x509.Certificate, dcqlCredentials []map[string]any, now time.Time) (map[string]any, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("a registration certificate needs the relying party's name")
	}
	identifier, legalName, country := strings.TrimSpace(req.Identifier), strings.TrimSpace(req.LegalName), strings.TrimSpace(req.Country)
	if accessCertificate != nil {
		certIdentifier, certLegalName, certCountry := accessCertificateSubject(accessCertificate)
		identifier = firstNonEmpty(identifier, certIdentifier)
		legalName = firstNonEmpty(legalName, certLegalName)
		country = firstNonEmpty(country, certCountry)
	}
	if identifier == "" {
		return nil, fmt.Errorf("a registration certificate needs the relying party's identifier or its access certificate")
	}
	validity, err := registrationValidity(req.Validity)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{
		"sub":             identifier,
		"sub_ln":          firstNonEmpty(legalName, name),
		"name":            name,
		"country":         firstNonEmpty(country, "EU"),
		"registry_uri":    firstNonEmpty(req.RegistryURI, base+"/api/registrar/wrp"),
		"srv_description": multiLangClaim(req.Description, name),
		"entitlements":    entitlementsOrDefault(req.Entitlements),
		"privacy_policy":  firstNonEmpty(req.PrivacyPolicy, base+"/privacy-policy"),
		"support_uri":     firstNonEmpty(req.SupportURI, base+"/support"),
		"supervisory_authority": map[string]any{
			"email": firstNonEmpty(req.SupervisoryAuthorityEmail, "dpa@eudi-test.dev"),
			"uri":   firstNonEmpty(req.SupervisoryAuthorityURI, base+"/supervisory-authority"),
		},
		"iat":         now.Unix(),
		"exp":         now.Add(validity).Unix(),
		"credentials": RegisteredCredentials(dcqlCredentials),
		// ETSI TS 119 475 V1.2.1 Table 7 requires status (GEN-6.2.6.1-04).
		"status": registrationStatusClaim(firstNonEmpty(req.StatusListURI, base+registrationStatusListPath), req.StatusIndex),
	}
	if purpose := multiLangClaim(req.Purpose, ""); len(purpose) > 0 {
		claims["purpose"] = purpose
	}
	return claims, nil
}

// multiLangClaim writes localised strings as ETSI TS 119 475 does, with lang
// and value. Without strings it uses fallback in English.
func multiLangClaim(values []MultiLangString, fallback string) []map[string]any {
	out := make([]map[string]any, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v.Content) != "" {
			out = append(out, map[string]any{"lang": firstNonEmpty(v.Lang, "en"), "value": v.Content})
		}
	}
	if len(out) == 0 && fallback != "" {
		out = append(out, map[string]any{"lang": "en", "value": fallback})
	}
	return out
}

func entitlementsOrDefault(entitlements []string) []string {
	if len(entitlements) == 0 {
		return []string{serviceProviderEntitlement}
	}
	return entitlements
}

// RegisteredCredentials converts DCQL credential queries into the credentials
// claim of a registration certificate.
func RegisteredCredentials(dcqlCredentials []map[string]any) []map[string]any {
	registered := make([]map[string]any, 0, len(dcqlCredentials))
	for _, c := range dcqlCredentials {
		registered = append(registered, map[string]any{
			"format": c["format"],
			"meta":   c["meta"],
			"claim":  c["claims"],
		})
	}
	return registered
}

// accessCertificateSubject reads the identifier that TS 119 475 V1.2.1 §5.1.1 uses
// to link registration and access certificates (organizationIdentifier, OID
// 2.5.4.97), falling back to the common name.
func accessCertificateSubject(cert *x509.Certificate) (identifier, legalName, country string) {
	identifier = cert.Subject.CommonName
	for _, attribute := range cert.Subject.Names {
		if attribute.Type.String() == "2.5.4.97" {
			identifier, _ = attribute.Value.(string)
			break
		}
	}
	if len(cert.Subject.Organization) > 0 {
		legalName = cert.Subject.Organization[0]
	}
	if len(cert.Subject.Country) > 0 {
		country = cert.Subject.Country[0]
	}
	return identifier, legalName, country
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// registrationValidity parses a validity, at most 12 months (ETSI TS 119 475
// GEN-5.2.4-08).
func registrationValidity(value string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return defaultRegistrationValidity, nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("validity %q is not a positive Go duration", value)
	}
	if parsed > maxRegistrationValidity {
		return 0, fmt.Errorf("validity %s exceeds the 12 months of ETSI TS 119 475 GEN-5.2.4-08", value)
	}
	return parsed, nil
}
