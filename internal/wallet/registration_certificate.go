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
	"slices"
	"strings"
	"time"
)

// RegistrationCertificateRequest selects what to certify. A verifier gets one
// certificate per intended use (ARF RPRC_09). An attestation provider gets one
// per service (ARF RPRC_13), so the request names the service and no intended
// use.
type RegistrationCertificateRequest struct {
	Identifier            string `json:"identifier"`
	ServiceIdentifier     string `json:"serviceIdentifier,omitempty"`
	IntendedUseIdentifier string `json:"intendedUseIdentifier,omitempty"`
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
	// ProvidesAttestations are the attestation types a provider issues (ETSI TS
	// 119 475 V1.2.1 Table 8).
	ProvidesAttestations []ProvidedAttestation
	Validity             string
	// StatusIndex is the certificate's entry in the registrar's status list.
	// Zero is the entry of the wallet's own certificates.
	StatusIndex int
	// StatusListURI defaults to the status list under base.
	StatusListURI string
}

// RegistrationCertificateResult holds the signed certificate, wrapped in
// verifier_info for a verifier (OpenID4VP 1.0 §5.1) or in issuer_info for an
// attestation provider (ETSI TS 119 472-3 V1.1.1 §4.2.3).
type RegistrationCertificateResult struct {
	RegistrationCertificate string `json:"registrationCertificate"`
	// VerifierInfo and IssuerInfo are JSON arrays as strings, ready for a request
	// parameter or the issuer metadata.
	VerifierInfo string `json:"verifierInfo,omitempty"`
	IssuerInfo   string `json:"issuerInfo,omitempty"`
}

// The certificate policy of ETSI TS 119 475 V1.2.1 OVR-6.1.3-01 and the
// document that describes the registrar's test certificates.
const (
	registrationCertificatePolicy    = "0.4.0.19475.3.1"
	registrationCertificatePolicyURI = "https://github.com/dominikschlosser/eudi-dev/blob/main/docs/test-certificates.md"
)

// errRegistrarSigning marks a failure of the wallet's own signer (HTTP 500).
var errRegistrarSigning = errors.New("registrar signer")

const (
	defaultRegistrationValidity = 6 * 30 * 24 * time.Hour
	maxRegistrationValidity     = 365 * 24 * time.Hour
)

// IssueRegistrationCertificate signs a registration certificate for a
// registered intended use, or for a provider service without one, with the
// wallet's registrar key.
func (w *Wallet) IssueRegistrationCertificate(req RegistrationCertificateRequest) (*RegistrationCertificateResult, error) {
	rp, ok := w.RelyingParty(req.Identifier)
	if !ok {
		return nil, fmt.Errorf("%w: %s", errRelyingPartyNotFound, req.Identifier)
	}
	if req.IntendedUseIdentifier == "" {
		return w.issueProviderCertificate(rp, req)
	}
	service, use, ok := findIntendedUse(rp, req.ServiceIdentifier, req.IntendedUseIdentifier)
	if !ok {
		return nil, fmt.Errorf("%w: no intended use %q", errRelyingPartyNotFound, req.IntendedUseIdentifier)
	}
	content := registrationContent(rp, service, use)
	credentials := make([]map[string]any, 0, len(use.Credentials))
	for _, c := range use.Credentials {
		credentials = append(credentials, map[string]any{"format": c.Format, "meta": c.Meta, "claims": c.Claims})
	}
	signed, err := w.issueCertificate(rp, certificateKey{intendedUse: use.IntendedUseIdentifier}, content, credentials, req.Validity)
	if err != nil {
		return nil, err
	}
	return &RegistrationCertificateResult{RegistrationCertificate: signed, VerifierInfo: VerifierInfoValue(signed)}, nil
}

// issueProviderCertificate certifies a provider service and its attestation
// types (ARF RPRC_13 and RPRC_15).
func (w *Wallet) issueProviderCertificate(rp WalletRelyingParty, req RegistrationCertificateRequest) (*RegistrationCertificateResult, error) {
	service, err := providerService(rp, req.ServiceIdentifier)
	if err != nil {
		return nil, err
	}
	signed, err := w.issueCertificate(rp, certificateKey{service: service.ServiceIdentifier}, providerContent(rp, service), nil, req.Validity)
	if err != nil {
		return nil, err
	}
	info, err := IssuerInfoValue(registrarDataset(rp, service), signed)
	if err != nil {
		return nil, err
	}
	return &RegistrationCertificateResult{RegistrationCertificate: signed, IssuerInfo: info}, nil
}

// providerService returns the provider service a certificate is for. Without a
// service identifier the relying party must have exactly one.
func providerService(rp WalletRelyingParty, serviceIdentifier string) (WalletRelyingPartyService, error) {
	if serviceIdentifier != "" {
		service, ok := serviceByIdentifier(rp, serviceIdentifier)
		if !ok {
			return service, fmt.Errorf("%w: no service %q", errRelyingPartyNotFound, serviceIdentifier)
		}
		if !isAttestationProvider(service) {
			return service, fmt.Errorf("service %q is not an attestation provider. Issue its certificates per intended use", serviceIdentifier)
		}
		return service, nil
	}
	providers := slices.DeleteFunc(slices.Clone(rp.Services), func(s WalletRelyingPartyService) bool { return !isAttestationProvider(s) })
	if len(providers) != 1 {
		return WalletRelyingPartyService{}, fmt.Errorf("%s has %d attestation provider services and no intended use was given, so name the service or the intended use", rp.Identifier[0].Identifier, len(providers))
	}
	return providers[0], nil
}

// issueCertificate reserves a status entry, signs the certificate and revokes
// the one it replaces.
func (w *Wallet) issueCertificate(rp WalletRelyingParty, key certificateKey, content RegistrationCertificateContent, credentials []map[string]any, validityValue string) (string, error) {
	content.Validity = validityValue
	validity, err := registrationValidity(validityValue)
	if err != nil {
		return "", err
	}
	now := time.Now()
	content.StatusListURI = w.RegistrationStatusListURL()
	content.StatusIndex, err = w.allocateRegistrationStatus(rp, key, now.Add(validity))
	if err != nil {
		return "", err
	}
	signed, err := w.signRegistrationCertificate(content, credentials, now)
	if err != nil {
		w.releaseRegistrationStatus(content.StatusIndex)
		return "", err
	}
	w.replaceRegistrationStatus(content.Identifier, key, content.StatusIndex)
	return signed, nil
}

// providerContent returns what a provider certificate for the service contains.
// A provider certificate has no intended use (ARF RPRC_05). TS05 registers the
// purpose, the privacy policy and the credentials with an intended use, so the
// register holds none of them for the certificate (ETSI TS 119 475 V1.2.1
// GEN-5.2.4-01 fills the certificate from the register).
func providerContent(rp WalletRelyingParty, service WalletRelyingPartyService) RegistrationCertificateContent {
	content := registrationContent(rp, service, IntendedUse{})
	content.Entitlements = service.Entitlements
	content.ProvidesAttestations = service.ProvidesAttestations
	return content
}

// registrarDataset is the registrar_dataset entry of issuer_info (ETSI TS 119
// 472-3 V1.1.1 §4.2.3). It sits next to the registration certificate.
func registrarDataset(rp WalletRelyingParty, service WalletRelyingPartyService) RegistrarDataset {
	return RegistrarDataset{
		Identifier:           rp.Identifier,
		TradeName:            service.ServiceTradeName,
		SupportURI:           service.SupportURI,
		SrvDescription:       service.SrvDescription,
		IsPSB:                rp.IsPSB,
		Entitlements:         service.Entitlements,
		ProvidesAttestations: service.ProvidesAttestations,
		SupervisoryAuthority: rp.SupervisoryAuthority,
		RegistryURI:          rp.RegistryURI,
		IsIntermediary:       service.IsIntermediary,
	}
}

// IssuerInfoValue builds the issuer_info array of ETSI TS 119 472-3 V1.1.1
// §4.2.3: the registrar dataset and the registration certificate.
func IssuerInfoValue(dataset RegistrarDataset, registrationCertificate string) (string, error) {
	encoded, err := json.Marshal([]IssuerInfoEntry{
		{Format: "registrar_dataset", Data: dataset},
		{Format: "registration_cert", Data: registrationCertificate},
	})
	if err != nil {
		return "", fmt.Errorf("encoding issuer_info: %w", err)
	}
	return string(encoded), nil
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
		PrivacyPolicy:             privacyPolicyURI(use),
		SupportURI:                firstNonEmpty(service.SupportURI...),
		SupervisoryAuthorityEmail: firstNonEmpty(rp.SupervisoryAuthority.Email...),
		SupervisoryAuthorityURI:   firstNonEmpty(rp.SupervisoryAuthority.FormURI...),
	}
}

func privacyPolicyURI(use IntendedUse) string {
	if len(use.PrivacyPolicy) == 0 {
		return ""
	}
	return use.PrivacyPolicy[0].PolicyURI
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
		"iat": now.Unix(),
		"exp": now.Add(validity).Unix(),
		// ETSI TS 119 475 V1.2.1 Table 7 lists the policy (OVR-6.1.3-01) and
		// status (GEN-6.2.6.1-04).
		"policy_id":          []string{registrationCertificatePolicy},
		"certificate_policy": registrationCertificatePolicyURI,
		"status":             registrationStatusClaim(firstNonEmpty(req.StatusListURI, base+registrationStatusListPath), req.StatusIndex),
	}
	if dcqlCredentials != nil {
		claims["credentials"] = RegisteredCredentials(dcqlCredentials)
	} else {
		delete(claims, "privacy_policy")
	}
	if len(req.ProvidesAttestations) > 0 {
		claims["provides_attestations"] = req.ProvidesAttestations
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
