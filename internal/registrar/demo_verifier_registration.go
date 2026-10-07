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

package registrar

import (
	"encoding/json"
	"fmt"
	"time"
)

// The demo issuer and the demo verifier sign with the wallet's access
// certificate, so the registrar holds them as one relying party with two
// services (TS05 v1.5 §2.4.1).
const (
	demoRelyingPartyName      = "EUDI Dev Demo"
	DemoIssuerName            = "EUDI Dev Demo Issuer"
	demoVerifierName          = "EUDI Dev Demo Verifier"
	demoVerifierIntendedUseID = "demo-requests"
)

// demoVerifierService registers the demo verifier with one intended use. It
// covers the top-level claims of every predefined credential template, so the
// demo requests ask only for registered claims (ARF RPRC_21).
func (r *Registrar) demoVerifierService(base string) WalletRelyingPartyService {
	var credentials []RegisteredCredential
	for _, entry := range r.templateCatalog(base) {
		for _, c := range entry.Credentials {
			meta := map[string]any{"vct_values": []string{c.Type}}
			if c.Format == "mso_mdoc" {
				meta = map[string]any{"doctype_value": c.Type}
			}
			rc := RegisteredCredential{Format: c.Format, Meta: meta}
			for _, path := range c.Claims {
				rc.Claims = append(rc.Claims, RegisteredClaim{Path: path})
			}
			credentials = append(credentials, rc)
		}
	}
	return WalletRelyingPartyService{
		ServiceTradeName: demoVerifierName,
		SupportURI:       []string{base + "/support"},
		SrvDescription:   []MultiLangString{{Lang: "en", Content: "Demo verifier of the eudi-dev test wallet"}},
		Entitlements:     []string{ServiceProviderEntitlement},
		IntendedUses: []IntendedUse{{
			IntendedUseIdentifier: demoVerifierIntendedUseID,
			Purpose:               []MultiLangString{{Lang: "en", Content: "Shows how a verifier requests and checks credentials"}},
			PrivacyPolicy:         []Policy{{PolicyURI: base + "/privacy-policy"}},
			Credentials:           credentials,
		}},
	}
}

// DemoVerifierInfo returns the verifier_info value of the demo verifier
// (OpenID4VP 1.0 §5.1): the registration certificate of its intended use.
func (r *Registrar) DemoVerifierInfo() ([]any, error) {
	rp := r.providerRelyingParty(r.env.RegistrarBase())
	service := rp.Services[len(rp.Services)-1]
	use := service.IntendedUses[0]
	content := registrationContent(rp, service, use)
	content.StatusListURI = r.RegistrationStatusListURL()
	content.StatusIndex = ownRegistrationStatusIndex
	credentials := make([]map[string]any, 0, len(use.Credentials))
	for _, c := range use.Credentials {
		credentials = append(credentials, map[string]any{"format": c.Format, "meta": c.Meta, "claims": c.Claims})
	}
	signed, err := r.signRegistrationCertificate(content, credentials, time.Now())
	if err != nil {
		return nil, err
	}
	var info []any
	if err := json.Unmarshal([]byte(VerifierInfoValue(signed)), &info); err != nil {
		return nil, fmt.Errorf("encoding verifier_info: %w", err)
	}
	return info, nil
}

// ProviderIssuerInfo returns the issuer_info of the wallet's own issuer (ETSI
// TS 119 472-3 V1.1.1 §4.2.3): the dataset and a registration certificate for
// it.
func (r *Registrar) ProviderIssuerInfo(issuer string, dataset RegistrarDataset) ([]IssuerInfoEntry, error) {
	_, access, err := r.env.AccessSigningMaterial()
	if err != nil {
		return nil, err
	}
	key, chain, err := r.env.RegistrarSigningMaterial()
	if err != nil {
		return nil, err
	}
	identifier, _, _ := AccessCertificateSubject(access[0])
	// ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-10 and -12: the dataset
	// names the provider by the organizationIdentifier of its certificates and
	// links to its record at the registrar.
	dataset.Identifier = []Identifier{{Identifier: identifier, Type: euidIdentifierType}}
	dataset.RegistryURI = r.env.RegistrarBase() + "/api/registrar/wrp/" + identifier
	now := time.Now()
	claims := map[string]any{
		"sub": identifier, "sub_ln": access[0].Subject.Organization[0],
		"country": access[0].Subject.Country[0], "name": dataset.TradeName,
		"registry_uri":    dataset.RegistryURI,
		"srv_description": []map[string]any{{"lang": "en", "value": dataset.SrvDescription[0].Content}},
		"entitlements":    dataset.Entitlements, "provides_attestations": dataset.ProvidesAttestations,
		"support_uri": issuer, "info_uri": issuer,
		"supervisory_authority": map[string]any{"email": dataset.SupervisoryAuthority.Email[0]},
		"policy_id":             []string{registrationCertificatePolicy},
		"certificate_policy":    registrationCertificatePolicyURI,
		"iat":                   now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"status": registrationStatusClaim(r.RegistrationStatusListURL(), ownRegistrationStatusIndex),
	}
	registration, err := SignRegistrationCertificateJWT(claims, key, chain)
	if err != nil {
		return nil, err
	}
	return []IssuerInfoEntry{
		{Format: "registrar_dataset", Data: dataset},
		{Format: "registration_cert", Data: registration},
	}, nil
}
