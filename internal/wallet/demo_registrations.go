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
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

// The demo issuer and the demo verifier are registered with the wallet's
// registrar like any relying party. Each is identified by the
// organizationIdentifier of its access certificate (ETSI TS 119 475 V1.2.1
// §5.1.1).
const (
	DemoIssuerName             = "EUDI Dev Demo Issuer"
	demoVerifierName           = "EUDI Dev Demo Verifier"
	demoIssuerServiceID        = "issuance"
	demoVerifierServiceID      = "verification"
	demoVerifierIntendedUseID  = "demo-requests"
	identityCheckIntendedUseID = "identity-check"
)

// DemoVerifierAccessSigningMaterial is the access certificate of the demo
// verifier. It names another organization than the issuer's access
// certificate, so the two have their own registrations. Its CommonName is the
// trade name of the registration (ARF RPRC_06).
func (w *Wallet) DemoVerifierAccessSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.auxiliarySigningMaterial("demo-verifier-access", mock.LeafCertOptions{
		CommonName:             demoVerifierName,
		Organization:           "EUDI Dev Test Verifier",
		OrganizationIdentifier: "NTR" + mock.DefaultCertificateCountry + "-00000001",
		Role:                   mock.AccessCertificate,
	})
}

// EnsureDemoRegistrations registers the demo issuer and the demo verifier, or
// updates them to the wallet's templates, and makes sure both have a current
// registration certificate. It reports whether the registrar state changed.
func (w *Wallet) EnsureDemoRegistrations() (bool, error) {
	changed := false
	for _, build := range []demoRegistration{w.demoIssuerRegistration, w.demoVerifierRegistration} {
		_, updated, err := w.ensureDemoRegistration(build)
		if err != nil {
			return changed, err
		}
		changed = changed || updated
	}
	return changed, nil
}

// DemoIssuerInfo is the issuer_info of the demo issuer (ETSI TS 119 472-3
// V1.1.1 §4.2.3): its registrar dataset and its registration certificate.
func (w *Wallet) DemoIssuerInfo() ([]any, error) {
	result, err := w.demoCertificate(w.demoIssuerRegistration)
	if err != nil {
		return nil, err
	}
	return decodeInfo(result.IssuerInfo, "issuer_info")
}

// DemoVerifierInfo is the verifier_info of the demo verifier (OpenID4VP 1.0
// §5.1): the registration certificate of its intended use.
func (w *Wallet) DemoVerifierInfo() ([]any, error) {
	result, err := w.demoCertificate(w.demoVerifierRegistration)
	if err != nil {
		return nil, err
	}
	return decodeInfo(result.VerifierInfo, "verifier_info")
}

// DemoIdentityCheckVerifierInfo is the verifier_info of the demo issuer's
// identity check: the registration certificate of the intended use under
// which it asks for a PID before issuing.
func (w *Wallet) DemoIdentityCheckVerifierInfo() ([]any, error) {
	result, err := w.demoCertificate(func() (registrar.WalletRelyingParty, registrar.RegistrationCertificateRequest, error) {
		rp, req, err := w.demoIssuerRegistration()
		req.IntendedUseIdentifier = identityCheckIntendedUseID
		return rp, req, err
	})
	if err != nil {
		return nil, err
	}
	return decodeInfo(result.VerifierInfo, "verifier_info")
}

type demoRegistration func() (registrar.WalletRelyingParty, registrar.RegistrationCertificateRequest, error)

// demoCertificate returns the current certificate of a demo registration. A
// server saves the registrar change this makes.
func (w *Wallet) demoCertificate(build demoRegistration) (*registrar.RegistrationCertificateResult, error) {
	var result *registrar.RegistrationCertificateResult
	var err error
	change := func() bool {
		var changed bool
		result, changed, err = w.ensureDemoRegistration(build)
		return changed
	}
	if w.saveRegistrarChange != nil {
		w.saveRegistrarChange(change)
	} else {
		change()
	}
	return result, err
}

func (w *Wallet) ensureDemoRegistration(build demoRegistration) (*registrar.RegistrationCertificateResult, bool, error) {
	w.demoRegistrationMu.Lock()
	defer w.demoRegistrationMu.Unlock()
	rp, req, err := build()
	if err != nil {
		return nil, false, err
	}
	_, updated, err := w.Registrar().EnsureRelyingParty(rp)
	if err != nil {
		return nil, false, err
	}
	result, issued, err := w.Registrar().CurrentRegistrationCertificate(req)
	return result, updated || issued, err
}

func decodeInfo(value, name string) ([]any, error) {
	var info []any
	if err := json.Unmarshal([]byte(value), &info); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", name, err)
	}
	return info, nil
}

// demoIssuerRegistration registers the demo issuer as a provider of the
// credential types that have a category, with the entitlements of those
// categories (ETSI TS 119 475 V1.2.1 Table 8). A type gets its category from
// its template or its catalogue entry. Its identity check asks for a PID
// before it issues, so it registers that intended use too.
func (w *Wallet) demoIssuerRegistration() (registrar.WalletRelyingParty, registrar.RegistrationCertificateRequest, error) {
	_, access, err := w.AccessSigningMaterial()
	if err != nil {
		return registrar.WalletRelyingParty{}, registrar.RegistrationCertificateRequest{}, err
	}
	catalogue := w.Registrar().CatalogAttestations()
	var entitlements, vcts, docTypes []string
	add := func(category, format, vct, docType string) {
		if entry, ok := catalogueEntryIn(catalogue, format, []string{vct, docType}); ok && category == "" {
			category = entry.Category
		}
		if category == "" {
			return
		}
		switch format {
		case "dc+sd-jwt":
			vcts = append(vcts, vct)
		case "mso_mdoc":
			docTypes = append(docTypes, docType)
		default:
			return
		}
		entitlements = append(entitlements, categoryEntitlement(category))
	}
	templates, err := credtemplate.List(w.Templates)
	if err != nil {
		templates = credtemplate.PredefinedTemplates()
	}
	for _, t := range templates {
		switch format, _ := credtemplate.NormalizeFormat(t.Format); {
		case format == "sdjwt" && t.VCT != "":
			add(t.Category, "dc+sd-jwt", t.VCT, "")
		case format == "mdoc" && t.DocType != "":
			add(t.Category, "mso_mdoc", "", t.DocType)
		}
	}
	for _, spec := range w.issuedAttestationSpecs() {
		add(spec.Category, spec.Format, spec.VCT, spec.DocType)
	}
	var provides []registrar.ProvidedAttestation
	for _, vct := range sortedUnique(vcts) {
		provides = append(provides, registrar.ProvidedAttestation{Format: "dc+sd-jwt", Type: vct})
	}
	for _, docType := range sortedUnique(docTypes) {
		provides = append(provides, registrar.ProvidedAttestation{Format: "mso_mdoc", Type: docType})
	}
	rp := w.demoRelyingParty(access[0], registrar.WalletRelyingPartyService{
		ServiceTradeName:     DemoIssuerName,
		ServiceIdentifier:    demoIssuerServiceID,
		SrvDescription:       []registrar.MultiLangString{{Lang: "en", Content: "Demo issuer of the eudi-dev test wallet"}},
		Entitlements:         sortedUnique(entitlements),
		ProvidesAttestations: provides,
		IntendedUses: []registrar.IntendedUse{{
			IntendedUseIdentifier: identityCheckIntendedUseID,
			Purpose:               []registrar.MultiLangString{{Lang: "en", Content: "Checks who you are before a credential is issued"}},
			Credentials: []registrar.RegisteredCredential{
				{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{credtype.PIDVCT}}, Claims: []registrar.RegisteredClaim{{Path: []any{"given_name"}}, {Path: []any{"family_name"}}}},
				{Format: "mso_mdoc", Meta: map[string]any{"doctype_value": credtype.PIDDocType}, Claims: []registrar.RegisteredClaim{{Path: []any{credtype.PIDDocType, "given_name"}}, {Path: []any{credtype.PIDDocType, "family_name"}}}},
			},
		}},
	})
	return rp, registrar.RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, ServiceIdentifier: demoIssuerServiceID}, nil
}

// demoVerifierRegistration registers the demo verifier with one intended use.
// It covers the claims of every predefined credential template, so the demo
// requests ask only for registered claims (ARF RPRC_21).
func (w *Wallet) demoVerifierRegistration() (registrar.WalletRelyingParty, registrar.RegistrationCertificateRequest, error) {
	_, access, err := w.DemoVerifierAccessSigningMaterial()
	if err != nil {
		return registrar.WalletRelyingParty{}, registrar.RegistrationCertificateRequest{}, err
	}
	var credentials []registrar.RegisteredCredential
	for _, entry := range w.Registrar().CatalogAttestations() {
		if !entry.Template {
			continue
		}
		for _, c := range entry.Credentials {
			meta := map[string]any{"vct_values": []string{c.Type}}
			if c.Format == "mso_mdoc" {
				meta = map[string]any{"doctype_value": c.Type}
			}
			rc := registrar.RegisteredCredential{Format: c.Format, Meta: meta}
			for _, path := range c.Claims {
				rc.Claims = append(rc.Claims, registrar.RegisteredClaim{Path: path})
			}
			credentials = append(credentials, rc)
		}
	}
	rp := w.demoRelyingParty(access[0], registrar.WalletRelyingPartyService{
		ServiceTradeName:  demoVerifierName,
		ServiceIdentifier: demoVerifierServiceID,
		SrvDescription:    []registrar.MultiLangString{{Lang: "en", Content: "Demo verifier of the eudi-dev test wallet"}},
		IntendedUses: []registrar.IntendedUse{{
			IntendedUseIdentifier: demoVerifierIntendedUseID,
			Purpose:               []registrar.MultiLangString{{Lang: "en", Content: "Shows how a verifier requests and checks credentials"}},
			Credentials:           credentials,
		}},
	})
	return rp, registrar.RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: demoVerifierIntendedUseID}, nil
}

// demoRelyingParty takes the identifier, legal name and country from the
// access certificate.
func (w *Wallet) demoRelyingParty(access *x509.Certificate, service registrar.WalletRelyingPartyService) registrar.WalletRelyingParty {
	identifier, legalName, country := registrar.AccessCertificateSubject(access)
	return registrar.WalletRelyingParty{
		Identifier:  []registrar.Identifier{{Identifier: identifier, Type: "http://data.europa.eu/eudi/id/EUID"}},
		LegalPerson: registrar.LegalPerson{LegalName: []string{legalName}},
		Country:     country,
		TradeName:   service.ServiceTradeName,
		Services:    []registrar.WalletRelyingPartyService{service},
	}
}

func sortedUnique(values []string) []string {
	out := slices.DeleteFunc(slices.Clone(values), func(v string) bool { return strings.TrimSpace(v) == "" })
	slices.Sort(out)
	return slices.Compact(out)
}
