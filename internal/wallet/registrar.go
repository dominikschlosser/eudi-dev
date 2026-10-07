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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// WalletRelyingParty is the relying party data model of TS05 v1.5 §2. A relying
// party offers services, and each service has intended uses that list the
// credentials and claims it may request. Field names follow the TS05 JSON
// schema.
type WalletRelyingParty struct {
	Identifier           []Identifier                `json:"identifier"`
	LegalPerson          LegalPerson                 `json:"legalPerson"`
	Country              string                      `json:"country"`
	TradeName            string                      `json:"tradeName,omitempty"`
	IsPSB                bool                        `json:"isPSB"`
	SupervisoryAuthority SupervisoryAuthority        `json:"supervisoryAuthority"`
	RegistryURI          string                      `json:"registryURI"`
	Services             []WalletRelyingPartyService `json:"services"`
}

type LegalPerson struct {
	LegalName []string `json:"legalName"`
}

// WalletRelyingPartyService is one service of a relying party (TS05 v1.5
// §2.4.1). Both certificates of the service carry its trade name.
type WalletRelyingPartyService struct {
	ServiceTradeName     string                `json:"serviceTradeName"`
	ServiceIdentifier    string                `json:"serviceIdentifier,omitempty"`
	SupportURI           []string              `json:"supportURI,omitempty"`
	SrvDescription       []MultiLangString     `json:"srvDescription,omitempty"`
	Entitlements         []string              `json:"entitlements"`
	ProvidesAttestations []ProvidedAttestation `json:"providesAttestations,omitempty"`
	IsIntermediary       bool                  `json:"isIntermediary"`
	IntendedUses         []IntendedUse         `json:"intendedUses,omitempty"`
}

// IntendedUse is what a registration certificate certifies (TS05 v1.5 §2.4.4).
type IntendedUse struct {
	IntendedUseIdentifier string                 `json:"intendedUseIdentifier"`
	Purpose               []MultiLangString      `json:"purpose"`
	PrivacyPolicy         []Policy               `json:"privacyPolicy"`
	CreatedAt             string                 `json:"createdAt"`
	Credentials           []RegisteredCredential `json:"credentials"`
}

type Policy struct {
	PolicyURI string `json:"policyURI"`
	Type      string `json:"type,omitempty"`
}

// RegisteredCredential has the DCQL shape: meta holds vct_values or
// doctype_value.
type RegisteredCredential struct {
	Format string            `json:"format"`
	Meta   map[string]any    `json:"meta"`
	Claims []RegisteredClaim `json:"claims"`
}

type RegisteredClaim struct {
	Path []any `json:"path"`
}

const euidIdentifierType = "http://data.europa.eu/eudi/id/EUID"

var (
	errRelyingPartyNotFound = errors.New("relying party not registered")
	errRelyingPartyExists   = errors.New("relying party already registered")
	errRegistrarFull        = errors.New("the registrar holds the maximum number of relying parties")
	countryCodePattern      = regexp.MustCompile(`^[A-Z]{2}$`)
)

// RegisterRelyingParty stores a new relying party. If the request leaves them
// out, the registrar assigns the identifier and the intended use identifiers,
// and sets the contact URLs under base.
func (w *Wallet) RegisterRelyingParty(rp WalletRelyingParty, base string) (WalletRelyingParty, error) {
	rp, err := cloneRelyingParty(rp)
	if err != nil {
		return WalletRelyingParty{}, err
	}
	if err := normalizeRelyingParty(&rp, base, nil); err != nil {
		return WalletRelyingParty{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.RelyingParties) >= maxRelyingParties {
		return WalletRelyingParty{}, errRegistrarFull
	}
	for _, id := range rp.Identifier {
		if relyingPartyIndex(w.RelyingParties, id.Identifier) >= 0 {
			return WalletRelyingParty{}, fmt.Errorf("%w: %s", errRelyingPartyExists, id.Identifier)
		}
	}
	w.RelyingParties = append(w.RelyingParties, rp)
	return cloneRelyingParty(rp)
}

// UpdateRelyingParty replaces the registration with the same identifier. New
// intended uses get identifiers, and existing ones keep theirs.
func (w *Wallet) UpdateRelyingParty(rp WalletRelyingParty, base string) (WalletRelyingParty, error) {
	rp, err := cloneRelyingParty(rp)
	if err != nil {
		return WalletRelyingParty{}, err
	}
	if len(rp.Identifier) == 0 || strings.TrimSpace(rp.Identifier[0].Identifier) == "" {
		return WalletRelyingParty{}, fmt.Errorf("an update needs the identifier of the registered relying party")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	i := relyingPartyIndex(w.RelyingParties, rp.Identifier[0].Identifier)
	if i < 0 {
		return WalletRelyingParty{}, fmt.Errorf("%w: %s", errRelyingPartyNotFound, rp.Identifier[0].Identifier)
	}
	// The first identifier never changes, because the issued certificates and
	// their status entries contain it.
	stored := w.RelyingParties[i].Identifier[0]
	rp.Identifier = append([]Identifier{stored}, slices.DeleteFunc(rp.Identifier, func(id Identifier) bool { return id.Identifier == stored.Identifier })...)
	for _, id := range rp.Identifier[1:] {
		if j := relyingPartyIndex(w.RelyingParties, id.Identifier); j >= 0 && j != i {
			return WalletRelyingParty{}, fmt.Errorf("%w: %s", errRelyingPartyExists, id.Identifier)
		}
	}
	if err := normalizeRelyingParty(&rp, base, &w.RelyingParties[i]); err != nil {
		return WalletRelyingParty{}, err
	}
	// A certificate certifies the content of its intended use. When an update
	// changes that content or drops the intended use, its certificates are
	// revoked for good.
	before := w.RelyingParties[i]
	w.supersedeRegistrationsLocked(func(s RegistrationStatus) bool {
		return s.Identifier == stored.Identifier && !sameCertificateContent(before, rp, statusKey(s))
	})
	w.RelyingParties[i] = rp
	return cloneRelyingParty(rp)
}

func (w *Wallet) DeleteRelyingParty(identifier string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	i := relyingPartyIndex(w.RelyingParties, identifier)
	if i < 0 {
		return fmt.Errorf("%w: %s", errRelyingPartyNotFound, identifier)
	}
	deleted := w.RelyingParties[i].Identifier[0].Identifier
	w.supersedeRegistrationsLocked(func(s RegistrationStatus) bool { return s.Identifier == deleted })
	w.RelyingParties = slices.Delete(w.RelyingParties, i, i+1)
	return nil
}

func (w *Wallet) RelyingParty(identifier string) (WalletRelyingParty, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if i := relyingPartyIndex(w.RelyingParties, identifier); i >= 0 {
		rp, err := cloneRelyingParty(w.RelyingParties[i])
		return rp, err == nil
	}
	return WalletRelyingParty{}, false
}

func (w *Wallet) RegisteredRelyingParties() []WalletRelyingParty {
	w.mu.RLock()
	defer w.mu.RUnlock()
	parties := make([]WalletRelyingParty, 0, len(w.RelyingParties))
	for _, stored := range w.RelyingParties {
		if rp, err := cloneRelyingParty(stored); err == nil {
			parties = append(parties, rp)
		}
	}
	return parties
}

// cloneRelyingParty copies a registration through its JSON form. Callers then
// can't change the stored registration through shared slices or maps. Stored
// and updated values also get the same types as in an API request, so comparing
// them works.
func cloneRelyingParty(rp WalletRelyingParty) (WalletRelyingParty, error) {
	encoded, err := json.Marshal(rp)
	if err != nil {
		return WalletRelyingParty{}, fmt.Errorf("encoding the relying party: %w", err)
	}
	var clone WalletRelyingParty
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return WalletRelyingParty{}, fmt.Errorf("decoding the relying party: %w", err)
	}
	return clone, nil
}

// RegistrarRecords are the wallet's own provider registration followed by the
// registered relying parties, as the registrar API lists them.
func (w *Wallet) RegistrarRecords() []WalletRelyingParty {
	return append([]WalletRelyingParty{providerRelyingParty(w, w.RegistrarBase())}, w.RegisteredRelyingParties()...)
}

func relyingPartyIndex(parties []WalletRelyingParty, identifier string) int {
	return slices.IndexFunc(parties, func(rp WalletRelyingParty) bool { return hasIdentifier(rp, identifier) })
}

func hasIdentifier(rp WalletRelyingParty, identifier string) bool {
	identifier = strings.TrimSpace(identifier)
	return slices.ContainsFunc(rp.Identifier, func(id Identifier) bool { return id.Identifier == identifier })
}

// normalizeRelyingParty checks a registration and fills in what the registrar
// assigns. For an update, before is the stored registration.
func normalizeRelyingParty(rp *WalletRelyingParty, base string, before *WalletRelyingParty) error {
	if err := checkRegistrationSize(*rp); err != nil {
		return err
	}
	rp.TradeName = strings.TrimSpace(rp.TradeName)
	if rp.TradeName == "" && len(rp.Services) > 0 {
		rp.TradeName = strings.TrimSpace(rp.Services[0].ServiceTradeName)
	}
	if rp.TradeName == "" {
		return fmt.Errorf("a relying party needs a trade name")
	}
	rp.Country = strings.ToUpper(strings.TrimSpace(rp.Country))
	if rp.Country != "" && !countryCodePattern.MatchString(rp.Country) {
		return fmt.Errorf("country %q is not a two-letter country code", rp.Country)
	}
	if len(rp.Identifier) == 0 || strings.TrimSpace(rp.Identifier[0].Identifier) == "" {
		rp.Identifier = []Identifier{{Identifier: newOrganizationIdentifier(firstNonEmpty(rp.Country, mock.DefaultCertificateCountry)), Type: euidIdentifierType}}
	}
	identifier := strings.TrimSpace(rp.Identifier[0].Identifier)
	if !organizationIdentifierPattern.MatchString(identifier) {
		return fmt.Errorf("identifier %q is not an organizationIdentifier such as LEIXG-5299000ABCDEF12345 (type LEI, NTR, VAT, EOR or EXC, country code, dash, value)", identifier)
	}
	rp.Identifier[0].Identifier = identifier
	if rp.Country == "" {
		rp.Country = identifier[3:5]
	}
	if len(rp.LegalPerson.LegalName) == 0 || strings.TrimSpace(rp.LegalPerson.LegalName[0]) == "" {
		rp.LegalPerson.LegalName = []string{rp.TradeName}
	}
	if rp.SupervisoryAuthority.Name == "" {
		rp.SupervisoryAuthority = SupervisoryAuthority{Name: "Test Supervisory Authority", Country: rp.Country, Email: []string{"dpa@eudi-test.dev"}}
	}
	rp.RegistryURI = base + "/api/registrar/wrp/" + identifier
	if len(rp.Services) == 0 {
		rp.Services = []WalletRelyingPartyService{{}}
	}
	services := map[string]bool{}
	for i := range rp.Services {
		service := &rp.Services[i]
		if services[service.ServiceIdentifier] {
			if service.ServiceIdentifier == "" {
				return fmt.Errorf("each service needs its own serviceIdentifier")
			}
			return fmt.Errorf("service identifier %q is registered twice", service.ServiceIdentifier)
		}
		services[service.ServiceIdentifier] = true
		service.ServiceTradeName = firstNonEmpty(service.ServiceTradeName, rp.TradeName)
		if len(service.SupportURI) == 0 {
			service.SupportURI = []string{base + "/support"}
		}
		if len(service.SrvDescription) == 0 {
			service.SrvDescription = []MultiLangString{{Lang: "en", Content: service.ServiceTradeName}}
		}
		if err := normalizeEntitlements(service); err != nil {
			return err
		}
		for j := range service.IntendedUses {
			if err := normalizeIntendedUse(&service.IntendedUses[j], base, before); err != nil {
				return err
			}
		}
	}
	uses := map[string]bool{}
	for _, service := range rp.Services {
		for _, use := range service.IntendedUses {
			if uses[use.IntendedUseIdentifier] {
				return fmt.Errorf("intended use identifier %q is registered twice", use.IntendedUseIdentifier)
			}
			uses[use.IntendedUseIdentifier] = true
		}
	}
	return nil
}

// Size limits keep a public demo's registrar small between resets.
const (
	maxRelyingParties    = 500
	maxRegistrationItems = 20
	maxRegisteredClaims  = 100
)

func checkRegistrationSize(rp WalletRelyingParty) error {
	tooMany := func(what string, n, limit int) error {
		if n > limit {
			return fmt.Errorf("a registration may list at most %d %s", limit, what)
		}
		return nil
	}
	if err := tooMany("identifiers", len(rp.Identifier), maxRegistrationItems); err != nil {
		return err
	}
	if err := tooMany("services", len(rp.Services), maxRegistrationItems); err != nil {
		return err
	}
	for _, service := range rp.Services {
		if err := tooMany("provided attestations per service", len(service.ProvidesAttestations), maxRegistrationItems); err != nil {
			return err
		}
		if err := tooMany("intended uses per service", len(service.IntendedUses), maxRegistrationItems); err != nil {
			return err
		}
		for _, use := range service.IntendedUses {
			if err := tooMany("credentials per intended use", len(use.Credentials), maxRegistrationItems); err != nil {
				return err
			}
			for _, credential := range use.Credentials {
				if err := tooMany("claims per credential", len(credential.Claims), maxRegisteredClaims); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func normalizeIntendedUse(use *IntendedUse, base string, before *WalletRelyingParty) error {
	if len(use.Credentials) == 0 {
		return fmt.Errorf("an intended use needs at least one credential")
	}
	for _, credential := range use.Credentials {
		if credential.Format != "dc+sd-jwt" && credential.Format != "mso_mdoc" {
			return fmt.Errorf("credential format %q is not dc+sd-jwt or mso_mdoc", credential.Format)
		}
		if len(credentialTypes(credential.Meta)) == 0 {
			return fmt.Errorf("a %s credential needs its type in meta (vct_values or doctype_value)", credential.Format)
		}
		// TS05 v1.5 §2.4.5: a credential always lists the attributes it asks for.
		if !slices.ContainsFunc(credential.Claims, func(c RegisteredClaim) bool { return len(c.Path) > 0 }) {
			return fmt.Errorf("the %s credential %s needs at least one claim", credential.Format, strings.Join(credentialTypes(credential.Meta), ", "))
		}
	}
	use.CreatedAt = time.Now().UTC().Format(time.DateOnly)
	if before != nil {
		if _, kept, ok := findIntendedUse(*before, "", use.IntendedUseIdentifier); ok {
			use.CreatedAt = kept.CreatedAt
		} else {
			use.IntendedUseIdentifier = ""
		}
	}
	if use.IntendedUseIdentifier == "" {
		use.IntendedUseIdentifier = newRegistrarID()
	}
	if len(use.PrivacyPolicy) == 0 {
		use.PrivacyPolicy = []Policy{{PolicyURI: base + "/privacy-policy"}}
	}
	return nil
}

// normalizeEntitlements checks a service's entitlements against what it
// registers. ETSI TS 119 475 V1.2.1 GEN-5.2.4-03 requires an entitlement from
// Annex A.2. Table 8 lists provided attestations only for attestation
// providers, and ARF RPRC_15 requires a provider to list them. A provider that
// also requests attributes is a service provider too (ARF RPRC_05 note).
func normalizeEntitlements(service *WalletRelyingPartyService) error {
	service.Entitlements = dedupeStrings(service.Entitlements)
	if len(service.Entitlements) == 0 && len(service.ProvidesAttestations) == 0 {
		service.Entitlements = []string{serviceProviderEntitlement}
	}
	provider := isAttestationProvider(*service)
	switch {
	case !provider && len(service.ProvidesAttestations) > 0:
		return fmt.Errorf("service %q lists attestation types, so it needs an attestation provider entitlement (PID_Provider, QEAA_Provider, PUB_EAA_Provider or Non_Q_EAA_Provider)", service.ServiceTradeName)
	case provider && len(service.ProvidesAttestations) == 0:
		return fmt.Errorf("service %q is an attestation provider, so it has to list its attestation types (ARF RPRC_15)", service.ServiceTradeName)
	case !slices.ContainsFunc(service.Entitlements, func(e string) bool { return slices.Contains(registeredEntitlements, e) }):
		return fmt.Errorf("service %q needs an entitlement from ETSI TS 119 475 Annex A.2, such as %s", service.ServiceTradeName, serviceProviderEntitlement)
	}
	for _, attestation := range service.ProvidesAttestations {
		if attestation.Format != "dc+sd-jwt" && attestation.Format != "mso_mdoc" {
			return fmt.Errorf("attestation format %q is not dc+sd-jwt or mso_mdoc", attestation.Format)
		}
		if len(credentialTypes(attestation.Meta)) == 0 {
			return fmt.Errorf("a %s attestation needs its type in meta (vct_values or doctype_value)", attestation.Format)
		}
	}
	if len(service.IntendedUses) > 0 && !slices.Contains(service.Entitlements, serviceProviderEntitlement) {
		service.Entitlements = append(service.Entitlements, serviceProviderEntitlement)
	}
	return nil
}

// isAttestationProvider reports whether the service has an entitlement to
// issue attestations (ETSI TS 119 475 V1.2.1 Table 8).
func isAttestationProvider(service WalletRelyingPartyService) bool {
	return slices.ContainsFunc(service.Entitlements, func(e string) bool { return slices.Contains(providerEntitlements, e) })
}

// sameCertificateContent reports whether the certificate for key has the same
// content in before and after.
func sameCertificateContent(before, after WalletRelyingParty, key certificateKey) bool {
	if key.intendedUse == "" {
		afterService, ok := serviceByIdentifier(after, key.service)
		if !ok || !isAttestationProvider(afterService) {
			return false
		}
		beforeService, _ := serviceByIdentifier(before, key.service)
		return reflect.DeepEqual(providerContent(before, beforeService), providerContent(after, afterService))
	}
	afterService, afterUse, ok := findIntendedUse(after, "", key.intendedUse)
	if !ok {
		return false
	}
	beforeService, beforeUse, _ := findIntendedUse(before, "", key.intendedUse)
	return reflect.DeepEqual(registrationContent(before, beforeService, beforeUse), registrationContent(after, afterService, afterUse)) &&
		reflect.DeepEqual(beforeUse.Credentials, afterUse.Credentials)
}

// serviceByIdentifier finds the service with exactly this identifier. The only
// service of a relying party may have an empty one.
func serviceByIdentifier(rp WalletRelyingParty, identifier string) (WalletRelyingPartyService, bool) {
	i := slices.IndexFunc(rp.Services, func(s WalletRelyingPartyService) bool { return s.ServiceIdentifier == identifier })
	if i < 0 {
		return WalletRelyingPartyService{}, false
	}
	return rp.Services[i], true
}

// findIntendedUse returns the service and intended use. An empty service
// identifier searches every service.
func findIntendedUse(rp WalletRelyingParty, serviceIdentifier, intendedUseIdentifier string) (WalletRelyingPartyService, IntendedUse, bool) {
	for _, service := range rp.Services {
		if serviceIdentifier != "" && service.ServiceIdentifier != serviceIdentifier {
			continue
		}
		for _, use := range service.IntendedUses {
			if use.IntendedUseIdentifier == intendedUseIdentifier {
				return service, use, true
			}
		}
	}
	return WalletRelyingPartyService{}, IntendedUse{}, false
}

// findService returns the service with the identifier. An empty identifier
// selects the first service.
func findService(rp WalletRelyingParty, serviceIdentifier string) (WalletRelyingPartyService, bool) {
	for _, service := range rp.Services {
		if serviceIdentifier == "" || service.ServiceIdentifier == serviceIdentifier {
			return service, true
		}
	}
	return WalletRelyingPartyService{}, false
}

// newOrganizationIdentifier assigns an EUID in the organizationIdentifier form
// of ETSI EN 319 412-1 §5.1.4 (prefix NTR).
func newOrganizationIdentifier(country string) string {
	return "NTR" + strings.ToUpper(country) + "-" + strings.ToUpper(newRegistrarID())
}

func newRegistrarID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// providerRelyingParty is the wallet's own registration as a credential
// provider, in the TS05 v1.5 shape. Issuers look up its entitlements and the
// attestations it provides.
func providerRelyingParty(w *Wallet, base string) WalletRelyingParty {
	dataset := buildRegistrarDataset(w, base)
	if _, access, err := w.AccessSigningMaterial(); err == nil {
		identifier, _, _ := accessCertificateSubject(access[0])
		dataset.Identifier = []Identifier{{Identifier: identifier, Type: euidIdentifierType}}
		dataset.RegistryURI = strings.TrimRight(base, "/") + "/api/registrar/wrp/" + identifier
	}
	return WalletRelyingParty{
		Identifier:           dataset.Identifier,
		LegalPerson:          LegalPerson{LegalName: []string{dataset.TradeName}},
		Country:              dataset.SupervisoryAuthority.Country,
		TradeName:            dataset.TradeName,
		IsPSB:                dataset.IsPSB,
		SupervisoryAuthority: dataset.SupervisoryAuthority,
		RegistryURI:          dataset.RegistryURI,
		Services: []WalletRelyingPartyService{{
			ServiceTradeName:     dataset.TradeName,
			SupportURI:           dataset.SupportURI,
			SrvDescription:       dataset.SrvDescription,
			Entitlements:         dataset.Entitlements,
			ProvidesAttestations: dataset.ProvidesAttestations,
			IsIntermediary:       dataset.IsIntermediary,
		}},
	}
}

// matchesWRPQuery applies the TS05 v1.5 §3.2.2 search parameters.
func matchesWRPQuery(rp WalletRelyingParty, q url.Values) bool {
	has := func(name string, match func(string) bool) bool {
		value := strings.TrimSpace(q.Get(name))
		return value == "" || match(value)
	}
	anyService := func(match func(WalletRelyingPartyService) bool) bool { return slices.ContainsFunc(rp.Services, match) }
	anyUse := func(match func(IntendedUse) bool) bool {
		return anyService(func(s WalletRelyingPartyService) bool { return slices.ContainsFunc(s.IntendedUses, match) })
	}
	anyCredential := func(match func(RegisteredCredential) bool) bool {
		return anyUse(func(u IntendedUse) bool { return slices.ContainsFunc(u.Credentials, match) })
	}
	contains := func(text, part string) bool { return strings.Contains(strings.ToLower(text), strings.ToLower(part)) }
	return has("identifier", func(v string) bool { return hasIdentifier(rp, v) }) &&
		has("serviceidentifier", func(v string) bool {
			return anyService(func(s WalletRelyingPartyService) bool { return s.ServiceIdentifier == v })
		}) &&
		has("legalname", func(v string) bool {
			return slices.ContainsFunc(rp.LegalPerson.LegalName, func(n string) bool { return contains(n, v) })
		}) &&
		has("tradename", func(v string) bool {
			return contains(rp.TradeName, v) || anyService(func(s WalletRelyingPartyService) bool { return contains(s.ServiceTradeName, v) })
		}) &&
		has("entitlement", func(v string) bool {
			return anyService(func(s WalletRelyingPartyService) bool { return slices.Contains(s.Entitlements, v) })
		}) &&
		has("providedattestation", func(v string) bool {
			return anyService(func(s WalletRelyingPartyService) bool {
				return slices.ContainsFunc(s.ProvidesAttestations, func(a ProvidedAttestation) bool { return slices.Contains(credentialTypes(a.Meta), v) })
			})
		}) &&
		has("intendeduseidentifier", func(v string) bool { return anyUse(func(u IntendedUse) bool { return u.IntendedUseIdentifier == v }) }) &&
		has("credentialformat", func(v string) bool { return anyCredential(func(c RegisteredCredential) bool { return c.Format == v }) }) &&
		has("credentialmeta", func(v string) bool {
			return anyCredential(func(c RegisteredCredential) bool { return slices.Contains(credentialTypes(c.Meta), v) })
		})
}

// checkIntendedUse answers whether the relying party registered an intended
// use, and with credentialmeta and claimpath, whether that use covers the
// credential type and claim (TS05 v1.5 §3.2.4). claimpath separates path
// components with dots.
func checkIntendedUse(rp WalletRelyingParty, q url.Values) (bool, string) {
	useID := strings.TrimSpace(q.Get("intendeduseidentifier"))
	_, use, ok := findIntendedUse(rp, strings.TrimSpace(q.Get("serviceidentifier")), useID)
	if !ok {
		return false, "no intended use " + useID
	}
	format, meta, claimPath := strings.TrimSpace(q.Get("credentialformat")), strings.TrimSpace(q.Get("credentialmeta")), strings.TrimSpace(q.Get("claimpath"))
	for _, credential := range use.Credentials {
		if (format != "" && credential.Format != format) || (meta != "" && !slices.Contains(credentialTypes(credential.Meta), meta)) {
			continue
		}
		if claimPath == "" {
			return true, "registered"
		}
		for _, claim := range credential.Claims {
			if pathString(claim.Path) == claimPath {
				return true, "registered"
			}
		}
	}
	return false, "the intended use does not register this credential or claim"
}

func pathString(path []any) string {
	parts := make([]string, 0, len(path))
	for _, p := range path {
		parts = append(parts, fmt.Sprint(p))
	}
	return strings.Join(parts, ".")
}
