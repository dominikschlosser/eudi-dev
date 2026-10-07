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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

type trustListOptions struct {
	OperatorName           string
	Issuer                 string
	TrustListPath          string
	Profile                trustListProfile
	Sequence               int
	IssuanceCertificates   []string
	RevocationCertificates []string
}

type TrustListGroup struct {
	ID      string
	Profile trustListProfile
	Specs   []IssuedAttestationSpec
}

type TrustListIndexEntry struct {
	ID                    string                  `json:"id"`
	Default               bool                    `json:"default"`
	Description           string                  `json:"description,omitempty"`
	Category              string                  `json:"category,omitempty"`
	Path                  string                  `json:"path"`
	LoTEType              string                  `json:"loTEType"`
	EntityName            string                  `json:"entityName"`
	IssuanceServiceType   string                  `json:"issuanceServiceType"`
	RevocationServiceType string                  `json:"revocationServiceType"`
	Attestations          []IssuedAttestationSpec `json:"attestations"`
	AdvertisedURL         string                  `json:"advertised_url,omitempty"`
	URL                   string                  `json:"url,omitempty"`
}

func GenerateTrustListJWTForWallet(w *Wallet, issuer string) (string, error) {
	if w == nil || w.CAKey == nil || len(w.CertChain) < 2 {
		return "", fmt.Errorf("wallet has no CA certificate chain")
	}
	return GenerateTrustListJWTForWalletGroup(w, issuer, DefaultTrustListGroupForWallet(w), "/api/trustlist")
}

func GenerateTrustListJWTForWalletGroup(w *Wallet, issuer string, group TrustListGroup, path string) (string, error) {
	if w == nil || w.CAKey == nil || len(w.CertChain) < 2 {
		return "", fmt.Errorf("wallet has no CA certificate chain")
	}
	if path == "" {
		path = "/api/trustlist"
	}
	var issuanceCertificates []string
	countries := []string{""}
	if group.Profile.Category == credtemplate.CategoryPID {
		countries = []string{"NL", "DE", "IT"}
	}
	for _, country := range countries {
		_, chain, err := w.signingMaterialForProfile(group.Profile, country)
		if err != nil {
			return "", err
		}
		issuanceCertificates = append(issuanceCertificates, base64.StdEncoding.EncodeToString(chain[0].Raw))
	}
	_, profileChain, err := w.signingMaterialForProfile(group.Profile, "")
	if err != nil {
		return "", err
	}
	certificates, err := w.signingStore().profileCertificates(profileChain[0], w.TrustAnchorCertificate())
	if err != nil {
		return "", err
	}
	seen := make(map[string]bool)
	for _, certificate := range issuanceCertificates {
		seen[certificate] = true
	}
	for _, certificate := range certificates {
		if !seen[certificate] {
			issuanceCertificates = append(issuanceCertificates, certificate)
			seen[certificate] = true
		}
	}
	_, statusChain, err := w.StatusListSigningMaterial()
	if err != nil {
		return "", err
	}
	listKey, listChain, err := w.TrustListSigningMaterial("EUDI Dev Wallet", mock.DefaultCertificateCountry)
	if err != nil {
		return "", err
	}
	return w.signingStore().trustList(listKey, listChain[0], trustListOptions{
		OperatorName:           "EUDI Dev Wallet",
		Issuer:                 strings.TrimRight(strings.TrimSpace(issuer), "/"),
		TrustListPath:          path,
		Profile:                group.Profile,
		IssuanceCertificates:   issuanceCertificates,
		RevocationCertificates: []string{base64.StdEncoding.EncodeToString(statusChain[0].Raw)},
	})
}

// TrustListGroupsForWallet lists one trusted list per credential category,
// the lists of credential types with their own trust profile, and the wallet
// provider list. Credential types without a category are on no list.
func TrustListGroupsForWallet(w *Wallet) []TrustListGroup {
	byID := make(map[string]*TrustListGroup)
	var groups []*TrustListGroup
	add := func(profile trustListProfile) *TrustListGroup {
		id := trustListGroupID(profile)
		if group := byID[id]; group != nil {
			return group
		}
		group := &TrustListGroup{ID: id, Profile: profile}
		byID[id] = group
		groups = append(groups, group)
		return group
	}
	for _, category := range credtemplate.Categories {
		add(categoryTrustListProfile(category))
	}
	add(walletProviderTrustListProfile())
	if w != nil {
		for _, spec := range w.issuedAttestationSpecs() {
			if spec.TrustListType == "" {
				continue
			}
			profile := trustListProfileFromSpec(spec)
			group := add(profile)
			group.Specs = append(group.Specs, spec)
		}
	}
	out := make([]TrustListGroup, 0, len(groups))
	for _, group := range groups {
		sort.Slice(group.Specs, func(i, j int) bool {
			if group.Specs[i].Format != group.Specs[j].Format {
				return group.Specs[i].Format < group.Specs[j].Format
			}
			if group.Specs[i].VCT != group.Specs[j].VCT {
				return group.Specs[i].VCT < group.Specs[j].VCT
			}
			return group.Specs[i].DocType < group.Specs[j].DocType
		})
		out = append(out, *group)
	}
	return out
}

// The wallet provider's CA anchors wallet and key attestations sent to issuers.
func walletProviderTrustListProfile() trustListProfile {
	return trustListProfile{
		LoTEType:                    walletProviderTrustListType,
		StatusDeterminationApproach: walletProviderStatusDetermination,
		SchemeTypeCommunityRules:    walletProviderSchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         walletProviderIssuanceServiceType,
		RevocationServiceType:       walletProviderRevocationServiceType,
		IssuanceServiceName:         "Wallet Attestation Issuance",
		RevocationServiceName:       "Wallet Attestation Revocation",
		EntityName:                  "EUDI Dev Wallet Provider",
	}
}

// DefaultTrustListGroupForWallet is the PID provider list.
func DefaultTrustListGroupForWallet(w *Wallet) TrustListGroup {
	return TrustListGroupsForWallet(w)[0]
}

func FindTrustListGroupForWallet(w *Wallet, id, vct, docType string) (TrustListGroup, bool) {
	groups := TrustListGroupsForWallet(w)
	if len(groups) == 0 {
		return TrustListGroup{}, false
	}
	id = strings.TrimSpace(id)
	vct = strings.TrimSpace(vct)
	docType = strings.TrimSpace(docType)

	if id != "" {
		for _, group := range groups {
			if group.ID == id {
				return group, true
			}
		}
		return TrustListGroup{}, false
	}
	if vct != "" || docType != "" {
		for _, group := range groups {
			for _, spec := range group.Specs {
				if (vct == "" || spec.VCT == vct) && (docType == "" || spec.DocType == docType) {
					return group, true
				}
			}
		}
		return TrustListGroup{}, false
	}
	return DefaultTrustListGroupForWallet(w), true
}

func BuildTrustListIndexEntries(w *Wallet, issuer string) []TrustListIndexEntry {
	groups := TrustListGroupsForWallet(w)
	defaultGroup := DefaultTrustListGroupForWallet(w)
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	entries := make([]TrustListIndexEntry, 0, len(groups))
	for _, group := range groups {
		path := "/api/trustlists/" + group.ID
		entry := TrustListIndexEntry{
			ID:                    group.ID,
			Default:               group.ID == defaultGroup.ID,
			Description:           trustListDescription(group),
			Category:              trustListCategory(group),
			Path:                  path,
			LoTEType:              group.Profile.LoTEType,
			EntityName:            group.Profile.EntityName,
			IssuanceServiceType:   group.Profile.IssuanceServiceType,
			RevocationServiceType: group.Profile.RevocationServiceType,
			Attestations:          append([]IssuedAttestationSpec(nil), group.Specs...),
		}
		if issuer != "" {
			entry.AdvertisedURL = issuer + path
			entry.URL = entry.AdvertisedURL
		}
		entries = append(entries, entry)
	}
	return entries
}

func trustListDescription(group TrustListGroup) string {
	if group.Profile.LoTEType == walletProviderTrustListType {
		return "Wallet and key attestations, for issuers"
	}
	if group.ID != group.Profile.Category {
		return "Credentials with their own trust profile, for verifiers"
	}
	return map[string]string{
		credtemplate.CategoryPID:    "PIDs this wallet issues, for verifiers",
		credtemplate.CategoryQEAA:   "QEAAs this wallet issues, for verifiers",
		credtemplate.CategoryPubEAA: "PuB-EAAs this wallet issues, for verifiers",
		credtemplate.CategoryEAA:    "EAAs this wallet issues, for verifiers",
	}[group.Profile.Category]
}

func trustListCategory(group TrustListGroup) string {
	if group.Profile.LoTEType == walletProviderTrustListType {
		return "Wallet providers"
	}
	return "Credential providers"
}

func trustListProfileFromSpec(spec IssuedAttestationSpec) trustListProfile {
	return trustListProfile{
		Category:                    spec.Category,
		LoTEType:                    spec.TrustListType,
		StatusDeterminationApproach: spec.StatusDeterminationApproach,
		SchemeTypeCommunityRules:    spec.SchemeTypeCommunityRules,
		SchemeTerritory:             spec.SchemeTerritory,
		IssuanceServiceType:         spec.IssuanceServiceType,
		RevocationServiceType:       spec.RevocationServiceType,
		IssuanceServiceName:         spec.IssuanceServiceName,
		RevocationServiceName:       spec.RevocationServiceName,
		EntityName:                  spec.EntityName,
	}
}

func trustListProfileKey(profile trustListProfile) string {
	parts := []string{
		profile.Category,
		profile.LoTEType,
		profile.StatusDeterminationApproach,
		profile.SchemeTypeCommunityRules,
		profile.SchemeTerritory,
		profile.IssuanceServiceType,
		profile.RevocationServiceType,
		profile.IssuanceServiceName,
		profile.RevocationServiceName,
		profile.EntityName,
	}
	return strings.Join(parts, "|")
}

// trustListGroupID names a category's list by the category. A spec that
// changes its category's defaults gets a list of its own.
func trustListGroupID(profile trustListProfile) string {
	if profile.LoTEType == walletProviderTrustListType {
		return "wallet-provider"
	}
	if profile.Category != "" && profile == categoryTrustListProfile(profile.Category) {
		return profile.Category
	}
	hash := sha256.Sum256([]byte(trustListProfileKey(profile)))
	return "tl-" + hex.EncodeToString(hash[:4])
}

// The listed provider is test data. ETSI TS 119 602 V1.1.1 Tables D.2, E.2
// and H.2 ask for its registration identifier as trade name and for a contact
// email and phone. A PID or PuB-EAA provider also names its Member State with
// a URI, and a PuB-EAA provider the law it is established under.
const (
	listedProviderName       = "EUDI Dev Test Provider"
	listedProviderIdentifier = "NTR" + mock.DefaultCertificateCountry + "-00000000"
	pubEAANotifiedStatus     = "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified"
)

func trustedEntityInformation(opts trustListOptions) map[string]any {
	tradeName := []map[string]string{{"lang": "en", "value": listedProviderIdentifier}}
	electronic := []map[string]string{
		{"lang": "en", "uriValue": firstNonEmpty(opts.Issuer, "https://github.com/dominikschlosser/eudi-dev")},
		{"lang": "en", "uriValue": "mailto:provider@example.invalid"},
		{"lang": "en", "uriValue": "tel:+31000000000"},
	}
	information := []map[string]string{{"lang": "en", "uriValue": firstNonEmpty(opts.Issuer, "https://github.com/dominikschlosser/eudi-dev")}}
	country := mock.DefaultCertificateCountry
	switch opts.Profile.LoTEType {
	case pidTrustListType:
		information = append(information, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/" + country})
	case pubEAATrustListType:
		tradeName = append(tradeName, map[string]string{"lang": "en", "value": "OJ:" + country + "-eudi-dev-test"})
		electronic = append(electronic, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/" + country})
	}
	return map[string]any{
		"TEName":      []map[string]string{{"lang": "en", "value": listedProviderName}},
		"TETradeName": tradeName,
		"TEAddress": map[string]any{
			"TEPostalAddress":     []map[string]string{{"lang": "en", "StreetAddress": "Test address", "Locality": "Test city", "PostalCode": "0000", "Country": country}},
			"TEElectronicAddress": electronic,
		},
		"TEInformationURI": information,
	}
}

func trustListService(serviceType, name string, certificates []string) map[string]any {
	return map[string]any{
		"ServiceInformation": map[string]any{
			"ServiceTypeIdentifier":  serviceType,
			"ServiceName":            []map[string]string{{"lang": "en", "value": name}},
			"ServiceDigitalIdentity": map[string]any{"X509Certificates": trustListCertificates(certificates)},
		},
	}
}

func generateTrustListJWTWithOptions(signingKey *ecdsa.PrivateKey, caCert *x509.Certificate, opts trustListOptions) (string, error) {
	certB64 := base64.StdEncoding.EncodeToString(caCert.Raw)
	certDigest := sha256.Sum256(caCert.Raw)
	if len(opts.IssuanceCertificates) == 0 {
		opts.IssuanceCertificates = []string{certB64}
	}
	if len(opts.RevocationCertificates) == 0 {
		opts.RevocationCertificates = []string{certB64}
	}
	now := time.Now().UTC().Truncate(time.Second)
	if opts.Sequence == 0 {
		opts.Sequence = 1
	}
	if strings.TrimSpace(opts.OperatorName) == "" {
		opts.OperatorName = "EUDI Dev Wallet"
	}
	if opts.Profile.LoTEType == "" {
		opts.Profile = trustListProfile{
			LoTEType:              localTrustListType,
			IssuanceServiceType:   localIssuanceServiceType,
			RevocationServiceType: localRevocationServiceType,
			IssuanceServiceName:   "Issuance Service",
			RevocationServiceName: "Revocation Service",
			EntityName:            "EUDI Dev Wallet Issuer",
		}
	}

	if opts.Profile.SchemeTerritory == "" {
		opts.Profile.SchemeTerritory = "NL"
	}
	issueTime := now.Format(time.RFC3339Nano)
	nextUpdate := now.Add(24 * time.Hour).Format(time.RFC3339Nano)

	schemeInfo := map[string]any{
		"LoTEVersionIdentifier": 1,
		"LoTESequenceNumber":    opts.Sequence,
		"LoTEType":              opts.Profile.LoTEType,
		"SchemeOperatorName":    []map[string]string{{"lang": "en", "value": opts.OperatorName}},
		"ListIssueDateTime":     issueTime,
		"NextUpdate":            nextUpdate,
	}
	schemeInfo["SchemeName"] = []map[string]string{{"lang": "en", "value": opts.Profile.SchemeTerritory + ": EUDI Dev Test Providers"}}
	schemeInfo["SchemeOperatorAddress"] = map[string]any{
		"SchemeOperatorPostalAddress":     []map[string]string{{"lang": "en", "StreetAddress": "Test address", "Country": "NL"}},
		"SchemeOperatorElectronicAddress": []map[string]string{{"lang": "en", "uriValue": "https://github.com/dominikschlosser/eudi-dev"}},
	}
	if opts.Profile.StatusDeterminationApproach != "" {
		schemeInfo["StatusDeterminationApproach"] = opts.Profile.StatusDeterminationApproach
	}
	if opts.Profile.SchemeTypeCommunityRules != "" {
		schemeInfo["SchemeTypeCommunityRules"] = []map[string]string{{"lang": "en", "uriValue": opts.Profile.SchemeTypeCommunityRules}}
	}
	if opts.Profile.SchemeTerritory != "" {
		schemeInfo["SchemeTerritory"] = opts.Profile.SchemeTerritory
	}
	path := firstNonEmpty(opts.TrustListPath, "/api/trustlist")
	if opts.Issuer != "" {
		schemeInfo["SchemeInformationURI"] = []map[string]string{
			{"lang": "en", "uriValue": "https://github.com/dominikschlosser/eudi-dev/blob/main/docs/test-certificates.md"},
			{"lang": "en", "uriValue": opts.Issuer + path + "/history"},
		}
		schemeInfo["DistributionPoints"] = []string{opts.Issuer + path}
	}
	// ETSI TS 119 602 V1.1.1 Table D.1 and Table E.1 require a pointer to the
	// list itself. Table H.1 forbids pointers and fixes the history period.
	if opts.Profile.LoTEType == pubEAATrustListType {
		schemeInfo["HistoricalInformationPeriod"] = 65535
	} else if opts.Issuer != "" {
		schemeInfo["PointersToOtherLoTE"] = []map[string]any{{
			"LoTELocation":             opts.Issuer + path,
			"ServiceDigitalIdentities": []map[string]any{{"X509Certificates": []map[string]string{{"val": certB64}}}},
			"LoTEQualifiers":           []map[string]any{{"LoTEType": opts.Profile.LoTEType, "SchemeOperatorName": schemeInfo["SchemeOperatorName"], "MimeType": "application/jwt"}},
		}}
	}

	issuanceServices := []map[string]any{trustListService(opts.Profile.IssuanceServiceType, opts.Profile.IssuanceServiceName, opts.IssuanceCertificates)}
	revocationService := trustListService(opts.Profile.RevocationServiceType, opts.Profile.RevocationServiceName, opts.RevocationCertificates)
	if opts.Profile.LoTEType == pubEAATrustListType {
		// Table H.3: the certificates of a service relate to one public key, and
		// every service has a status.
		issuanceServices = nil
		for _, certificate := range opts.IssuanceCertificates {
			issuanceServices = append(issuanceServices, trustListService(opts.Profile.IssuanceServiceType, opts.Profile.IssuanceServiceName, []string{certificate}))
		}
		for _, service := range append(issuanceServices, revocationService) {
			service["ServiceInformation"].(map[string]any)["ServiceStatus"] = pubEAANotifiedStatus
		}
	}
	services := make([]map[string]any, 0, len(issuanceServices)+1)
	services = append(append(services, issuanceServices...), revocationService)

	// ETSI trust lists use a JSON wrapper object.
	payload := map[string]any{
		"LoTE": map[string]any{
			"ListAndSchemeInformation": schemeInfo,
			"TrustedEntitiesList": []map[string]any{{
				"TrustedEntityInformation": trustedEntityInformation(opts),
				"TrustedEntityServices":    services,
			}},
		},
	}

	header := map[string]any{
		"alg":      "ES256",
		"typ":      "JWT",
		"x5c":      []string{certB64},
		"iat":      now.Unix(),
		"x5t#S256": base64.RawURLEncoding.EncodeToString(certDigest[:]),
	}

	return jws.Sign(header, payload, signingKey)
}

func trustListCertificates(certificates []string) []map[string]string {
	values := make([]map[string]string, len(certificates))
	for i, cert := range certificates {
		values[i] = map[string]string{"val": cert}
	}
	return values
}
