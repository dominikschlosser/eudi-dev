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

	"github.com/dominikschlosser/eudi-dev/internal/jws"
)

type trustListOptions struct {
	OperatorName  string
	Issuer        string
	TrustListPath string
	Profile       trustListProfile
}

// TrustListGroup is one coherent trust-list profile covering one or more
// attestation types registered in the wallet.
type TrustListGroup struct {
	ID      string
	Profile trustListProfile
	Specs   []IssuedAttestationSpec
}

// TrustListIndexEntry is the JSON index representation exposed by /api/trustlists.
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

// GenerateTrustListJWT generates an ETSI TS 119 602 trust list JWT
// containing the CA certificate as the trust anchor. The trust list is
// signed with the provided signing key.
func GenerateTrustListJWT(signingKey *ecdsa.PrivateKey, caCert *x509.Certificate) (string, error) {
	return generateTrustListJWTWithOptions(signingKey, caCert, trustListOptions{
		OperatorName: "EUDI Dev Wallet",
		Profile: trustListProfile{
			LoTEType:              localTrustListType,
			IssuanceServiceType:   localIssuanceServiceType,
			RevocationServiceType: localRevocationServiceType,
			IssuanceServiceName:   "Issuance Service",
			RevocationServiceName: "Revocation Service",
			EntityName:            "EUDI Dev Wallet Issuer",
		},
	})
}

func GenerateTrustListJWTForWallet(w *Wallet, issuer string) (string, error) {
	if w == nil || w.CAKey == nil || len(w.CertChain) < 2 {
		return "", fmt.Errorf("wallet has no CA certificate chain")
	}
	group, ok := DefaultTrustListGroupForWallet(w)
	if !ok {
		return "", fmt.Errorf("wallet has no trust-list profile")
	}
	return GenerateTrustListJWTForWalletGroup(w, issuer, group, "/api/trustlist")
}

func GenerateTrustListJWTForWalletGroup(w *Wallet, issuer string, group TrustListGroup, path string) (string, error) {
	if w == nil || w.CAKey == nil || len(w.CertChain) < 2 {
		return "", fmt.Errorf("wallet has no CA certificate chain")
	}
	if path == "" {
		path = "/api/trustlist"
	}
	return generateTrustListJWTWithOptions(w.CAKey, w.CertChain[len(w.CertChain)-1], trustListOptions{
		OperatorName:  "EUDI Dev Wallet",
		Issuer:        strings.TrimRight(strings.TrimSpace(issuer), "/"),
		TrustListPath: path,
		Profile:       group.Profile,
	})
}

func TrustListGroupsForWallet(w *Wallet) []TrustListGroup {
	specs := []IssuedAttestationSpec(nil)
	if w != nil {
		specs = w.issuedAttestationSpecs()
	}
	if len(specs) == 0 {
		profile := inferWalletTrustListProfile(w)
		return withWalletProviderGroup([]TrustListGroup{{
			ID:      trustListGroupID(profile),
			Profile: profile,
		}})
	}

	byKey := make(map[string]*TrustListGroup)
	for _, spec := range specs {
		profile := trustListProfileFromSpec(spec)
		key := trustListProfileKey(profile)
		group := byKey[key]
		if group == nil {
			group = &TrustListGroup{
				ID:      trustListGroupID(profile),
				Profile: profile,
			}
			byKey[key] = group
		}
		group.Specs = append(group.Specs, spec)
	}

	groups := make([]TrustListGroup, 0, len(byKey)+1)
	for _, group := range byKey {
		sort.Slice(group.Specs, func(i, j int) bool {
			if group.Specs[i].Format != group.Specs[j].Format {
				return group.Specs[i].Format < group.Specs[j].Format
			}
			if group.Specs[i].VCT != group.Specs[j].VCT {
				return group.Specs[i].VCT < group.Specs[j].VCT
			}
			return group.Specs[i].DocType < group.Specs[j].DocType
		})
		groups = append(groups, *group)
	}
	groups = withWalletProviderGroup(groups)
	sort.Slice(groups, func(i, j int) bool {
		return trustListGroupSortKey(groups[i]) < trustListGroupSortKey(groups[j])
	})
	return groups
}

// walletProviderTrustListProfile describes the wallet in its Wallet Provider
// role: the entity whose CA anchors the wallet attestation and the key
// attestations sent to issuers.
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

// withWalletProviderGroup adds the wallet-provider list to a set of
// credential lists. It does not depend on the issued-attestation registry:
// the wallet attestation exists whether or not the wallet has issued
// anything, and an issuer should not have to work out that a list named
// "pid" happens to carry the anchor it needs. The certificate inside is the
// same shared CA, only the list that presents it differs.
func withWalletProviderGroup(groups []TrustListGroup) []TrustListGroup {
	profile := walletProviderTrustListProfile()
	id := trustListGroupID(profile)
	for _, group := range groups {
		if group.ID == id {
			return groups
		}
	}
	return append(groups, TrustListGroup{ID: id, Profile: profile})
}

func DefaultTrustListGroupForWallet(w *Wallet) (TrustListGroup, bool) {
	groups := TrustListGroupsForWallet(w)
	if len(groups) == 0 {
		return TrustListGroup{}, false
	}
	for _, group := range groups {
		if group.Profile.LoTEType == pidTrustListType {
			return group, true
		}
	}
	// The wallet-provider list anchors attestations rather than credentials,
	// so it never becomes the default that `/api/trustlist` serves, however
	// few other lists exist.
	for _, group := range groups {
		if group.Profile.LoTEType != walletProviderTrustListType {
			return group, true
		}
	}
	return groups[0], true
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
	return DefaultTrustListGroupForWallet(w)
}

func BuildTrustListIndexEntries(w *Wallet, issuer string) []TrustListIndexEntry {
	groups := TrustListGroupsForWallet(w)
	defaultGroup, hasDefault := DefaultTrustListGroupForWallet(w)
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	entries := make([]TrustListIndexEntry, 0, len(groups))
	for _, group := range groups {
		path := "/api/trustlists/" + group.ID
		entry := TrustListIndexEntry{
			ID:                    group.ID,
			Default:               hasDefault && group.ID == defaultGroup.ID,
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

// trustListDescription says who a list is for, because the id alone does not.
// "pid" reads like a list about PID credentials only, and nothing about it
// suggests that an issuer verifying a wallet attestation has its own list.
func trustListDescription(group TrustListGroup) string {
	if group.Profile.LoTEType == walletProviderTrustListType {
		return "Wallet and key attestations, for issuers"
	}
	return "Credentials this wallet issues, for verifiers"
}

// trustListCategory groups lists by what they anchor, so a reader looking for
// one kind is not reading past the other.
func trustListCategory(group TrustListGroup) string {
	if group.Profile.LoTEType == walletProviderTrustListType {
		return "Wallet providers"
	}
	return "Credential providers"
}

func trustListProfileFromSpec(spec IssuedAttestationSpec) trustListProfile {
	return trustListProfile{
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

func trustListGroupID(profile trustListProfile) string {
	switch profile.LoTEType {
	case pidTrustListType:
		return "pid"
	case walletProviderTrustListType:
		return "wallet-provider"
	case localTrustListType:
		return "local"
	}
	hash := sha256.Sum256([]byte(trustListProfileKey(profile)))
	return "tl-" + hex.EncodeToString(hash[:4])
}

func trustListGroupSortKey(group TrustListGroup) string {
	switch group.Profile.LoTEType {
	case pidTrustListType:
		return "0|" + group.ID
	case walletProviderTrustListType:
		return "1|" + group.ID
	case localTrustListType:
		return "9|" + group.ID
	default:
		return "5|" + group.ID
	}
}

func generateTrustListJWTWithOptions(signingKey *ecdsa.PrivateKey, caCert *x509.Certificate, opts trustListOptions) (string, error) {
	certB64 := base64.StdEncoding.EncodeToString(caCert.Raw)
	now := time.Now().UTC().Truncate(time.Millisecond)
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

	issueTime := now.Format(time.RFC3339Nano)
	nextUpdate := now.Add(24 * time.Hour).Format(time.RFC3339Nano)

	schemeInfo := map[string]any{
		"LoTEVersionIdentifier": 1,
		"LoTESequenceNumber":    1,
		"LoTEType":              opts.Profile.LoTEType,
		"SchemeOperatorName":    []map[string]string{{"lang": "en-US", "value": opts.OperatorName}},
		"ListIssueDateTime":     issueTime,
		"NextUpdate":            nextUpdate,
	}
	if opts.Profile.StatusDeterminationApproach != "" {
		schemeInfo["StatusDeterminationApproach"] = opts.Profile.StatusDeterminationApproach
	}
	if opts.Profile.SchemeTypeCommunityRules != "" {
		schemeInfo["SchemeTypeCommunityRules"] = []map[string]string{{"lang": "en-US", "uriValue": opts.Profile.SchemeTypeCommunityRules}}
	}
	if opts.Profile.SchemeTerritory != "" {
		schemeInfo["SchemeTerritory"] = opts.Profile.SchemeTerritory
	}
	if opts.Issuer != "" {
		path := opts.TrustListPath
		if path == "" {
			path = "/api/trustlist"
		}
		schemeInfo["SchemeInformationURI"] = []map[string]string{{"lang": "en-US", "uriValue": opts.Issuer + path}}
	}

	entityInfo := map[string]any{
		"TEName": []map[string]string{{"lang": "en-US", "value": opts.Profile.EntityName}},
	}
	if opts.Issuer != "" {
		entityInfo["TEInformationURI"] = []map[string]string{{"lang": "en-US", "uriValue": opts.Issuer}}
		entityInfo["TEAddress"] = map[string]any{
			"TEElectronicAddress": []map[string]string{{"lang": "en-US", "uriValue": opts.Issuer}},
		}
	}

	// Build ETSI trust list payload using the JSON binding wrapper object.
	payload := map[string]any{
		"LoTE": map[string]any{
			"ListAndSchemeInformation": schemeInfo,
			"TrustedEntitiesList": []map[string]any{
				{
					"TrustedEntityInformation": entityInfo,
					"TrustedEntityServices": []map[string]any{
						{
							"ServiceInformation": map[string]any{
								"ServiceTypeIdentifier": opts.Profile.IssuanceServiceType,
								"ServiceName":           []map[string]string{{"lang": "en-US", "value": opts.Profile.IssuanceServiceName}},
								"ServiceDigitalIdentity": map[string]any{
									"X509Certificates": []map[string]string{{"val": certB64}},
								},
							},
						},
						{
							"ServiceInformation": map[string]any{
								"ServiceTypeIdentifier": opts.Profile.RevocationServiceType,
								"ServiceName":           []map[string]string{{"lang": "en-US", "value": opts.Profile.RevocationServiceName}},
								"ServiceDigitalIdentity": map[string]any{
									"X509Certificates": []map[string]string{{"val": certB64}},
								},
							},
						},
					},
				},
			},
		},
	}

	// Build JWT header
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
	}

	return jws.Sign(header, payload, signingKey)
}
