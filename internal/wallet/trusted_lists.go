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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/validate"
)

// The wallet publishes the providers of access certificates and of
// registration certificates on lists of their own (ARF RPACANot_05 and
// RPACANot_05a). The URIs come from ETSI TS 119 602 V1.1.1 Annexes F and G.
// Annex G registers its status determination URI with this spelling.
const (
	accessCAListType              = "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList"
	accessCAStatusDetermination   = "http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU"
	accessCASchemeCommunityRules  = "http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU"
	accessCAIssuanceServiceType   = "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance"
	accessCARevocationServiceType = "http://uri.etsi.org/19602/SvcType/WRPAC/Revocation"

	registrarListType              = "http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList"
	registrarStatusDetermination   = "http://uri.etsi.org/19602/WRPRCrovidersList/StatusDetn/EU"
	registrarSchemeCommunityRules  = "http://uri.etsi.org/19602/WRPRCProvidersList/schemerules/EU"
	registrarIssuanceServiceType   = "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance"
	registrarRevocationServiceType = "http://uri.etsi.org/19602/SvcType/WRPRC/Revocation"

	accessCAListID   = "access-ca"
	registrarListID  = "registrar"
	walletProviderID = "wallet-provider"
	// listOfListsID is the list that points to every trusted list the wallet
	// uses (ETSI TS 119 602 V1.1.1 §6.3.13).
	listOfListsID = "lists"
)

// listsCredentialProviders reports whether the group lists the providers of
// credentials, as opposed to wallet providers, access CAs and registrars.
func (g TrustListGroup) listsCredentialProviders() bool {
	switch g.Profile.LoTEType {
	case walletProviderTrustListType, accessCAListType, registrarListType:
		return false
	}
	return true
}

func accessCATrustListProfile() trustListProfile {
	return trustListProfile{
		LoTEType:                    accessCAListType,
		StatusDeterminationApproach: accessCAStatusDetermination,
		SchemeTypeCommunityRules:    accessCASchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         accessCAIssuanceServiceType,
		RevocationServiceType:       accessCARevocationServiceType,
		IssuanceServiceName:         "Access Certificate Issuance",
		RevocationServiceName:       "Access Certificate Revocation",
		EntityName:                  "EUDI Dev Relying Party Access CA",
	}
}

func registrarTrustListProfile() trustListProfile {
	return trustListProfile{
		LoTEType:                    registrarListType,
		StatusDeterminationApproach: registrarStatusDetermination,
		SchemeTypeCommunityRules:    registrarSchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         registrarIssuanceServiceType,
		RevocationServiceType:       registrarRevocationServiceType,
		IssuanceServiceName:         "Registration Certificate Issuance",
		RevocationServiceName:       "Registration Certificate Revocation",
		EntityName:                  "EUDI Dev Registrar",
	}
}

// TrustedEntity is a provider that a user put on one of the wallet's trusted
// lists. The wallet signs the list with the entity on it, so its certificates
// anchor the --arf checks like the wallet's own providers.
type TrustedEntity struct {
	ID   string `json:"id"`
	List string `json:"list"`
	Name string `json:"name"`
	// Certificates are base64 DER certificates of the provider's CAs or
	// signers.
	Certificates []string `json:"certificates"`
}

// ErrTrustNotFound reports a trusted entity or list that the wallet does not
// have.
var ErrTrustNotFound = errors.New("not on the wallet's trusted lists")

// TrustedEntityLists are the wallet lists that take trusted entities.
func TrustedEntityLists() []string {
	return append(slices.Clone(credtemplate.Categories), walletProviderID, accessCAListID, registrarListID)
}

// AddTrustedEntity puts a provider with the certificates in PEM on the list.
// The same certificates on the same list replace the earlier entry.
func (w *Wallet) AddTrustedEntity(list, name, certificatesPEM string) (TrustedEntity, error) {
	list, name = strings.TrimSpace(list), strings.TrimSpace(name)
	if !slices.Contains(TrustedEntityLists(), list) {
		return TrustedEntity{}, fmt.Errorf("list %q is not one of %s", list, strings.Join(TrustedEntityLists(), ", "))
	}
	certs, err := keys.ParseCertificatesPEM([]byte(certificatesPEM))
	if err != nil {
		return TrustedEntity{}, fmt.Errorf("the certificates: %w", err)
	}
	entity := TrustedEntity{List: list, Name: firstNonEmpty(name, certs[0].Subject.CommonName, "Trusted provider")}
	digest := sha256.New()
	digest.Write([]byte(list))
	for _, cert := range certs {
		entity.Certificates = append(entity.Certificates, base64.StdEncoding.EncodeToString(cert.Raw))
		digest.Write(cert.Raw)
	}
	entity.ID = hex.EncodeToString(digest.Sum(nil)[:8])
	w.mu.Lock()
	defer w.mu.Unlock()
	w.TrustedEntities = append(slices.DeleteFunc(w.TrustedEntities, func(e TrustedEntity) bool { return e.ID == entity.ID }), entity)
	return entity, nil
}

// RemoveTrustedEntity takes a provider off its list.
func (w *Wallet) RemoveTrustedEntity(id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	before := len(w.TrustedEntities)
	w.TrustedEntities = slices.DeleteFunc(w.TrustedEntities, func(e TrustedEntity) bool { return e.ID == id })
	if len(w.TrustedEntities) == before {
		return fmt.Errorf("%w: %q", ErrTrustNotFound, id)
	}
	return nil
}

// ListTrustedEntities returns the entities users put on the wallet's lists.
func (w *Wallet) ListTrustedEntities() []TrustedEntity {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return slices.Clone(w.TrustedEntities)
}

// trustListEntities are the entities of a wallet list next to the wallet's
// own provider: the ones users added and, for the access CA and registrar
// lists, the CAs from --relying-party-ca.
func (w *Wallet) trustListEntities(listID string) []trustListEntity {
	var out []trustListEntity
	for _, entity := range w.ListTrustedEntities() {
		if entity.List == listID {
			out = append(out, trustListEntity{Name: entity.Name, Issuance: entity.Certificates})
		}
	}
	if listID == accessCAListID || listID == registrarListID {
		w.mu.RLock()
		configured, err := keys.ParseCertificatesPEM(w.RelyingPartyCAPEM)
		w.mu.RUnlock()
		if err == nil {
			for _, cert := range configured {
				encoded := base64.StdEncoding.EncodeToString(cert.Raw)
				out = append(out, trustListEntity{Name: firstNonEmpty(cert.Subject.CommonName, "Relying party CA"), Issuance: []string{encoded}, Revocation: []string{encoded}})
			}
		}
	}
	return out
}

// AddTrustedList puts an external list of trusted entities on the wallet's
// list of trusted lists. The --arf checks then take anchors from it.
func (w *Wallet) AddTrustedList(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if u, err := url.Parse(rawURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("%q is not an http or https URL", rawURL)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !slices.Contains(w.AddedTrustedLists, rawURL) {
		w.AddedTrustedLists = append(w.AddedTrustedLists, rawURL)
	}
	return rawURL, nil
}

// RemoveTrustedList takes an external list off the list of trusted lists.
func (w *Wallet) RemoveTrustedList(rawURL string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	before := len(w.AddedTrustedLists)
	w.AddedTrustedLists = slices.DeleteFunc(w.AddedTrustedLists, func(u string) bool { return u == strings.TrimSpace(rawURL) })
	if len(w.AddedTrustedLists) == before {
		return fmt.Errorf("%w: %q", ErrTrustNotFound, rawURL)
	}
	return nil
}

// ExternalTrustedLists are the external lists on the list of trusted lists:
// the ones from --trusted-list and the ones users added.
func (w *Wallet) ExternalTrustedLists() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := slices.Clone(w.ConfiguredTrustedListURLs)
	for _, u := range w.AddedTrustedLists {
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

// ownTrustListURL is where the wallet publishes one of its lists.
func (w *Wallet) ownTrustListURL(id string) string {
	return w.RegistrarBase() + "/api/trustlists/" + id
}

// rawTrustedList builds one of the wallet's own lists in process, because the
// wallet may not serve them over HTTP. It fetches every other list.
func (w *Wallet) rawTrustedList(rawURL string) (string, error) {
	if id, ok := strings.CutPrefix(rawURL, w.RegistrarBase()+"/api/trustlists/"); ok {
		group, found := FindTrustListGroupForWallet(w, id, "", "")
		if !found {
			return "", fmt.Errorf("the wallet has no trusted list %q", id)
		}
		return GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, "/api/trustlists/"+group.ID)
	}
	raw, err := format.FetchURL(rawURL, w.HTTPClient())
	if err != nil {
		return "", fmt.Errorf("fetching the trusted list: %w", err)
	}
	return raw, nil
}

// readTrustedList returns a list that a trusted list operator signed. The ARF
// has the wallet accept the provider trust anchors on a list because of that
// signature (PPNot_05, TLPub_05, TLPub_07). A list past its next update is
// expired (ETSI TS 119 602 V1.1.1 §6.3.15).
func (w *Wallet) readTrustedList(rawURL string) (*trustlist.TrustList, error) {
	raw, err := w.rawTrustedList(rawURL)
	if err != nil {
		return nil, err
	}
	if err := verifyTrustListSigner(raw, w.TrustListCAs()); err != nil {
		return nil, err
	}
	list, err := trustlist.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing the trusted list: %w", err)
	}
	if next, err := time.Parse(time.RFC3339, list.SchemeInfo.NextUpdate); err == nil && next.Before(time.Now()) {
		return nil, fmt.Errorf("the trusted list expired at %s (ETSI TS 119 602 V1.1.1 §6.3.15)", list.SchemeInfo.NextUpdate)
	}
	return list, nil
}

// Service kinds of a trusted list. A service type ends in /Issuance or
// /Revocation (ETSI TS 119 602 V1.1.1 Annexes D to H).
const (
	issuanceServices   = "Issuance"
	revocationServices = "Revocation"
)

// serviceAnchors are the certificates of the services of a kind that a list
// names. A withdrawn service anchors nothing (ETSI TS 119 602 V1.1.1 Table
// H.3).
func serviceAnchors(list *trustlist.TrustList, kind string) []trustlist.CertInfo {
	var anchors []trustlist.CertInfo
	for _, entity := range list.Entities {
		for _, service := range entity.Services {
			if !strings.HasSuffix(service.ServiceType, "/"+kind) || strings.HasSuffix(service.ServiceStatus, "/withdrawn") {
				continue
			}
			anchors = append(anchors, service.Certificates...)
		}
	}
	return anchors
}

// TrustedListURLs are the lists on the wallet's list of trusted lists: its
// own lists and the external ones.
func (w *Wallet) TrustedListURLs() []string {
	var urls []string
	for _, group := range TrustListGroupsForWallet(w) {
		urls = append(urls, w.ownTrustListURL(group.ID))
	}
	return append(urls, w.ExternalTrustedLists()...)
}

// listAnchors are the certificates of the services of a kind on every list of
// the type on the list of trusted lists. A list that can't be read anchors
// nothing.
func (w *Wallet) listAnchors(listType, kind string) []*x509.Certificate {
	var anchors []*x509.Certificate
	for _, u := range w.TrustedListURLs() {
		list, err := w.readTrustedList(u)
		if err != nil || list.SchemeInfo.LoTEType != listType {
			continue
		}
		anchors = append(anchors, parsedAnchors(serviceAnchors(list, kind))...)
	}
	return anchors
}

// GenerateListOfTrustedLists signs the list that points to every trusted
// list the wallet uses: its own lists and the external ones (ETSI TS 119 602
// V1.1.1 §6.3.13). Each pointer names the list's location, its type and the
// certificate of its signer. An external list that can't be read has no
// pointer.
func GenerateListOfTrustedLists(w *Wallet, issuer string) (string, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	key, chain, err := w.TrustListSigningMaterial("EUDI Dev Wallet", mock.DefaultCertificateCountry)
	if err != nil {
		return "", err
	}
	signer := base64.StdEncoding.EncodeToString(chain[0].Raw)
	pointer := func(location, listType, signerCert string) map[string]any {
		return map[string]any{
			"LoTELocation":             location,
			"ServiceDigitalIdentities": []map[string]any{{"X509Certificates": []map[string]string{{"val": signerCert}}}},
			"LoTEQualifiers":           []map[string]any{{"LoTEType": listType, "MimeType": "application/jwt"}},
		}
	}
	var pointers []map[string]any
	for _, group := range TrustListGroupsForWallet(w) {
		pointers = append(pointers, pointer(firstNonEmpty(issuer, w.RegistrarBase())+"/api/trustlists/"+group.ID, group.Profile.LoTEType, signer))
	}
	for _, u := range w.ExternalTrustedLists() {
		raw, err := w.rawTrustedList(u)
		if err != nil {
			continue
		}
		header, _, err := decodeCompactJWT(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		certs, err := validate.X5CCertificates(header)
		list, parseErr := trustlist.Parse(raw)
		if err != nil || len(certs) == 0 || parseErr != nil {
			continue
		}
		pointers = append(pointers, pointer(u, list.SchemeInfo.LoTEType, base64.StdEncoding.EncodeToString(certs[0].Raw)))
	}
	now := time.Now().UTC().Truncate(time.Second)
	payload := map[string]any{
		"LoTE": map[string]any{
			"ListAndSchemeInformation": map[string]any{
				"LoTEVersionIdentifier": 1,
				"LoTESequenceNumber":    1,
				"LoTEType":              localTrustListType,
				"SchemeOperatorName":    []map[string]string{{"lang": "en", "value": "EUDI Dev Wallet"}},
				"SchemeName":            []map[string]string{{"lang": "en", "value": "EUDI Dev list of trusted lists"}},
				"SchemeTerritory":       "EU",
				"ListIssueDateTime":     now.Format(time.RFC3339),
				"NextUpdate":            now.Add(24 * time.Hour).Format(time.RFC3339),
				"PointersToOtherLoTE":   pointers,
			},
			"TrustedEntitiesList": []map[string]any{},
		},
	}
	digest := sha256.Sum256(chain[0].Raw)
	header := map[string]any{
		"alg":      "ES256",
		"typ":      "JWT",
		"x5c":      []string{signer},
		"iat":      now.Unix(),
		"x5t#S256": base64.RawURLEncoding.EncodeToString(digest[:]),
	}
	return jws.Sign(header, payload, key)
}

// CredentialProviderAnchors are the certificates of the services of a kind on
// the credential provider lists of the wallet's list of trusted lists. The
// demo verifier trusts them like a verifier trusts the lists it reads: the
// issuance services for credentials and the revocation services for status
// lists.
func (w *Wallet) CredentialProviderAnchors(kind string) []*x509.Certificate {
	var anchors []*x509.Certificate
	for _, u := range w.TrustedListURLs() {
		list, err := w.readTrustedList(u)
		if err != nil {
			continue
		}
		switch list.SchemeInfo.LoTEType {
		case walletProviderTrustListType, accessCAListType, registrarListType:
			continue
		}
		anchors = append(anchors, parsedAnchors(serviceAnchors(list, kind))...)
	}
	return anchors
}

// Service kinds for CredentialProviderAnchors.
const (
	IssuanceServices   = issuanceServices
	RevocationServices = revocationServices
)

// WalletProviderAnchors are the issuance certificates of the wallet provider
// lists, which anchor wallet and key attestations (ETSI TS 119 602 V1.1.1
// Annex E).
func (w *Wallet) WalletProviderAnchors() []*x509.Certificate {
	return w.listAnchors(walletProviderTrustListType, issuanceServices)
}

func parsedAnchors(infos []trustlist.CertInfo) []*x509.Certificate {
	var out []*x509.Certificate
	for _, info := range infos {
		if cert, err := x509.ParseCertificate(info.Raw); err == nil {
			out = append(out, cert)
		}
	}
	return out
}
