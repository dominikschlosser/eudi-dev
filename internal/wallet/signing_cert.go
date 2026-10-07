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
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// SigningCertChainForIssuedAttestation is the signer chain of the type's trust
// profile.
func (w *Wallet) SigningCertChainForIssuedAttestation(spec IssuedAttestationSpec) ([]*x509.Certificate, error) {
	_, chain, err := w.signingMaterialForProfile(trustListProfileFromSpec(spec), "")
	return chain, err
}

// SigningMaterialForIssuedCredential returns the signing key and chain of the
// type's trust profile. The signer's countryName matches issuing_country, as
// ISO/IEC 18013-5 Table B.3 requires.
func (w *Wallet) SigningMaterialForIssuedCredential(spec IssuedAttestationSpec, claims map[string]any) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.signingMaterialForProfile(trustListProfileFromSpec(spec), IssuingCountryFromClaims(claims))
}

// SigningMaterialForIssuedAttestation reads the key and chain together so a reset
// cannot pair values from before and after it.
func (w *Wallet) SigningMaterialForIssuedAttestation(spec IssuedAttestationSpec) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.signingMaterialForProfile(trustListProfileFromSpec(spec), "")
}

func IssuingCountryFromClaims(claims map[string]any) string {
	country, _ := claims["issuing_country"].(string)
	if len(country) == 2 && country == strings.ToUpper(country) {
		return country
	}
	return ""
}

// Hold one lock while reading the key and chain. A concurrent reset could
// otherwise pair a new key with an old chain.
func (w *Wallet) signingMaterialForProfile(profile trustListProfile, country string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if w == nil {
		return nil, nil, fmt.Errorf("wallet has no issuer certificate chain")
	}
	if country == "" {
		country = mock.DefaultCertificateCountry
	}
	w.mu.RLock()
	issuerKey, caKey := w.IssuerKey, w.CAKey
	chain := append([]*x509.Certificate(nil), w.CertChain...)
	w.mu.RUnlock()

	if issuerKey == nil || caKey == nil || len(chain) < 2 {
		return nil, nil, fmt.Errorf("wallet has no issuer certificate chain")
	}
	caCert := chain[len(chain)-1]
	opts := mock.LeafCertOptions{
		CommonName:            signingLeafCommonName(profile),
		Country:               country,
		CRLDistributionPoints: crlDistributionPoints(w.IssuerURL),
	}
	role := providerRole(profile)
	switch {
	case profile.Category == credtemplate.CategoryPID:
		opts.Role = mock.PIDProviderCertificate
	case role == string(mock.WalletProviderCertificate):
		opts.Role = mock.WalletProviderCertificate
	}
	if role != credtemplate.CategoryPID {
		var err error
		if issuerKey, err = w.signingStore().key(signingKeyName(role)); err != nil {
			return nil, nil, err
		}
	}
	opts.IssuingCertificateURL = issuingCertificateURLs(w.IssuerURL)
	parentKey, parent, err := w.signingStore().providerCA(caKey, caCert, w.IssuerURL, role, country)
	if err != nil {
		return nil, nil, fmt.Errorf("generating provider CA: %w", err)
	}
	if !parent.Equal(caCert) {
		certificateCountry := country
		if certificateCountry == "" {
			certificateCountry = mock.DefaultCertificateCountry
		}
		base := strings.TrimRight(w.IssuerURL, "/")
		if base != "" {
			opts.IssuingCertificateURL = []string{base + "/api/certificates/providers/" + role + "/" + certificateCountry + ".der"}
			opts.CRLDistributionPoints = []string{base + "/api/crl/providers/" + role + "/" + certificateCountry}
		}
	}
	opts.DNSNames, opts.IPAddresses, opts.URIs = issuerSubjectAltNames(w.IssuerURL)
	leafCert, err := w.signingStore().certificate(parentKey, parent, &issuerKey.PublicKey, opts, false)
	if err != nil {
		return nil, nil, fmt.Errorf("generating signing leaf certificate: %w", err)
	}
	certs := []*x509.Certificate{leafCert, parent}
	if !parent.Equal(caCert) {
		certs = append(certs, caCert)
	}
	return issuerKey, certs, nil
}

// providerRole names the provider CA and signing key of a trust profile. A
// category's list, every custom list and the wallet provider list each have
// their own, so a list anchors only the credentials signed for it. A PID
// signer uses the wallet's issuer key.
func providerRole(profile trustListProfile) string {
	switch {
	case profile.LoTEType == walletProviderTrustListType:
		return string(mock.WalletProviderCertificate)
	case profile.LoTEType == "":
		return unlistedRole
	}
	return trustListGroupID(profile)
}

const unlistedRole = "unlisted"

var customRolePattern = regexp.MustCompile(`^tl-[0-9a-f]{8}$`)

// isProviderRole accepts the roles that providerRole returns.
func isProviderRole(role string) bool {
	return slices.Contains(credtemplate.Categories, role) || role == unlistedRole ||
		role == string(mock.WalletProviderCertificate) || customRolePattern.MatchString(role)
}

func signingKeyName(role string) string {
	if role == string(mock.WalletProviderCertificate) {
		return "wallet-provider"
	}
	return "issuer-" + role
}

// ISO/IEC 18013-5 Table B.3 requires a CRL distribution point URI in document signer
// certificates.
func crlDistributionPoints(issuerURL string) []string {
	issuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuer == "" {
		return nil
	}
	return []string{issuer + "/api/crl"}
}

func issuingCertificateURLs(issuerURL string) []string {
	issuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuer == "" {
		return nil
	}
	return []string{issuer + "/api/certificates/ca.der"}
}

func (w *Wallet) WalletProviderSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.signingMaterialForProfile(walletProviderTrustListProfile(), "")
}

// AccessSigningMaterial is the access certificate of the wallet's issuer, the
// demo issuer. Its CommonName is the trade name of its registration, as ARF
// RPRC_06 and ETSI TS 119 411-8 V1.1.1 GEN-6.1.1-04 require.
func (w *Wallet) AccessSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.auxiliarySigningMaterial("access", mock.LeafCertOptions{CommonName: DemoIssuerName, Role: mock.AccessCertificate})
}

// RelyingPartyAccessCA issues the access certificates of registered relying
// parties. It is a separate root, because the wallet CA is the trust anchor for
// credential issuers and a visitor's CSR must never produce a certificate under
// it.
func (w *Wallet) RelyingPartyAccessCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	return w.signingStore().selfSignedCA("relying-party-access-ca", "EUDI Dev Test Relying Party Access CA")
}

func (w *Wallet) RegistrarSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.auxiliarySigningMaterial("registrar", mock.LeafCertOptions{CommonName: "EUDI Dev Test Registrar", Role: mock.RegistrarCertificate})
}

func (w *Wallet) TrustListSigningMaterial(operator, country string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.auxiliarySigningMaterial("trustlist", mock.LeafCertOptions{CommonName: "EUDI Dev Test List Operator", Role: mock.TrustListCertificate, Organization: operator, Country: country})
}

func (w *Wallet) auxiliarySigningMaterial(keyRole string, opts mock.LeafCertOptions) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if w == nil {
		return nil, nil, fmt.Errorf("wallet has no signing material")
	}
	w.mu.RLock()
	caKey, chain, issuer := w.CAKey, append([]*x509.Certificate(nil), w.CertChain...), w.IssuerURL
	w.mu.RUnlock()
	if caKey == nil || len(chain) < 2 {
		return nil, nil, fmt.Errorf("wallet has no access certificate authority")
	}
	key, err := w.signingStore().key(keyRole)
	if err != nil {
		return nil, nil, err
	}
	opts.IssuingCertificateURL = issuingCertificateURLs(issuer)
	opts.CRLDistributionPoints = crlDistributionPoints(issuer)
	opts.DNSNames, opts.IPAddresses, opts.URIs = issuerSubjectAltNames(issuer)
	ca := chain[len(chain)-1]
	leaf, err := w.signingStore().certificate(caKey, ca, &key.PublicKey, opts, false)
	if err != nil {
		return nil, nil, err
	}
	return key, []*x509.Certificate{leaf, ca}, nil
}

// TrustAnchorCertificate holds the read lock because a reset can replace the
// chain concurrently.
func (w *Wallet) TrustAnchorCertificate() *x509.Certificate {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.CertChain) == 0 {
		return nil
	}
	return w.CertChain[len(w.CertChain)-1]
}

func (w *Wallet) DefaultSigningCertChain() ([]*x509.Certificate, error) {
	_, chain, err := w.DefaultSigningMaterial()
	return chain, err
}

func (w *Wallet) StatusListSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	w.mu.RLock()
	issuerKey, caKey := w.IssuerKey, w.CAKey
	chain := append([]*x509.Certificate(nil), w.CertChain...)
	w.mu.RUnlock()
	if issuerKey == nil || len(chain) == 0 {
		return nil, nil, fmt.Errorf("wallet has no status list signing material")
	}
	if caKey == nil || len(chain) < 2 {
		return issuerKey, chain, nil
	}
	caCert := chain[len(chain)-1]
	var err error
	issuerKey, err = w.signingStore().key("status")
	if err != nil {
		return nil, nil, err
	}
	leaf, err := w.signingStore().certificate(caKey, caCert, &issuerKey.PublicKey, mock.LeafCertOptions{
		CommonName:            "EUDI Dev Status List Signer",
		StatusListSigner:      true,
		CRLDistributionPoints: crlDistributionPoints(w.IssuerURL),
	}, false)
	if err != nil {
		return nil, nil, fmt.Errorf("generating status list signer certificate: %w", err)
	}
	return issuerKey, []*x509.Certificate{leaf, caCert}, nil
}

// DefaultSigningMaterial reads the key and chain together. A reload or reset between
// two separate reads could return a key that does not match the chain.
func (w *Wallet) DefaultSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.signingMaterialForProfile(DefaultTrustListGroupForWallet(w).Profile, "")
}

// SD-JWT VC draft-08 and earlier require the issuer identifier in the signing
// leaf's SANs. Verifiers check either the DNS or the URI form, so both are
// included. IP hosts get an IP SAN.
func issuerSubjectAltNames(issuerURL string) (dnsNames []string, ips []net.IP, uris []*url.URL) {
	raw := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if raw == "" {
		return nil, nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, nil, nil
	}
	if host := parsed.Hostname(); host != "" {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	return dnsNames, ips, []*url.URL{parsed}
}

func signingLeafCommonName(profile trustListProfile) string {
	if profile.LoTEType == "" {
		return "EUDI Dev Wallet Issuer"
	}
	return firstNonEmpty(profile.EntityName, "EUDI Dev Wallet Issuer") + " (" + trustListGroupID(profile) + ")"
}
