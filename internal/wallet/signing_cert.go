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
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// SigningCertChainForIssuedAttestation returns the signing certificate chain for one
// issued-attestation profile. The CA stays shared, but the leaf certificate is
// derived from the trust-list profile so different profiles can present distinct
// signer certificates.
func (w *Wallet) SigningCertChainForIssuedAttestation(spec IssuedAttestationSpec) ([]*x509.Certificate, error) {
	return w.SigningCertChainForProfile(trustListProfileFromSpec(spec))
}

// SigningCertChainForGroup returns the signing certificate chain for one trust-list group.
func (w *Wallet) SigningCertChainForGroup(group TrustListGroup) ([]*x509.Certificate, error) {
	return w.SigningCertChainForProfile(group.Profile)
}

// SigningCertChainForProfile returns a signing certificate chain for the given trust-list profile.
func (w *Wallet) SigningCertChainForProfile(profile trustListProfile) ([]*x509.Certificate, error) {
	if w == nil {
		return nil, fmt.Errorf("wallet has no issuer certificate chain")
	}
	// Read together under the lock: the demo reset replaces the CA key and the
	// chain while requests are in flight, and a leaf signed with one against a
	// CA from the other chains to nothing.
	w.mu.RLock()
	issuerKey, caKey := w.IssuerKey, w.CAKey
	chain := append([]*x509.Certificate(nil), w.CertChain...)
	w.mu.RUnlock()

	if issuerKey == nil || caKey == nil || len(chain) < 2 {
		return nil, fmt.Errorf("wallet has no issuer certificate chain")
	}
	caCert := chain[len(chain)-1]
	opts := mock.LeafCertOptions{
		CommonName:   signingLeafCommonName(profile),
		SerialNumber: signingLeafSerial(profile),
	}
	opts.DNSNames, opts.IPAddresses, opts.URIs = issuerSubjectAltNames(w.IssuerURL)
	leafCert, err := mock.GenerateLeafCertWithOptions(caKey, caCert, &issuerKey.PublicKey, opts)
	if err != nil {
		return nil, fmt.Errorf("generating signing leaf certificate: %w", err)
	}
	return []*x509.Certificate{leafCert, caCert}, nil
}

// DefaultSigningCertChain returns the signing certificate chain used for wallet-wide
// endpoints that do not yet select a profile explicitly.
func (w *Wallet) DefaultSigningCertChain() ([]*x509.Certificate, error) {
	group, ok := DefaultTrustListGroupForWallet(w)
	if !ok {
		if w == nil || len(w.CertChain) == 0 {
			return nil, fmt.Errorf("wallet has no signing certificate chain")
		}
		return append([]*x509.Certificate(nil), w.CertChain...), nil
	}
	return w.SigningCertChainForGroup(group)
}

// issuerSubjectAltNames are the subject alternative names a signing leaf needs
// to carry so the credentials it signs can be verified from their x5c header.
//
// HAIP 1.0 section 6.1.1 ties the two together: "the iss value MUST be an URL
// with a FQDN matching a dNSName Subject Alternative Name (SAN) entry in the
// leaf certificate", and a value that is not such a URL "MUST match a
// uniformResourceIdentifier SAN entry". Credentials this wallet issues carry
// its issuer URL as iss, so that URL is what the leaf has to name. Both forms
// are written, since a verifier is free to check either one.
//
// A host that is an IP address goes into an iPAddress SAN, where an address
// belongs, and leaves the dNSName list empty.
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
	label := strings.TrimSpace(profile.EntityName)
	if label == "" {
		label = "EUDI Dev Wallet Issuer"
	}
	id := trustListGroupID(profile)
	if id == "" {
		return label
	}
	return label + " (" + id + ")"
}

func signingLeafSerial(profile trustListProfile) *big.Int {
	sum := sha256.Sum256([]byte("oid4vc-dev/signing-leaf/" + trustListProfileKey(profile)))
	serial := new(big.Int).SetBytes(sum[:16])
	if serial.Sign() <= 0 {
		serial = big.NewInt(2)
	}
	return serial
}
