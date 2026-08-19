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

// SigningMaterialForIssuedAttestation returns the signing key together with
// the chain for one issued-attestation profile, read as one for the same
// reason DefaultSigningMaterial does.
func (w *Wallet) SigningMaterialForIssuedAttestation(spec IssuedAttestationSpec) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return w.signingMaterialForProfile(trustListProfileFromSpec(spec))
}

// SigningCertChainForGroup returns the signing certificate chain for one trust-list group.
func (w *Wallet) SigningCertChainForGroup(group TrustListGroup) ([]*x509.Certificate, error) {
	return w.SigningCertChainForProfile(group.Profile)
}

// SigningCertChainForProfile returns a signing certificate chain for the given trust-list profile.
func (w *Wallet) SigningCertChainForProfile(profile trustListProfile) ([]*x509.Certificate, error) {
	_, chain, err := w.signingMaterialForProfile(profile)
	return chain, err
}

// signingMaterialForProfile returns the signing key together with a chain
// whose leaf wraps its public half. Key and chain are captured under one
// lock: the demo reset replaces the CA key and the chain while requests are
// in flight, and a leaf signed with one against a CA from the other chains to
// nothing.
func (w *Wallet) signingMaterialForProfile(profile trustListProfile) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if w == nil {
		return nil, nil, fmt.Errorf("wallet has no issuer certificate chain")
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
		CommonName:   signingLeafCommonName(profile),
		SerialNumber: signingLeafSerial(profile),
	}
	opts.DNSNames, opts.IPAddresses, opts.URIs = issuerSubjectAltNames(w.IssuerURL)
	leafCert, err := mock.GenerateLeafCertWithOptions(caKey, caCert, &issuerKey.PublicKey, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("generating signing leaf certificate: %w", err)
	}
	return issuerKey, []*x509.Certificate{leafCert, caCert}, nil
}

// TrustAnchorCertificate returns the wallet CA certificate, read under the
// lock: the demo reset swaps the chain while requests are in flight, and a
// slice header is not written atomically.
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

// DefaultSigningCertChain returns the signing certificate chain used for wallet-wide
// endpoints that do not yet select a profile explicitly.
func (w *Wallet) DefaultSigningCertChain() ([]*x509.Certificate, error) {
	_, chain, err := w.DefaultSigningMaterial()
	return chain, err
}

// DefaultSigningMaterial returns the signing key together with the default
// chain, read as one. Reading them separately can pair a fresh key with a
// stale chain when a reload or the demo reset lands in between, and nothing
// verifies a signature made from that pair.
func (w *Wallet) DefaultSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	group, ok := DefaultTrustListGroupForWallet(w)
	if !ok {
		if w == nil {
			return nil, nil, fmt.Errorf("wallet has no signing certificate chain")
		}
		w.mu.RLock()
		issuerKey := w.IssuerKey
		chain := append([]*x509.Certificate(nil), w.CertChain...)
		w.mu.RUnlock()
		if len(chain) == 0 {
			return nil, nil, fmt.Errorf("wallet has no signing certificate chain")
		}
		return issuerKey, chain, nil
	}
	return w.signingMaterialForProfile(group.Profile)
}

// issuerSubjectAltNames are the subject alternative names a signing leaf
// carries, so a verifier can see that this certificate speaks for this issuer
// identifier. Both the dNSName and the uniformResourceIdentifier form are
// written, since a verifier may check either.
//
// They are written for the verifiers that ask for them: SD-JWT VC required
// iss to be named by a SAN of the leaf up to draft-08, and one built against
// that rule refuses a leaf without them.
//
// A host that is an IP address goes into an iPAddress SAN instead.
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
