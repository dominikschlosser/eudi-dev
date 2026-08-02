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
	if w == nil || w.IssuerKey == nil || w.CAKey == nil || len(w.CertChain) < 2 {
		return nil, fmt.Errorf("wallet has no issuer certificate chain")
	}
	caCert := w.CertChain[len(w.CertChain)-1]
	leafCert, err := mock.GenerateLeafCertWithOptions(w.CAKey, caCert, &w.IssuerKey.PublicKey, mock.LeafCertOptions{
		CommonName:   signingLeafCommonName(profile),
		SerialNumber: signingLeafSerial(profile),
	})
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
