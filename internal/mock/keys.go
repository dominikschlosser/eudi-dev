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

package mock

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

// GenerateKey creates an ephemeral P-256 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PublicKeyJWKMap returns the JWK representation of a P-256 public key as a map.
func PublicKeyJWKMap(key *ecdsa.PublicKey) map[string]string {
	xBytes, yBytes, err := format.ECPublicCoords(key)
	if err != nil {
		return nil
	}
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   format.EncodeBase64URL(xBytes),
		"y":   format.EncodeBase64URL(yBytes),
	}
}

// KeyIDForPublicKey computes the RFC 7638 JWK thumbprint for a P-256 public key.
func KeyIDForPublicKey(key *ecdsa.PublicKey) string {
	jwk := PublicKeyJWKMap(key)
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`,
		jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	sum := sha256.Sum256([]byte(canonical))
	return format.EncodeBase64URL(sum[:])
}

// SigningJWKMap returns a public JWK suitable for issuer metadata/JWKS publishing.
func SigningJWKMap(key *ecdsa.PublicKey) map[string]any {
	jwk := PublicKeyJWKMap(key)
	return map[string]any{
		"kty": jwk["kty"],
		"crv": jwk["crv"],
		"x":   jwk["x"],
		"y":   jwk["y"],
		"kid": KeyIDForPublicKey(key),
		"use": "sig",
		"alg": "ES256",
	}
}

// PublicKeyJWK returns the JSON JWK representation of a P-256 public key.
func PublicKeyJWK(key *ecdsa.PublicKey) string {
	xBytes, yBytes, err := format.ECPublicCoords(key)
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err)
	}
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   format.EncodeBase64URL(xBytes),
		"y":   format.EncodeBase64URL(yBytes),
	}

	b, _ := json.MarshalIndent(jwk, "", "  ")
	return string(b)
}

// GenerateCACert creates a self-signed CA certificate for the given key.
func GenerateCACert(caKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OID4VC Dev Wallet CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	return x509.ParseCertificate(der)
}

// GenerateLeafCert creates a leaf certificate signed by the CA.
func GenerateLeafCert(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, leafPubKey *ecdsa.PublicKey) (*x509.Certificate, error) {
	return GenerateLeafCertWithOptions(caKey, caCert, leafPubKey, LeafCertOptions{})
}

// LeafCertOptions customizes the generated leaf certificate.
type LeafCertOptions struct {
	CommonName   string
	SerialNumber *big.Int
	// DNSNames, URIs and IPAddresses become the subject alternative names.
	// A verifier resolving an issuer key from the x5c header checks the
	// credential's iss against them (HAIP 1.0), so a signing leaf without
	// them signs credentials that verifier refuses.
	DNSNames    []string
	URIs        []*url.URL
	IPAddresses []net.IP
}

// GenerateLeafCertWithOptions creates a leaf certificate signed by the CA.
func GenerateLeafCertWithOptions(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, leafPubKey *ecdsa.PublicKey, opts LeafCertOptions) (*x509.Certificate, error) {
	commonName := opts.CommonName
	if commonName == "" {
		commonName = "OID4VC Dev Wallet Issuer"
	}
	serialNumber := opts.SerialNumber
	if serialNumber == nil || serialNumber.Sign() <= 0 {
		serialNumber = big.NewInt(2)
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              opts.DNSNames,
		URIs:                  opts.URIs,
		IPAddresses:           opts.IPAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, leafPubKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating leaf certificate: %w", err)
	}

	return x509.ParseCertificate(der)
}

// WithoutSelfSignedTrustAnchor removes a terminal self-signed root certificate from
// a certificate chain before publishing it in JOSE headers or JWK metadata.
func WithoutSelfSignedTrustAnchor(chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) == 0 {
		return nil
	}
	out := make([]*x509.Certificate, len(chain))
	copy(out, chain)
	last := out[len(out)-1]
	if bytes.Equal(last.RawSubject, last.RawIssuer) && last.CheckSignatureFrom(last) == nil {
		return out[:len(out)-1]
	}
	return out
}

// PrivateKeyJWK returns the JSON JWK representation of a P-256 private key (includes d).
func PrivateKeyJWK(key *ecdsa.PrivateKey) string {
	xBytes, yBytes, err := format.ECPublicCoords(&key.PublicKey)
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err)
	}
	dBytes, err := key.Bytes()
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err)
	}

	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   format.EncodeBase64URL(xBytes),
		"y":   format.EncodeBase64URL(yBytes),
		"d":   format.EncodeBase64URL(dBytes),
	}

	b, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err)
	}
	return string(b)
}
