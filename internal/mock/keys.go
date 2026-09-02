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
	"crypto/sha1" //nolint:gosec // ISO/IEC 18013-5 Annex B mandates SHA-1 for the subject key identifier, a name, not a security primitive
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

// DefaultCertificateCountry is the subject countryName generated certificates
// carry when the credential being signed does not name an issuing country. It
// matches the issuing_country of the default PID claim sets, because ISO/IEC
// 18013-5 Table B.3 requires the document signer certificate's countryName to
// equal the credential's issuing_country element.
const DefaultCertificateCountry = "NL"

// issuerContactURI is where the operator of a generated CA can be reached.
// ISO/IEC 18013-5 Annex B requires an issuer alternative name extension with
// issuer contact information on IACA and document signer certificates.
const issuerContactURI = "https://github.com/dominikschlosser/eudi-dev"

var (
	oidExtensionIssuerAltName    = asn1.ObjectIdentifier{2, 5, 29, 18}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	// mdlDS, the document signing key purpose of ISO/IEC 18013-5 Annex B.
	oidMdlDocumentSigner = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}
)

// randomSerialNumber returns a positive certificate serial of at most 20
// octets (RFC 5280 §4.1.2.2, mirrored by ISO/IEC 18013-5 Annex B).
func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating certificate serial: %w", err)
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

// issuerAltNameExtension builds the issuer alternative name extension with the
// issuer contact URI, non-critical as ISO/IEC 18013-5 Annex B requires.
func issuerAltNameExtension() (pkix.Extension, error) {
	generalNames, err := asn1.Marshal([]asn1.RawValue{{
		Class: asn1.ClassContextSpecific,
		Tag:   6, // uniformResourceIdentifier
		Bytes: []byte(issuerContactURI),
	}})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding issuer alternative name: %w", err)
	}
	return pkix.Extension{Id: oidExtensionIssuerAltName, Value: generalNames}, nil
}

// subjectKeyIdentifier computes the SHA-1 hash of the subject public key BIT
// STRING value, the derivation every ISO/IEC 18013-5 Annex B profile requires.
func subjectKeyIdentifier(pub *ecdsa.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encoding subject public key: %w", err)
	}
	var wrapper struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &wrapper); err != nil {
		return nil, fmt.Errorf("parsing subject public key info: %w", err)
	}
	sum := sha1.Sum(wrapper.PublicKey.Bytes) //nolint:gosec // the RFC 5280 §4.2.1.2 method 1 key identifier every Annex B profile requires
	return sum[:], nil
}

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

// GenerateCACert creates a self-signed CA certificate for the given key. It
// follows the IACA root certificate profile of ISO/IEC 18013-5 Table B.1:
// subject countryName, keyCertSign and cRLSign only, critical basicConstraints
// with a pathLenConstraint of 0, a SHA-1 subject key identifier, and an issuer
// alternative name with issuer contact information.
func GenerateCACert(caKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	issuerAltName, err := issuerAltNameExtension()
	if err != nil {
		return nil, err
	}
	// Explicit, because the identifier Go would generate on its own follows
	// RFC 7093 (truncated SHA-256) while Annex B requires the RFC 5280
	// method 1 SHA-1 derivation.
	subjectKeyID, err := subjectKeyIdentifier(&caKey.PublicKey)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		SubjectKeyId: subjectKeyID,
		Subject: pkix.Name{
			CommonName: "OID4VC Dev Wallet CA",
			Country:    []string{DefaultCertificateCountry},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		ExtraExtensions:       []pkix.Extension{issuerAltName},
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
	// Country becomes the subject countryName. ISO/IEC 18013-5 Table B.3
	// requires it to equal the signed credential's issuing_country element,
	// so pass that value when the claims carry one. Empty uses
	// DefaultCertificateCountry.
	Country string
	// CRLDistributionPoints name where revocation information for this
	// certificate is published. Table B.3 requires at least one URI.
	CRLDistributionPoints []string
	// DNSNames, URIs and IPAddresses become the subject alternative names.
	// A verifier resolving an issuer key from the x5c header checks the
	// credential's iss against them (HAIP 1.0), so a signing leaf without
	// them signs credentials that verifier refuses.
	DNSNames    []string
	URIs        []*url.URL
	IPAddresses []net.IP
}

// GenerateLeafCertWithOptions creates a leaf certificate signed by the CA. It
// follows the document signer certificate profile of ISO/IEC 18013-5 Table
// B.3: subject countryName, digitalSignature only, a critical extended key
// usage with the mdlDS document signing purpose, a SHA-1 subject key
// identifier, CRL distribution points, an issuer alternative name with issuer
// contact information, and no basicConstraints (an end-entity certificate).
func GenerateLeafCertWithOptions(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, leafPubKey *ecdsa.PublicKey, opts LeafCertOptions) (*x509.Certificate, error) {
	commonName := opts.CommonName
	if commonName == "" {
		commonName = "OID4VC Dev Wallet Issuer"
	}
	country := opts.Country
	if country == "" {
		country = DefaultCertificateCountry
	}
	serialNumber := opts.SerialNumber
	if serialNumber == nil || serialNumber.Sign() <= 0 {
		var err error
		serialNumber, err = randomSerialNumber()
		if err != nil {
			return nil, err
		}
	}
	subjectKeyID, err := subjectKeyIdentifier(leafPubKey)
	if err != nil {
		return nil, err
	}
	extendedKeyUsage, err := asn1.Marshal([]asn1.ObjectIdentifier{oidMdlDocumentSigner})
	if err != nil {
		return nil, fmt.Errorf("encoding extended key usage: %w", err)
	}
	issuerAltName, err := issuerAltNameExtension()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
			Country:    []string{country},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          subjectKeyID,
		CRLDistributionPoints: opts.CRLDistributionPoints,
		DNSNames:              opts.DNSNames,
		URIs:                  opts.URIs,
		IPAddresses:           opts.IPAddresses,
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtensionExtendedKeyUsage, Critical: true, Value: extendedKeyUsage},
			issuerAltName,
		},
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
