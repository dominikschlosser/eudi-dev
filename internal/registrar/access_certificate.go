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

package registrar

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// AccessCertificateRequest asks the wallet's access certificate authority for
// an access certificate of a registered relying party (ETSI TS 119 411-8). The
// relying party keeps its private key and sends only a PKCS#10 CSR. The
// certificate takes the public key from the CSR and the subject from the
// registration (TS 119 411-8 GEN-6.6.1-10).
type AccessCertificateRequest struct {
	Identifier        string `json:"identifier"`
	ServiceIdentifier string `json:"serviceIdentifier,omitempty"`
	// CSR is the PEM certificate signing request. Its subject may be empty.
	CSR string `json:"csr"`
	// DNSNames are extra subject alternative names, for a verifier that uses
	// the x509_san_dns client identifier prefix.
	DNSNames []string `json:"dnsNames,omitempty"`
	// Validity is a Go duration of at most one year.
	Validity string `json:"validity,omitempty"`
}

// AccessCertificateResult carries the issued certificate and the client
// identifiers that work with it (OpenID4VP 1.0 §5.9.3).
type AccessCertificateResult struct {
	// Certificate is the PEM leaf. A request object's x5c carries it without
	// the trust anchor (HAIP 1.0).
	Certificate string `json:"certificate"`
	// Chain is the PEM leaf followed by the issuing CA (ARF Reg_10b).
	Chain     string   `json:"chain"`
	ClientIDs []string `json:"clientIds"`
}

const maxAccessCertificateValidity = 365 * 24 * time.Hour

// x509_san_dns names one host, so a DNS name may not contain a wildcard
// (OpenID4VP 1.0 §5.9.3).
var dnsNamePattern = regexp.MustCompile(`^(?i:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.(?i:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?))*$`)

// ETSI EN 319 412-1 §5.1.4 with the identifier types of ETSI TS 119 475 §5.1.3.
var organizationIdentifierPattern = regexp.MustCompile(`^(LEI|NTR|VAT|EOR|EXC)[A-Z]{2}-[A-Za-z0-9.-]+$`)

// IssueAccessCertificate signs an access certificate for the public key of a
// CSR.
func (r *Registrar) IssueAccessCertificate(req AccessCertificateRequest) (*AccessCertificateResult, error) {
	rp, ok := r.RelyingParty(req.Identifier)
	if !ok {
		return nil, fmt.Errorf("%w: %s", errRelyingPartyNotFound, req.Identifier)
	}
	service, ok := findService(rp, req.ServiceIdentifier)
	if !ok {
		return nil, fmt.Errorf("%w: no service %q", errRelyingPartyNotFound, req.ServiceIdentifier)
	}
	publicKey, err := csrPublicKey(req.CSR)
	if err != nil {
		return nil, err
	}
	dnsNames := trimmedNonEmpty(req.DNSNames)
	if len(dnsNames) > maxRegistrationItems {
		return nil, fmt.Errorf("an access certificate may name at most %d DNS names", maxRegistrationItems)
	}
	for _, name := range dnsNames {
		if !dnsNamePattern.MatchString(name) {
			return nil, fmt.Errorf("%q is not a DNS name", name)
		}
	}
	validity := maxAccessCertificateValidity
	if strings.TrimSpace(req.Validity) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(req.Validity))
		if err != nil || parsed <= 0 || parsed > maxAccessCertificateValidity {
			return nil, fmt.Errorf("validity %q is not a Go duration of at most %s", req.Validity, maxAccessCertificateValidity)
		}
		validity = parsed
	}
	var uris []*url.URL
	if u, err := url.Parse(service.SupportURI); err == nil && u.Scheme != "" {
		uris = append(uris, u)
	}

	caKey, ca, err := r.env.RelyingPartyAccessCA()
	if err != nil {
		return nil, fmt.Errorf("%w: loading the relying party access CA: %w", errRegistrarSigning, err)
	}
	leaf, err := mock.GenerateLeafCertWithOptions(caKey, ca, publicKey, mock.LeafCertOptions{
		CommonName:             service.ServiceTradeName,
		Organization:           rp.LegalPerson.LegalName[0],
		OrganizationalUnit:     service.ServiceIdentifier,
		Country:                rp.Country,
		OrganizationIdentifier: rp.Identifier[0].Identifier,
		Role:                   mock.AccessCertificate,
		URIs:                   uris,
		DNSNames:               dnsNames,
		Validity:               validity,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: signing the access certificate: %w", errRegistrarSigning, err)
	}

	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	hash := sha256.Sum256(leaf.Raw)
	clientIDs := []string{"x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])}
	for _, dnsName := range leaf.DNSNames {
		clientIDs = append(clientIDs, "x509_san_dns:"+dnsName)
	}
	return &AccessCertificateResult{
		Certificate: certificate,
		Chain:       certificate + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
		ClientIDs:   clientIDs,
	}, nil
}

// csrPublicKey returns the P-256 key of a CSR after checking that its signature
// proves possession of the private key. HAIP 1.0 requires ES256 for request
// objects.
func csrPublicKey(pemData string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemData)))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("the CSR is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the CSR signature does not verify: %w", err)
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("the CSR key is not a P-256 key")
	}
	return key, nil
}

func trimmedNonEmpty(values []string) []string {
	var out []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
