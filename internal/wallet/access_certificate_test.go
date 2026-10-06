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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

func testAccessCSR(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// A verifier signs its request object with the key behind the CSR. The wallet
// accepts the issued certificate for the x509_hash client identifier.
func TestAnAccessCertificateFromACSRSignsARequest(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.IssueAccessCertificate(AccessCertificateRequest{
		Identifier: rp.Identifier[0].Identifier, CSR: testAccessCSR(t, key), DNSNames: []string{"shop.example"},
	})
	if err != nil {
		t.Fatalf("IssueAccessCertificate: %v", err)
	}
	block, _ := pem.Decode([]byte(result.Certificate))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	identifier, legalName, country := accessCertificateSubject(leaf)
	if identifier != rp.Identifier[0].Identifier || legalName != "Example Shop" || country != rp.Country || leaf.Subject.CommonName != "Example Shop" {
		t.Errorf("subject %v, want the registration's identifier, names and country", leaf.Subject)
	}
	if strings.Count(result.Chain, "BEGIN CERTIFICATE") != 2 {
		t.Errorf("chain holds %d certificates, want the leaf and the CA", strings.Count(result.Chain, "BEGIN CERTIFICATE"))
	}

	clientID := result.ClientIDs[0]
	header := map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": []any{base64.StdEncoding.EncodeToString(leaf.Raw)}}
	raw, err := jws.Sign(header, map[string]any{"client_id": clientID}, key)
	if err != nil {
		t.Fatal(err)
	}
	reqObj := &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: map[string]any{"client_id": clientID}}
	if finding := VerifyClientID(clientID, reqObj, "", ""); finding != "" {
		t.Errorf("x509_hash client_id: %s", finding)
	}
	if finding := VerifyClientID(result.ClientIDs[1], reqObj, "", ""); finding != "" {
		t.Errorf("x509_san_dns client_id: %s", finding)
	}
	if finding := VerifyRequestObjectSignature(clientID, reqObj); finding != "" {
		t.Errorf("request object signature: %s", finding)
	}
}

func TestAccessCertificateRequestsTheRegistrarRefuses(t *testing.T) {
	w := generateTestWallet(t)
	id := registerTestRelyingParty(t, w).Identifier[0].Identifier
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for _, tc := range []struct {
		name string
		req  AccessCertificateRequest
		want string
	}{
		{"unregistered", AccessCertificateRequest{Identifier: "LEIXG-1", CSR: testAccessCSR(t, key)}, "not registered"},
		{"no CSR", AccessCertificateRequest{Identifier: id}, "not a PEM certificate request"},
		{"P-384 key", AccessCertificateRequest{Identifier: id, CSR: testAccessCSR(t, p384Key)}, "not a P-256 key"},
		{"long validity", AccessCertificateRequest{Identifier: id, CSR: testAccessCSR(t, key), Validity: "9000h"}, "at most"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := w.IssueAccessCertificate(tc.req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAccessCertificateDNSNamesAreChecked(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"*.shop.example", "shop example", "-shop.example"} {
		if _, err := w.IssueAccessCertificate(AccessCertificateRequest{Identifier: rp.Identifier[0].Identifier, CSR: testAccessCSR(t, key), DNSNames: []string{name}}); err == nil || !strings.Contains(err.Error(), "not a DNS name") {
			t.Errorf("%q: error %v, want a DNS name error", name, err)
		}
	}
}

// The registrar signs anyone's CSR, so access certificates have a separate CA.
// No credential issuer chain leads to it.
func TestAccessCertificatesDoNotChainToTheWalletCA(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.IssueAccessCertificate(AccessCertificateRequest{Identifier: rp.Identifier[0].Identifier, CSR: testAccessCSR(t, key)})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(result.Certificate))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	walletCA := x509.NewCertPool()
	walletCA.AddCert(w.CertChain[len(w.CertChain)-1])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: walletCA, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		t.Error("an access certificate chains to the wallet CA, which anchors credential issuers")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: w.RelyingPartyCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("an access certificate does not verify to the relying party CAs: %v", err)
	}
}
