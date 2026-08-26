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

package validate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// A self-signed leaf is what HAIP §6.1.1 forbids for the credential's signer,
// and it is the case an earlier check missed: CheckSignatureFrom rejects a
// non-CA certificate on CA constraints before it verifies the signature.
func TestSelfSignedCertificate(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("generating CA: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	caSignedLeaf, err := mock.GenerateLeafCert(caKey, caCert, &leafKey.PublicKey)
	if err != nil {
		t.Fatalf("generating CA-signed leaf: %v", err)
	}

	// A self-signed end-entity certificate: its own issuer, IsCA false.
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "self-signed leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &leafKey.PublicKey, leafKey)
	if err != nil {
		t.Fatalf("generating self-signed leaf: %v", err)
	}
	selfSignedLeaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing self-signed leaf: %v", err)
	}

	for _, tc := range []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{"self-signed CA", caCert, true},
		{"self-signed leaf", selfSignedLeaf, true},
		{"CA-signed leaf", caSignedLeaf, false},
		{"nil", nil, false},
	} {
		if got := SelfSignedCertificate(tc.cert); got != tc.want {
			t.Errorf("SelfSignedCertificate(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
