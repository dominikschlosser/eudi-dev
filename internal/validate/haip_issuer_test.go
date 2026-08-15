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
	"crypto/x509"
	"net"
	"net/url"
	"strings"
	"testing"
)

func leafWithNames(t *testing.T, dnsNames []string, uris []string, ips []string) []*x509.Certificate {
	t.Helper()
	leaf := &x509.Certificate{DNSNames: dnsNames}
	for _, raw := range uris {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parsing %q: %v", raw, err)
		}
		leaf.URIs = append(leaf.URIs, parsed)
	}
	for _, raw := range ips {
		leaf.IPAddresses = append(leaf.IPAddresses, net.ParseIP(raw))
	}
	return []*x509.Certificate{leaf}
}

// HAIP 1.0 section 6.1.1: an issuer key taken from x5c is bound to the
// credential by the leaf's subject alternative names. Without the binding any
// certificate the chain accepts signs for any issuer.
func TestHAIPIssuerBinding(t *testing.T) {
	tests := []struct {
		name  string
		iss   string
		chain []*x509.Certificate
		want  bool // want a violation
	}{
		{
			name:  "dNSName matches the issuer host",
			iss:   "https://eudi-test.dev",
			chain: leafWithNames(t, []string{"eudi-test.dev"}, nil, nil),
		},
		{
			name:  "dNSName matching is case insensitive",
			iss:   "https://EUDI-Test.dev",
			chain: leafWithNames(t, []string{"eudi-test.dev"}, nil, nil),
		},
		{
			name:  "uniformResourceIdentifier matches the issuer",
			iss:   "https://eudi-test.dev",
			chain: leafWithNames(t, nil, []string{"https://eudi-test.dev"}, nil),
		},
		{
			// An issuer identifier that is not an https URL takes the URI
			// comparison, which is the branch the profile spells out for it.
			name:  "a non-URL issuer matches a URI entry",
			iss:   "urn:example:issuer:1",
			chain: leafWithNames(t, []string{"eudi-test.dev"}, []string{"urn:example:issuer:1"}, nil),
		},
		{
			name:  "an address issuer matches an iPAddress entry",
			iss:   "https://159.195.213.172",
			chain: leafWithNames(t, nil, nil, []string{"159.195.213.172"}),
		},
		{
			// What the Animo playground refused: a leaf that names nobody.
			name:  "no subject alternative name at all",
			iss:   "https://eudi-test.dev",
			chain: leafWithNames(t, nil, nil, nil),
			want:  true,
		},
		{
			name:  "the certificate names a different issuer",
			iss:   "https://eudi-test.dev",
			chain: leafWithNames(t, []string{"issuer.example"}, []string{"https://issuer.example"}, nil),
			want:  true,
		},
		{
			// A host is not a suffix match: sub.eudi-test.dev is another host.
			name:  "a subdomain does not stand in for the issuer",
			iss:   "https://eudi-test.dev",
			chain: leafWithNames(t, []string{"sub.eudi-test.dev"}, nil, nil),
			want:  true,
		},
		{
			name:  "an x5c chain with no iss to bind",
			iss:   "",
			chain: leafWithNames(t, []string{"eudi-test.dev"}, nil, nil),
			want:  true,
		},
		{
			// Nothing to check without a certificate: the issuer key then
			// comes from metadata, which binds iss by where it was fetched.
			name:  "no certificate chain",
			iss:   "https://eudi-test.dev",
			chain: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HAIPIssuerBinding(tt.iss, tt.chain)
			if tt.want && len(got) == 0 {
				t.Error("expected a violation, got none")
			}
			if !tt.want && len(got) > 0 {
				t.Errorf("expected no violation, got %v", got)
			}
			for _, v := range got {
				if !strings.HasPrefix(v, "HAIP: ") {
					t.Errorf("violation %q does not name the profile it comes from", v)
				}
			}
		})
	}
}
