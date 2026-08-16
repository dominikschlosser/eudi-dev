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
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// HAIPIssuerBinding checks that a credential names its issuer in the
// certificate it is verified with. HAIP 1.0 §6.1.1: "the iss value MUST be an
// URL with a FQDN matching a dNSName Subject Alternative Name (SAN) entry in
// the leaf certificate", or match a uniformResourceIdentifier SAN. Without it
// any certificate the chain accepts could sign for any issuer.
//
// Only credentials carrying x5c are checked: a key found through issuer
// metadata is bound to iss by where that document was fetched from.
func HAIPIssuerBinding(iss string, chain []*x509.Certificate) []string {
	if len(chain) == 0 || chain[0] == nil {
		return nil
	}
	iss = strings.TrimSpace(iss)
	if iss == "" {
		return []string{"HAIP: the credential carries an x5c chain but no iss to bind it to"}
	}
	leaf := chain[0]

	if host := issuerFQDN(iss); host != "" {
		for _, name := range leaf.DNSNames {
			if strings.EqualFold(strings.TrimSpace(name), host) {
				return nil
			}
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			for _, ip := range leaf.IPAddresses {
				if other, ok := netip.AddrFromSlice(ip); ok && other.Unmap() == addr.Unmap() {
					return nil
				}
			}
		}
	}
	for _, uri := range leaf.URIs {
		if uri != nil && uri.String() == iss {
			return nil
		}
	}

	return []string{fmt.Sprintf(
		"HAIP: iss %q is named by no subject alternative name of the signing certificate (dNSName %v, uniformResourceIdentifier %v)",
		iss, leaf.DNSNames, leaf.URIs)}
}

// issuerFQDN is the host of an https issuer identifier, and empty for an iss
// that is not one (a URN, a DID, a DNS URI). Those take the URI comparison.
func issuerFQDN(iss string) string {
	parsed, err := url.Parse(iss)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return ""
	}
	return parsed.Hostname()
}
