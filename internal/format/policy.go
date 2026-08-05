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

package format

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
)

// FetchPolicy decides whether an outbound connection is allowed. It receives
// the network ("tcp4"/"tcp6") and the resolved "ip:port" address, so DNS
// tricks (rebinding, redirects to internal names) cannot bypass it.
type FetchPolicy func(network, address string) error

var fetchPolicy atomic.Value // holds FetchPolicy

// SetFetchPolicy installs a policy applied to every outbound connection made
// by this package's HTTP clients. Pass nil to remove the policy.
func SetFetchPolicy(policy FetchPolicy) {
	fetchPolicy.Store(policy)
}

// dialControl is the net.Dialer.Control hook consulting the active policy.
// It runs per connection attempt with the already-resolved address.
func dialControl(network, address string, _ syscall.RawConn) error {
	policy, _ := fetchPolicy.Load().(FetchPolicy)
	if policy == nil {
		return nil
	}
	return policy(network, address)
}

// AllowOwnOrigins wraps a policy so the wallet can always reach its own
// advertised origins, whatever they resolve to.
//
// A wallet legitimately fetches from itself: a request_uri or a response_uri
// belonging to its own demo verifier, or a credential offer pointing at its
// own issuer. Those URLs are operator configuration, not visitor input, so
// exempting them is not an SSRF hole. While without the exemption a demo
// instance on localhost cannot complete its own flows, because every one of
// them resolves to loopback and is refused at dial time.
//
// The allowance is by exact resolved address and port, so a visitor-supplied
// URL that merely happens to point at loopback is still blocked.
func AllowOwnOrigins(next FetchPolicy, urls ...string) FetchPolicy {
	allowed := make(map[string]bool)
	for _, raw := range urls {
		for _, addr := range resolveOriginAddresses(raw) {
			allowed[addr] = true
		}
	}
	if len(allowed) == 0 {
		return next
	}
	return func(network, address string) error {
		if allowed[address] {
			return nil
		}
		if next == nil {
			return nil
		}
		return next(network, address)
	}
}

// resolveOriginAddresses expands a URL into the "ip:port" strings a dial to
// it can produce.
func resolveOriginAddresses(raw string) []string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return nil
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return nil
		}
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, netip.AddrPortFrom(addr.Unmap(), portNumber(port)).String())
		}
	}
	return out
}

func portNumber(port string) uint16 {
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

var extraBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("fc00::/7"),      // IPv6 unique-local
}

// BlockPrivateAddresses is a FetchPolicy that rejects connections to
// loopback, private (RFC 1918), link-local (including cloud metadata
// endpoints), CGNAT, unique-local, unspecified and multicast addresses.
// Install it when visitor-supplied URLs are fetched from a host that can
// reach internal networks.
func BlockPrivateAddresses(network, address string) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("blocked connection to unparseable address %q", address)
	}
	addr := addrPort.Addr().Unmap()
	blocked := addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified() || addr.IsMulticast()
	for _, prefix := range extraBlockedPrefixes {
		blocked = blocked || prefix.Contains(addr)
	}
	if blocked {
		return fmt.Errorf("connections to internal address %s are not allowed", addr)
	}
	return nil
}
