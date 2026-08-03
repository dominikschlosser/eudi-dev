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
	"net/netip"
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
