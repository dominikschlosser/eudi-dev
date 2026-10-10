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

// Package netaddr decides which hosts are local to the machine that runs
// eudi-dev.
package netaddr

import (
	"net/netip"
	"strings"
)

// DockerHost is the name a Docker container uses for the machine it runs on.
const DockerHost = "host.docker.internal"

// IsLoopback reports whether host is the name localhost or an address in
// 127.0.0.0/8 or ::1. Host names compare case insensitively (RFC 4343) and may
// end with the root dot. An IPv6 address may be bracketed.
func IsLoopback(host string) bool {
	host = normalize(host)
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && addr.Unmap().IsLoopback()
}

// IsLocal reports whether host is a loopback host or DockerHost. Both reach
// the machine itself, so local development uses them for wallet, issuer and
// verifier.
func IsLocal(host string) bool {
	return IsLoopback(host) || normalize(host) == DockerHost
}

func normalize(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
