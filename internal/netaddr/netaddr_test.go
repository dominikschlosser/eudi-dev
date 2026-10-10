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

package netaddr

import "testing"

func TestIsLocal(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":             true,
		"LOCALHOST":             true,
		"localhost.":            true,
		"127.0.0.1":             true,
		"127.0.0.2":             true,
		"127.255.255.254":       true,
		"::1":                   true,
		"[::1]":                 true,
		"::ffff:127.0.0.1":      true,
		"host.docker.internal":  true,
		"Host.Docker.Internal":  true,
		"10.0.0.1":              false,
		"192.168.1.1":           false,
		"example.com":           false,
		"localhost.example.com": false,
		"":                      false,
	} {
		if got := IsLocal(host); got != want {
			t.Errorf("IsLocal(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestIsLoopbackLeavesOutTheDockerHost(t *testing.T) {
	if IsLoopback("host.docker.internal") {
		t.Error("host.docker.internal counts as loopback")
	}
	if !IsLoopback("127.0.0.2") {
		t.Error("127.0.0.2 does not count as loopback")
	}
}
