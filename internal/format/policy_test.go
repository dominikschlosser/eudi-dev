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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBlockPrivateAddresses(t *testing.T) {
	tests := []struct {
		address string
		blocked bool
	}{
		{"127.0.0.1:80", true},
		{"[::1]:443", true},
		{"10.0.0.1:8080", true},
		{"172.16.0.1:80", true},
		{"192.168.1.1:80", true},
		{"169.254.169.254:80", true}, // cloud metadata
		{"[fe80::1]:80", true},
		{"[::ffff:10.0.0.1]:80", true}, // IPv4-mapped IPv6
		{"100.64.0.1:80", true},        // CGNAT
		{"[fc00::1]:80", true},         // unique-local
		{"0.0.0.0:80", true},
		{"1.1.1.1:443", false},
		{"93.184.216.34:443", false},
		{"[2606:4700:4700::1111]:443", false},
	}
	for _, tt := range tests {
		err := BlockPrivateAddresses("tcp", tt.address)
		if tt.blocked && err == nil {
			t.Errorf("BlockPrivateAddresses(%q) = nil, want error", tt.address)
		}
		if !tt.blocked && err != nil {
			t.Errorf("BlockPrivateAddresses(%q) = %v, want nil", tt.address, err)
		}
	}
}

func TestFetchPolicyBlocksLoopbackFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("payload"))
	}))
	defer srv.Close()

	SetFetchPolicy(BlockPrivateAddresses)
	t.Cleanup(func() { SetFetchPolicy(nil) })

	if _, err := FetchURL(srv.URL); err == nil {
		t.Fatal("FetchURL to loopback succeeded despite BlockPrivateAddresses policy")
	} else if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("unexpected error: %v", err)
	}

	SetFetchPolicy(nil)
	got, err := FetchURL(srv.URL)
	if err != nil {
		t.Fatalf("FetchURL without policy: %v", err)
	}
	if got != "payload" {
		t.Fatalf("FetchURL = %q, want %q", got, "payload")
	}
}

func TestReadRemoteInputNeverReadsFiles(t *testing.T) {
	got, err := ReadRemoteInput("/etc/hosts")
	if err != nil {
		t.Fatalf("ReadRemoteInput: %v", err)
	}
	if got != "/etc/hosts" {
		t.Fatalf("ReadRemoteInput(/etc/hosts) = %q, want the literal input back", got)
	}

	got, err = ReadRemoteInput("file:///etc/hosts")
	if err != nil {
		t.Fatalf("ReadRemoteInput: %v", err)
	}
	if got != "file:///etc/hosts" {
		t.Fatalf("ReadRemoteInput(file URL) = %q, want the literal input back", got)
	}
}

func TestReadRemoteInputFetchesHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("remote"))
	}))
	defer srv.Close()

	got, err := ReadRemoteInput(srv.URL)
	if err != nil {
		t.Fatalf("ReadRemoteInput: %v", err)
	}
	if got != "remote" {
		t.Fatalf("ReadRemoteInput = %q, want %q", got, "remote")
	}
}

func TestFetchURLSizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, maxFetchBytes+1))
	}))
	defer srv.Close()

	if _, err := FetchURL(srv.URL); err == nil {
		t.Fatal("FetchURL accepted an oversized response")
	}
}

// The wallet has to be able to reach its own demo issuer and verifier: their
// request_uri and response_uri sit on its own origin, which on a local demo
// instance resolves to loopback and would otherwise be refused. Everything
// else internal stays blocked.
func TestAllowOwnOrigins(t *testing.T) {
	policy := AllowOwnOrigins(BlockPrivateAddresses, "http://localhost:18951", "https://localhost:18952")

	allowed := []string{"127.0.0.1:18951", "127.0.0.1:18952"}
	for _, addr := range allowed {
		if err := policy("tcp4", addr); err != nil {
			t.Errorf("policy(%q) = %v, want the wallet's own origin to be allowed", addr, err)
		}
	}

	// A different port on the same loopback host is somebody else's service.
	blocked := []string{"127.0.0.1:18999", "10.0.0.5:80", "169.254.169.254:80", "192.168.1.10:443"}
	for _, addr := range blocked {
		if err := policy("tcp4", addr); err == nil {
			t.Errorf("policy(%q) = nil, want it blocked", addr)
		}
	}
}

// Without any resolvable origin the wrapper must not weaken the policy.
func TestAllowOwnOriginsKeepsBlockingWhenEmpty(t *testing.T) {
	for _, urls := range [][]string{nil, {""}, {"not a url"}, {"ftp://example.test"}} {
		policy := AllowOwnOrigins(BlockPrivateAddresses, urls...)
		if err := policy("tcp4", "127.0.0.1:8085"); err == nil {
			t.Errorf("AllowOwnOrigins(%v) stopped blocking loopback", urls)
		}
	}
}
