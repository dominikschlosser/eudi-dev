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

package remote

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"
)

func withTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := configBaseDir
	configBaseDir = func() string { return dir }
	t.Cleanup(func() { configBaseDir = prev })
	return dir
}

func TestActiveRemoteRoundTrip(t *testing.T) {
	withTempConfigDir(t)

	if Active() != "" {
		t.Fatalf("expected no active remote, got %q", Active())
	}

	normalized, err := SetActive("localhost:9099/")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "http://localhost:9099" {
		t.Errorf("unexpected normalization: %q", normalized)
	}
	if Active() != "http://localhost:9099" {
		t.Errorf("active mismatch: %q", Active())
	}

	if err := ClearActive(); err != nil {
		t.Fatal(err)
	}
	if Active() != "" {
		t.Errorf("expected cleared remote, got %q", Active())
	}
	if err := ClearActive(); err != nil {
		t.Errorf("clearing twice must not fail: %v", err)
	}
}

func TestNormalizeURLRejectsInvalid(t *testing.T) {
	for _, raw := range []string{"", "ftp://host", "http://"} {
		if _, err := NormalizeURL(raw); err == nil {
			t.Errorf("expected error for %q", raw)
		}
	}
}

func TestClientErrorsCarryServerMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "nope"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.Credentials()
	if err == nil || !contains(err.Error(), "nope") {
		t.Errorf("expected server error message, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestDiscoverRegistryAndPrune(t *testing.T) {
	withTempConfigDir(t)

	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/version" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"build_id": "test-build", "pid": 4242}`))
	}))
	defer live.Close()

	liveURL, _ := url.Parse(live.URL)
	livePort, _ := strconv.Atoi(liveURL.Port())

	if err := RegisterInstance(Instance{PID: 4242, Port: livePort, URL: live.URL, WalletDir: "/tmp/w", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterInstance(Instance{PID: 9999, Port: 1, URL: "http://localhost:1", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	found := Discover(500 * time.Millisecond)
	var registryHits []DiscoveredInstance
	for _, di := range found {
		if di.Source == "registry" {
			registryHits = append(registryHits, di)
		}
	}
	if len(registryHits) != 1 {
		t.Fatalf("expected exactly the live registry instance, got %v", found)
	}
	if registryHits[0].PID != 4242 || registryHits[0].BuildID != "test-build" || registryHits[0].WalletDir != "/tmp/w" {
		t.Errorf("unexpected instance: %+v", registryHits[0])
	}

	// The dead instance's registry file is pruned.
	if _, err := os.Stat(instanceFile(9999)); !os.IsNotExist(err) {
		t.Error("stale instance file not pruned")
	}
	if _, err := os.Stat(instanceFile(4242)); err != nil {
		t.Error("live instance file must remain")
	}

	UnregisterInstance(4242)
	if _, err := os.Stat(instanceFile(4242)); !os.IsNotExist(err) {
		t.Error("unregister did not remove the instance file")
	}
}

func TestDiscoverDedupesStaleRegistryFilesOnSamePort(t *testing.T) {
	withTempConfigDir(t)

	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/version" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"build_id": "b", "pid": 5555}`))
	}))
	defer live.Close()
	liveURL, _ := url.Parse(live.URL)
	port, _ := strconv.Atoi(liveURL.Port())

	// A stale file from a dead server that used the same port, plus the
	// current server's file. Both pass the health check because the current
	// server answers on the port.
	if err := RegisterInstance(Instance{PID: 1111, Port: port, URL: live.URL, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterInstance(Instance{PID: 5555, Port: port, URL: live.URL, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	found := Discover(500 * time.Millisecond)
	count := 0
	for _, di := range found {
		if di.Port == port {
			count++
			if di.PID != 5555 {
				t.Errorf("expected live pid 5555, got %d", di.PID)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one instance for the port, got %d (%v)", count, found)
	}
	if _, err := os.Stat(instanceFile(1111)); !os.IsNotExist(err) {
		t.Error("stale registry file for the dead pid not pruned")
	}
	if _, err := os.Stat(instanceFile(5555)); err != nil {
		t.Error("live instance file must remain")
	}
}
