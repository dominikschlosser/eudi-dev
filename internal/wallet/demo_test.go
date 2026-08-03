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
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

func newDemoTestServer(t *testing.T) *Server {
	t.Helper()
	srv := newTestServer(t, true)
	srv.wallet.TemplatesDir = t.TempDir()
	srv.SetDemo(DemoOptions{ResetInterval: time.Hour})
	return srv
}

func TestDemoBlocksAdminEndpoints(t *testing.T) {
	srv := newDemoTestServer(t)
	blocked := []struct {
		method, path, body string
	}{
		{"POST", "/api/shutdown", ""},
		{"PUT", "/api/templates/x", `{"format":"sdjwt"}`},
		{"DELETE", "/api/templates/x", ""},
		{"POST", "/api/next-error", `{"error":"access_denied"}`},
		{"DELETE", "/api/next-error", ""},
		{"PUT", "/api/config/preferred-format", `{"preferred_format":"dc+sd-jwt"}`},
	}
	for _, tt := range blocked {
		w := serverRequest(t, srv, tt.method, tt.path, tt.body)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", tt.method, tt.path, w.Code)
		}
	}
}

func TestDemoAllowsVisitorFlows(t *testing.T) {
	srv := newDemoTestServer(t)

	if w := serverRequest(t, srv, "GET", "/api/credentials", ""); w.Code != http.StatusOK {
		t.Fatalf("GET /api/credentials = %d, want 200", w.Code)
	}
	if w := serverRequest(t, srv, "POST", "/api/issue", `{"format":"sdjwt"}`); w.Code != http.StatusCreated {
		t.Fatalf("POST /api/issue = %d, want 201: %s", w.Code, w.Body.String())
	}
	if w := serverRequest(t, srv, "GET", "/api/templates", ""); w.Code != http.StatusOK {
		t.Fatalf("GET /api/templates = %d, want 200 (reads stay allowed)", w.Code)
	}
	if w := serverRequest(t, srv, "DELETE", "/api/credentials", ""); w.Code != http.StatusOK {
		t.Fatalf("DELETE /api/credentials = %d, want 200 (visitor deletes allowed)", w.Code)
	}
}

func TestDemoRejectsSaveAsTemplate(t *testing.T) {
	srv := newDemoTestServer(t)
	w := serverRequest(t, srv, "POST", "/api/issue", `{"format":"sdjwt","save_as_template":"sneaky"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST /api/issue with save_as_template = %d, want 403", w.Code)
	}
}

func TestDemoConfigRedaction(t *testing.T) {
	srv := newDemoTestServer(t)
	config := decodeJSON(t, serverRequest(t, srv, "GET", "/api/config", ""))
	for _, key := range []string{"wallet_dir", "templates_dir", "pid"} {
		if _, ok := config[key]; ok {
			t.Errorf("/api/config leaks %q in demo mode", key)
		}
	}
	demo, ok := config["demo"].(map[string]any)
	if !ok {
		t.Fatalf("/api/config missing demo object: %v", config)
	}
	if demo["reset_interval_seconds"] != float64(3600) {
		t.Errorf("reset_interval_seconds = %v, want 3600", demo["reset_interval_seconds"])
	}

	version := decodeJSON(t, serverRequest(t, srv, "GET", "/api/version", ""))
	if _, ok := version["pid"]; ok {
		t.Error("/api/version leaks pid in demo mode")
	}
}

func TestNonDemoConfigKeepsPaths(t *testing.T) {
	srv := newTestServer(t, true)
	config := decodeJSON(t, serverRequest(t, srv, "GET", "/api/config", ""))
	if _, ok := config["pid"]; !ok {
		t.Error("/api/config missing pid outside demo mode")
	}
	if _, ok := config["demo"]; ok {
		t.Error("/api/config has demo object outside demo mode")
	}
}

func TestDemoLogCapped(t *testing.T) {
	srv := newDemoTestServer(t)
	for i := 0; i < demoLogLimit+10; i++ {
		srv.wallet.AddLog("management", fmt.Sprintf("entry %d", i), true)
	}
	rec := serverRequest(t, srv, "GET", "/api/log", "")
	var log []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &log); err != nil {
		t.Fatalf("parsing log: %v", err)
	}
	if len(log) != demoLogLimit {
		t.Fatalf("demo log length = %d, want %d", len(log), demoLogLimit)
	}
	if detail := log[len(log)-1]["detail"]; detail != fmt.Sprintf("entry %d", demoLogLimit+9) {
		t.Errorf("last entry = %v, want the newest", detail)
	}
}

func TestConfigReportsTLSListener(t *testing.T) {
	srv := newTestServer(t, true)
	srv.SetIssuerListenPort(9999)
	config := decodeJSON(t, serverRequest(t, srv, "GET", "/api/config", ""))
	if config["tls_listener"] != true {
		t.Errorf("tls_listener = %v, want true with the built-in HTTPS listener", config["tls_listener"])
	}

	srv.SetIssuerListenPort(-1)
	config = decodeJSON(t, serverRequest(t, srv, "GET", "/api/config", ""))
	if config["tls_listener"] != false {
		t.Errorf("tls_listener = %v, want false when the issuer is served by the base URL", config["tls_listener"])
	}
}

func TestDemoReset(t *testing.T) {
	srv := newDemoTestServer(t)
	store := NewWalletStore(t.TempDir())
	srv.SetStore(store)

	if w := serverRequest(t, srv, "POST", "/api/issue", `{"format":"sdjwt","vct":"urn:example:extra"}`); w.Code != http.StatusCreated {
		t.Fatalf("seeding credential: %d %s", w.Code, w.Body.String())
	}
	before := len(srv.wallet.GetCredentials())

	if err := srv.demoReset(); err != nil {
		t.Fatalf("demoReset: %v", err)
	}

	creds := srv.wallet.GetCredentials()
	if len(creds) != 2 {
		t.Fatalf("after reset: %d credentials (before %d), want the 2 default PIDs", len(creds), before)
	}
	for _, c := range creds {
		if c.VCT == "urn:example:extra" {
			t.Fatal("visitor credential survived the reset")
		}
	}
	if len(srv.wallet.GetLog()) != 0 {
		t.Fatalf("activity log not cleared: %d entries", len(srv.wallet.GetLog()))
	}

	// The reset state is persisted: a reload keeps the baseline.
	if err := srv.reloadFromStore(); err != nil {
		t.Fatalf("reload after reset: %v", err)
	}
	if got := len(srv.wallet.GetCredentials()); got != 2 {
		t.Fatalf("after reload: %d credentials, want 2", got)
	}
}

func TestDemoResetConcurrentWithRequests(t *testing.T) {
	srv := newDemoTestServer(t)
	store := NewWalletStore(t.TempDir())
	srv.SetStore(store)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				serverRequest(t, srv, "POST", "/api/issue", fmt.Sprintf(`{"format":"sdjwt","vct":"urn:example:%d-%d"}`, i, j))
				serverRequest(t, srv, "GET", "/api/credentials", "")
			}
		}(i)
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.demoReset(); err != nil {
				t.Errorf("demoReset: %v", err)
			}
		}()
	}
	wg.Wait()
}
