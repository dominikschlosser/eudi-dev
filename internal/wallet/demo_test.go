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
	"strings"
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

func TestStartDemoResetUsesDailySchedule(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatalf("loading zone: %v", err)
	}
	srv := newTestServer(t, true)
	srv.SetDemo(DemoOptions{ResetDaily: &DailySchedule{Hour: 3, Minute: 30, Location: berlin}})
	srv.startDemoReset()
	defer srv.stopDemoReset()

	srv.demo.mu.Lock()
	next := srv.demo.nextReset
	srv.demo.mu.Unlock()

	// The next reset must be the upcoming 03:30 in Berlin, never an offset
	// from process start.
	local := next.In(berlin)
	if local.Hour() != 3 || local.Minute() != 30 {
		t.Fatalf("next reset is %s, want the next 03:30 Berlin time", local)
	}
	if !next.After(time.Now()) || next.After(time.Now().Add(25*time.Hour)) {
		t.Fatalf("next reset %s is not within the coming day", next)
	}

	// The schedule is also what /api/config advertises.
	cfg := decodeJSON(t, serverRequest(t, srv, "GET", "/api/config", ""))
	demo := cfg["demo"].(map[string]any)
	if got, ok := demo["reset_daily_at"].(string); !ok || !strings.HasPrefix(got, "03:30 ") {
		t.Fatalf("reset_daily_at = %v, want 03:30 with a zone", demo["reset_daily_at"])
	}
	if demo["reset_interval_seconds"] != float64(0) {
		t.Errorf("interval should be reported as 0 for a daily schedule, got %v", demo["reset_interval_seconds"])
	}
}

// TestProtectedCredentials pins the baseline guarantee of a shared
// deployment: visitors can do anything except remove or revoke the
// credentials the wallet was seeded with.
func TestProtectedCredentials(t *testing.T) {
	srv := newDemoTestServer(t)
	srv.SetStore(NewWalletStore(t.TempDir()))
	// Requests reload the store, so mutations have to be persisted the way
	// the serve command wires it up.
	srv.onSave = func() {
		if err := srv.store.Save(srv.wallet); err != nil {
			t.Errorf("saving wallet: %v", err)
		}
	}
	srv.wallet.ClearCredentials()
	if err := srv.wallet.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("generating protected defaults: %v", err)
	}
	// Every request reloads the store, so the baseline has to be on disk.
	if err := srv.store.Save(srv.wallet); err != nil {
		t.Fatalf("saving baseline: %v", err)
	}
	baseline := srv.wallet.GetCredentials()
	if len(baseline) != 2 {
		t.Fatalf("expected 2 baseline credentials, got %d", len(baseline))
	}
	for _, c := range baseline {
		if !c.Protected {
			t.Fatalf("baseline credential %s is not protected", c.ID)
		}
	}
	protectedID := baseline[0].ID

	t.Run("delete is refused", func(t *testing.T) {
		if w := serverRequest(t, srv, "DELETE", "/api/credentials/"+protectedID, ""); w.Code != http.StatusForbidden {
			t.Fatalf("DELETE = %d, want 403", w.Code)
		}
		if _, ok := srv.wallet.GetCredential(protectedID); !ok {
			t.Fatal("protected credential disappeared")
		}
	})

	t.Run("revocation is refused", func(t *testing.T) {
		body := `{"status":1}`
		if w := serverRequest(t, srv, "POST", "/api/credentials/"+protectedID+"/status", body); w.Code != http.StatusForbidden {
			t.Fatalf("status change = %d, want 403", w.Code)
		}
		if entry, ok := srv.wallet.StatusEntryFor(protectedID); ok && entry.Status != 0 {
			t.Fatalf("status changed to %d despite protection", entry.Status)
		}
	})

	t.Run("newly issued credentials stay deletable", func(t *testing.T) {
		rec := serverRequest(t, srv, "POST", "/api/issue", `{"format":"sdjwt","pid":true}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("issue = %d: %s", rec.Code, rec.Body.String())
		}
		issued := decodeJSON(t, rec)
		if _, ok := issued["protected"]; ok {
			t.Fatal("a freshly issued credential must not be protected")
		}
		id := issued["id"].(string)
		if w := serverRequest(t, srv, "DELETE", "/api/credentials/"+id, ""); w.Code != http.StatusNoContent {
			t.Fatalf("DELETE issued = %d, want 204", w.Code)
		}
	})

	t.Run("delete all keeps the baseline", func(t *testing.T) {
		if w := serverRequest(t, srv, "POST", "/api/issue", `{"format":"sdjwt"}`); w.Code != http.StatusCreated {
			t.Fatalf("seeding: %d", w.Code)
		}
		rec := serverRequest(t, srv, "DELETE", "/api/credentials", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("DELETE all = %d", rec.Code)
		}
		result := decodeJSON(t, rec)
		if result["kept_protected"] != float64(2) {
			t.Errorf("kept_protected = %v, want 2", result["kept_protected"])
		}
		remaining := srv.wallet.GetCredentials()
		if len(remaining) != 2 {
			t.Fatalf("after delete-all: %d credentials, want the 2 protected ones", len(remaining))
		}
		for _, c := range remaining {
			if !c.Protected {
				t.Errorf("unprotected credential %s survived delete-all", c.ID)
			}
		}
	})

	t.Run("protection survives a save and reload", func(t *testing.T) {
		if err := srv.store.Save(srv.wallet); err != nil {
			t.Fatalf("save: %v", err)
		}
		if err := srv.reloadFromStore(); err != nil {
			t.Fatalf("reload: %v", err)
		}
		for _, c := range srv.wallet.GetCredentials() {
			if !c.Protected {
				t.Fatalf("credential %s lost its protection across a reload", c.ID)
			}
		}
	})
}
