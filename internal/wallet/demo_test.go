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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// TestGenerateProtectedDefaults_ReplacesABaselineOfAnyType covers a release
// that changes the PID identifiers. The old baseline has to go, or the demo
// ends up showing one PID per identifier it has ever used.
func TestGenerateProtectedDefaults_ReplacesABaselineOfAnyType(t *testing.T) {
	w := generateTestWallet(t)

	// A baseline from an earlier release, under the old country-specific vct.
	w.Credentials = append(w.Credentials, StoredCredential{
		ID:        "stale-baseline",
		Format:    "dc+sd-jwt",
		VCT:       "urn:eudi:pid:de:1",
		Protected: true,
	})
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("GenerateProtectedDefaults: %v", err)
	}

	for _, c := range w.GetCredentials() {
		if c.ID == "stale-baseline" {
			t.Fatal("the previous baseline survived under its old vct")
		}
		if c.VCT == "urn:eudi:pid:de:1" {
			t.Errorf("a credential still carries the old vct: %s", c.ID)
		}
	}
	var protectedSDJWT int
	for _, c := range w.GetCredentials() {
		if c.Protected && c.Format == "dc+sd-jwt" {
			protectedSDJWT++
		}
	}
	if protectedSDJWT != 1 {
		t.Errorf("wallet holds %d protected SD-JWT PIDs, want exactly 1", protectedSDJWT)
	}
}

// TestRefreshSigningCertificate covers the daily reset keeping the signing
// leaf current without moving the CA anyone may have pinned.
func TestRefreshSigningCertificate(t *testing.T) {
	w := generateTestWallet(t)
	before := w.CertChain
	if len(before) < 2 {
		t.Fatal("test wallet has no certificate chain")
	}
	oldLeaf, oldCA := before[0], before[len(before)-1]

	if err := w.RefreshSigningCertificate(); err != nil {
		t.Fatalf("RefreshSigningCertificate: %v", err)
	}
	newLeaf, newCA := w.CertChain[0], w.CertChain[len(w.CertChain)-1]

	if newLeaf.NotAfter.Before(oldLeaf.NotAfter) {
		t.Error("the refreshed leaf expires no later than the one it replaced")
	}
	if !newCA.Equal(oldCA) {
		t.Error("the CA changed; anything that pinned it would break")
	}
	leafKey, ok := newLeaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafKey.Equal(&w.IssuerKey.PublicKey) {
		t.Error("the refreshed leaf does not carry the wallet's issuer key")
	}
}

// TestSigningKeyExpiry_FollowsTheCertificate covers what the wallet publishes
// as its signing key expiry. It used to be computed once when the server was
// built, so a wallet running for more than a day advertised a key that had
// already expired in its JWKS and signed issuer metadata.
func TestSigningKeyExpiry_FollowsTheCertificate(t *testing.T) {
	w := generateTestWallet(t)
	s := NewServer(w, 0, nil)

	if got, want := s.signingKeyExpiry(), w.SigningCertificateExpiry(); !got.Equal(want) {
		t.Errorf("published expiry = %s, want the certificate's %s", got, want)
	}
	if s.signingKeyExpiry().Before(time.Now().Add(300 * 24 * time.Hour)) {
		t.Error("a fresh wallet should publish an expiry roughly a year out")
	}

	// Re-issuing the leaf moves the published expiry with it.
	before := s.signingKeyExpiry()
	if err := w.RefreshSigningCertificate(); err != nil {
		t.Fatalf("RefreshSigningCertificate: %v", err)
	}
	if !s.signingKeyExpiry().After(before.Add(-time.Minute)) {
		t.Error("the published expiry did not follow the re-issued certificate")
	}
}

// TestRefreshSigningCertificateIfExpiring covers the renewal a long-running
// wallet depends on: nothing renews near expiry, everything does once inside
// the window.
func TestRefreshSigningCertificateIfExpiring(t *testing.T) {
	w := generateTestWallet(t)
	expiry := w.SigningCertificateExpiry()

	renewed, err := w.RefreshSigningCertificateIfExpiring(time.Now())
	if err != nil {
		t.Fatalf("RefreshSigningCertificateIfExpiring: %v", err)
	}
	if renewed {
		t.Error("a certificate with a year left should not be re-issued")
	}

	// A wallet that has been running until just before its leaf expires.
	almostExpired := expiry.Add(-signingCertificateRenewBefore).Add(time.Hour)
	renewed, err = w.RefreshSigningCertificateIfExpiring(almostExpired)
	if err != nil {
		t.Fatalf("RefreshSigningCertificateIfExpiring near expiry: %v", err)
	}
	if !renewed {
		t.Fatal("a certificate inside the renewal window should be re-issued")
	}
	// The re-issued leaf is dated from the real clock, so its validity is
	// measured from now rather than from the simulated expiry above.
	if w.SigningCertificateExpiry().Before(time.Now().Add(300 * 24 * time.Hour)) {
		t.Errorf("the re-issued certificate expires %s, want roughly a year out",
			w.SigningCertificateExpiry())
	}
}

// TestRenewIssuerTLSCertificateIfNeeded covers the HTTPS leaf on a wallet that
// outlives it. The listener resolves the certificate per handshake, so a
// renewal reaches clients without a restart.
func TestRenewIssuerTLSCertificateIfNeeded(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	s := NewServer(w, 0, nil)

	var caCert *x509.Certificate
	if len(w.CertChain) > 1 {
		caCert = w.CertChain[len(w.CertChain)-1]
	}
	cert, err := generateIssuerTLSCertificate("localhost", w.CAKey, caCert)
	if err != nil {
		t.Fatalf("generateIssuerTLSCertificate: %v", err)
	}
	s.setIssuerTLSCertificate(cert)
	leaf, err := x509.ParseCertificate(s.currentIssuerTLSCertificate().Certificate[0])
	if err != nil {
		t.Fatalf("parsing the leaf: %v", err)
	}
	first := leaf.SerialNumber.String()

	// Well before expiry nothing changes.
	s.renewIssuerTLSCertificateIfNeeded(time.Now())
	same, _ := x509.ParseCertificate(s.currentIssuerTLSCertificate().Certificate[0])
	if same.SerialNumber.String() != first {
		t.Error("a certificate with a year left was re-issued")
	}

	// Inside the renewal window it is replaced, and the listener sees the new
	// one because it asks for it per handshake.
	s.renewIssuerTLSCertificateIfNeeded(leaf.NotAfter.Add(-time.Hour))
	renewed, err := x509.ParseCertificate(s.currentIssuerTLSCertificate().Certificate[0])
	if err != nil {
		t.Fatalf("parsing the renewed leaf: %v", err)
	}
	if renewed.SerialNumber.String() == first {
		t.Fatal("the HTTPS certificate was not re-issued inside the renewal window")
	}
	if renewed.NotAfter.Before(time.Now().Add(300 * 24 * time.Hour)) {
		t.Errorf("renewed HTTPS certificate expires %s, want roughly a year out", renewed.NotAfter)
	}
}

// The cap used to apply in demo mode alone, so a plain wallet server read
// whatever it was sent into memory. It is a testing wallet either way, but
// the size of a request it will read should not be the caller's choice.
func TestRequestBodyIsCapped(t *testing.T) {
	for _, demo := range []bool{false, true} {
		name := "plain"
		if demo {
			name = "demo"
		}
		t.Run(name, func(t *testing.T) {
			srv := newTestServer(t, false)
			if demo {
				srv.SetDemo(DemoOptions{})
			}

			// An oversized credential is refused either way, so the status
			// alone proves nothing. The import handler answers "reading
			// body" only when the read itself failed, which is the cap
			// firing rather than the credential being rejected.
			oversized := strings.Repeat("a", maxRequestBodyBytes+1)
			req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader(oversized))
			req.Host = "localhost:8085"
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if !strings.Contains(rec.Body.String(), "reading body") {
				t.Errorf("body over the cap was read anyway: status %d, body %q", rec.Code, rec.Body.String())
			}
		})
	}
}

// Clearing the activity log or the last error changes what every other
// visitor sees, and nothing on a demo instance needs it.
func TestDemoBlocksClearingSharedHistory(t *testing.T) {
	srv := newDemoTestServer(t)

	for _, path := range []string{"/api/log", "/api/error"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, path, nil)
			req.Host = "localhost:8085"
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
		})
	}
}

// A local wallet still clears its own log.
func TestLocalWalletStillClearsItsLog(t *testing.T) {
	srv := newTestServer(t, false)
	req := httptest.NewRequest(http.MethodDelete, "/api/log", nil)
	req.Host = "localhost:8085"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Error("a local wallet was refused permission to clear its own log")
	}
}
