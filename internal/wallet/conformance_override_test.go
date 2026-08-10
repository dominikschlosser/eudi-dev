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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func requestWithConformanceCookie(t *testing.T, rawJSON string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	r.AddCookie(&http.Cookie{Name: conformanceCookieName, Value: url.QueryEscape(rawJSON)})
	return r
}

func TestConformanceOverrideFromRequest(t *testing.T) {
	t.Run("no cookie inherits the server", func(t *testing.T) {
		o := conformanceOverrideFromRequest(httptest.NewRequest(http.MethodGet, "/authorize", nil))
		if o.Mode != "" || o.HAIP != nil || o.Encrypted != nil {
			t.Fatalf("expected empty override, got %+v", o)
		}
	})

	t.Run("valid cookie is parsed", func(t *testing.T) {
		o := conformanceOverrideFromRequest(requestWithConformanceCookie(t, `{"mode":"debug","haip":false,"encrypted":true}`))
		if o.Mode != "debug" {
			t.Errorf("mode = %q, want debug", o.Mode)
		}
		if o.HAIP == nil || *o.HAIP != false {
			t.Errorf("haip = %v, want false", o.HAIP)
		}
		if o.Encrypted == nil || *o.Encrypted != true {
			t.Errorf("encrypted = %v, want true", o.Encrypted)
		}
	})

	t.Run("malformed cookie is ignored, not an error", func(t *testing.T) {
		o := conformanceOverrideFromRequest(requestWithConformanceCookie(t, `not json`))
		if o.Mode != "" || o.HAIP != nil || o.Encrypted != nil {
			t.Fatalf("expected empty override for malformed cookie, got %+v", o)
		}
	})
}

func TestConformanceOverrideApplyToPrecedence(t *testing.T) {
	off := false
	cookie := conformanceOverride{Mode: "debug", HAIP: &off}

	// An explicit body/header value wins over the cookie.
	explicit := true
	got := cookie.applyTo(presentationRequestOptions{RequireHAIP: &explicit, ValidationMode: "strict"})
	if got.ValidationMode != "strict" {
		t.Errorf("mode = %q, want strict (explicit wins)", got.ValidationMode)
	}
	if got.RequireHAIP == nil || *got.RequireHAIP != true {
		t.Errorf("haip = %v, want true (explicit wins)", got.RequireHAIP)
	}

	// Empty explicit fields fall back to the cookie.
	got = cookie.applyTo(presentationRequestOptions{})
	if got.ValidationMode != "debug" {
		t.Errorf("mode = %q, want debug (from cookie)", got.ValidationMode)
	}
	if got.RequireHAIP == nil || *got.RequireHAIP != false {
		t.Errorf("haip = %v, want false (from cookie)", got.RequireHAIP)
	}
	if !got.hasConformanceOverride() {
		t.Error("expected hasConformanceOverride to be true")
	}

	if (presentationRequestOptions{}).hasConformanceOverride() {
		t.Error("expected empty options to report no conformance override")
	}
}

func TestHandleSetAndResetConformance(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeDebug
	w.RequireHAIP = false
	w.RequireEncryptedRequest = false
	s := NewServer(w, 0, nil)

	putReq := httptest.NewRequest(http.MethodPut, "/api/config/conformance", strings.NewReader(`{"mode":"strict","haip":true,"encrypted":true}`))
	putRec := httptest.NewRecorder()
	s.mux.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d: %s", putRec.Code, putRec.Body.String())
	}
	if s.wallet.ValidationMode != ValidationModeStrict {
		t.Errorf("mode = %q, want strict", s.wallet.ValidationMode)
	}
	if !s.wallet.RequireHAIP {
		t.Error("HAIP was not enabled")
	}
	if !s.wallet.RequireEncryptedRequest {
		t.Error("encrypted requests were not enabled")
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/config/conformance", nil)
	delRec := httptest.NewRecorder()
	s.mux.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d", delRec.Code)
	}
	if s.wallet.ValidationMode != ValidationModeDebug {
		t.Errorf("mode after reset = %q, want the startup default debug", s.wallet.ValidationMode)
	}
	if s.wallet.RequireHAIP {
		t.Error("HAIP was not reset to the startup default")
	}
	if s.wallet.RequireEncryptedRequest {
		t.Error("encrypted requests were not reset to the startup default")
	}
}

func TestHandleSetConformanceRefusedInDemo(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	s := NewServer(w, 0, nil)
	s.demo = &demoState{}

	req := httptest.NewRequest(http.MethodPut, "/api/config/conformance", strings.NewReader(`{"mode":"debug"}`))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 in demo mode, got %d", rec.Code)
	}
	if s.wallet.ValidationMode != ValidationModeStrict {
		t.Errorf("demo-mode PUT must not change the setting; mode = %q", s.wallet.ValidationMode)
	}
}

func TestMergedConformanceOptionsPrecedence(t *testing.T) {
	// body (base) beats header beats cookie.
	r := requestWithConformanceCookie(t, `{"mode":"strict","haip":true}`)
	r.Header.Set("X-Eudi-Dev-Mode", "debug")
	strict := true
	got := mergedConformanceOptions(r, presentationRequestOptions{RequireHAIP: &strict})
	if got.ValidationMode != "debug" {
		t.Errorf("mode = %q, want debug (header beats cookie)", got.ValidationMode)
	}
	if got.RequireHAIP == nil || *got.RequireHAIP != true {
		t.Errorf("haip = %v, want true (body beats cookie)", got.RequireHAIP)
	}

	// header-only encrypted is honored (the CLI path, not just DC-API).
	r2 := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
	r2.Header.Set("X-Eudi-Dev-Encrypted", "true")
	got2 := mergedConformanceOptions(r2, presentationRequestOptions{})
	if got2.RequireEncryptedRequest == nil || *got2.RequireEncryptedRequest != true {
		t.Errorf("encrypted = %v, want true from header", got2.RequireEncryptedRequest)
	}

	// cookie-only falls through when nothing else is set.
	r3 := requestWithConformanceCookie(t, `{"mode":"strict"}`)
	got3 := mergedConformanceOptions(r3, presentationRequestOptions{})
	if got3.ValidationMode != "strict" {
		t.Errorf("mode = %q, want strict from cookie", got3.ValidationMode)
	}
}

// TestAuthorizeHonorsConformanceOverride is the end-to-end proof that the
// override changes real validation, on the top-level /authorize navigation:
// the same request is rejected as strict and accepted (past validation) as
// debug, driven by the cookie and by the header, over the server's own default.
func TestAuthorizeHonorsConformanceOverride(t *testing.T) {
	// A request whose client_id uses an unsupported prefix is a validation
	// finding: fatal in strict, a warning in debug.
	const reqURL = "/authorize?response_type=vp_token&client_id=bogusprefix:foo&nonce=n1&response_mode=direct_post&response_uri=http://localhost:9/cb&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22c%22%2C%22format%22%3A%22dc%2Bsd-jwt%22%7D%5D%7D"

	newSrv := func() *Server {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeStrict // server default is strict
		return NewServer(w, 0, nil)
	}

	get := func(s *Server, apply func(*http.Request)) int {
		req := httptest.NewRequest(http.MethodGet, reqURL, nil)
		if apply != nil {
			apply(req)
		}
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		return rec.Code
	}

	// Strict default rejects the finding.
	if code := get(newSrv(), nil); code != http.StatusBadRequest {
		t.Fatalf("strict default: got %d, want 400", code)
	}
	// A debug cookie overrides the strict default: validation no longer rejects.
	if code := get(newSrv(), func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: conformanceCookieName, Value: url.QueryEscape(`{"mode":"debug"}`)})
	}); code == http.StatusBadRequest {
		t.Fatal("debug cookie: request was still rejected, override not honored")
	}
	// A debug header does the same (the CLI path).
	if code := get(newSrv(), func(r *http.Request) {
		r.Header.Set("X-Eudi-Dev-Mode", "debug")
	}); code == http.StatusBadRequest {
		t.Fatal("debug header: request was still rejected, override not honored")
	}
}

func TestConformanceOverrideDropsInvalidMode(t *testing.T) {
	o := conformanceOverrideFromRequest(requestWithConformanceCookie(t, `{"mode":"garbage"}`))
	if o.Mode != "" {
		t.Fatalf("an unrecognized mode should be dropped, got %q", o.Mode)
	}
	// A valid mode still comes through.
	if got := conformanceOverrideFromRequest(requestWithConformanceCookie(t, `{"mode":"strict"}`)); got.Mode != "strict" {
		t.Fatalf("valid mode = %q, want strict", got.Mode)
	}
}

func TestHandleResetConformanceRefusedInDemo(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	s := NewServer(w, 0, nil)
	s.demo = &demoState{}

	req := httptest.NewRequest(http.MethodDelete, "/api/config/conformance", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for DELETE in demo mode, got %d", rec.Code)
	}
	if s.wallet.ValidationMode != ValidationModeStrict {
		t.Errorf("demo-mode DELETE must not change the setting; mode = %q", s.wallet.ValidationMode)
	}
}

func TestConformanceRoutesBlockedInDemo(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/config/conformance", nil)
		if !demoBlockedRoute(req) {
			t.Errorf("%s /api/config/conformance should be blocked in demo mode", method)
		}
	}
}

func TestConformanceSettingsRaceFree(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeDebug
	s := NewServer(w, 0, nil)

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			mode := "strict"
			if i%2 == 0 {
				mode = "debug"
			}
			body := strings.NewReader(`{"mode":"` + mode + `","haip":true,"encrypted":true}`)
			s.mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/api/config/conformance", body))
		}(i)
		go func() {
			defer wg.Done()
			// /api/config reads the mode string concurrently with the PUT above,
			// so -race would flag a torn read if the fields were not guarded.
			s.mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/config", nil))
		}()
	}
	wg.Wait()
}

// findingRequestURL is an /authorize request whose client_id uses an
// unsupported prefix: a validation finding, fatal in strict, a warning in debug.
const findingRequestURL = "/authorize?response_type=vp_token&client_id=bogusprefix:foo&nonce=n1&response_mode=direct_post&response_uri=http://localhost:9/cb&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22c%22%2C%22format%22%3A%22dc%2Bsd-jwt%22%7D%5D%7D"

func authorizeCode(t *testing.T, s *Server, apply func(*http.Request)) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, findingRequestURL, nil)
	if apply != nil {
		apply(req)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec.Code
}

// TestConformanceEndpointDrivesValidation proves the local-UI surface: flipping
// the wallet's setting through PUT /api/config/conformance changes how a later
// flow validates, end to end.
func TestConformanceEndpointDrivesValidation(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	s := NewServer(w, 0, nil)

	if code := authorizeCode(t, s, nil); code != http.StatusBadRequest {
		t.Fatalf("strict default should reject the finding, got %d", code)
	}
	putRec := httptest.NewRecorder()
	s.mux.ServeHTTP(putRec, httptest.NewRequest(http.MethodPut, "/api/config/conformance", strings.NewReader(`{"mode":"debug"}`)))
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT /api/config/conformance: got %d", putRec.Code)
	}
	if code := authorizeCode(t, s, nil); code == http.StatusBadRequest {
		t.Fatal("after the endpoint set debug, the same request must no longer be rejected on the finding")
	}
}

// TestConformanceCookieIsolationOnDemo proves per-visitor isolation on a shared
// demo: one visitor's cookie changes only their own request, not another
// visitor's outcome and not the shared wallet's setting.
func TestConformanceCookieIsolationOnDemo(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	s := NewServer(w, 0, nil)
	s.demo = &demoState{}

	// Visitor A carries a debug cookie: accepted past validation.
	if code := authorizeCode(t, s, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: conformanceCookieName, Value: url.QueryEscape(`{"mode":"debug"}`)})
	}); code == http.StatusBadRequest {
		t.Fatal("visitor A's debug cookie should let the request through")
	}
	// Visitor B has no cookie: still held to the demo's strict default.
	if code := authorizeCode(t, s, nil); code != http.StatusBadRequest {
		t.Fatalf("visitor B (no cookie) must still see the strict default, got %d", code)
	}
	// The shared wallet's own setting was never touched by a visitor cookie.
	if s.wallet.ValidationMode != ValidationModeStrict {
		t.Fatalf("a visitor cookie must not change the shared wallet; mode = %q", s.wallet.ValidationMode)
	}
	// And the demo refuses attempts to change the shared setting.
	putRec := httptest.NewRecorder()
	s.mux.ServeHTTP(putRec, httptest.NewRequest(http.MethodPut, "/api/config/conformance", strings.NewReader(`{"mode":"debug"}`)))
	if putRec.Code != http.StatusForbidden {
		t.Fatalf("demo must refuse the settings endpoint, got %d", putRec.Code)
	}
}
