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

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOriginalURL(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *http.Request
		want  string
	}{
		{
			name: "plain HTTP request",
			setup: func() *http.Request {
				r := httptest.NewRequest("GET", "http://localhost:9090/authorize?foo=bar", nil)
				r.RequestURI = "/authorize?foo=bar"
				return r
			},
			want: "http://localhost:9090/authorize?foo=bar",
		},
		{
			name: "X-Forwarded headers",
			setup: func() *http.Request {
				r := httptest.NewRequest("GET", "http://localhost:9090/path", nil)
				r.RequestURI = "/path"
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "external.example.com")
				return r
			},
			want: "https://external.example.com/path",
		},
		{
			name: "X-Forwarded-Proto only",
			setup: func() *http.Request {
				r := httptest.NewRequest("GET", "http://myhost:8080/test", nil)
				r.RequestURI = "/test"
				r.Header.Set("X-Forwarded-Proto", "https")
				return r
			},
			want: "https://myhost:8080/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := originalURL(tt.setup())
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewServerStore(t *testing.T) {
	target, _ := url.Parse("http://localhost:8080")
	cfg := Config{TargetURL: target, ProxyPort: 9090}
	srv := NewServer(cfg, nil)

	if srv.Store() == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestServerSetsForwardedPublicHost(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-Host"); got != "demo.ngrok.app" {
			t.Errorf("X-Forwarded-Host = %q, want demo.ngrok.app", got)
		}
		if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Errorf("X-Forwarded-Proto = %q, want https", got)
		}
		if got := r.Header.Get("X-Forwarded-Port"); got != "443" {
			t.Errorf("X-Forwarded-Port = %q, want 443", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	targetURL, _ := url.Parse(backend.URL)
	var captured []*TrafficEntry
	srv := NewServer(Config{
		TargetURL:  targetURL,
		ProxyPort:  9090,
		AllTraffic: true,
	}, &testWriter{entries: &captured})

	req := httptest.NewRequest(http.MethodGet, "http://localhost:9090/realms/demo", nil)
	req.Host = "demo.ngrok.app"
	req.Header.Set("X-Forwarded-Proto", "https")

	resp := httptest.NewRecorder()
	srv.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusNoContent)
	}
}

func TestServerEndToEnd(t *testing.T) {
	// Create a target backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	targetURL, _ := url.Parse(backend.URL)

	// Collect entries via a test writer
	var captured []*TrafficEntry
	writer := &testWriter{entries: &captured}

	cfg := Config{
		TargetURL:  targetURL,
		ProxyPort:  0,
		AllTraffic: true,
	}
	srv := NewServer(cfg, writer)

	// Make a request through the proxy
	proxy := httptest.NewServer(srv)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("unexpected body: %s", string(body))
	}

	if len(captured) != 1 {
		t.Fatalf("expected 1 captured entry, got %d", len(captured))
	}
	if captured[0].Method != "GET" {
		t.Errorf("expected GET, got %s", captured[0].Method)
	}
	if captured[0].StatusCode != 200 {
		t.Errorf("expected 200, got %d", captured[0].StatusCode)
	}
}

func TestServerCapturesRequestBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}))
	defer backend.Close()

	targetURL, _ := url.Parse(backend.URL)
	var captured []*TrafficEntry
	writer := &testWriter{entries: &captured}

	srv := NewServer(Config{TargetURL: targetURL, AllTraffic: true}, writer)
	proxy := httptest.NewServer(srv)
	defer proxy.Close()

	resp, err := http.Post(proxy.URL+"/submit", "application/x-www-form-urlencoded", strings.NewReader("state=abc&vp_token=test"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if len(captured) != 1 {
		t.Fatalf("expected 1 captured entry, got %d", len(captured))
	}
	if captured[0].RequestBody != "state=abc&vp_token=test" {
		t.Errorf("unexpected request body: %q", captured[0].RequestBody)
	}
}

func TestServerNilWriter(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer backend.Close()

	targetURL, _ := url.Parse(backend.URL)
	srv := NewServer(Config{TargetURL: targetURL}, nil)
	proxy := httptest.NewServer(srv)
	defer proxy.Close()

	// Should not panic with nil writer
	resp, err := http.Get(proxy.URL + "/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 204 {
		t.Errorf("expected 204, got %d", resp.StatusCode)
	}
}

func TestServerClassifiesVPAuthRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	targetURL, _ := url.Parse(backend.URL)
	var captured []*TrafficEntry
	writer := &testWriter{entries: &captured}

	srv := NewServer(Config{TargetURL: targetURL}, writer)
	proxy := httptest.NewServer(srv)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/authorize?client_id=test&response_type=vp_token&state=s1")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if len(captured) != 1 {
		t.Fatalf("expected 1 captured entry, got %d", len(captured))
	}
	if captured[0].Class != ClassVPAuthRequest {
		t.Errorf("expected ClassVPAuthRequest, got %d (%s)", captured[0].Class, captured[0].ClassLabel)
	}
}

func TestShouldEmitEntrySuppressesUnknownWithoutAllTraffic(t *testing.T) {
	entry := &TrafficEntry{Class: ClassUnknown}
	if shouldEmitEntry(entry, false) {
		t.Fatal("expected unknown traffic to be suppressed when allTraffic=false")
	}
	if !shouldEmitEntry(entry, true) {
		t.Fatal("expected unknown traffic to be emitted when allTraffic=true")
	}
	if !shouldEmitEntry(&TrafficEntry{Class: ClassVPAuthRequest}, false) {
		t.Fatal("expected classified traffic to be emitted")
	}
}

func TestServerStripsAndCapturesDebugJWEKeyHeader(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	targetURL, _ := url.Parse(backend.URL)
	var captured []*TrafficEntry
	writer := &testWriter{entries: &captured}

	srv := NewServer(Config{TargetURL: targetURL, AllTraffic: true}, writer)
	proxy := httptest.NewServer(srv)
	defer proxy.Close()

	req, _ := http.NewRequest("POST", proxy.URL+"/response", strings.NewReader("response=jwe-value"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Debug-JWE-CEK", "test-cek-value")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if got := receivedHeaders.Get("X-Debug-JWE-CEK"); got != "" {
		t.Errorf("X-Debug-JWE-CEK = %q, want stripped", got)
	}

	if len(captured) != 1 {
		t.Fatalf("expected 1 captured entry, got %d", len(captured))
	}
	if captured[0].DebugJWEKey != "test-cek-value" {
		t.Errorf("expected DebugJWEKey=test-cek-value, got %q", captured[0].DebugJWEKey)
	}
}

func TestServerCapturesMultilineBodyWithoutForwardingInternalHeaders(t *testing.T) {
	body := "{\n  \"name\": \"wallet-app-demo\"\n}"
	var receivedHeaders http.Header
	var receivedBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		receivedBody = string(raw)
		w.WriteHeader(http.StatusCreated)
	}))
	defer backend.Close()

	targetURL, _ := url.Parse(backend.URL)
	var captured []*TrafficEntry
	srv := NewServer(Config{TargetURL: targetURL, AllTraffic: true}, &testWriter{entries: &captured})
	proxy := httptest.NewServer(srv)
	defer proxy.Close()

	resp, err := http.Post(proxy.URL+"/admin/realms/demo/components", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if receivedBody != body {
		t.Fatalf("backend body = %q, want %q", receivedBody, body)
	}
	if got := receivedHeaders.Get("X-Proxy-ReqBody"); got != "" {
		t.Fatalf("backend received internal X-Proxy-ReqBody header %q", got)
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1 captured entry, got %d", len(captured))
	}
	if captured[0].RequestBody != body {
		t.Fatalf("captured body = %q, want %q", captured[0].RequestBody, body)
	}
}

func TestServerErrorHandler(t *testing.T) {
	// The error handler answers 502 when the backend drops the connection
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Force close the connection immediately
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(200)
			return
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer backend.Close()

	targetURL, _ := url.Parse(backend.URL)
	srv := NewServer(Config{TargetURL: targetURL, AllTraffic: true}, nil)
	proxy := httptest.NewServer(srv)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", resp.StatusCode)
	}
}

// testWriter is a simple EntryWriter that records all entries.
type testWriter struct {
	entries *[]*TrafficEntry
}

func (tw *testWriter) WriteEntry(entry *TrafficEntry) {
	*tw.entries = append(*tw.entries, entry)
}
