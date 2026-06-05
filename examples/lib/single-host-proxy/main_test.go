package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestReverseProxyPreservesRequest(t *testing.T) {
	const body = "request-body"
	var gotHost string
	var gotHeaders http.Header
	var gotBody string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotHeaders = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newReverseProxy(target)

	req := httptest.NewRequest(http.MethodPost, "https://wallet-test.ngrok.dev/realms/demo", strings.NewReader(body))
	req.Host = "wallet-test.ngrok.dev"
	req.Header.Set("X-Forwarded-Host", "wallet-test.ngrok.dev")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Custom", "value")

	resp := httptest.NewRecorder()
	proxy.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusNoContent)
	}
	if gotHost != "wallet-test.ngrok.dev" {
		t.Fatalf("Host = %q, want wallet-test.ngrok.dev", gotHost)
	}
	if gotHeaders.Get("X-Forwarded-Host") != "wallet-test.ngrok.dev" {
		t.Fatalf("X-Forwarded-Host = %q", gotHeaders.Get("X-Forwarded-Host"))
	}
	if gotHeaders.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("X-Forwarded-Proto = %q", gotHeaders.Get("X-Forwarded-Proto"))
	}
	if gotHeaders.Get("X-Custom") != "value" {
		t.Fatalf("X-Custom = %q, want value", gotHeaders.Get("X-Custom"))
	}
	if gotBody != body {
		t.Fatalf("body = %q, want %q", gotBody, body)
	}
}
