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
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const prefixBaseURL = "https://mydomain.de/some/context"

func newPrefixTestServer(t *testing.T, baseURL string) *Server {
	t.Helper()
	srv := newTestServer(t, true)
	srv.wallet.BaseURL = baseURL
	srv.wallet.IssuerURL = baseURL
	srv.Mount("/issuer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "issuer %s", r.URL.Path)
	}))
	srv.Handle("GET /.well-known/openid-credential-issuer/issuer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("demo issuer metadata"))
	}))
	if err := srv.CheckBasePath(); err != nil {
		t.Fatal(err)
	}
	return srv
}

// prefixRequest sends a request the way a reverse proxy forwards it to the wallet.
func prefixRequest(srv *Server, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "mydomain.de"
	req.Header.Set("X-Forwarded-Proto", "https")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// proxyModes covers a proxy that forwards the prefix and one that strips it, as an
// Istio VirtualService with a rewrite does.
var proxyModes = []struct {
	name  string
	route func(path string) string
}{
	{"prefix kept", func(path string) string { return "/some/context" + path }},
	{"prefix stripped", func(path string) string { return path }},
}

func TestPrefixServesUIUnderBasePath(t *testing.T) {
	srv := newPrefixTestServer(t, prefixBaseURL)
	for _, mode := range proxyModes {
		t.Run(mode.name, func(t *testing.T) {
			rec := prefixRequest(srv, http.MethodGet, mode.route("/"), nil)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<base href="/some/context/">`) {
				t.Fatalf("index: %d %.300s", rec.Code, rec.Body.String())
			}
			cookie := rec.Result().Cookies()
			if len(cookie) != 1 || cookie[0].Path != "/some/context" || !cookie[0].Secure {
				t.Fatalf("session cookie = %+v", cookie)
			}
			if rec := prefixRequest(srv, http.MethodGet, mode.route("/app.js"), nil); rec.Code != http.StatusOK {
				t.Fatalf("app.js: %d", rec.Code)
			}
			if rec := prefixRequest(srv, http.MethodGet, mode.route("/api/credentials"), nil); rec.Code != http.StatusOK {
				t.Fatalf("api: %d %s", rec.Code, rec.Body.String())
			}
			if rec := prefixRequest(srv, http.MethodGet, mode.route("/issuer/offer"), nil); rec.Body.String() != "issuer /offer" {
				t.Fatalf("mounted issuer: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPrefixRedirectsStayUnderBasePath(t *testing.T) {
	srv := newPrefixTestServer(t, prefixBaseURL)
	for _, mode := range proxyModes {
		t.Run(mode.name, func(t *testing.T) {
			rec := prefixRequest(srv, http.MethodGet, mode.route("/issuer"), nil)
			if got := rec.Header().Get("Location"); rec.Code != http.StatusMovedPermanently || got != "/some/context/issuer/" {
				t.Fatalf("bare mount: %d Location %q", rec.Code, got)
			}
			// A relative location resolves against the browser's URL, under the prefix.
			rec = prefixRequest(srv, http.MethodGet, mode.route("/index.html"), nil)
			if got := rec.Header().Get("Location"); got != "./" {
				t.Fatalf("index.html: %d Location %q", rec.Code, got)
			}
		})
	}
}

func TestPrefixServesWellKnownAtHostRoot(t *testing.T) {
	srv := newPrefixTestServer(t, prefixBaseURL)
	for _, tc := range []struct{ path, issuer string }{
		{"/.well-known/jwt-vc-issuer/some/context", prefixBaseURL},
		{"/.well-known/openid-credential-issuer/some/context", prefixBaseURL},
	} {
		rec := prefixRequest(srv, http.MethodGet, tc.path, nil)
		var doc map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &doc) != nil {
			t.Fatalf("%s: %d %.200s", tc.path, rec.Code, rec.Body.String())
		}
		if doc["issuer"] != tc.issuer && doc["credential_issuer"] != tc.issuer {
			t.Fatalf("%s names issuer %v / %v, want %s", tc.path, doc["issuer"], doc["credential_issuer"], tc.issuer)
		}
	}
	rec := prefixRequest(srv, http.MethodGet, "/.well-known/openid-credential-issuer/some/context/issuer", nil)
	if rec.Body.String() != "demo issuer metadata" {
		t.Fatalf("demo issuer metadata: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPrefixKeepsAPIProtections(t *testing.T) {
	srv := newPrefixTestServer(t, prefixBaseURL)
	if err := srv.SetDemo(DemoOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range proxyModes {
		t.Run(mode.name, func(t *testing.T) {
			if rec := prefixRequest(srv, http.MethodPost, mode.route("/api/shutdown"), nil); rec.Code != http.StatusForbidden {
				t.Fatalf("demo shutdown: %d", rec.Code)
			}
			rec := prefixRequest(srv, http.MethodDelete, mode.route("/api/credentials"), map[string]string{"Origin": "https://evil.example"})
			if rec.Code != http.StatusForbidden {
				t.Fatalf("cross-origin request: %d", rec.Code)
			}
		})
	}
}

func TestRootDeploymentUnchanged(t *testing.T) {
	for _, baseURL := range []string{"", "https://mydomain.de", "http://localhost:8085"} {
		t.Run(baseURL, func(t *testing.T) {
			srv := newTestServer(t, true)
			srv.wallet.BaseURL = baseURL
			srv.Mount("/decoder", http.NotFoundHandler())
			if err := srv.CheckBasePath(); err != nil {
				t.Fatal(err)
			}
			rec := serverRequest(t, srv, http.MethodGet, "/", "")
			if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "<base") {
				t.Fatalf("index: %d", rec.Code)
			}
			if cookies := rec.Result().Cookies(); len(cookies) != 1 || cookies[0].Path != "/" {
				t.Fatalf("session cookie = %+v", cookies)
			}
			rec = serverRequest(t, srv, http.MethodGet, "/decoder", "")
			if got := rec.Header().Get("Location"); got != "/decoder/" {
				t.Fatalf("decoder redirect Location %q", got)
			}
			if rec := serverRequest(t, srv, http.MethodGet, "/api/version", ""); rec.Code != http.StatusOK {
				t.Fatalf("api: %d", rec.Code)
			}
		})
	}
}

func TestPrefixAllowsDirectAccess(t *testing.T) {
	srv := newPrefixTestServer(t, prefixBaseURL)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "localhost:8085"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "<base") {
		t.Fatalf("direct index: %d", rec.Code)
	}
}

func TestPrefixLogsMismatchingForwardedHost(t *testing.T) {
	srv := newPrefixTestServer(t, prefixBaseURL)
	var mu sync.Mutex
	var logs []string
	srv.SetLogger(func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	prefixRequest(srv, http.MethodGet, "/api/version", map[string]string{"X-Forwarded-Host": "other.example"})
	mu.Lock()
	defer mu.Unlock()
	if len(logs) != 1 || !strings.Contains(logs[0], `host "other.example"`) || !strings.Contains(logs[0], prefixBaseURL) {
		t.Fatalf("logs = %q", logs)
	}
}

func TestCheckBasePathRejectsWalletRoutes(t *testing.T) {
	for _, path := range []string{"/api", "/issuer/x", "/app.js", "/.well-known", "/authorize", "/decoder"} {
		srv := newTestServer(t, true)
		srv.Mount("/issuer", http.NotFoundHandler())
		srv.Mount("/decoder", http.NotFoundHandler())
		srv.wallet.BaseURL = "https://mydomain.de" + path
		if err := srv.CheckBasePath(); err == nil {
			t.Errorf("base path %s accepted", path)
		}
	}
}

// Links in API responses must work for any client, not only the wallet's own page.
func TestPrefixAPILinksIncludePrefix(t *testing.T) {
	for _, tc := range []struct {
		name, baseURL, target, want string
	}{
		{"under a path prefix", prefixBaseURL, "/some/context", "/some/context/api/"},
		{"at the root", "https://mydomain.de", "", "/api/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newPrefixTestServer(t, tc.baseURL)
			issueReq := httptest.NewRequest(http.MethodPost, tc.target+"/api/issue",
				strings.NewReader(`{"format":"sdjwt","vct":"urn:example:logo","display":{"name":"Badge","logo":"`+tinyPNGDataURI+`"}}`))
			issueReq.Host = "mydomain.de"
			issueReq.Header.Set("Content-Type", "application/json")
			issued := httptest.NewRecorder()
			srv.Handler().ServeHTTP(issued, issueReq)
			var created map[string]any
			if issued.Code != http.StatusCreated || json.Unmarshal(issued.Body.Bytes(), &created) != nil {
				t.Fatalf("issue: %d %s", issued.Code, issued.Body.String())
			}
			id := created["id"].(string)
			wantLogo := tc.want + "credentials/" + id + "/display/logo"
			if got := created["display"].(map[string]any)["logo_uri"]; got != wantLogo {
				t.Fatalf("issue response logo_uri = %v, want %s", got, wantLogo)
			}

			for _, path := range []string{"/api/credentials", "/api/credentials/" + id} {
				rec := prefixRequest(srv, http.MethodGet, tc.target+path, nil)
				if !strings.Contains(rec.Body.String(), `"logo_uri":"`+wantLogo+`"`) {
					t.Fatalf("%s: logo_uri missing %s: %.300s", path, wantLogo, rec.Body.String())
				}
			}
			if rec := prefixRequest(srv, http.MethodGet, strings.TrimPrefix(wantLogo, "/some/context"), nil); rec.Code != http.StatusOK {
				t.Fatalf("logo: %d", rec.Code)
			}

			rec := prefixRequest(srv, http.MethodGet, tc.target+"/api/trustlists", nil)
			if !strings.Contains(rec.Body.String(), `"path":"`+tc.want+`trustlists/`) {
				t.Fatalf("trusted list paths: %.300s", rec.Body.String())
			}
		})
	}
}
