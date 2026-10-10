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
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewProxyFunc(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://env-proxy:3128")
	t.Setenv("HTTP_PROXY", "http://env-proxy:3128")
	t.Setenv("NO_PROXY", "skip.example")
	for _, tc := range []struct {
		name     string
		settings ProxySettings
		target   string
		want     string
	}{
		{name: "environment", target: "https://issuer.example", want: "http://env-proxy:3128"},
		{name: "environment no proxy", target: "https://skip.example", want: ""},
		{name: "https override", settings: ProxySettings{HTTPSProxy: "http://flag-proxy:8080"}, target: "https://issuer.example", want: "http://flag-proxy:8080"},
		{name: "https override leaves http", settings: ProxySettings{HTTPSProxy: "http://flag-proxy:8080"}, target: "http://issuer.example", want: "http://env-proxy:3128"},
		{name: "http override without scheme", settings: ProxySettings{HTTPProxy: "flag-proxy:8080"}, target: "http://issuer.example", want: "http://flag-proxy:8080"},
		{name: "override keeps environment no proxy", settings: ProxySettings{HTTPSProxy: "http://flag-proxy:8080"}, target: "https://skip.example", want: ""},
		{name: "no proxy override replaces environment", settings: ProxySettings{NoProxy: ".corp.example"}, target: "https://skip.example", want: "http://env-proxy:3128"},
		{name: "no proxy override domain", settings: ProxySettings{NoProxy: ".corp.example"}, target: "https://issuer.corp.example", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy, err := NewProxyFunc(tc.settings)
			if err != nil {
				t.Fatal(err)
			}
			target, _ := url.Parse(tc.target)
			got, err := proxy(&http.Request{URL: target})
			if err != nil {
				t.Fatal(err)
			}
			if gotString := urlString(got); gotString != tc.want {
				t.Fatalf("proxy for %s = %q, want %q", tc.target, gotString, tc.want)
			}
		})
	}
}

func TestProxyURLs(t *testing.T) {
	t.Setenv("HTTP_PROXY", "env-proxy:3128")
	t.Setenv("HTTPS_PROXY", "http://env-proxy:3129")
	got := ProxyURLs(ProxySettings{HTTPSProxy: "socks5://flag-proxy:1080"})
	want := []string{"http://env-proxy:3128", "socks5://flag-proxy:1080"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("ProxyURLs = %v, want %v", got, want)
	}
}

func TestNewProxyFuncRejectsInvalidURL(t *testing.T) {
	for _, raw := range []string{"ftp://proxy:21", "http://", "://"} {
		if _, err := NewProxyFunc(ProxySettings{HTTPSProxy: raw}); err == nil {
			t.Fatalf("accepted proxy URL %q", raw)
		}
	}
}

func TestHTTPClientUsesProxyForRemoteHostsOnly(t *testing.T) {
	proxied := make(chan string, 1)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied <- r.URL.String()
		_, _ = io.WriteString(w, "via proxy")
	}))
	defer proxyServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "direct") }))
	defer local.Close()
	proxy, err := NewProxyFunc(ProxySettings{HTTPProxy: proxyServer.URL})
	if err != nil {
		t.Fatal(err)
	}
	client := NewHTTPClient(nil, nil, proxy)
	defer client.CloseIdleConnections()

	if body := getBody(t, client, "http://issuer.example/.well-known/openid-credential-issuer"); body != "via proxy" {
		t.Fatalf("remote request body = %q", body)
	}
	if got := <-proxied; got != "http://issuer.example/.well-known/openid-credential-issuer" {
		t.Fatalf("proxy saw %q", got)
	}
	if body := getBody(t, client, local.URL); body != "direct" {
		t.Fatalf("local request body = %q", body)
	}
	if len(proxied) != 0 {
		t.Fatal("local request went through the proxy")
	}
}

func TestHTTPClientSendsEveryLocalHostDirect(t *testing.T) {
	var proxied []string
	proxy := func(r *http.Request) (*url.URL, error) {
		proxied = append(proxied, r.URL.Host)
		return nil, errors.New("proxy consulted")
	}
	client := NewHTTPClient(nil, nil, proxy)
	defer client.CloseIdleConnections()
	for _, host := range []string{"LOCALHOST:1", "127.0.0.2:1", "[::1]:1", "Host.Docker.Internal:1"} {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/", nil)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
		cancel()
	}
	if len(proxied) != 0 {
		t.Fatalf("local hosts went to the proxy: %v", proxied)
	}
}

func getBody(t *testing.T, client *http.Client, rawURL string) string {
	t.Helper()
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func urlString(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}
