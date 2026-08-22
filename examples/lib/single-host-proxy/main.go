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

package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type proxyHandler struct {
	app      *httputil.ReverseProxy
	keycloak *httputil.ReverseProxy
}

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:18090", "listen address")
	appURL := flag.String("app", "http://127.0.0.1:8090", "local app base URL")
	keycloakURL := flag.String("keycloak", "http://127.0.0.1:8080", "local keycloak base URL")
	flag.Parse()

	appTarget, err := url.Parse(*appURL)
	if err != nil {
		log.Fatalf("parse app URL: %v", err)
	}
	keycloakTarget, err := url.Parse(*keycloakURL)
	if err != nil {
		log.Fatalf("parse keycloak URL: %v", err)
	}

	handler := proxyHandler{
		app:      newReverseProxy(appTarget),
		keycloak: newReverseProxy(keycloakTarget),
	}

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("single-host proxy listening on %s", *listenAddr)
	log.Printf("app target: %s", appTarget)
	log.Printf("keycloak target: %s", keycloakTarget)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("proxy failed: %v", err)
	}
}

func (p proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isKeycloakRequest(r.URL.Path) {
		p.keycloak.ServeHTTP(w, r)
		return
	}
	p.app.ServeHTTP(w, r)
}

func isKeycloakRequest(path string) bool {
	for _, prefix := range []string{
		"/.well-known",
		"/admin",
		"/realms",
		"/resources",
		"/health",
		"/metrics",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			in, out := pr.In, pr.Out
			forwardedHost := in.Header.Get("X-Forwarded-Host")
			if forwardedHost == "" {
				forwardedHost = in.Host
			}
			forwardedProto := in.Header.Get("X-Forwarded-Proto")
			if forwardedProto == "" {
				if in.TLS != nil {
					forwardedProto = "https"
				} else {
					forwardedProto = "http"
				}
			}
			forwardedPort := in.Header.Get("X-Forwarded-Port")
			if forwardedPort == "" {
				if forwardedProto == "https" {
					forwardedPort = "443"
				} else {
					forwardedPort = "80"
				}
			}
			pr.SetURL(target)
			// Preserve the original Host header for the backend.
			out.Host = forwardedHost
			out.Header.Set("X-Forwarded-Host", forwardedHost)
			out.Header.Set("X-Forwarded-Proto", forwardedProto)
			out.Header.Set("X-Forwarded-Port", forwardedPort)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "upstream unavailable: "+err.Error(), http.StatusBadGateway)
		},
	}
	return proxy
}
