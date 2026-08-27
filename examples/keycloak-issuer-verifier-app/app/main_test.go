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
	"net/url"
	"testing"
)

func TestCreateLoginURLRequestsTheWalletIdP(t *testing.T) {
	s := newServer(config{
		KeycloakBaseURL: "http://localhost:8080",
		KeycloakRealm:   "wallet-app-demo",
		AppClientID:     "wallet-app",
		AppRedirectURI:  "http://127.0.0.1:8090/callback",
	})

	loginURL, err := s.createLoginURL()
	if err != nil {
		t.Fatalf("createLoginURL() error = %v", err)
	}

	parsed, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("parse login URL: %v", err)
	}
	if parsed.Path != "/realms/wallet-app-demo/protocol/openid-connect/auth" {
		t.Fatalf("login URL path = %q", parsed.Path)
	}
	q := parsed.Query()
	for key, want := range map[string]string{
		"client_id":             "wallet-app",
		"response_type":         "code",
		"scope":                 "openid",
		"code_challenge_method": "S256",
		"redirect_uri":          "http://127.0.0.1:8090/callback",
		"kc_idp_hint":           "oid4vp",
	} {
		if got := q.Get(key); got != want {
			t.Fatalf("login URL %s = %q, want %q", key, got, want)
		}
	}
	if q.Get("code_challenge") == "" {
		t.Fatal("login URL is missing a PKCE code_challenge")
	}
	if q.Get("state") == "" {
		t.Fatal("login URL is missing state")
	}
}

func TestCreateLoginURLRegistersPKCEVerifier(t *testing.T) {
	s := newServer(config{KeycloakBaseURL: "http://localhost:8080", KeycloakRealm: "wallet-app-demo"})

	loginURL, err := s.createLoginURL()
	if err != nil {
		t.Fatalf("createLoginURL() error = %v", err)
	}
	parsed, _ := url.Parse(loginURL)
	state := parsed.Query().Get("state")

	s.authMu.Lock()
	_, ok := s.authSessions[state]
	s.authMu.Unlock()
	if !ok {
		t.Fatalf("createLoginURL did not register a verifier for state %q", state)
	}
}
