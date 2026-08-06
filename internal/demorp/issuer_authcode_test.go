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

package demorp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func postForm(t *testing.T, h http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The pushed authorization request is where the wallet authenticates, so
// every requirement it fails has to be refused before the request is stored
// and turned into a request_uri somebody can redeem.
func TestPushedAuthorizationRequestRejections(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.IssuerHandler()

	tests := []struct {
		name       string
		form       url.Values
		wantStatus int
		wantError  string
	}{
		{
			name: "no DPoP proof",
			form: url.Values{
				"client_id":             {"wallet"},
				"response_type":         {"code"},
				"code_challenge_method": {"S256"},
				"code_challenge":        {"abc"},
				"redirect_uri":          {"http://wallet.example/cb"},
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_dpop_proof",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postForm(t, h, "/par", tt.form)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantError) {
				t.Errorf("body = %s, want it to name %s", rec.Body.String(), tt.wantError)
			}
		})
	}
}

// A request_uri nobody pushed cannot be resolved, and the error stays on the
// authorization endpoint rather than being redirected to a URL the caller
// supplied.
func TestAuthorizeRejectsAnUnknownRequestURI(t *testing.T) {
	d, _, _ := newDemoRP(t)

	req := httptest.NewRequest(http.MethodGet, "/authorize?request_uri="+url.QueryEscape("urn:ietf:params:oauth:request_uri:nope"), nil)
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Errorf("body = %s, want an invalid_request error", rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Errorf("Location = %q, want the error kept here rather than redirected", location)
	}
}

func TestAuthorizeRejectsAMissingRequestURI(t *testing.T) {
	d, _, _ := newDemoRP(t)

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

// Signing in is what turns a pushed request into a code, so a submission
// naming no request has nothing to complete.
func TestAuthorizeSubmitRejectsAnUnknownRequest(t *testing.T) {
	d, _, _ := newDemoRP(t)

	rec := postForm(t, d.IssuerHandler(), "/authorize", url.Values{
		"request_uri": {"urn:ietf:params:oauth:request_uri:nope"},
		"username":    {"erika"},
		"password":    {"whatever"},
	})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Errorf("body = %s, want an invalid_request error", rec.Body.String())
	}
}

func TestAuthorizeSubmitRejectsAMissingRequestURI(t *testing.T) {
	d, _, _ := newDemoRP(t)

	rec := postForm(t, d.IssuerHandler(), "/authorize", url.Values{"username": {"erika"}})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

// The authorization server metadata is what tells a wallet where to push its
// request and that PKCE with S256 is required.
func TestAuthorizationServerMetadata(t *testing.T) {
	d, _, _ := newDemoRP(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"pushed_authorization_request_endpoint",
		"authorization_endpoint",
		"token_endpoint",
		"S256",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metadata does not mention %s: %s", want, body)
		}
	}
}
