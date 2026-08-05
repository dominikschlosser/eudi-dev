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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A renewed credential keeps its id: a verifier query, a UI selection and the
// activity log all refer to credentials by id, so a new entry would read as
// the old one being deleted and an unrelated one appearing.
func TestRefreshCredentialKeepsTheIdentity(t *testing.T) {
	w := generateTestWallet(t)
	original := generateTestCredential(t, w)
	renewed := generateTestCredential(t, w)

	var refreshGrants int
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "refresh-1" {
				rw.WriteHeader(http.StatusBadRequest)
				return
			}
			refreshGrants++
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "fresh", "token_type": "Bearer",
				"refresh_token": "refresh-2", "expires_in": 300,
			})
		case strings.HasSuffix(r.URL.Path, "/credential"):
			if r.Header.Get("Authorization") != "Bearer fresh" {
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(rw).Encode(map[string]any{"credential": renewed})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	imported, err := w.ImportCredential(original)
	if err != nil {
		t.Fatal(err)
	}
	id := imported.ID
	w.rememberRenewal(id, "refresh-1", CredentialRenewal{
		Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
		CredentialEndpoint: srv.URL + "/credential", ConfigurationID: "cfg",
	})

	server := NewServer(w, 0, nil)
	before := len(w.GetCredentials())
	result, err := server.RefreshCredential(id)
	if err != nil {
		t.Fatalf("RefreshCredential: %v", err)
	}

	if result.ID != id {
		t.Errorf("the renewed credential has id %s, want the original %s", result.ID, id)
	}
	if got := len(w.GetCredentials()); got != before {
		t.Errorf("the wallet holds %d credentials, want %d: renewing must replace, not add", got, before)
	}
	stored, ok := w.GetCredential(id)
	if !ok {
		t.Fatal("the credential is gone after renewing it")
	}
	if stored.Raw != renewed {
		t.Error("the stored credential is still the old one")
	}
	// A rotated refresh token has to replace the stored one, or the next
	// renewal presents one the issuer already retired.
	if stored.Renewal == nil || stored.Renewal.RefreshToken != "refresh-2" {
		t.Errorf("the rotated refresh token was not stored: %+v", stored.Renewal)
	}
	if refreshGrants != 1 {
		t.Errorf("the issuer saw %d refresh grants, want 1", refreshGrants)
	}
}

func TestRefreshCredentialRefusesWithoutARefreshToken(t *testing.T) {
	w := generateTestWallet(t)
	imported, err := w.ImportCredential(generateTestCredential(t, w))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(w, 0, nil)
	if _, err := server.RefreshCredential(imported.ID); err == nil {
		t.Error("a credential with no refresh token was renewed")
	}
}
