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
	"time"
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

// The automatic sweep renews what is near expiry and leaves the rest alone,
// and one credential failing must not stop the others: the task would
// otherwise be abandoned over a single issuer being unreachable.
func TestRenewExpiringCredentialsSweep(t *testing.T) {
	w := generateTestWallet(t)

	fresh, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:test:fresh:1",
		Claims: map[string]any{"a": "1"}, ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	expiring, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:test:expiring:1",
		Claims: map[string]any{"a": "1"}, ExpiresIn: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Both can be renewed, but only one is close enough to expiry.
	unreachable := CredentialRenewal{
		Issuer: "https://issuer.example", TokenEndpoint: "https://127.0.0.1:1/token",
		CredentialEndpoint: "https://127.0.0.1:1/credential",
	}
	w.rememberRenewal(fresh.Credential.ID, "refresh-1", unreachable)
	w.rememberRenewal(expiring.Credential.ID, "refresh-1", unreachable)

	server := NewServer(w, 0, nil)
	now := time.Now()
	if err := server.renewExpiringCredentials(now); err != nil {
		t.Fatalf("the sweep reported failure over one credential: %v", err)
	}

	// The unreachable issuer failed, so the credential is held off rather than
	// retried on the next sweep half a minute later.
	if server.renewalDue(expiring.Credential.ID, now) {
		t.Error("a credential whose renewal just failed is due again immediately")
	}
	if !server.renewalDue(expiring.Credential.ID, now.Add(renewalRetryAfter+time.Second)) {
		t.Error("a failed renewal is never retried")
	}
	// The one nowhere near expiry was never attempted, so it has no backoff.
	if !server.renewalDue(fresh.Credential.ID, now) {
		t.Error("a credential far from expiry was attempted")
	}
}

// A credential about to expire is renewed on the way out. The background task
// only runs on a wallet server, so one that lapses between two presentations
// would otherwise be sent for the verifier to reject.
func TestPresentingRenewsACredentialAboutToExpire(t *testing.T) {
	w := generateTestWallet(t)
	replacement := generateTestCredential(t, w)

	var credentialRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(rw).Encode(map[string]any{"access_token": "fresh", "token_type": "Bearer"})
		case strings.HasSuffix(r.URL.Path, "/credential"):
			credentialRequests++
			_ = json.NewEncoder(rw).Encode(map[string]any{"credential": replacement})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	expiring, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:test:expiring:1",
		Claims: map[string]any{"given_name": "Alice"}, ExpiresIn: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := expiring.Credential.ID
	w.rememberRenewal(id, "refresh-1", CredentialRenewal{
		Issuer: srv.URL, TokenEndpoint: srv.URL + "/token", CredentialEndpoint: srv.URL + "/credential",
	})

	if _, err := w.CreateVPToken(CredentialMatch{
		CredentialID: id, QueryID: "q", Format: "dc+sd-jwt", SelectedKeys: []string{"given_name"},
	}, PresentationParams{Nonce: "n", ClientID: "verifier"}); err != nil {
		t.Fatalf("creating the VP token: %v", err)
	}

	if credentialRequests != 1 {
		t.Errorf("the issuer saw %d credential requests, want 1: a credential about to expire is renewed before it is presented", credentialRequests)
	}
	if stored, _ := w.GetCredential(id); stored.Raw != replacement {
		t.Error("the renewed credential was not stored")
	}
}

// An issuer that required client authentication at issuance requires it on
// every later token request too, and a refresh is a token request. The flow
// that discovered the requirement is long gone by then, so what it learned
// travels with the credential.
func TestRefreshCredentialAuthenticatesTheClient(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	original := generateTestCredential(t, w)
	renewed := generateTestCredential(t, w)

	var challenges int
	var sawAttestation, sawPoP, sawAssertion string
	newIssuer := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			switch {
			case strings.HasSuffix(r.URL.Path, "/challenge"):
				challenges++
				_ = json.NewEncoder(rw).Encode(map[string]any{"attestation_challenge": "chal-1"})
			case strings.HasSuffix(r.URL.Path, "/token"):
				body, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(body))
				sawAttestation = r.Header.Get("OAuth-Client-Attestation")
				sawPoP = r.Header.Get("OAuth-Client-Attestation-PoP")
				sawAssertion = form.Get("client_assertion")
				_ = json.NewEncoder(rw).Encode(map[string]any{
					"access_token": "fresh", "token_type": "Bearer", "expires_in": 300,
				})
			case strings.HasSuffix(r.URL.Path, "/credential"):
				_ = json.NewEncoder(rw).Encode(map[string]any{"credential": renewed})
			default:
				rw.WriteHeader(http.StatusNotFound)
			}
		}))
	}

	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	t.Run("wallet attestation", func(t *testing.T) {
		srv := newIssuer()
		defer srv.Close()
		httpClient = srv.Client()
		challenges, sawAttestation, sawPoP, sawAssertion = 0, "", "", ""

		imported, err := w.ImportCredential(original)
		if err != nil {
			t.Fatal(err)
		}
		w.rememberRenewal(imported.ID, "refresh-1", CredentialRenewal{
			Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
			CredentialEndpoint: srv.URL + "/credential",
			ClientAuth: &ClientAuthentication{
				Method:            ClientAuthAttestation,
				ClientID:          "https://wallet.example",
				Audience:          srv.URL,
				ChallengeEndpoint: srv.URL + "/challenge",
			},
		})
		if _, err := w.RefreshCredential(imported.ID); err != nil {
			t.Fatalf("RefreshCredential: %v", err)
		}
		if sawAttestation == "" || sawPoP == "" {
			t.Error("the refresh carried no client attestation")
		}
		// A server that mints challenges rejects a stale one, so the refresh
		// has to ask for its own rather than replay one from issuance.
		if challenges != 1 {
			t.Errorf("the refresh fetched %d attestation challenges, want 1", challenges)
		}
	})

	t.Run("private_key_jwt", func(t *testing.T) {
		srv := newIssuer()
		defer srv.Close()
		httpClient = srv.Client()
		challenges, sawAttestation, sawPoP, sawAssertion = 0, "", "", ""

		imported, err := w.ImportCredential(original)
		if err != nil {
			t.Fatal(err)
		}
		w.rememberRenewal(imported.ID, "refresh-1", CredentialRenewal{
			Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
			CredentialEndpoint: srv.URL + "/credential",
			ClientAuth: &ClientAuthentication{
				Method: ClientAuthPrivateKeyJWT, ClientID: "wallet-1", Audience: srv.URL,
			},
		})
		if _, err := w.RefreshCredential(imported.ID); err != nil {
			t.Fatalf("RefreshCredential: %v", err)
		}
		if sawAssertion == "" {
			t.Error("the refresh carried no client assertion")
		}
		if sawAttestation != "" || sawPoP != "" {
			t.Error("private_key_jwt authenticates in the form, not with an attestation on top")
		}
	})

	t.Run("nothing required", func(t *testing.T) {
		srv := newIssuer()
		defer srv.Close()
		httpClient = srv.Client()
		challenges, sawAttestation, sawPoP, sawAssertion = 0, "", "", ""

		imported, err := w.ImportCredential(original)
		if err != nil {
			t.Fatal(err)
		}
		w.rememberRenewal(imported.ID, "refresh-1", CredentialRenewal{
			Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
			CredentialEndpoint: srv.URL + "/credential",
		})
		if _, err := w.RefreshCredential(imported.ID); err != nil {
			t.Fatalf("RefreshCredential: %v", err)
		}
		if sawAttestation != "" || sawAssertion != "" {
			t.Error("an issuer that asked for no client authentication got one anyway")
		}
	})
}

// What the issuance flow keeps with the credential is read off the
// authorization server's metadata, so it has to be read the same way a
// request would.
func TestResolveClientAuthentication(t *testing.T) {
	w := generateTestWallet(t)
	ctx := clientAuthContext{
		clientID:      "https://wallet.example",
		tokenEndpoint: "https://issuer.example/token",
		oauthMeta: map[string]any{
			"issuer":                                "https://issuer.example",
			"challenge_endpoint":                    "https://issuer.example/challenge",
			"token_endpoint_auth_methods_supported": []any{"attest_jwt_client_auth"},
		},
	}

	auth := w.resolveClientAuthentication(detectTokenEndpointAuthMethod(ctx.oauthMeta), ctx)
	if auth == nil || auth.Method != ClientAuthAttestation {
		t.Fatalf("an attesting issuer resolved to %+v", auth)
	}
	if auth.Audience != "https://issuer.example" || auth.ChallengeEndpoint != "https://issuer.example/challenge" {
		t.Errorf("the attestation does not carry what rebuilding it needs: %+v", auth)
	}

	private := clientAuthContext{clientID: ctx.clientID, tokenEndpoint: ctx.tokenEndpoint, oauthMeta: map[string]any{
		"issuer":                                "https://issuer.example",
		"token_endpoint_auth_methods_supported": []any{"private_key_jwt"},
	}}
	auth = w.resolveClientAuthentication(detectTokenEndpointAuthMethod(private.oauthMeta), private)
	if auth == nil || auth.Method != ClientAuthPrivateKeyJWT {
		t.Fatalf("a private_key_jwt issuer resolved to %+v", auth)
	}

	// An issuer that asks for nothing, with a wallet that is not enforcing
	// the profile, gets the same plain request as before.
	plain := clientAuthContext{clientID: ctx.clientID, tokenEndpoint: ctx.tokenEndpoint, oauthMeta: map[string]any{}}
	if auth := w.resolveClientAuthentication("", plain); auth != nil {
		t.Errorf("an issuer that asked for nothing resolved to %+v", auth)
	}

	// Enforcing HAIP means authenticating whatever the metadata says.
	w.RequireHAIP = true
	if auth := w.resolveClientAuthentication("", plain); auth == nil || auth.Method != ClientAuthAttestation {
		t.Errorf("HAIP enforcement did not authenticate the client: %+v", auth)
	}
}
