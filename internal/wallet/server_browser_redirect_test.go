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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func browserGet(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	return w
}

func presentationAuthorizePath(t *testing.T, verifierURL string) string {
	t.Helper()
	dcqlJSON, err := json.Marshal(pidDCQLQuery())
	if err != nil {
		t.Fatalf("marshal dcql: %v", err)
	}
	return "/authorize?" + url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifierURL},
		"dcql_query":    {string(dcqlJSON)},
	}.Encode()
}

func TestAuthorize_BrowserRedirectsToVerifier(t *testing.T) {
	srv := newTestServer(t, true)

	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"redirect_uri":"https://verifier.example/continue?code=xyz"}`))
	}))
	defer verifier.Close()

	rec := browserGet(t, srv, presentationAuthorizePath(t, verifier.URL))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "https://verifier.example/continue?code=xyz" {
		t.Fatalf("unexpected Location: %q", got)
	}
}

func TestAuthorize_BrowserWithoutVerifierRedirectLandsOnWalletUI(t *testing.T) {
	srv := newTestServer(t, true)

	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	rec := browserGet(t, srv, presentationAuthorizePath(t, verifier.URL))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("unexpected Location: %q", got)
	}
}

func TestAuthorize_APICallStillGetsJSON(t *testing.T) {
	srv := newTestServer(t, true)

	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"redirect_uri":"https://verifier.example/continue"}`))
	}))
	defer verifier.Close()

	// No HTML Accept header: same request must keep returning JSON.
	rec := serverRequest(t, srv, "GET", presentationAuthorizePath(t, verifier.URL), "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	result := decodeJSON(t, rec)
	if result["status"] != "submitted" {
		t.Fatalf("expected status submitted, got %v", result["status"])
	}
}

func TestAuthorize_InteractiveBrowserRedirectsToWalletUIThenSubmits(t *testing.T) {
	srv := newTestServer(t, false)

	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"redirect_uri":"https://verifier.example/continue?code=xyz"}`))
	}))
	defer verifier.Close()

	// The navigation must not block on consent: it redirects to the wallet
	// UI immediately, leaving the consent request pending.
	rec := browserGet(t, srv, presentationAuthorizePath(t, verifier.URL))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("unexpected Location: %q", got)
	}

	pending := srv.wallet.GetPendingRequests()
	if len(pending) != 1 {
		t.Fatalf("expected one pending consent request, got %d", len(pending))
	}

	// Approving finishes the detached flow; the approve response carries the
	// verifier redirect_uri the UI navigates to.
	approveRec := serverRequest(t, srv, "POST", "/api/requests/"+pending[0].ID+"/approve", `{}`)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", approveRec.Code, approveRec.Body.String())
	}
	result := decodeJSON(t, approveRec)
	if result["redirect_uri"] != "https://verifier.example/continue?code=xyz" {
		t.Fatalf("expected verifier redirect_uri in approve response, got %v", result["redirect_uri"])
	}
}

func TestCredentialOfferEndpoint_InteractiveBrowserRedirectsToWalletUIThenImports(t *testing.T) {
	srv := newTestServer(t, false)

	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{})
	defer issuer.Close()

	parsed, err := url.Parse(offerURI)
	if err != nil {
		t.Fatalf("parsing offer URI: %v", err)
	}
	credentialOffer := parsed.Query().Get("credential_offer")

	before := len(srv.wallet.GetCredentials())
	rec := browserGet(t, srv, "/credential-offer?credential_offer="+url.QueryEscape(credentialOffer))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("unexpected Location: %q", got)
	}
	if after := len(srv.wallet.GetCredentials()); after != before {
		t.Fatalf("credential must not be imported before consent, before=%d after=%d", before, after)
	}

	pending := srv.wallet.GetPendingRequests()
	if len(pending) != 1 {
		t.Fatalf("expected one pending consent request, got %d", len(pending))
	}

	approveRec := serverRequest(t, srv, "POST", "/api/requests/"+pending[0].ID+"/approve", `{}`)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", approveRec.Code, approveRec.Body.String())
	}

	if after := len(srv.wallet.GetCredentials()); after != before+1 {
		t.Fatalf("expected one imported credential after approval, got before=%d after=%d", before, after)
	}
}

func TestCredentialOfferEndpoint_BrowserRedirectsToWalletUI(t *testing.T) {
	srv := newTestServer(t, true)

	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{})
	defer issuer.Close()

	parsed, err := url.Parse(offerURI)
	if err != nil {
		t.Fatalf("parsing offer URI: %v", err)
	}
	credentialOffer := parsed.Query().Get("credential_offer")

	before := len(srv.wallet.GetCredentials())
	rec := browserGet(t, srv, "/credential-offer?credential_offer="+url.QueryEscape(credentialOffer))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("unexpected Location: %q", got)
	}
	if after := len(srv.wallet.GetCredentials()); after != before+1 {
		t.Fatalf("expected one imported credential, got before=%d after=%d", before, after)
	}
}
