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
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

// interactiveTestWallet is a wallet at the feature level that uses Interactive
// Authorization, holding the PID the demo issuer asks for.
func interactiveTestWallet(t *testing.T) *wallet.Wallet {
	t.Helper()

	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	w.VCIVersion = wallet.VCIVersion11
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}
	return w
}

// The whole of OpenID4VCI 1.1 §6 between this toolkit's own wallet and its own
// issuer: the wallet asks the Authorization Challenge Endpoint, the issuer
// answers that a PID must be presented first, the wallet presents one, the
// issuer verifies it as a Verifier would, and only then hands over the
// authorization code the credential is collected with. No browser is involved.
func TestInteractiveAuthorizationEndToEnd(t *testing.T) {
	w := interactiveTestWallet(t)
	d, ts := serveDemoStack(t, w)

	offer := postJSONTo(t, ts.URL+"/issuer/api/offers?grant="+authCodeGrant+"&authorization="+authorizationPresentation, `{}`)
	uri, _ := offer["scheme_uri"].(string)
	if uri == "" {
		t.Fatalf("unexpected offer response: %v", offer)
	}

	before := len(w.GetCredentials())
	result, err := w.ProcessCredentialOffer(uri)
	if err != nil {
		t.Fatalf("redeeming the offer through interactive authorization: %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}
	if got := len(w.GetCredentials()); got != before+1 {
		t.Errorf("credential count = %d, want %d", got, before+1)
	}

	// The ticket names the holder of the PID that was presented, which is the
	// only thing that authorized this issuance.
	issued, ok := w.GetCredential(result.CredentialID)
	if !ok {
		t.Fatalf("credential %s is not in the wallet", result.CredentialID)
	}
	if got, _ := issued.Claims["family_name"].(string); got != "MUSTERMANN" {
		t.Errorf("issued credential family_name = %q, want the presented holder", got)
	}

	// The issuer verified a presentation bound to its challenge endpoint.
	if got := d.challengeEndpoint(); !strings.HasSuffix(got, "/issuer/authorize-challenge") {
		t.Errorf("challenge endpoint = %q", got)
	}
	for _, entry := range w.GetLog() {
		details := entry.Details
		if details == nil {
			continue
		}
		if details["event"] == "interactive_authorization_presentation" {
			return
		}
	}
	t.Errorf("no log entry recorded the presentation, log: %v", w.GetLog())
}

// The issuer decides per offer. An offer that wants the browser sign-in asks
// a wallet that advertises it for the auth_via_web interaction (OpenID4VCI
// 1.1 §6.2.1.2), and the wallet publishes the sign-in URL rather than
// finishing on its own.
func TestOfferCanAskForTheBrowserSignInInstead(t *testing.T) {
	w := interactiveTestWallet(t)
	_, ts := serveDemoStack(t, w)

	offer := postJSONTo(t, ts.URL+"/issuer/api/offers?grant="+authCodeGrant+"&authorization="+authorizationBrowser, `{}`)
	uri, _ := offer["scheme_uri"].(string)
	if uri == "" {
		t.Fatalf("unexpected offer response: %v", offer)
	}

	authCh, unsubscribe := w.SubscribeAuthorization()
	defer unsubscribe()
	done := make(chan error, 1)
	go func() {
		_, err := w.ProcessCredentialOffer(uri)
		done <- err
	}()

	select {
	case authURL := <-authCh:
		if !strings.Contains(authURL, "/issuer/authorize") {
			t.Errorf("sign-in URL = %q, want the issuer's authorization endpoint", authURL)
		}
		if !strings.Contains(authURL, "request_uri=") {
			t.Errorf("sign-in URL = %q, want the pushed request the challenge endpoint handed back", authURL)
		}
	case err := <-done:
		t.Fatalf("the flow ended without asking for a sign-in: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the sign-in URL")
	}

	for _, entry := range w.GetLog() {
		if entry.Details != nil && entry.Details["event"] == "interactive_authorization_auth_via_web" {
			return
		}
	}
	t.Errorf("no log entry recorded the browser interaction, log: %v", w.GetLog())
}

// A wallet that offers only the presentation interaction still reaches the
// browser sign-in: the issuer falls back to redirect_to_web (Section
// 5.2.2.1.1 of the first-party-apps specification), which needs no
// interaction support from the wallet.
func TestBrowserOfferFallsBackToRedirectToWeb(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	rec := postAuthorizationChallenge(t, d, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	}, url.Values{"interaction_types_supported": {interactionTypePresentation}})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"redirect_to_web"`) {
		t.Errorf("body = %s, want redirect_to_web", rec.Body.String())
	}
}

// A browser offer redeemed by a wallet that advertises auth_via_web gets the
// Interaction Required Response of §6.2.1.2: insufficient_authorization
// naming the interaction, an auth_session, and the request_uri the wallet
// takes to the authorization endpoint.
func TestBrowserOfferAsksForTheAuthViaWebInteraction(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	rec := postAuthorizationChallenge(t, d, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	}, url.Values{"interaction_types_supported": {interactionTypePresentation + "," + interactionTypeAuthViaWeb}})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("parsing response %q: %v", rec.Body.String(), err)
	}
	if got := response["error"]; got != "insufficient_authorization" {
		t.Errorf("error = %v, want insufficient_authorization", got)
	}
	if got := response["interaction_type_required"]; got != interactionTypeAuthViaWeb {
		t.Errorf("interaction_type_required = %v, want %s", got, interactionTypeAuthViaWeb)
	}
	if session, _ := response["auth_session"].(string); session == "" {
		t.Error("the interaction required response carries no auth_session (§6.2.1)")
	}
	requestURI, _ := response["request_uri"].(string)
	if !strings.HasPrefix(requestURI, requestURIPrefix) {
		t.Errorf("request_uri = %q, want a pushed authorization request URI", requestURI)
	}
	if _, ok := response["expires_in"].(float64); !ok {
		t.Errorf("expires_in = %v, want a number", response["expires_in"])
	}
}

// A wallet at 1.0 is offered the same credential by the same issuer and takes
// the redirect flow, so the feature level is the only thing that decides.
func TestInteractiveAuthorizationIsNotOfferedAtFeatureLevel10(t *testing.T) {
	w := interactiveTestWallet(t)
	w.VCIVersion = wallet.VCIVersion10
	d, _ := serveDemoStack(t, w)

	metadata := d.authorizationServerMetadata()
	if _, published := metadata["authorization_challenge_endpoint"]; published {
		t.Error("the demo issuer published a challenge endpoint to a 1.0 wallet")
	}
	// require_interactive_authorization is never published: the redirect flow
	// works here too, so this server does not only accept the interactive one.
	if _, published := metadata["require_interactive_authorization"]; published {
		t.Error("the demo issuer claims to require interactive authorization")
	}
}

// §6.2.2: a wallet redeeming a presentation offer without offering the
// presentation interaction is told which type is missing, rather than being
// asked for one it cannot do.
func TestAuthorizationChallengeReportsAMissingInteractionType(t *testing.T) {
	d, _, _ := newDemoRP(t)
	issuerState := createPresentationOfferState(t, d)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	rec := postAuthorizationChallenge(t, d, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	}, url.Values{
		"issuer_state":                {issuerState},
		"interaction_types_supported": {interactionTypeAuthViaWeb},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "missing_interaction_type") {
		t.Errorf("body = %s, want missing_interaction_type", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), interactionTypePresentation) {
		t.Errorf("body = %s, want it to name the missing presentation type", rec.Body.String())
	}
}

// createPresentationOfferState creates an authorization code offer that wants
// the presentation, and returns its issuer_state.
func createPresentationOfferState(t *testing.T, d *DemoRP) string {
	t.Helper()
	status, created := doJSON(t, d.IssuerHandler(), http.MethodPost, "/api/offers?grant="+authCodeGrant+"&authorization="+authorizationPresentation, "{}", nil)
	if status != http.StatusCreated {
		t.Fatalf("creating the offer: status %d (%v)", status, created)
	}
	offerURI, _ := created["offer_uri"].(string)
	path := strings.TrimPrefix(offerURI, demoIssuerID)
	if path == offerURI || path == "" {
		t.Fatalf("unexpected offer_uri %q", offerURI)
	}
	status, offer := doJSON(t, d.IssuerHandler(), http.MethodGet, path, "", nil)
	if status != http.StatusOK {
		t.Fatalf("fetching the offer: status %d (%v)", status, offer)
	}
	grants, _ := offer["grants"].(map[string]any)
	authCode, _ := grants["authorization_code"].(map[string]any)
	issuerState, _ := authCode["issuer_state"].(string)
	if issuerState == "" {
		t.Fatalf("the offer carries no issuer_state: %v", offer)
	}
	return issuerState
}

// postAuthorizationChallenge sends a minimal challenge request with a valid
// DPoP proof, whatever client authentication the headers carry, and any extra
// form values. Without extras the form names no offer, so it lands on the
// browser sign-in path, whose redirect_to_web answer runs after client
// authentication: reaching it is proof the authentication passed.
func postAuthorizationChallenge(t *testing.T, d *DemoRP, headers map[string]string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	dpopKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating DPoP key: %v", err)
	}
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {"http://wallet.example"},
		"redirect_uri":          {"http://wallet.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	for key, values := range extra {
		form[key] = values
	}
	req := httptest.NewRequest(http.MethodPost, challengePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof(t, dpopKey, "POST", demoIssuerID+challengePath))
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)
	return rec
}

// The Authorization Challenge Endpoint is client-authenticated exactly like
// the PAR and token endpoints (§6.1 notes the Wallet Attestation "has to be
// included in this request" where the server requires one), so a wallet that
// sends no OAuth-Client-Attestation headers is refused in the default
// required mode and served in optional mode.
func TestAuthorizationChallengeRequiresClientAttestation(t *testing.T) {
	t.Run("required by default", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		rec := postAuthorizationChallenge(t, d, nil, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"invalid_client"`) {
			t.Errorf("body = %s, want an invalid_client error", rec.Body.String())
		}
	})

	t.Run("an attested request passes authentication", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		provider := foreignWalletProvider(t)
		clientKey, err := mock.GenerateKey()
		if err != nil {
			t.Fatalf("generating client key: %v", err)
		}
		rec := postAuthorizationChallenge(t, d, map[string]string{
			"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
			"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
		}, nil)
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("an attested request was refused as unauthenticated: %s", rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "redirect_to_web") {
			t.Errorf("body = %s, want the redirect_to_web answer that follows authentication", rec.Body.String())
		}
	})

	t.Run("optional", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		d.SetClientAuthMode(ClientAuthOptional)
		rec := postAuthorizationChallenge(t, d, nil, nil)
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("optional mode refused an unauthenticated client: %s", rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "redirect_to_web") {
			t.Errorf("body = %s, want the redirect_to_web answer that follows authentication", rec.Body.String())
		}
	})
}

// The whole auth_via_web flow of §6.2.1.2 against the demo issuer: the wallet
// asks the challenge endpoint, is handed a request_uri, sends the user to the
// authorization endpoint with it, and the login's redirect back to the wallet
// carries the code the ticket is issued with. The ticket names the account
// that signed in, which is only knowable if the login drove the flow.
func TestAuthViaWebFlowEndToEnd(t *testing.T) {
	w := interactiveTestWallet(t)
	_, ts := serveDemoStack(t, w)

	created := postJSONTo(t, ts.URL+"/issuer/api/offers?grant="+authCodeGrant+"&authorization="+authorizationBrowser, `{}`)
	schemeURI, _ := created["scheme_uri"].(string)
	if schemeURI == "" {
		t.Fatalf("unexpected offer response: %v", created)
	}

	accepted := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
	if accepted["status"] != "authorization_required" {
		t.Fatalf("redeeming the offer did not ask for a sign-in: %v", accepted)
	}
	authURL, _ := accepted["authorization_url"].(string)
	offerID, _ := accepted["offer_id"].(string)
	if !strings.Contains(authURL, "/issuer/authorize") || !strings.Contains(authURL, "request_uri=") {
		t.Fatalf("unexpected authorization URL %q", authURL)
	}

	// The URL came from the auth_via_web interaction, not from redirect_to_web.
	sawInteraction := false
	for _, entry := range w.GetLog() {
		if entry.Details == nil {
			continue
		}
		if entry.Details["event"] == "interactive_authorization_auth_via_web" {
			sawInteraction = true
		}
		if entry.Details["event"] == "interactive_authorization_redirect_to_web" {
			t.Error("the flow fell back to redirect_to_web although the wallet offered auth_via_web")
		}
	}
	if !sawInteraction {
		t.Error("no log entry recorded the auth_via_web interaction")
	}

	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	page, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("opening the authorization URL: %v", err)
	}
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in") {
		t.Fatalf("the authorization endpoint did not ask for a login: %d %s", page.StatusCode, truncate(string(body)))
	}

	login, err := client.PostForm(ts.URL+"/issuer/authorize", url.Values{
		"request_uri": {requestURIFromLoginPage(t, string(body))},
		"username":    {"alice"},
		"password":    {"alice"},
	})
	if err != nil {
		t.Fatalf("signing in: %v", err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusFound {
		t.Fatalf("login returned %d, want a redirect back to the wallet", login.StatusCode)
	}
	callback := login.Header.Get("Location")
	if !strings.Contains(callback, "code=") {
		t.Fatalf("login redirect %q carries no authorization code", callback)
	}
	cb, err := client.Get(callback)
	if err != nil {
		t.Fatalf("following the callback: %v", err)
	}
	cb.Body.Close()

	deadline := time.Now().Add(20 * time.Second)
	for {
		status := getJSONFrom(t, ts.URL+"/api/offers/"+offerID)
		state, _ := status["status"].(string)
		if state == "completed" {
			break
		}
		if state == "failed" {
			t.Fatalf("the auth_via_web flow failed: %v", status["error"])
		}
		if time.Now().After(deadline) {
			t.Fatalf("the issuance never completed after the login, last status %v", status)
		}
		time.Sleep(50 * time.Millisecond)
	}

	var ticket *wallet.StoredCredential
	for _, c := range w.GetCredentials() {
		if c.VCT == TicketVCT {
			credential := c
			ticket = &credential
		}
	}
	if ticket == nil {
		t.Fatal("no demo ticket was stored in the wallet")
	}
	if got := ticket.Claims["given_name"]; got != demoAccountGivenName {
		t.Errorf("ticket given_name = %v, want %q from the logged-in account", got, demoAccountGivenName)
	}
}

// signPID issues a holder-bound PID under the wallet's CA, the credential the
// interactive request asks for.
func signPID(t *testing.T, d *DemoRP, holderKey *ecdsa.PrivateKey) string {
	t.Helper()
	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       PIDVCT,
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"given_name": "ERIKA", "family_name": "MUSTERMANN"},
		Key:       d.wallet.IssuerKey,
		HolderKey: &holderKey.PublicKey,
		CertChain: chain,
	})
	if err != nil {
		t.Fatalf("signing PID: %v", err)
	}
	return raw
}

// startInteractiveSession runs an attested initial challenge request for a
// presentation offer and returns the auth_session and the nonce of the
// presentation request the issuer asked for.
func startInteractiveSession(t *testing.T, d *DemoRP, provider walletProvider, clientKey *ecdsa.PrivateKey, issuerState string) (session, nonce string) {
	t.Helper()
	rec := postAuthorizationChallenge(t, d, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	}, url.Values{
		"issuer_state":                {issuerState},
		"interaction_types_supported": {interactionTypePresentation},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("initial challenge request: status %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("parsing challenge response: %v", err)
	}
	session, _ = response["auth_session"].(string)
	request, _ := response["openid4vp_request"].(map[string]any)
	nonce, _ = request["nonce"].(string)
	if session == "" || nonce == "" {
		t.Fatalf("challenge response carries no session or nonce: %v", response)
	}
	return session, nonce
}

// The presentation an interactive session hands back is verified as a
// verifier would verify it, and a presentation that fails any check is
// answered with access_denied and no authorization code. The passing case
// runs last, so the refusals cannot be the harness getting the exchange
// wrong.
func TestInteractiveAuthorizationVerifiesThePresentation(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	issuerState := createPresentationOfferState(t, d)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	credential := signPID(t, d, holderKey)
	audience := "ia:" + d.challengeEndpoint()

	continueWith := func(t *testing.T, session, presentation string) *httptest.ResponseRecorder {
		t.Helper()
		vpToken, err := json.Marshal(map[string]any{"vp_token": map[string]any{"pid": []string{presentation}}})
		if err != nil {
			t.Fatalf("encoding openid4vp_response: %v", err)
		}
		return postAuthorizationChallenge(t, d, map[string]string{
			"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
			"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
		}, url.Values{
			"auth_session":       {session},
			"openid4vp_response": {string(vpToken)},
		})
	}

	refused := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "access_denied") {
			t.Errorf("body = %s, want access_denied", rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "authorization_code") {
			t.Errorf("a refused presentation was answered with a code: %s", rec.Body.String())
		}
	}

	t.Run("a wrong nonce is refused", func(t *testing.T) {
		session, _ := startInteractiveSession(t, d, provider, clientKey, issuerState)
		refused(t, continueWith(t, session, presentCredential(t, holderKey, credential, audience, "wrong-nonce")))
	})

	t.Run("an audience naming somebody else is refused", func(t *testing.T) {
		session, nonce := startInteractiveSession(t, d, provider, clientKey, issuerState)
		refused(t, continueWith(t, session, presentCredential(t, holderKey, credential, "https://verifier.example", nonce)))
	})

	t.Run("a key binding signed by another key is refused", func(t *testing.T) {
		otherKey, err := mock.GenerateKey()
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}
		session, nonce := startInteractiveSession(t, d, provider, clientKey, issuerState)
		refused(t, continueWith(t, session, presentCredential(t, otherKey, credential, audience, nonce)))
	})

	t.Run("a presentation passing every check gets the code", func(t *testing.T) {
		session, nonce := startInteractiveSession(t, d, provider, clientKey, issuerState)
		rec := continueWith(t, session, presentCredential(t, holderKey, credential, audience, nonce))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "authorization_code") {
			t.Errorf("body = %s, want an authorization code", rec.Body.String())
		}
	})
}

// The pushed requests a browser sign-in continues with live in the same
// state map the PAR endpoint fills and get the same cap: a full map answers
// 429.
func TestBrowserOfferChallengeIsCappedLikePAR(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	d.mu.Lock()
	for i := 0; i < maxEntries; i++ {
		uri := fmt.Sprintf("%sfill-%d", requestURIPrefix, i)
		d.authRequests[uri] = &authRequestState{requestURI: uri, expires: time.Now().Add(authRequestTTL)}
	}
	d.mu.Unlock()

	rec := postAuthorizationChallenge(t, d, map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	}, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once the state map is full (%s)", rec.Code, rec.Body.String())
	}
}

// §6.2.1 has the wallet send its auth_session on every further challenge
// request. A wallet coming back with the one the auth_via_web answer handed
// out gets the interaction again with a fresh request_uri, not
// invalid_grant.
func TestAuthViaWebSessionIsReOffered(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	attested := func() map[string]string {
		return map[string]string{
			"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
			"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
		}
	}

	first := postAuthorizationChallenge(t, d, attested(), url.Values{
		"interaction_types_supported": {interactionTypeAuthViaWeb},
	})
	if first.Code != http.StatusForbidden {
		t.Fatalf("initial answer: status %d, want 403 (%s)", first.Code, first.Body.String())
	}
	var initial map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &initial); err != nil {
		t.Fatalf("parsing initial answer: %v", err)
	}
	session, _ := initial["auth_session"].(string)
	firstRequestURI, _ := initial["request_uri"].(string)
	if session == "" || firstRequestURI == "" {
		t.Fatalf("initial answer carries no session or request_uri: %v", initial)
	}

	retry := postAuthorizationChallenge(t, d, attested(), url.Values{
		"auth_session": {session},
	})
	if retry.Code != http.StatusForbidden {
		t.Fatalf("retry: status %d, want the interaction again (%s)", retry.Code, retry.Body.String())
	}
	var again map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &again); err != nil {
		t.Fatalf("parsing retry answer: %v", err)
	}
	if got := again["interaction_type_required"]; got != interactionTypeAuthViaWeb {
		t.Errorf("interaction_type_required = %v, want %s", got, interactionTypeAuthViaWeb)
	}
	if got, _ := again["auth_session"].(string); got != session {
		t.Errorf("auth_session = %q, want the same session %q", got, session)
	}
	if got, _ := again["request_uri"].(string); got == "" || got == firstRequestURI {
		t.Errorf("request_uri = %q, want a fresh pushed request (first was %q)", got, firstRequestURI)
	}
}
