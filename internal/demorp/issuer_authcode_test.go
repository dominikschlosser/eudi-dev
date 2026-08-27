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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
)

// demoIssuerID is what newDemoRP's base URL makes of the issuer, and what
// every audience and DPoP htu in these tests has to name.
const demoIssuerID = "http://demo.example/issuer"

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

// walletProvider is an attester with a certificate authority of its own, which
// is what every wallet this issuer was not built alongside carries.
type walletProvider struct {
	key  *ecdsa.PrivateKey
	leaf *x509.Certificate
}

func foreignWalletProvider(t *testing.T) walletProvider {
	t.Helper()
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating attester CA key: %v", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("generating attester CA certificate: %v", err)
	}
	signingKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating attester signing key: %v", err)
	}
	leaf, err := mock.GenerateLeafCert(caKey, caCert, &signingKey.PublicKey)
	if err != nil {
		t.Fatalf("generating attester leaf certificate: %v", err)
	}
	return walletProvider{key: signingKey, leaf: leaf}
}

// attest issues a Client Attestation JWT for a client and the key it holds.
// The claims are those draft-ietf-oauth-attestation-based-client-auth-10 §4
// requires, which since draft -08 no longer include iss.
func (p walletProvider) attest(t *testing.T, clientID string, clientKey *ecdsa.PrivateKey) string {
	t.Helper()
	return signES256(t, p.key,
		map[string]any{
			"alg": "ES256",
			"typ": "oauth-client-attestation+jwt",
			"x5c": []any{base64.StdEncoding.EncodeToString(p.leaf.Raw)},
		},
		map[string]any{
			"sub": clientID,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"cnf": map[string]any{"jwk": holderJWK(t, clientKey)},
		},
	)
}

// attestationPoP proves possession of the attested key for one request, with
// the claims §5.1 requires and none of the ones it dropped.
func attestationPoP(t *testing.T, clientKey *ecdsa.PrivateKey, audience string) string {
	t.Helper()
	return signES256(t, clientKey,
		map[string]any{"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt", "jwk": holderJWK(t, clientKey)},
		map[string]any{"aud": audience, "iat": time.Now().Unix(), "jti": "pop-" + audience},
	)
}

func dpopProof(t *testing.T, key *ecdsa.PrivateKey, method, htu string) string {
	t.Helper()
	return dpopProofForToken(t, key, method, htu, "")
}

// dpopProofForToken adds the ath claim RFC 9449 requires of a proof that
// accompanies an access token.
func dpopProofForToken(t *testing.T, key *ecdsa.PrivateKey, method, htu, accessToken string) string {
	t.Helper()
	payload := map[string]any{"htm": method, "htu": htu, "iat": time.Now().Unix(), "jti": "dpop-" + htu}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		payload["ath"] = format.EncodeBase64URL(sum[:])
	}
	return signES256(t, key,
		map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": holderJWK(t, key)},
		payload,
	)
}

// pushAuthorizationRequest pushes a minimal but complete authorization request
// with whatever client authentication the headers carry.
func pushAuthorizationRequest(t *testing.T, h http.Handler, clientID string, dpopKey *ecdsa.PrivateKey, challenge string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {challenge},
		"redirect_uri":          {"http://wallet.example/cb"},
	}
	req := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof(t, dpopKey, "POST", demoIssuerID+"/par"))
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// An attestation signed by a wallet provider this issuer was never given is
// what an external wallet brings, and refusing every one of them would leave
// the authorization code flow completable by this project's own wallet alone.
// It is accepted, and what the issuer could not establish about it travels with
// the credential instead.
func TestPushedAuthorizationRequestAcceptsAnUntrustedAttester(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", map[string]string{
		"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
		"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
}

// The DPoP-combined method of draft -10 §5.2: the request carries the
// attestation and a DPoP proof signed by the attested key, and no separate PoP
// JWT. The key is what ties the two together, so a DPoP proof from any other
// key proves nothing about the attestation.
func TestPushedAuthorizationRequestAcceptsADPoPCombinedProof(t *testing.T) {
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	otherKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating second key: %v", err)
	}

	t.Run("the DPoP proof is signed by the attested key", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", map[string]string{
			"OAuth-Client-Attestation": provider.attest(t, "http://wallet.example", clientKey),
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("the DPoP proof is signed by another key", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", otherKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", map[string]string{
			"OAuth-Client-Attestation": provider.attest(t, "http://wallet.example", clientKey),
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invalid_client_attestation") {
			t.Errorf("body = %s, want an invalid_client_attestation error", rec.Body.String())
		}
	})
}

// An attestation that was presented and did not verify is a different answer
// from no attestation at all, and draft -10 §6.2 has a code for it.
func TestPushedAuthorizationRequestNamesABrokenAttestation(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "the attestation names another client",
			headers: map[string]string{
				"OAuth-Client-Attestation":     provider.attest(t, "http://somebody.else", clientKey),
				"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
			},
		},
		{
			name: "the PoP is signed by a key the attestation does not attest",
			headers: map[string]string{
				"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
				"OAuth-Client-Attestation-PoP": attestationPoP(t, provider.key, demoIssuerID),
			},
		},
		{
			name: "the PoP is addressed to another server",
			headers: map[string]string{
				"OAuth-Client-Attestation":     provider.attest(t, "http://wallet.example", clientKey),
				"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, "http://another.example"),
			},
		},
		{
			name: "a PoP arrives without the attestation it proves",
			headers: map[string]string{
				"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", tt.headers)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "invalid_client_attestation") {
				t.Errorf("body = %s, want an invalid_client_attestation error", rec.Body.String())
			}
		})
	}
}

// A client that presents nothing is the general case of no client
// authentication, which is invalid_client rather than a complaint about an
// attestation nobody sent.
func TestPushedAuthorizationRequestWithoutClientAuthentication(t *testing.T) {
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}

	t.Run("required by default", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"invalid_client"`) {
			t.Errorf("body = %s, want an invalid_client error", rec.Body.String())
		}
	})

	t.Run("optional", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		d.SetClientAuthMode(ClientAuthOptional)
		rec := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body.String())
		}
	})

	// An unauthenticated client is identified by client_id alone, so a request
	// that carries neither identifies nobody.
	t.Run("optional and nameless", func(t *testing.T) {
		d, _, _ := newDemoRP(t)
		d.SetClientAuthMode(ClientAuthOptional)
		rec := pushAuthorizationRequest(t, d.IssuerHandler(), "", clientKey, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
		}
	})
}

// The whole authorization code flow driven by a wallet that authenticates with
// nothing, which is what an interoperability test against another wallet needs
// and what the optional mode is for. The ticket says how it was collected.
func TestAuthorizationCodeFlowWithoutClientAuthentication(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)
	h := d.IssuerHandler()

	verifier := "aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"
	sum := sha256.Sum256([]byte(verifier))
	challenge := format.EncodeBase64URL(sum[:])

	code, offerDoc := doJSON(t, h, "POST", "/api/offers?grant="+authCodeGrant, "", nil)
	if code != http.StatusCreated {
		t.Fatalf("creating offer: %d %v", code, offerDoc)
	}

	pushed := pushAuthorizationRequest(t, h, "http://wallet.example", holderKey, challenge, nil)
	if pushed.Code != http.StatusCreated {
		t.Fatalf("pushing the authorization request: %d %s", pushed.Code, pushed.Body.String())
	}
	var pushedDoc map[string]any
	if err := json.Unmarshal(pushed.Body.Bytes(), &pushedDoc); err != nil {
		t.Fatalf("decoding the pushed authorization response: %v", err)
	}
	requestURI, _ := pushedDoc["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("no request_uri in %v", pushedDoc)
	}

	login := postForm(t, h, "/authorize", url.Values{
		"request_uri": {requestURI},
		"username":    {demoAccountUsername},
		"password":    {demoAccountPassword},
	})
	if login.Code != http.StatusFound {
		t.Fatalf("signing in: %d %s", login.Code, login.Body.String())
	}
	redirect, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the callback: %v", err)
	}
	authCode := redirect.Query().Get("code")
	if authCode == "" {
		t.Fatalf("the callback %q carries no code", redirect)
	}

	tokenForm := url.Values{
		"grant_type":    {authCodeGrant},
		"code":          {authCode},
		"client_id":     {"http://wallet.example"},
		"redirect_uri":  {"http://wallet.example/cb"},
		"code_verifier": {verifier},
	}
	code, tokenDoc := doJSON(t, h, "POST", "/token", tokenForm.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"DPoP":         dpopProof(t, holderKey, "POST", demoIssuerID+"/token"),
	})
	if code != http.StatusOK {
		t.Fatalf("token request: %d %v", code, tokenDoc)
	}
	accessToken, _ := tokenDoc["access_token"].(string)

	_, nonceDoc := doJSON(t, h, "POST", "/nonce", "", nil)
	proof := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holderJWK(t, holderKey)},
		map[string]any{"aud": demoIssuerID, "iat": time.Now().Unix(), "nonce": nonceDoc["c_nonce"]},
	)
	body := fmt.Sprintf(`{"credential_configuration_id":%q,"proofs":{"jwt":[%q]}}`, ticketConfigurationID, proof)
	code, credDoc := doJSON(t, h, "POST", "/credential", body, map[string]string{
		"Authorization": "DPoP " + accessToken,
		"Content-Type":  "application/json",
		"DPoP":          dpopProofForToken(t, holderKey, "POST", demoIssuerID+"/credential", accessToken),
	})
	if code != http.StatusOK {
		t.Fatalf("credential request: %d %v", code, credDoc)
	}

	creds, _ := credDoc["credentials"].([]any)
	first, _ := creds[0].(map[string]any)
	raw, _ := first["credential"].(string)
	issued, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("parsing the issued credential: %v", err)
	}
	// A credential collected by a client that never authenticated says so, so
	// that it cannot be mistaken for one backed by a wallet attestation.
	if got := issued.ResolvedClaims["wallet_attestation"]; got != "none" {
		t.Errorf("wallet_attestation = %v, want none", got)
	}
	// The login still happened, and it is what the ticket is made out to.
	if got := issued.ResolvedClaims["given_name"]; got != demoAccountGivenName {
		t.Errorf("given_name = %v, want %q", got, demoAccountGivenName)
	}
}

// RFC 9126 §4 gives a client one use of a request_uri, which is how this
// issuer catches a wallet that resolves one pushed request twice.
func TestAuthorizeSpendsTheRequestURI(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)
	h := d.IssuerHandler()

	verifier := "aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"
	sum := sha256.Sum256([]byte(verifier))
	pushed := pushAuthorizationRequest(t, h, "http://wallet.example", holderKey, format.EncodeBase64URL(sum[:]), nil)
	if pushed.Code != http.StatusCreated {
		t.Fatalf("pushing the authorization request: %d %s", pushed.Code, pushed.Body.String())
	}
	var pushedDoc map[string]any
	if err := json.Unmarshal(pushed.Body.Bytes(), &pushedDoc); err != nil {
		t.Fatalf("decoding the pushed authorization response: %v", err)
	}
	requestURI, _ := pushedDoc["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("no request_uri in %v", pushedDoc)
	}

	authorize := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/authorize?request_uri="+url.QueryEscape(requestURI), nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if first := authorize(); first.Code != http.StatusOK {
		t.Fatalf("the first authorization request: %d %s", first.Code, first.Body.String())
	}
	second := authorize()
	if second.Code != http.StatusBadRequest {
		t.Errorf("the second authorization request: %d, want 400 (%s)", second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "already") {
		t.Errorf("body = %s, want it to say the request_uri is spent", second.Body.String())
	}

	// The login form carries the same value back, as the issuer's own step.
	login := postForm(t, h, "/authorize", url.Values{
		"request_uri": {requestURI},
		"username":    {demoAccountUsername},
		"password":    {demoAccountPassword},
	})
	if login.Code != http.StatusFound {
		t.Fatalf("signing in after the login page was served: %d %s", login.Code, login.Body.String())
	}
}

// The login page must widen form-action to the client's redirect_uri. Under
// the toolkit's global form-action 'self', a browser enforcing form-action
// across the post-login redirect blocks a cross-origin or custom-scheme
// redirect_uri (every real mobile wallet), so the login silently does nothing.
func TestLoginPageAllowsTheRedirectTarget(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)
	h := d.IssuerHandler()

	verifier := "aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"
	sum := sha256.Sum256([]byte(verifier))
	pushed := pushAuthorizationRequest(t, h, "http://wallet.example", holderKey, format.EncodeBase64URL(sum[:]), nil)
	if pushed.Code != http.StatusCreated {
		t.Fatalf("pushing the authorization request: %d %s", pushed.Code, pushed.Body.String())
	}
	var pushedDoc map[string]any
	if err := json.Unmarshal(pushed.Body.Bytes(), &pushedDoc); err != nil {
		t.Fatalf("decoding the pushed authorization response: %v", err)
	}
	requestURI, _ := pushedDoc["request_uri"].(string)

	req := httptest.NewRequest(http.MethodGet, "/authorize?request_uri="+url.QueryEscape(requestURI), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("serving the login page: %d %s", rec.Code, rec.Body.String())
	}
	// The helper pushes redirect_uri http://wallet.example/cb, so the login must
	// let its form submission reach that origin.
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' http://wallet.example;") {
		t.Errorf("login CSP must allow the redirect origin, got %q", csp)
	}
}

// The sign-in page's debug panel shows the client authentication the wallet
// sent, so a wallet developer can inspect the client_id, the attestation and
// the attestation PoP their client presented.
func TestLoginPageDebugPanelShowsClientAuthentication(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.IssuerHandler()

	provider := foreignWalletProvider(t)
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	attestation := provider.attest(t, "wallet", clientKey)
	pop := attestationPoP(t, clientKey, demoIssuerID)

	verifier := "aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"
	sum := sha256.Sum256([]byte(verifier))
	pushed := pushAuthorizationRequest(t, h, "wallet", holderKey, format.EncodeBase64URL(sum[:]), map[string]string{
		"OAuth-Client-Attestation":     attestation,
		"OAuth-Client-Attestation-PoP": pop,
	})
	if pushed.Code != http.StatusCreated {
		t.Fatalf("pushing the authorization request: %d %s", pushed.Code, pushed.Body.String())
	}
	var pushedDoc map[string]any
	if err := json.Unmarshal(pushed.Body.Bytes(), &pushedDoc); err != nil {
		t.Fatalf("decoding the pushed authorization response: %v", err)
	}
	requestURI, _ := pushedDoc["request_uri"].(string)

	req := httptest.NewRequest(http.MethodGet, "/authorize?request_uri="+url.QueryEscape(requestURI), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("serving the login page: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{">wallet<", attestation, pop} {
		if !strings.Contains(body, want) {
			t.Errorf("the debug panel does not show %q\nbody = %s", want, body)
		}
	}
}

func TestRedirectFormActionSource(t *testing.T) {
	cases := map[string]string{
		"https://wallet.example/cb":           "https://wallet.example",
		"http://wallet.example:8080/cb":       "http://wallet.example:8080",
		"openid-credential-offer://authorize": "openid-credential-offer:",
		"eudi-openid4ci://cb":                 "eudi-openid4ci:",
		"not a url":                           "",
		"":                                    "",
	}
	for in, want := range cases {
		if got := redirectFormActionSource(in); got != want {
			t.Errorf("redirectFormActionSource(%q) = %q, want %q", in, got, want)
		}
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
		// draft-ietf-oauth-attestation-based-client-auth-10 §10.1 requires
		// both of a server that supports the method.
		"client_attestation_signing_alg_values_supported",
		"client_attestation_pop_signing_alg_values_supported",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metadata does not mention %s: %s", want, body)
		}
	}
}

// What the endpoints accept and what the metadata says have to be the same
// thing: the auth methods list is where a wallet reads whether it has to
// authenticate here at all.
func TestAuthorizationServerMetadataFollowsTheClientAuthMode(t *testing.T) {
	authMethods := func(d *DemoRP) []string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		rec := httptest.NewRecorder()
		d.IssuerHandler().ServeHTTP(rec, req)
		var metadata map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
			t.Fatalf("decoding metadata: %v", err)
		}
		raw, _ := metadata["token_endpoint_auth_methods_supported"].([]any)
		methods := make([]string, 0, len(raw))
		for _, entry := range raw {
			method, _ := entry.(string)
			methods = append(methods, method)
		}
		return methods
	}
	has := func(methods []string, want string) bool {
		for _, method := range methods {
			if method == want {
				return true
			}
		}
		return false
	}

	required, _, _ := newDemoRP(t)
	methods := authMethods(required)
	for _, want := range []string{attestationClientAuth, attestationDPoPClientAuth} {
		if !has(methods, want) {
			t.Errorf("methods = %v, want it to offer %s", methods, want)
		}
	}
	if has(methods, unauthenticatedClientAuth) {
		t.Errorf("methods = %v, want no unauthenticated client where HAIP requires one", methods)
	}

	optional, _, _ := newDemoRP(t)
	optional.SetClientAuthMode(ClientAuthOptional)
	methods = authMethods(optional)
	if !has(methods, unauthenticatedClientAuth) {
		t.Errorf("methods = %v, want the unauthenticated client offered in optional mode", methods)
	}
	if !has(methods, attestationClientAuth) {
		t.Errorf("methods = %v, want the attestation still offered in optional mode", methods)
	}
}
