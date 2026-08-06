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
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// The demo authorization server authenticates exactly one hardcoded account.
// It exists so the authorization code flow can be demonstrated end to end
// against a public demo instance. It is not an account system: there is no
// registration, no password storage, no session beyond the flow it belongs
// to, and the credentials are printed on the login page.
const (
	demoAccountUsername  = "alice"
	demoAccountPassword  = "alice"
	demoAccountGivenName = "Alice"
	demoAccountFamily    = "Anderson"

	authCodeGrant = "authorization_code"
	ticketScope   = "demo-ticket"

	// requestURIPrefix is the URN form RFC 9126 requires for a PAR request URI.
	requestURIPrefix = "urn:ietf:params:oauth:request_uri:"
	// authRequestTTL bounds a pushed authorization request. Short by design,
	// the wallet redeems it immediately.
	authRequestTTL = 5 * time.Minute
	// clockSkew is the tolerance applied to nbf and to a DPoP proof's iat.
	clockSkew = time.Minute
	// dpopProofMaxAge bounds how long a DPoP proof stays acceptable. Proofs
	// are created per request, so this only has to cover the trip.
	dpopProofMaxAge = 5 * time.Minute
)

// authRequestState is one pushed authorization request and the code issued
// from it once the account has authenticated.
type authRequestState struct {
	requestURI    string
	clientID      string
	redirectURI   string
	state         string
	scope         string
	codeChallenge string
	issuerState   string
	code          string
	codeUsed      bool
	subject       string
	expires       time.Time
}

// authorizationServerMetadata describes this issuer in its authorization
// server role. It satisfies HAIP 1.0: PAR required, PKCE S256, DPoP, and
// client authentication through attestation-based client authentication.
func (d *DemoRP) authorizationServerMetadata() map[string]any {
	issuer := d.issuerID()
	return map[string]any{
		"issuer":                                           issuer,
		"authorization_endpoint":                           issuer + "/authorize",
		"pushed_authorization_request_endpoint":            issuer + "/par",
		"require_pushed_authorization_requests":            true,
		"token_endpoint":                                   issuer + "/token",
		"response_types_supported":                         []string{"code"},
		"response_modes_supported":                         []string{"query"},
		"grant_types_supported":                            []string{authCodeGrant, preAuthGrant},
		"scopes_supported":                                 []string{ticketScope},
		"code_challenge_methods_supported":                 []string{"S256"},
		"dpop_signing_alg_values_supported":                []string{"ES256"},
		"token_endpoint_auth_methods_supported":            []string{"attest_jwt_client_auth"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"ES256"},
	}
}

// AuthorizationServerMetadataHandler serves the OAuth authorization server
// metadata. Like the credential issuer metadata it must additionally be
// registered at the server root, at
// /.well-known/oauth-authorization-server/issuer, because RFC 8414 inserts
// the well-known segment before the issuer path.
func (d *DemoRP) AuthorizationServerMetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, d.authorizationServerMetadata())
	}
}

// handleAuthorize resolves a pushed authorization request and asks the user to
// authenticate. This is where the login belongs: the offer is handed to the
// wallet unauthenticated, and the user proves who they are during redemption,
// between the pushed authorization request and the token exchange, exactly as
// the authorization code flow prescribes.
func (d *DemoRP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	request, err := d.lookupAuthRequest(r.URL.Query().Get("request_uri"))
	if err != nil {
		writeAuthorizeError(w, err.Error())
		return
	}
	if clientID := r.URL.Query().Get("client_id"); clientID != "" && clientID != request.clientID {
		writeAuthorizeError(w, "client_id does not match the pushed authorization request")
		return
	}
	renderLoginPage(w, loginPageData{
		Action:      "authorize",
		RequestURI:  request.requestURI,
		Title:       "Sign in",
		Explanation: "Your wallet is collecting a Demo Event Ticket. Sign in to approve it.",
	})
}

// handlePushedAuthorizationRequest implements RFC 9126. The wallet
// authenticates here with attestation-based client authentication and a DPoP
// proof, both of which are verified before the request is stored.
func (d *DemoRP) handlePushedAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "could not read the request body"))
		return
	}
	clientID := r.PostFormValue("client_id")
	if _, err := d.verifyDPoPProof(r, d.issuerID()+"/par", ""); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", err.Error()))
		return
	}
	if err := d.verifyClientAttestation(r, clientID); err != nil {
		writeJSON(w, http.StatusUnauthorized, oauthError("invalid_client", err.Error()))
		return
	}
	if r.PostFormValue("response_type") != "code" {
		writeJSON(w, http.StatusBadRequest, oauthError("unsupported_response_type", "only response_type=code is supported"))
		return
	}
	if r.PostFormValue("code_challenge_method") != "S256" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "PKCE with S256 is required"))
		return
	}
	challenge := r.PostFormValue("code_challenge")
	redirectURI := r.PostFormValue("redirect_uri")
	if challenge == "" || redirectURI == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "code_challenge and redirect_uri are required"))
		return
	}

	request := &authRequestState{
		requestURI:    requestURIPrefix + randToken(),
		clientID:      clientID,
		redirectURI:   redirectURI,
		state:         r.PostFormValue("state"),
		scope:         r.PostFormValue("scope"),
		codeChallenge: challenge,
		issuerState:   r.PostFormValue("issuer_state"),
		expires:       time.Now().Add(authRequestTTL),
	}
	d.mu.Lock()
	d.pruneLocked()
	if len(d.authRequests) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, oauthError("temporarily_unavailable", "too many open authorization requests"))
		return
	}
	d.authRequests[request.requestURI] = request
	d.mu.Unlock()

	writeJSON(w, http.StatusCreated, map[string]any{
		"request_uri": request.requestURI,
		"expires_in":  int(authRequestTTL.Seconds()),
	})
}

// handleAuthorizeSubmit completes the login and hands the wallet its
// authorization code.
func (d *DemoRP) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeAuthorizeError(w, "could not read the form")
		return
	}
	request, err := d.lookupAuthRequest(r.PostFormValue("request_uri"))
	if err != nil {
		writeAuthorizeError(w, err.Error())
		return
	}
	if !validDemoAccount(r.PostFormValue("username"), r.PostFormValue("password")) {
		renderLoginPage(w, loginPageData{
			Action:     "authorize",
			RequestURI: request.requestURI,
			Title:      "Sign in",
			Error:      "Wrong account. The demo accepts alice / alice.",
		})
		return
	}
	d.redirectWithCode(w, r, request, demoAccountUsername)
}

// redirectWithCode issues the authorization code and sends the caller back to
// the wallet's redirect URI. The `iss` parameter (RFC 9207) is included
// because a wallet in strict mode requires it.
func (d *DemoRP) redirectWithCode(w http.ResponseWriter, r *http.Request, request *authRequestState, subject string) {
	// Everything read from the shared request happens under the lock: the
	// token endpoint reads the same struct concurrently.
	code := randToken()
	d.mu.Lock()
	request.code = code
	request.subject = subject
	d.codes[code] = request
	redirectURI, state := request.redirectURI, request.state
	d.mu.Unlock()

	target, err := url.Parse(redirectURI)
	if err != nil {
		writeAuthorizeError(w, "the pushed redirect_uri is not a valid URL")
		return
	}
	query := target.Query()
	query.Set("code", code)
	query.Set("iss", d.issuerID())
	if state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// handleAuthorizationCodeToken exchanges the code for an access token. It
// checks everything the flow promised: PKCE, the redirect URI, the client
// attestation and the DPoP key the token is then bound to.
func (d *DemoRP) handleAuthorizationCodeToken(w http.ResponseWriter, r *http.Request) {
	jkt, err := d.verifyDPoPProof(r, d.issuerID()+"/token", "")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", err.Error()))
		return
	}
	clientID := r.PostFormValue("client_id")
	if err := d.verifyClientAttestation(r, clientID); err != nil {
		writeJSON(w, http.StatusUnauthorized, oauthError("invalid_client", err.Error()))
		return
	}

	code := r.PostFormValue("code")
	d.mu.Lock()
	request, known := d.codes[code]
	if known && (time.Now().After(request.expires) || request.codeUsed) {
		delete(d.codes, code)
		known = false
	}
	// Copy under the lock: the authorization endpoint writes to the same
	// struct when it issues a code.
	var granted authRequestState
	if known {
		// An authorization code is single use (RFC 6749 §4.1.2).
		request.codeUsed = true
		granted = *request
	}
	d.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "unknown, used or expired authorization code"))
		return
	}
	if clientID != granted.clientID {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "client_id does not match the authorization request"))
		return
	}
	if redirect := r.PostFormValue("redirect_uri"); redirect != granted.redirectURI {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "redirect_uri does not match the authorization request"))
		return
	}
	if !pkceMatches(r.PostFormValue("code_verifier"), granted.codeChallenge) {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_grant", "code_verifier does not match the code_challenge"))
		return
	}

	offer := &offerState{
		id:          randToken(),
		issuerState: granted.issuerState,
		subject:     granted.subject,
		accessToken: randToken(),
		jkt:         jkt,
		expires:     time.Now().Add(entryTTL),
	}
	// This is a second state for the same offer, so what the offer was created
	// with has to travel with it: the issuer_state is the only thing tying the
	// two together.
	offer.withStatus = d.offerWantsStatus(granted.issuerState)

	d.mu.Lock()
	d.tokens[offer.accessToken] = offer
	d.mu.Unlock()

	// No c_nonce. OpenID4VCI 1.0 §6.2 lists what a token response may add to
	// RFC 6749 and defines no such parameter, and this issuer advertises a Nonce
	// Endpoint (§7), which is where the challenge comes from.
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": offer.accessToken,
		"token_type":   "DPoP",
		"expires_in":   int(entryTTL.Seconds()),
	})
}

// offerWantsStatus reports whether the offer an issuer_state belongs to was
// created with a status list reference.
func (d *DemoRP) offerWantsStatus(issuerState string) bool {
	if issuerState == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, offer := range d.offers {
		if offer.issuerState == issuerState {
			return offer.withStatus
		}
	}
	return false
}

func (d *DemoRP) lookupAuthRequest(requestURI string) (*authRequestState, error) {
	requestURI = strings.TrimSpace(requestURI)
	if requestURI == "" {
		return nil, fmt.Errorf("request_uri is required, this authorization server requires pushed authorization requests")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	request, ok := d.authRequests[requestURI]
	if !ok || time.Now().After(request.expires) {
		delete(d.authRequests, requestURI)
		return nil, fmt.Errorf("unknown or expired request_uri")
	}
	return request, nil
}

func validDemoAccount(username, password string) bool {
	return strings.TrimSpace(username) == demoAccountUsername && password == demoAccountPassword
}

func pkceMatches(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return format.EncodeBase64URL(sum[:]) == challenge
}

func oauthError(code, description string) map[string]string {
	return map[string]string{"error": code, "error_description": description}
}

// verifyDPoPProof checks the DPoP proof on a request (RFC 9449) and returns
// the JWK thumbprint the resulting token is bound to. Minimal but real: the
// signature must verify with the embedded key, and the method and URL must
// match the request being made.
func (d *DemoRP) verifyDPoPProof(r *http.Request, expectedURL, accessToken string) (string, error) {
	raw := strings.TrimSpace(r.Header.Get("DPoP"))
	if raw == "" {
		return "", fmt.Errorf("a DPoP proof is required")
	}
	proof, err := parseCompactJWT(raw)
	if err != nil {
		return "", fmt.Errorf("parsing DPoP proof: %w", err)
	}
	if typ, _ := proof.header["typ"].(string); typ != "dpop+jwt" {
		return "", fmt.Errorf("DPoP proof has typ %q, expected dpop+jwt", typ)
	}
	jwk, ok := proof.header["jwk"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("DPoP proof header has no jwk")
	}
	key, err := holderKeyFromJWK(jwk)
	if err != nil {
		return "", fmt.Errorf("parsing DPoP jwk: %w", err)
	}
	if !verifyES256(key, proof.signingInput, proof.signature) {
		return "", fmt.Errorf("DPoP proof signature does not verify")
	}
	if htm, _ := proof.payload["htm"].(string); !strings.EqualFold(htm, r.Method) {
		return "", fmt.Errorf("DPoP htm %q does not match the request method", htm)
	}
	if htu, _ := proof.payload["htu"].(string); htu != expectedURL {
		return "", fmt.Errorf("DPoP htu %q does not match %q", htu, expectedURL)
	}
	// A DPoP proof carries no expiry, so freshness comes from iat. Without
	// this check a proof captured once stays usable forever, which is the
	// whole thing DPoP is meant to prevent.
	iat, ok := proof.payload["iat"].(float64)
	if !ok {
		return "", fmt.Errorf("DPoP proof has no iat claim")
	}
	age := time.Since(time.Unix(int64(iat), 0))
	if age > dpopProofMaxAge || age < -clockSkew {
		return "", fmt.Errorf("DPoP proof iat is not within the accepted window")
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if ath, _ := proof.payload["ath"].(string); ath != format.EncodeBase64URL(sum[:]) {
			return "", fmt.Errorf("DPoP ath does not match the access token")
		}
	}
	return mock.KeyIDForPublicKey(key), nil
}

// verifyClientAttestation checks attestation-based client authentication
// (the HAIP wallet attestation): the OAuth-Client-Attestation JWT names the
// client and its key, and the OAuth-Client-Attestation-PoP proves possession
// of that key for this request.
//
// The demo trusts one wallet provider: the wallet this issuer is mounted on,
// whose CA it can read directly. A real issuer resolves the wallet provider's
// trust list instead (this wallet publishes one at
// /api/trustlists/wallet-provider) and pins the CA it finds there.
func (d *DemoRP) verifyClientAttestation(r *http.Request, clientID string) error {
	rawAttestation := strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation"))
	rawPoP := strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation-PoP"))
	if rawAttestation == "" || rawPoP == "" {
		return fmt.Errorf("this authorization server requires attestation-based client authentication (OAuth-Client-Attestation and OAuth-Client-Attestation-PoP)")
	}

	attestation, err := parseCompactJWT(rawAttestation)
	if err != nil {
		return fmt.Errorf("parsing client attestation: %w", err)
	}
	if typ, _ := attestation.header["typ"].(string); typ != "oauth-client-attestation+jwt" {
		return fmt.Errorf("client attestation has typ %q, expected oauth-client-attestation+jwt", typ)
	}
	attestationKey, err := d.walletProviderKeyFromX5C(attestation.header)
	if err != nil {
		return err
	}
	if !verifyES256(attestationKey, attestation.signingInput, attestation.signature) {
		return fmt.Errorf("client attestation signature does not verify with its certificate")
	}
	if sub, _ := attestation.payload["sub"].(string); sub != clientID {
		return fmt.Errorf("client attestation sub %q does not match client_id %q", sub, clientID)
	}
	if err := checkJWTValidity(attestation.payload); err != nil {
		return fmt.Errorf("client attestation: %w", err)
	}
	cnf, _ := attestation.payload["cnf"].(map[string]any)
	cnfJWK, _ := cnf["jwk"].(map[string]any)
	if cnfJWK == nil {
		return fmt.Errorf("client attestation has no cnf.jwk")
	}
	clientKey, err := holderKeyFromJWK(cnfJWK)
	if err != nil {
		return fmt.Errorf("parsing client attestation cnf.jwk: %w", err)
	}

	pop, err := parseCompactJWT(rawPoP)
	if err != nil {
		return fmt.Errorf("parsing client attestation PoP: %w", err)
	}
	if typ, _ := pop.header["typ"].(string); typ != "oauth-client-attestation-pop+jwt" {
		return fmt.Errorf("client attestation PoP has typ %q, expected oauth-client-attestation-pop+jwt", typ)
	}
	if !verifyES256(clientKey, pop.signingInput, pop.signature) {
		return fmt.Errorf("client attestation PoP is not signed by the attested key")
	}
	if iss, _ := pop.payload["iss"].(string); iss != clientID {
		return fmt.Errorf("client attestation PoP iss %q does not match client_id %q", iss, clientID)
	}
	if aud, _ := pop.payload["aud"].(string); aud != d.issuerID() {
		return fmt.Errorf("client attestation PoP aud %q is not this authorization server", aud)
	}
	if err := checkJWTValidity(pop.payload); err != nil {
		return fmt.Errorf("client attestation PoP: %w", err)
	}
	return nil
}

// walletProviderKeyFromX5C returns the signing key of a wallet attestation
// after checking that its leaf certificate chains to the wallet CA. The
// attestation carries the leaf only, the anchor comes from the trust list.
func (d *DemoRP) walletProviderKeyFromX5C(header map[string]any) (*ecdsa.PublicKey, error) {
	rawChain, _ := header["x5c"].([]any)
	if len(rawChain) == 0 {
		return nil, fmt.Errorf("client attestation header has no x5c certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawChain))
	for _, entry := range rawChain {
		encoded, _ := entry.(string)
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if d.wallet == nil || len(d.wallet.CertChain) < 2 {
		return nil, fmt.Errorf("no wallet provider trust anchor is configured")
	}
	roots := x509.NewCertPool()
	roots.AddCert(d.wallet.CertChain[len(d.wallet.CertChain)-1])
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("client attestation certificate does not chain to the wallet provider CA: %w", err)
	}
	key, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("client attestation certificate does not hold an EC key")
	}
	return key, nil
}

// checkJWTValidity applies the exp and nbf claims when present.
func checkJWTValidity(payload map[string]any) error {
	now := time.Now()
	// exp is required, not optional: without it a leaked attestation would be
	// usable forever, and an "if present" check would silently accept exactly
	// the token that omits it.
	exp, ok := payload["exp"].(float64)
	if !ok {
		return fmt.Errorf("has no exp claim")
	}
	if now.After(time.Unix(int64(exp), 0)) {
		return fmt.Errorf("expired")
	}
	if nbf, ok := payload["nbf"].(float64); ok && now.Add(clockSkew).Before(time.Unix(int64(nbf), 0)) {
		return fmt.Errorf("not valid yet")
	}
	return nil
}

type loginPageData struct {
	// Action is the form target relative to /issuer, always "authorize": the
	// login exists only as a step of the authorization code flow.
	Action      string
	RequestURI  string
	Title       string
	Explanation string
	Error       string
}

var loginPageTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/svg+xml" href="/favicon.svg?v=2">
<title>EUDI Test Demo Issuer</title>
<style>
:root { --bg:#1a1b26; --bg-surface:#24283b; --text:#c0caf5; --text-dim:#8b93b8; --border:#3b4261; --accent:#7aa2f7; }
@media (prefers-color-scheme: light) {
  :root { --bg:#f5f5f5; --bg-surface:#ffffff; --text:#343b58; --text-dim:#6b6f7b; --border:#d0d0d0; --accent:#2569d6; }
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:"SF Mono","Cascadia Code","Fira Code",Menlo,Consolas,monospace; background:var(--bg); color:var(--text); min-height:100vh; padding:40px 20px; }
.card { max-width:520px; margin:0 auto; background:var(--bg-surface); border:1px solid var(--border); border-radius:8px; padding:24px; }
h1 { font-size:16px; color:var(--accent); margin-bottom:10px; }
p { font-size:12px; line-height:1.6; color:var(--text-dim); margin-bottom:14px; }
label { display:block; font-size:11px; color:var(--text-dim); margin:10px 0 4px; }
input { font:inherit; font-size:12px; width:100%; padding:8px; background:var(--bg); color:var(--text); border:1px solid var(--border); border-radius:4px; }
.btn { font:inherit; font-size:12px; margin-top:16px; padding:8px 16px; border:1px solid var(--accent); border-radius:4px; background:var(--bg); color:var(--accent); cursor:pointer; }
.note { margin-top:16px; padding-top:12px; border-top:1px solid var(--border); font-size:10px; line-height:1.5; color:var(--text-dim); }
.error { color:#f7768e; font-size:12px; margin-top:12px; }
</style>
</head>
<body>
<div class="card">
  <h1>{{.Title}}</h1>
  <p>{{.Explanation}}</p>
  <form method="POST" action="{{.Action}}">
    {{if .RequestURI}}<input type="hidden" name="request_uri" value="{{.RequestURI}}">{{end}}
    <label for="username">Username</label>
    <input id="username" name="username" value="alice" autocomplete="off">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" value="alice" autocomplete="off">
    <button class="btn" type="submit">Sign in</button>
  </form>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <div class="note">
    Demo only. One hardcoded account, alice / alice. No user data is stored, everything issued here is test data.
  </div>
</div>
</body>
</html>
`))

func renderLoginPage(w http.ResponseWriter, data loginPageData) {
	if data.Explanation == "" {
		data.Explanation = "Sign in with the demo account."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusOK
	if data.Error != "" {
		status = http.StatusUnauthorized
	}
	w.WriteHeader(status)
	_ = loginPageTemplate.Execute(w, data)
}

func writeAuthorizeError(w http.ResponseWriter, message string) {
	// No redirect_uri can be trusted at this point, so the error stays here
	// rather than being sent to a client-supplied URL.
	writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", message))
}
