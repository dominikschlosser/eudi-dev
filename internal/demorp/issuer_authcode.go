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
	"log"
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

	// The client authentication methods of
	// draft-ietf-oauth-attestation-based-client-auth-10: one carrying a
	// dedicated Client Attestation PoP JWT, one where "a request using the
	// mechanism carries only one PoP, the DPoP proof, instead of two separate
	// PoP JWTs" (§5.2). unauthenticatedClientAuth is the registered name of a
	// client that authenticates with nothing. RFC 8414 takes all three from the
	// IANA "OAuth Token Endpoint Authentication Methods" registry.
	attestationClientAuth     = "attest_jwt_client_auth"
	attestationDPoPClientAuth = "attest_jwt_client_auth_dpop"
	unauthenticatedClientAuth = "none"
)

// ClientAuthMode decides what this authorization server demands of a wallet at
// the endpoints that authenticate a client, which here are the pushed
// authorization request endpoint and the token endpoint.
type ClientAuthMode string

const (
	// ClientAuthRequired is the default, and what HAIP 1.0 §4.4.1 asks for:
	// "Wallets MUST use, and Issuers MUST require, an OAuth2 Client
	// authentication mechanism at OAuth2 Endpoints that support client
	// authentication (such as the PAR and Token Endpoints)." Demonstrating that
	// requirement is most of why this authorization server exists.
	ClientAuthRequired ClientAuthMode = "required"
	// ClientAuthOptional also serves a wallet that authenticates with nothing,
	// which OpenID4VCI 1.0 §6.1 leaves open ("Requirements around how the
	// Wallet identifies and, if applicable, authenticates itself with the
	// Authorization Server in the Token Request depend on the Client type").
	// It exists so a wallet with no wallet attestation to send can still be
	// driven through the whole authorization code flow against this issuer,
	// which is what an interoperability test needs and what the profile
	// forbids. An attestation is still verified wherever one is presented.
	ClientAuthOptional ClientAuthMode = "optional"
)

// ParseClientAuthMode reads the mode from its command line spelling.
func ParseClientAuthMode(value string) (ClientAuthMode, error) {
	switch ClientAuthMode(strings.TrimSpace(value)) {
	case "", ClientAuthRequired:
		return ClientAuthRequired, nil
	case ClientAuthOptional:
		return ClientAuthOptional, nil
	}
	return "", fmt.Errorf("unknown client authentication mode %q, want %q or %q", value, ClientAuthRequired, ClientAuthOptional)
}

func (d *DemoRP) clientAuthMode() ClientAuthMode {
	if d.clientAuth == ClientAuthOptional {
		return ClientAuthOptional
	}
	return ClientAuthRequired
}

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
//
// The client authentication methods are the two of
// draft-ietf-oauth-attestation-based-client-auth-10, joined by the
// unauthenticated client when this server was started with
// ClientAuthOptional. The list is the only place a wallet can read whether it
// has to authenticate here, so what the endpoints accept and what this
// document says have to be the same thing.
func (d *DemoRP) authorizationServerMetadata() map[string]any {
	issuer := d.issuerID()
	authMethods := []string{attestationClientAuth, attestationDPoPClientAuth}
	if d.clientAuthMode() == ClientAuthOptional {
		authMethods = append(authMethods, unauthenticatedClientAuth)
	}
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
		"token_endpoint_auth_methods_supported":            authMethods,
		"token_endpoint_auth_signing_alg_values_supported": []string{"ES256"},
		// draft-ietf-oauth-attestation-based-client-auth-10 §10.1 requires
		// these two of a server that supports the method, and a wallet reading
		// only the auth methods list has no other way to learn which signature
		// algorithms it may use.
		"client_attestation_signing_alg_values_supported":     []string{"ES256"},
		"client_attestation_pop_signing_alg_values_supported": []string{"ES256"},
		// The proof of possession methods registry of the same document, whose
		// values name how the client proves the attested key: a dedicated PoP
		// JWT, or the DPoP proof standing in for one.
		"client_attestation_pop_methods_supported": []string{"attestation_pop_jwt", "dpop_combined"},
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
	// RFC 6749 §4.1.1 has client_id REQUIRED in an authorization request, and
	// a client that authenticates with nothing is identified by it alone. The
	// attestation used to be what enforced this, by matching its sub against
	// it, so with an unauthenticated client accepted the check has to be here.
	if clientID == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_request", "client_id is required"))
		return
	}
	jkt, err := d.verifyDPoPProof(r, d.issuerID()+"/par", "")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", err.Error()))
		return
	}
	if _, authErr := d.authenticateClient(r, clientID, jkt); authErr != nil {
		writeJSON(w, http.StatusUnauthorized, oauthError(authErr.code, authErr.description))
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
	clientAuth, authErr := d.authenticateClient(r, clientID, jkt)
	if authErr != nil {
		writeJSON(w, http.StatusUnauthorized, oauthError(authErr.code, authErr.description))
		return
	}
	// Said once per token exchange rather than at every authenticated endpoint,
	// because it is the exchange that produces a credential. Somebody driving
	// their own wallet through this flow reads it here and in the ticket.
	if clientAuth.method != unauthenticatedClientAuth && !clientAuth.trusted {
		log.Printf("[Demo issuer] client attestation from %q accepted on its own certificate, which does not chain to a wallet provider CA this issuer knows", clientAuth.attester)
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
		clientAuth:  &clientAuth,
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

// clientAuthentication is what one request proved about the wallet that made
// it: which method authenticated it, who attested it, and whether that
// attester is one this issuer was given.
type clientAuthentication struct {
	// method is the token endpoint authentication method that was used, one of
	// attest_jwt_client_auth, attest_jwt_client_auth_dpop and none.
	method string
	// attester names the signer of the wallet attestation, taken from its iss
	// claim or, since draft -08 made iss optional, from the subject of the
	// certificate that signed it. Empty without an attestation.
	attester string
	// trusted reports whether that certificate chained to the wallet provider
	// CA this issuer knows.
	trusted bool
}

// clientAuthError is a client authentication failure and the OAuth error code
// it is reported with.
type clientAuthError struct {
	code        string
	description string
}

// attestationFailed reports something wrong with an attestation that was
// presented. draft-ietf-oauth-attestation-based-client-auth-10 §6.2 defines
// the code for exactly this case: invalid_client_attestation "MAY be used in
// addition to the more general invalid_client error code as defined in
// [RFC6749] if the attestation or its proof of possession could not be
// successfully verified". A client that presented no attestation at all is
// answered with invalid_client instead, because there is nothing to fault.
func attestationFailed(format string, args ...any) *clientAuthError {
	return &clientAuthError{code: "invalid_client_attestation", description: fmt.Sprintf(format, args...)}
}

// authenticateClient runs attestation-based client authentication
// (draft-ietf-oauth-attestation-based-client-auth-10, the HAIP wallet
// attestation): the OAuth-Client-Attestation JWT names the client and its key,
// and possession of that key is proven for this request, either by a dedicated
// OAuth-Client-Attestation-PoP JWT or by the DPoP proof the request already
// carries, which is the attest_jwt_client_auth_dpop method. jkt is the
// thumbprint of the key that signed that DPoP proof.
//
// Two things are deliberately weaker here than in a production authorization
// server, and both are what makes this issuer usable as a counterparty for
// wallets it was not built alongside:
//
// An attestation whose certificate does not chain to a known wallet provider
// CA is accepted and marked untrusted rather than refused. The demo knows one
// wallet provider, the wallet this issuer is mounted on, whose CA it can read
// directly. Every other wallet in the world signs with an attester nobody
// handed this issuer, and refusing all of them would mean the flow can only
// ever be completed by ourselves. A real issuer resolves the wallet provider's
// trust list instead (this wallet publishes one at
// /api/trustlists/wallet-provider) and pins the CA it finds there, and what
// this one does instead travels with the credential (see clientAuthentication.
// ticketClaim).
//
// A client that authenticates with nothing is accepted when this server runs
// with ClientAuthOptional, which HAIP forbids and OpenID4VCI permits.
func (d *DemoRP) authenticateClient(r *http.Request, clientID, jkt string) (clientAuthentication, *clientAuthError) {
	rawAttestation := strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation"))
	rawPoP := strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation-PoP"))
	if rawAttestation == "" {
		if rawPoP != "" {
			return clientAuthentication{}, attestationFailed("OAuth-Client-Attestation-PoP was sent without the OAuth-Client-Attestation it proves possession for")
		}
		if d.clientAuthMode() == ClientAuthOptional {
			return clientAuthentication{method: unauthenticatedClientAuth}, nil
		}
		return clientAuthentication{}, &clientAuthError{
			code:        "invalid_client",
			description: "this authorization server requires attestation-based client authentication (OAuth-Client-Attestation and OAuth-Client-Attestation-PoP)",
		}
	}

	attestation, err := parseCompactJWT(rawAttestation)
	if err != nil {
		return clientAuthentication{}, attestationFailed("parsing client attestation: %v", err)
	}
	if typ, _ := attestation.header["typ"].(string); typ != "oauth-client-attestation+jwt" {
		return clientAuthentication{}, attestationFailed("client attestation has typ %q, expected oauth-client-attestation+jwt", typ)
	}
	attester, err := d.attestationSigner(attestation.header)
	if err != nil {
		return clientAuthentication{}, attestationFailed("%v", err)
	}
	if !verifyES256(attester.key, attestation.signingInput, attestation.signature) {
		return clientAuthentication{}, attestationFailed("client attestation signature does not verify with its certificate")
	}
	// §7.1: "If a client_id was provided, verify that it matches the sub claim
	// of the Client Attestation." The sub claim is REQUIRED, iss is not (it was
	// removed in draft -08), so the client is identified by sub alone.
	if sub, _ := attestation.payload["sub"].(string); sub != clientID {
		return clientAuthentication{}, attestationFailed("client attestation sub %q does not match client_id %q", sub, clientID)
	}
	// exp is REQUIRED of the attestation, so this rejects one that omits it.
	if err := checkJWTValidity(attestation.payload); err != nil {
		return clientAuthentication{}, attestationFailed("client attestation: %v", err)
	}
	cnf, _ := attestation.payload["cnf"].(map[string]any)
	cnfJWK, _ := cnf["jwk"].(map[string]any)
	if cnfJWK == nil {
		return clientAuthentication{}, attestationFailed("client attestation has no cnf.jwk")
	}
	clientKey, err := holderKeyFromJWK(cnfJWK)
	if err != nil {
		return clientAuthentication{}, attestationFailed("parsing client attestation cnf.jwk: %v", err)
	}

	authenticated := clientAuthentication{
		method:   attestationClientAuth,
		attester: attester.name(attestation.payload),
		trusted:  attester.trusted,
	}
	if rawPoP == "" {
		// attest_jwt_client_auth_dpop: the DPoP proof is the only proof of
		// possession, so §7.3 asks of it what the PoP JWT would otherwise
		// answer, that "the public key in the jwk header parameter of the DPoP
		// proof MUST be identical to the public key in the cnf claim of the
		// Client Attestation JWT". Everything else about that proof was
		// checked before this function was reached.
		authenticated.method = attestationDPoPClientAuth
		if jkt == "" {
			return clientAuthentication{}, attestationFailed("no OAuth-Client-Attestation-PoP and no DPoP proof, so nothing proves possession of the attested key")
		}
		if jkt != mock.KeyIDForPublicKey(clientKey) {
			return clientAuthentication{}, attestationFailed("the DPoP proof is signed by a different key than the one the client attestation attests")
		}
		return authenticated, nil
	}

	pop, err := parseCompactJWT(rawPoP)
	if err != nil {
		return clientAuthentication{}, attestationFailed("parsing client attestation PoP: %v", err)
	}
	if typ, _ := pop.header["typ"].(string); typ != "oauth-client-attestation-pop+jwt" {
		return clientAuthentication{}, attestationFailed("client attestation PoP has typ %q, expected oauth-client-attestation-pop+jwt", typ)
	}
	if !verifyES256(clientKey, pop.signingInput, pop.signature) {
		return clientAuthentication{}, attestationFailed("client attestation PoP is not signed by the attested key")
	}
	if aud, _ := pop.payload["aud"].(string); aud != d.issuerID() {
		return clientAuthentication{}, attestationFailed("client attestation PoP aud %q is not this authorization server", aud)
	}
	// jti and iat are REQUIRED of the PoP (§5.1), exp is not, and iss is no
	// longer among its claims at all. A PoP that carries iss is still held to
	// naming the client, because a value that disagrees with the client_id says
	// the proof was made for somebody else.
	if jti, _ := pop.payload["jti"].(string); jti == "" {
		return clientAuthentication{}, attestationFailed("client attestation PoP has no jti claim")
	}
	if iss, ok := pop.payload["iss"].(string); ok && iss != clientID {
		return clientAuthentication{}, attestationFailed("client attestation PoP iss %q does not match client_id %q", iss, clientID)
	}
	if err := checkPoPFreshness(pop.payload); err != nil {
		return clientAuthentication{}, attestationFailed("client attestation PoP: %v", err)
	}
	return authenticated, nil
}

// attestationSigner is the certificate a wallet attestation was signed with,
// and whether it belongs to a wallet provider this issuer trusts.
type attestationSigner struct {
	key     *ecdsa.PublicKey
	leaf    *x509.Certificate
	trusted bool
}

// name identifies the attester for the record kept with the issued credential.
// The iss claim is optional since draft -08, so the certificate subject is what
// remains when it is absent.
func (s attestationSigner) name(payload map[string]any) string {
	if iss, _ := payload["iss"].(string); iss != "" {
		return iss
	}
	if s.leaf != nil && s.leaf.Subject.CommonName != "" {
		return s.leaf.Subject.CommonName
	}
	return "unnamed attester"
}

// attestationSigner reads the signing key of a wallet attestation out of its
// x5c header and reports whether that certificate chains to the wallet
// provider CA. Trust and key resolution are out of scope for the draft, which
// leaves how the key is found to the deployment: this one takes the leaf the
// attestation carries and treats the chain as the trust question, not the key
// question.
func (d *DemoRP) attestationSigner(header map[string]any) (attestationSigner, error) {
	rawChain, _ := header["x5c"].([]any)
	if len(rawChain) == 0 {
		return attestationSigner{}, fmt.Errorf("client attestation header has no x5c certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawChain))
	for _, entry := range rawChain {
		encoded, _ := entry.(string)
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return attestationSigner{}, fmt.Errorf("decoding x5c certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return attestationSigner{}, fmt.Errorf("parsing x5c certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	key, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return attestationSigner{}, fmt.Errorf("client attestation certificate does not hold an EC key")
	}
	return attestationSigner{key: key, leaf: certs[0], trusted: d.chainsToWalletProviderCA(certs)}, nil
}

// chainsToWalletProviderCA reports whether an attestation's certificate chain
// reaches the one wallet provider CA this issuer was given. The attestation
// carries the leaf only, so the anchor comes from the wallet this issuer is
// mounted on, which is also what its trust lists publish.
func (d *DemoRP) chainsToWalletProviderCA(certs []*x509.Certificate) bool {
	if d.wallet == nil || len(d.wallet.CertChain) < 2 || len(certs) == 0 {
		return false
	}
	roots := x509.NewCertPool()
	roots.AddCert(d.wallet.CertChain[len(d.wallet.CertChain)-1])
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// checkPoPFreshness bounds a Client Attestation PoP in time. Its exp claim is
// optional (draft-ietf-oauth-attestation-based-client-auth-10 §5.1 requires
// aud, jti and iat), so freshness comes from iat the way it does for a DPoP
// proof, and exp is applied on top wherever a client sends one.
func checkPoPFreshness(payload map[string]any) error {
	iat, ok := payload["iat"].(float64)
	if !ok {
		return fmt.Errorf("has no iat claim")
	}
	age := time.Since(time.Unix(int64(iat), 0))
	if age > dpopProofMaxAge || age < -clockSkew {
		return fmt.Errorf("iat is not within the accepted window")
	}
	if exp, ok := payload["exp"].(float64); ok && time.Now().After(time.Unix(int64(exp), 0)) {
		return fmt.Errorf("expired")
	}
	if nbf, ok := payload["nbf"].(float64); ok && time.Now().Add(clockSkew).Before(time.Unix(int64(nbf), 0)) {
		return fmt.Errorf("not valid yet")
	}
	return nil
}

// ticketClaim describes this authentication in the issued ticket. A credential
// collected without a trusted wallet attestation should say so rather than
// look like one that came with it, which is the whole reason this issuer can
// afford to accept an attester it was never given.
func (c *clientAuthentication) ticketClaim() string {
	switch {
	case c == nil || c.method == "" || c.method == unauthenticatedClientAuth:
		return "none"
	case c.trusted:
		return "trusted"
	default:
		return "untrusted"
	}
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
