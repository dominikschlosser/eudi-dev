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
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/httpsec"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

//go:embed static
var staticFiles embed.FS

const (
	// TicketVCT is the credential type the demo issuer hands out.
	TicketVCT = "urn:eudi-test:demo-ticket:1"

	ticketConfigurationID = "demo-ticket"
	preAuthGrant          = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

// ticketClaims returns the ticket's test data, carrying the signed-in holder's
// name for an authorization code flow.
//
// It also records how the wallet authenticated, since this issuer accepts an
// attester it was never given and such a credential should be distinguishable
// from one backed by a trusted attestation. Both grants run the same client
// authentication, so the claim travels on every ticket.
func ticketClaims(subject string, holder map[string]any, auth *clientAuthentication) map[string]any {
	claims := map[string]any{
		"event":       "EUDI Interop Fest",
		"tier":        "backstage",
		"seat":        "42A",
		"given_name":  "Erika",
		"family_name": "Mustermann",
	}
	if subject == demoAccountUsername {
		claims["given_name"] = demoAccountGivenName
		claims["family_name"] = demoAccountFamily
	}
	// Interactive authorization identifies the holder by the credential they
	// presented rather than by an account they signed in to, so the ticket
	// names that holder.
	for _, name := range []string{"given_name", "family_name"} {
		if value, ok := holder[name].(string); ok && value != "" {
			claims[name] = value
		}
	}
	if auth != nil {
		claims["wallet_attestation"] = auth.ticketClaim()
	}
	return claims
}

// offerState tracks one credential offer from creation through the token
// exchange to the collected credential. A pre-authorized offer carries a
// pre-authorized code, an issuer-initiated authorization code offer carries
// the issuer_state that ties it to a browser login.
type offerState struct {
	id          string
	preAuthCode string
	// preAuthCodeUsed marks the code spent by its exchange, which is the one
	// that binds the offer to the redeeming client.
	preAuthCodeUsed bool
	issuerState     string
	subject         string
	// holderClaims are the claims of the credential presented to authorize
	// this issuance (OpenID4VCI 1.1 §6), empty for every other flow.
	holderClaims map[string]any
	// authorization is what an authorization code offer asks of the user:
	// authorizationPresentation or authorizationBrowser.
	authorization string
	accessToken   string
	// jkt is the DPoP key thumbprint the access token is bound to. Empty
	// for a bearer token.
	jkt string
	// withStatus issues the ticket with a reference to the wallet's own status
	// list, which is what makes the credential revocable and gives the
	// verifier's revocation check something to resolve.
	withStatus bool
	// clientAuth is how the wallet authenticated when it exchanged the code
	// for this access token. Nil until a token exchange has run.
	clientAuth *clientAuthentication
	expires    time.Time
}

// IssuerHandler returns the demo issuer, meant to be mounted with the
// /issuer prefix stripped.
func (d *DemoRP) IssuerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.serveStatic("static/issuer.html"))
	// Served as a file rather than inline, so the page needs no
	// script-src 'unsafe-inline' in the wallet's Content-Security-Policy.
	mux.HandleFunc("GET /issuer.js", d.serveStatic("static/issuer.js"))
	mux.HandleFunc("POST /api/offers", d.handleCreateOffer)
	mux.HandleFunc("GET /offer/{id}", d.handleOfferByReference)
	mux.HandleFunc("POST /token", d.handleToken)
	mux.HandleFunc("POST /credential", d.handleCredential)
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", d.handleIssuerMetadata)

	// Authorization code flow, with this issuer as its own authorization
	// server. The user signs in at /authorize, during redemption, not before
	// the offer is created.
	mux.HandleFunc("POST /nonce", d.handleNonce)
	mux.HandleFunc("POST /par", d.handlePushedAuthorizationRequest)
	mux.HandleFunc("GET /authorize", d.handleAuthorize)
	mux.HandleFunc("POST /authorize-challenge", d.handleAuthorizationChallenge)
	mux.HandleFunc("POST /authorize", d.handleAuthorizeSubmit)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", d.AuthorizationServerMetadataHandler())
	// Only /api/ is guarded, which is what the page itself calls. The
	// protocol endpoints above it are for wallets on other origins.
	return httpsec.GuardAPI(mux, d.baseURL())
}

// IssuerMetadataHandler serves the issuer metadata. It must additionally be
// registered at the server root under
// /.well-known/openid-credential-issuer/issuer, because OID4VCI inserts the
// well-known segment before the issuer path.
func (d *DemoRP) IssuerMetadataHandler() http.HandlerFunc {
	return d.handleIssuerMetadata
}

func (d *DemoRP) serveStatic(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		contentType := "text/html; charset=utf-8"
		if strings.HasSuffix(name, ".js") {
			contentType = "text/javascript; charset=utf-8"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	}
}

func (d *DemoRP) issuerID() string {
	return d.baseURL() + "/issuer"
}

func (d *DemoRP) handleIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := d.issuerID()
	writeJSON(w, http.StatusOK, map[string]any{
		"credential_issuer":   issuer,
		"credential_endpoint": issuer + "/credential",
		// This issuer is its own Authorization Server and says so rather than
		// leaving it to the §12.2.4 inference, so that a wallet which does not
		// implement that fallback still reaches the metadata carrying
		// attest_jwt_client_auth, PAR and DPoP.
		"authorization_servers": []string{issuer},
		// No token_endpoint here: §12.2.4 defines none among the Credential
		// Issuer Metadata parameters.
		// The Nonce Endpoint of §7 is the only place a 1.0 wallet looks for the
		// challenge its key proof must carry.
		"nonce_endpoint": issuer + "/nonce",
		"display": []map[string]any{
			{"name": "EUDI Test Demo Issuer", "locale": "en-US"},
		},
		"credential_configurations_supported": map[string]any{
			ticketConfigurationID: map[string]any{
				"format": "dc+sd-jwt",
				"vct":    TicketVCT,
				// The scope is what the wallet asks for in the authorization
				// code flow, so the configuration has to name one.
				"scope": ticketScope,
				"cryptographic_binding_methods_supported": []string{"jwk"},
				"proof_types_supported": map[string]any{
					"jwt": map[string]any{"proof_signing_alg_values_supported": []string{"ES256"}},
				},
				// §12.2.4 puts display and claims one level down, in
				// credential_metadata. A 1.0 wallet looks nowhere else, and one
				// that finds nothing asks the user to consent to a credential
				// with no name and no claims.
				"credential_metadata": map[string]any{
					"display": []map[string]any{
						{"name": "Demo Event Ticket", "description": "A sample event ticket issued by the demo issuer", "locale": "en-US"},
					},
					"claims": []map[string]any{
						{"path": []string{"event"}},
						{"path": []string{"tier"}},
						{"path": []string{"seat"}},
						{"path": []string{"given_name"}},
						{"path": []string{"family_name"}},
						// Present on the authorization code path only, where
						// there is a client authentication to describe. A claim
						// is not mandatory unless it says so, so listing it here
						// does not promise it on every ticket.
						{"path": []string{"wallet_attestation"}},
					},
				},
			},
		},
	})
}

// handleCreateOffer creates a credential offer. ?grant=authorization_code
// makes one redeemed through the authorization code flow; anything else makes a
// pre-authorized code offer. ?status=true issues the ticket with a status list
// reference so it can be revoked.
//
// ?authorization decides what the authorization code flow asks of the user:
// "presentation" requires a PID at the Authorization Challenge Endpoint
// (OpenID4VCI 1.1 §6), anything else the browser sign-in. A wallet that does
// not use interactive authorization gets the sign-in either way.
func (d *DemoRP) handleCreateOffer(w http.ResponseWriter, r *http.Request) {
	authCode := r.URL.Query().Get("grant") == authCodeGrant
	withStatus := r.URL.Query().Get("status") == "true"
	if withStatus && d.statusListURI() == "" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "this wallet has no status list URL, so the ticket cannot carry a status reference",
		})
		return
	}

	d.mu.Lock()
	d.pruneLocked()
	if len(d.offers) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open offers, try again later"})
		return
	}
	offer := &offerState{
		id:            randToken(),
		withStatus:    withStatus,
		authorization: normalizeAuthorizationMode(r.URL.Query().Get("authorization")),
		expires:       time.Now().Add(entryTTL),
	}
	if authCode {
		offer.issuerState = randToken()
	} else {
		offer.preAuthCode = randToken()
	}
	d.offers[offer.id] = offer
	d.mu.Unlock()

	base := d.baseURL()
	offerURI := d.issuerID() + "/offer/" + offer.id
	params := url.Values{"credential_offer_uri": {offerURI}}.Encode()
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         offer.id,
		"offer_uri":  offerURI,
		"wallet_url": base + "/credential-offer?" + params,
		"scheme_uri": "openid-credential-offer://?" + params,
	})
}

func (d *DemoRP) handleOfferByReference(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d.mu.Lock()
	offer, ok := d.offers[id]
	if ok && time.Now().After(offer.expires) {
		delete(d.offers, id)
		ok = false
	}
	d.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired credential offer"})
		return
	}
	grants := map[string]any{}
	if offer.issuerState != "" {
		grants[authCodeGrant] = map[string]any{"issuer_state": offer.issuerState}
	} else {
		grants[preAuthGrant] = map[string]any{"pre-authorized_code": offer.preAuthCode}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credential_issuer":            d.issuerID(),
		"credential_configuration_ids": []string{ticketConfigurationID},
		"grants":                       grants,
	})
}

func (d *DemoRP) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	switch grant := r.PostFormValue("grant_type"); grant {
	case preAuthGrant:
	case authCodeGrant:
		d.handleAuthorizationCodeToken(w, r)
		return
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": fmt.Sprintf("only %s and %s are supported", preAuthGrant, authCodeGrant),
		})
		return
	}
	// HAIP 1.0 §4.4.1 requires client authentication at the token endpoint,
	// and the metadata advertises attestation-based methods only, so the
	// pre-authorized code grant authenticates like the authorization code
	// grant. A DPoP proof binds the token where the wallet sends one.
	var jkt string
	if strings.TrimSpace(r.Header.Get("DPoP")) != "" {
		var err error
		jkt, err = d.verifyDPoPProof(r, d.issuerID()+"/token", "")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, oauthError("invalid_dpop_proof", err.Error()))
			return
		}
	}
	clientAuth, ok := d.authenticateTokenClient(w, r, r.PostFormValue("client_id"), jkt)
	if !ok {
		return
	}
	code := r.PostFormValue("pre-authorized_code")

	d.mu.Lock()
	defer d.mu.Unlock()
	var offer *offerState
	for _, o := range d.offers {
		if o.preAuthCode == code {
			offer = o
			break
		}
	}
	if offer == nil || time.Now().After(offer.expires) || offer.preAuthCodeUsed {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "unknown, used or expired pre-authorized code",
		})
		return
	}
	// The exchange binds the offer to the redeeming client, so the code is
	// spent by it, the way an authorization code is (RFC 6749 §4.1.2).
	offer.preAuthCodeUsed = true
	offer.accessToken = randToken()
	offer.jkt = jkt
	offer.clientAuth = &clientAuth
	d.tokens[offer.accessToken] = offer
	tokenType := "Bearer"
	if jkt != "" {
		tokenType = "DPoP"
	}
	// No c_nonce. OpenID4VCI 1.0 §6.2 lists what a token response may add to
	// RFC 6749 and defines no such parameter, and this issuer advertises a Nonce
	// Endpoint (§7), which is where the challenge comes from.
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": offer.accessToken,
		"token_type":   tokenType,
		"expires_in":   int(entryTTL.Seconds()),
	})
}

// credentialRequest is a Credential Request as defined in OpenID4VCI 1.0 §8.2.
// The key proofs arrive under proofs, "exactly one parameter named as the proof
// type in Appendix F, the value set for this parameter is a non-empty array".
// There is no singular proof member in 1.0.
type credentialRequest struct {
	CredentialConfigurationID string `json:"credential_configuration_id"`
	CredentialIdentifier      string `json:"credential_identifier"`
	Proofs                    struct {
		JWT []string `json:"jwt"`
	} `json:"proofs"`
}

func (d *DemoRP) handleCredential(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	token, ok := accessToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	d.mu.Lock()
	offer, known := d.tokens[token]
	if known && time.Now().After(offer.expires) {
		delete(d.tokens, token)
		known = false
	}
	// Copied under the lock: the token endpoint writes to the same struct.
	var granted ticketGrant
	if known {
		granted = ticketGrant{
			subject:      offer.subject,
			holderClaims: offer.holderClaims,
			jkt:          offer.jkt,
			withStatus:   offer.withStatus,
			clientAuth:   offer.clientAuth,
		}
	}
	d.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	// A DPoP-bound token requires the credential request to prove possession
	// of the same key again.
	if granted.jkt != "" {
		presented, err := d.verifyDPoPProof(r, d.issuerID()+"/credential", token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, oauthError("invalid_dpop_proof", err.Error()))
			return
		}
		if presented != granted.jkt {
			writeJSON(w, http.StatusUnauthorized, oauthError("invalid_token", "the access token is bound to a different DPoP key"))
			return
		}
	}

	var req credentialRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_credential_request", err.Error()))
		return
	}
	if status, errResp := d.checkRequestedCredential(req); errResp != nil {
		writeJSON(w, status, errResp)
		return
	}
	if len(req.Proofs.JWT) == 0 {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_proof", "proofs.jwt is required"))
		return
	}

	holderKey, err := d.verifyProofJWT(req.Proofs.JWT[0])
	if err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError(err.code, err.description))
		return
	}

	credential, signErr := d.signTicket(holderKey, granted)
	if signErr != nil {
		// Not a §8.3.1.2 error: those describe what is wrong with the request
		// and are answered with 400, and credential_request_denied in particular
		// tells the wallet "the Credential cannot be issued", so it stops asking.
		// A signing failure here is this issuer being broken, which the next
		// attempt may well survive.
		writeJSON(w, http.StatusInternalServerError, oauthError("server_error", signErr.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credentials": []map[string]any{{"credential": credential}},
	})
}

// checkRequestedCredential holds the request to §8.2, where
// credential_identifier is "REQUIRED when an Authorization Details of type
// openid_credential was returned from the Token Response [...] MUST NOT be
// used otherwise" and excludes credential_configuration_id.
//
// This issuer returns no authorization_details and knows one configuration, so
// the configuration id is the only way to ask it for anything. The error codes
// are those of §8.3.1.2.
func (d *DemoRP) checkRequestedCredential(req credentialRequest) (int, map[string]string) {
	switch {
	case req.CredentialIdentifier != "" && req.CredentialConfigurationID != "":
		return http.StatusBadRequest, oauthError("invalid_credential_request",
			"credential_identifier and credential_configuration_id must not both be present")
	case req.CredentialIdentifier != "":
		return http.StatusBadRequest, oauthError("unknown_credential_identifier",
			"this issuer returns no authorization_details, so no credential identifier is defined")
	case req.CredentialConfigurationID == "":
		return http.StatusBadRequest, oauthError("invalid_credential_request",
			"credential_configuration_id is required")
	case req.CredentialConfigurationID != ticketConfigurationID:
		return http.StatusBadRequest, oauthError("unknown_credential_configuration",
			fmt.Sprintf("this issuer only offers the %s configuration", ticketConfigurationID))
	}
	return 0, nil
}

// handleNonce is the Nonce Endpoint of OpenID4VCI 1.0 §7, the only source of
// the key proof challenge for a 1.0 wallet: a c_nonce in the token response
// belongs to the earlier drafts.
func (d *DemoRP) handleNonce(w http.ResponseWriter, r *http.Request) {
	nonce := randToken()

	d.mu.Lock()
	d.pruneLocked()
	if len(d.nonces) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, oauthError("temporarily_unavailable", "too many outstanding nonces"))
		return
	}
	d.nonces[nonce] = time.Now().Add(entryTTL)
	d.mu.Unlock()

	// A challenge that a cache could hand to somebody else is not one.
	w.Header().Set("Cache-Control", "no-store")
	// c_nonce alone: §7.2 defines it as the one parameter of a Nonce Response.
	writeJSON(w, http.StatusOK, map[string]any{"c_nonce": nonce})
}

// nonceIssued reports whether the nonce came from the Nonce Endpoint and has
// not expired. Nonces are left in place until they expire rather than being
// consumed on first use, which matches how the c_nonce carried with a token
// behaves and keeps a batch of proofs signed over one nonce working.
func (d *DemoRP) nonceIssued(nonce string) bool {
	if nonce == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	expires, ok := d.nonces[nonce]
	if !ok {
		return false
	}
	if time.Now().After(expires) {
		delete(d.nonces, nonce)
		return false
	}
	return true
}

// proofError is a rejected key proof, carrying the §8.3.1.2 error code that
// tells the wallet what to do about it. The distinction matters: invalid_nonce
// asks for a fresh challenge and another attempt, invalid_proof does not.
type proofError struct {
	code        string
	description string
}

func (e *proofError) Error() string { return e.code + ": " + e.description }

func invalidProof(format string, args ...any) *proofError {
	return &proofError{code: "invalid_proof", description: fmt.Sprintf(format, args...)}
}

// proofClockSkew is the window a key proof's iat may fall in. Appendix F.4
// requires "the creation time of the JWT [...] is within an acceptable window
// (see Section 13.8)" without naming one, so this is the round trip plus the
// clock difference between two machines that are trying.
const proofClockSkew = 5 * time.Minute

// verifyProofJWT validates a jwt key proof against Appendix F.4: the required
// claims, the explicit typ, a registered asymmetric alg, a signature that
// verifies with the key in the header, a nonce matching the one this server
// issued, and a creation time within an acceptable window.
//
// The audience check is what stops a proof from travelling: F.1 makes aud the
// Credential Issuer Identifier, and an issuer that skips it accepts a proof
// the holder made for somebody else.
func (d *DemoRP) verifyProofJWT(raw string) (*ecdsa.PublicKey, *proofError) {
	proof, err := parseCompactJWT(raw)
	if err != nil {
		return nil, invalidProof("parsing proof JWT: %v", err)
	}
	if typ, _ := proof.header["typ"].(string); typ != "openid4vci-proof+jwt" {
		return nil, invalidProof("proof JWT typ is %q, want openid4vci-proof+jwt", typ)
	}
	if alg, _ := proof.header["alg"].(string); alg != "ES256" {
		return nil, invalidProof("proof JWT alg is %q, and this issuer advertises ES256 only", alg)
	}

	holderKey, keyErr := proofKeyMaterial(proof.header)
	if keyErr != nil {
		return nil, keyErr
	}
	if !verifyES256(holderKey, proof.signingInput, proof.signature) {
		return nil, invalidProof("proof JWT signature does not verify with the key in its header")
	}

	if aud, _ := proof.payload["aud"].(string); aud != d.issuerID() {
		return nil, invalidProof("proof JWT aud is %q, want the credential issuer identifier %q", aud, d.issuerID())
	}
	iat, ok := proof.payload["iat"].(float64)
	if !ok {
		return nil, invalidProof("proof JWT has no numeric iat")
	}
	if age := time.Since(time.Unix(int64(iat), 0)); age > proofClockSkew || age < -proofClockSkew {
		return nil, invalidProof("proof JWT iat is %s away from now, outside the %s window this issuer accepts", age.Round(time.Second), proofClockSkew)
	}

	// This issuer has a Nonce Endpoint, so that endpoint is the only source of a
	// valid challenge: §8.2 says "The c_nonce value is retrieved from the Nonce
	// Endpoint as defined in Section 7".
	nonce, _ := proof.payload["nonce"].(string)
	if nonce == "" {
		// §8.3.1.2 puts a missing challenge under invalid_proof: "(3) if at
		// least one of the key proofs does not contain a c_nonce value".
		return nil, invalidProof("proof JWT carries no nonce: request one from the nonce endpoint")
	}
	if !d.nonceIssued(nonce) {
		// §8.3.1.2 invalid_nonce: "at least one of the key proofs contains an
		// invalid c_nonce value. The wallet should retrieve a new c_nonce value
		// (refer to Section 7)." Answering invalid_proof instead tells a
		// conformant wallet the request is beyond saving, so it never retries.
		return nil, &proofError{code: "invalid_nonce", description: "proof JWT nonce is not one this issuer handed out"}
	}
	return holderKey, nil
}

// proofKeyMaterial reads the key a proof is bound to. Appendix F.1 allows
// exactly one of jwk, kid and x5c. kid names a key this issuer would have to
// resolve (F.1 points at a DID URL), so it is refused with a reason rather
// than treated as malformed.
func proofKeyMaterial(header map[string]any) (*ecdsa.PublicKey, *proofError) {
	jwk, hasJWK := header["jwk"].(map[string]any)
	x5c, hasX5C := header["x5c"]
	kid, hasKID := header["kid"].(string)
	if hasKID && kid == "" {
		hasKID = false
	}

	present := 0
	for _, found := range []bool{hasJWK, hasX5C, hasKID} {
		if found {
			present++
		}
	}
	if present == 0 {
		return nil, invalidProof("proof JWT header carries none of jwk, x5c or kid")
	}
	if present > 1 {
		return nil, invalidProof("proof JWT header carries more than one of jwk, x5c and kid")
	}

	switch {
	case hasJWK:
		key, err := holderKeyFromJWK(jwk)
		if err != nil {
			return nil, invalidProof("parsing proof jwk: %v", err)
		}
		return key, nil
	case hasX5C:
		key, err := proofKeyFromX5C(x5c)
		if err != nil {
			return nil, invalidProof("%v", err)
		}
		return key, nil
	default:
		return nil, invalidProof("proof JWT identifies its key by kid, which this issuer cannot resolve: send jwk or x5c")
	}
}

// proofKeyFromX5C takes the key out of the first certificate of an x5c header,
// which Appendix F.1 defines as "at least one certificate where the first
// certificate contains the key that the Credential is to be bound to".
func proofKeyFromX5C(raw any) (*ecdsa.PublicKey, error) {
	entries, ok := raw.([]any)
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("proof JWT x5c is not a non-empty array")
	}
	encoded, ok := entries[0].(string)
	if !ok {
		return nil, fmt.Errorf("proof JWT x5c leaf is not a string")
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding proof JWT x5c leaf: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing proof JWT x5c leaf: %w", err)
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("proof JWT x5c leaf does not carry an EC key")
	}
	return key, nil
}

// statusListURI is the status list a ticket issued with a status reference
// points at: the wallet's own, so the wallet UI can revoke the credential and
// the demo verifier resolves the list from the same host it trusts.
func (d *DemoRP) statusListURI() string {
	return strings.TrimSpace(d.wallet.StatusListURL())
}

// ticketGrant is what the token exchange settled about the credential a wallet
// is now asking for, read out of the shared offer state under the lock.
type ticketGrant struct {
	subject string
	// holderClaims are the claims of a credential presented to authorize this
	// issuance, empty for a flow that authorized an account instead.
	holderClaims map[string]any
	// jkt is the DPoP key the access token is bound to, empty for a bearer
	// token.
	jkt        string
	withStatus bool
	clientAuth *clientAuthentication
}

// signTicket issues the demo ticket SD-JWT VC, holder-bound to the proof key
// and signed under the local trust profile of the ticket's own attestation
// spec, so the leaf names this issuer and the wallet's trust list carries the
// credential type under that profile.
func (d *DemoRP) signTicket(holderKey *ecdsa.PublicKey, granted ticketGrant) (string, error) {
	spec, err := wallet.NormalizeIssuedAttestationSpec(wallet.IssuedAttestationSpec{
		Format: "dc+sd-jwt",
		VCT:    TicketVCT,
	}, "local")
	if err != nil {
		return "", fmt.Errorf("building ticket attestation spec: %w", err)
	}
	_ = d.wallet.RegisterIssuedAttestation(spec)
	signingKey, chain, err := d.wallet.SigningMaterialForIssuedAttestation(spec)
	if err != nil {
		return "", fmt.Errorf("building signing certificate chain: %w", err)
	}
	config := mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       TicketVCT,
		ExpiresIn: 24 * time.Hour,
		Claims:    ticketClaims(granted.subject, granted.holderClaims, granted.clientAuth),
		Key:       signingKey,
		HolderKey: holderKey,
		CertChain: chain,
	}
	if granted.withStatus {
		uri := d.statusListURI()
		if uri == "" {
			return "", fmt.Errorf("this wallet has no status list URL")
		}
		config.StatusListURI = uri
		// The index has to survive this process: every wallet API request
		// reloads the store, which would otherwise hand the same index to the
		// next credential and revoking one would revoke both.
		config.StatusListIdx = d.wallet.NextStatusIndex()
		d.saveWallet()
	}
	return mock.GenerateSDJWT(config)
}

func decodeJSONBody(r *http.Request, target any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(target)
}

// accessToken reads the access token from the Authorization header. A
// DPoP-bound token arrives under the DPoP scheme, a bearer token under
// Bearer.
func accessToken(r *http.Request) (string, bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	for _, scheme := range []string{"Bearer ", "DPoP "} {
		if len(auth) > len(scheme) && strings.EqualFold(auth[:len(scheme)], scheme) {
			return strings.TrimSpace(auth[len(scheme):]), true
		}
	}
	return "", false
}
