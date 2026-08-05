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
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

//go:embed static
var staticFiles embed.FS

const (
	// TicketVCT is the credential type the demo issuer hands out.
	TicketVCT = "urn:eudi-test:demo-ticket:1"

	ticketConfigurationID = "demo-ticket"
	preAuthGrant          = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

// ticketClaims returns the ticket's test data. An authorization code flow
// authenticates an account first, so the ticket carries that holder's name
// instead of the generic one.
func ticketClaims(subject string) map[string]any {
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
	return claims
}

// offerState tracks one credential offer from creation through the token
// exchange to the collected credential. A pre-authorized offer carries a
// pre-authorized code, an issuer-initiated authorization code offer carries
// the issuer_state that ties it to a browser login.
type offerState struct {
	id          string
	preAuthCode string
	issuerState string
	subject     string
	accessToken string
	cNonce      string
	// jkt is the DPoP key thumbprint the access token is bound to. Empty for
	// the pre-authorized flow, which uses a bearer token.
	jkt     string
	expires time.Time
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
	mux.HandleFunc("POST /par", d.handlePushedAuthorizationRequest)
	mux.HandleFunc("GET /authorize", d.handleAuthorize)
	mux.HandleFunc("POST /authorize", d.handleAuthorizeSubmit)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", d.AuthorizationServerMetadataHandler())
	return mux
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
		"token_endpoint":      issuer + "/token",
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
				"claims": []map[string]any{
					{"path": []string{"event"}},
					{"path": []string{"tier"}},
					{"path": []string{"seat"}},
					{"path": []string{"given_name"}},
					{"path": []string{"family_name"}},
				},
				"proof_types_supported": map[string]any{
					"jwt": map[string]any{"proof_signing_alg_values_supported": []string{"ES256"}},
				},
				"display": []map[string]any{
					{"name": "Demo Event Ticket", "description": "A sample event ticket issued by the demo issuer", "locale": "en-US"},
				},
			},
		},
	})
}

// handleCreateOffer creates a credential offer. ?grant=authorization_code
// produces an offer the wallet redeems through the authorization code flow,
// where the user signs in at the authorization endpoint as part of the
// redemption. Anything else produces a pre-authorized code offer, which
// carries its own authorization and needs no login at all.
func (d *DemoRP) handleCreateOffer(w http.ResponseWriter, r *http.Request) {
	authCode := r.URL.Query().Get("grant") == authCodeGrant

	d.mu.Lock()
	d.pruneLocked()
	if len(d.offers) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open offers, try again later"})
		return
	}
	offer := &offerState{
		id:      randToken(),
		expires: time.Now().Add(entryTTL),
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
	if offer == nil || time.Now().After(offer.expires) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "unknown or expired pre-authorized code",
		})
		return
	}
	offer.accessToken = randToken()
	offer.cNonce = randToken()
	d.tokens[offer.accessToken] = offer
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":       offer.accessToken,
		"token_type":         "Bearer",
		"expires_in":         int(entryTTL.Seconds()),
		"c_nonce":            offer.cNonce,
		"c_nonce_expires_in": int(entryTTL.Seconds()),
	})
}

// credentialRequest covers both the current plural `proofs` form the wallet
// sends and the singular `proof` form for other clients.
type credentialRequest struct {
	CredentialConfigurationID string `json:"credential_configuration_id"`
	CredentialIdentifier      string `json:"credential_identifier"`
	Proofs                    struct {
		JWT []string `json:"jwt"`
	} `json:"proofs"`
	Proof struct {
		ProofType string `json:"proof_type"`
		JWT       string `json:"jwt"`
	} `json:"proof"`
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
	var cNonce, subject, jkt string
	if known {
		cNonce = offer.cNonce
		subject = offer.subject
		jkt = offer.jkt
	}
	d.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	// A token from the authorization code flow is DPoP-bound, so the
	// credential request has to prove possession of the same key again.
	if jkt != "" {
		presented, err := d.verifyDPoPProof(r, d.issuerID()+"/credential", token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, oauthError("invalid_dpop_proof", err.Error()))
			return
		}
		if presented != jkt {
			writeJSON(w, http.StatusUnauthorized, oauthError("invalid_token", "the access token is bound to a different DPoP key"))
			return
		}
	}

	var req credentialRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_credential_request", "error_description": err.Error()})
		return
	}
	proofJWT := req.Proof.JWT
	if len(req.Proofs.JWT) > 0 {
		proofJWT = req.Proofs.JWT[0]
	}
	if proofJWT == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_proof", "error_description": "a jwt proof is required"})
		return
	}

	holderKey, err := verifyProofJWT(proofJWT, cNonce)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_proof", "error_description": err.Error()})
		return
	}

	credential, err := d.signTicket(holderKey, subject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "credential_request_denied", "error_description": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credentials": []map[string]any{{"credential": credential}},
	})
}

// verifyProofJWT validates an openid4vci-proof+jwt: the signature must
// verify with the embedded holder JWK, and the nonce must match the c_nonce
// handed out with the token.
func verifyProofJWT(raw, cNonce string) (*ecdsa.PublicKey, error) {
	proof, err := parseCompactJWT(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing proof JWT: %w", err)
	}
	jwk, ok := proof.header["jwk"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("proof JWT header has no jwk")
	}
	holderKey, err := holderKeyFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("parsing proof jwk: %w", err)
	}
	if !verifyES256(holderKey, proof.signingInput, proof.signature) {
		return nil, fmt.Errorf("proof JWT signature does not verify with the embedded jwk")
	}
	if nonce, _ := proof.payload["nonce"].(string); nonce != cNonce {
		return nil, fmt.Errorf("proof JWT nonce does not match the issued c_nonce")
	}
	return holderKey, nil
}

// signTicket mints the demo ticket SD-JWT VC, holder-bound to the proof key
// and signed with the wallet's issuer key under a leaf certificate from the
// wallet CA, so the wallet's trust list covers the credential.
func (d *DemoRP) signTicket(holderKey *ecdsa.PublicKey, subject string) (string, error) {
	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		return "", fmt.Errorf("building signing certificate chain: %w", err)
	}
	return mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       TicketVCT,
		ExpiresIn: 24 * time.Hour,
		Claims:    ticketClaims(subject),
		Key:       d.wallet.IssuerKey,
		HolderKey: holderKey,
		CertChain: chain,
	})
}

func decodeJSONBody(r *http.Request, target any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(target)
}

// accessToken reads the access token from the Authorization header. The
// pre-authorized flow presents a bearer token, the authorization code flow a
// DPoP-bound one.
func accessToken(r *http.Request) (string, bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	for _, scheme := range []string{"Bearer ", "DPoP "} {
		if len(auth) > len(scheme) && strings.EqualFold(auth[:len(scheme)], scheme) {
			return strings.TrimSpace(auth[len(scheme):]), true
		}
	}
	return "", false
}
