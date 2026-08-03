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

func ticketClaims() map[string]any {
	return map[string]any{
		"event":       "EUDI Interop Fest",
		"tier":        "backstage",
		"seat":        "42A",
		"given_name":  "Erika",
		"family_name": "Mustermann",
	}
}

// offerState tracks one credential offer through the pre-authorized code
// flow: created, code exchanged for a token, credential collected.
type offerState struct {
	id          string
	preAuthCode string
	accessToken string
	cNonce      string
	expires     time.Time
}

// IssuerHandler returns the demo issuer, meant to be mounted with the
// /issuer prefix stripped.
func (d *DemoRP) IssuerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.serveStatic("static/issuer.html"))
	mux.HandleFunc("POST /api/offers", d.handleCreateOffer)
	mux.HandleFunc("GET /offer/{id}", d.handleOfferByReference)
	mux.HandleFunc("POST /token", d.handleToken)
	mux.HandleFunc("POST /credential", d.handleCredential)
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", d.handleIssuerMetadata)
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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
				"display": []map[string]any{
					{"name": "Demo Event Ticket", "locale": "en-US"},
				},
			},
		},
	})
}

func (d *DemoRP) handleCreateOffer(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.pruneLocked()
	if len(d.offers) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open offers, try again later"})
		return
	}
	offer := &offerState{
		id:          randToken(),
		preAuthCode: randToken(),
		expires:     time.Now().Add(entryTTL),
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
	writeJSON(w, http.StatusOK, map[string]any{
		"credential_issuer":            d.issuerID(),
		"credential_configuration_ids": []string{ticketConfigurationID},
		"grants": map[string]any{
			preAuthGrant: map[string]any{
				"pre-authorized_code": offer.preAuthCode,
			},
		},
	})
}

func (d *DemoRP) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if grant := r.PostFormValue("grant_type"); grant != preAuthGrant {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": fmt.Sprintf("only %s is supported", preAuthGrant),
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

	token, ok := bearerToken(r)
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
	var cNonce string
	if known {
		cNonce = offer.cNonce
	}
	d.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
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

	credential, err := d.signTicket(holderKey)
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
func (d *DemoRP) signTicket(holderKey *ecdsa.PublicKey) (string, error) {
	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		return "", fmt.Errorf("building signing certificate chain: %w", err)
	}
	return mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       TicketVCT,
		ExpiresIn: 24 * time.Hour,
		Claims:    ticketClaims(),
		Key:       d.wallet.IssuerKey,
		HolderKey: holderKey,
		CertChain: chain,
	})
}

func decodeJSONBody(r *http.Request, target any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(target)
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		return "", false
	}
	return auth[len(prefix):], true
}
