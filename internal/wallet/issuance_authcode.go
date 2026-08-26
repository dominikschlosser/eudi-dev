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
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

type dpopNonceState struct {
	authzServer string
	resource    string
}

func (w *Wallet) processAuthorizationCodeOffer(
	offer *oid4vc.CredentialOffer,
	metadata map[string]any,
	oauthMeta map[string]any,
	tokenEndpoint string,
	credentialEndpoint string,
	opts OfferOptions,
) (*IssuanceResult, error) {
	if w == nil {
		return nil, fmt.Errorf("wallet is nil")
	}
	clientID := strings.TrimSpace(w.VCIClientID)
	redirectURI := strings.TrimSpace(w.VCIRedirectURI)
	if clientID == "" {
		return nil, fmt.Errorf("OID4VCI authorization_code flow requires a configured wallet client_id")
	}

	// Interactive Authorization replaces the redirect flow below where the
	// server offers it and the feature level allows it. It needs no redirect
	// URI, since nothing is redirected anywhere.
	challengeEndpoint := interactiveAuthorizationEndpoint(oauthMeta)
	useInteractive := challengeEndpoint != "" && w.VCIFeatureVersion().UsesInteractiveAuthorization()
	if !useInteractive {
		w.noteDeclinedInteractiveAuthorization(oauthMeta, challengeEndpoint)
		if redirectURI == "" {
			return nil, fmt.Errorf("OID4VCI authorization_code flow requires configured wallet client_id and redirect_uri")
		}
	}

	// PAR is used where the server publishes the endpoint. RFC 9126 §2 makes
	// publishing it a SHOULD, so its absence means the request goes to the
	// authorization endpoint instead. OpenID4VCI requires neither.
	parEndpoint, _ := oauthMeta["pushed_authorization_request_endpoint"].(string)
	authorizationEndpoint, _ := oauthMeta["authorization_endpoint"].(string)
	if authorizationEndpoint == "" && !useInteractive {
		return nil, fmt.Errorf("authorization server metadata did not include authorization_endpoint")
	}

	clientAuthMethod := detectTokenEndpointAuthMethod(oauthMeta)
	switch clientAuthMethod {
	case "", unauthenticatedClientMethod, "private_key_jwt", "attest_jwt_client_auth", "attest_jwt_client_auth_dpop":
	case unregisteredPublicClientMethod:
		// RFC 8414 takes these values from the IANA registry, where an
		// unauthenticated client is "none". "public" is not registered.
		if err := w.reportServerDeviation(fmt.Sprintf("authorization server advertises the unregistered token endpoint auth method %q; RFC 8414 takes these values from the OAuth Token Endpoint Authentication Methods registry, where an unauthenticated client is %q", unregisteredPublicClientMethod, unauthenticatedClientMethod)); err != nil {
			return nil, err
		}
	default:
		// Everything else needs a credential the wallet was never issued, such
		// as the client secret the client_secret_* methods sign or send.
		return nil, fmt.Errorf("unsupported token endpoint auth method %q", clientAuthMethod)
	}
	dpopKey := w.dpopKeyFor(oauthMeta)

	configID := ""
	if len(offer.CredentialConfigurationIDs) > 0 {
		configID = offer.CredentialConfigurationIDs[0]
	}
	scope := resolveCredentialScope(metadata, configID)
	if scope == "" {
		return nil, fmt.Errorf("credential configuration %q did not expose a scope for authorization_code flow", configID)
	}

	state := randomBase64URL(18)
	codeVerifier := randomBase64URL(32)
	codeChallenge := codeChallengeS256(codeVerifier)
	nonces := &dpopNonceState{}
	parForm := url.Values{}
	parForm.Set("response_type", "code")
	parForm.Set("client_id", clientID)
	parForm.Set("redirect_uri", redirectURI)
	parForm.Set("scope", scope)
	parForm.Set("state", state)
	parForm.Set("code_challenge", codeChallenge)
	parForm.Set("code_challenge_method", "S256")
	if offer.Grants.IssuerState != "" {
		parForm.Set("issuer_state", offer.Grants.IssuerState)
	}
	// How this authorization server wants the client authenticated, resolved
	// once here and kept with the credential: a refresh is another token
	// request at the same endpoint, long after this metadata is gone.
	authCtx := clientAuthContext{oauthMeta: oauthMeta, clientID: clientID, tokenEndpoint: tokenEndpoint}
	clientAuth := w.resolveClientAuthentication(clientAuthMethod, authCtx)
	if err := applyClientAuthentication(parForm, clientAuth, w.HolderKey); err != nil {
		return nil, err
	}

	setup := authorizationCodeSetup{
		clientID:              clientID,
		redirectURI:           redirectURI,
		scope:                 scope,
		state:                 state,
		codeVerifier:          codeVerifier,
		codeChallenge:         codeChallenge,
		clientAuth:            clientAuth,
		dpopKey:               dpopKey,
		nonces:                nonces,
		authorizationEndpoint: authorizationEndpoint,
		issuer:                oauthIssuer(oauthMeta, ""),
		issRequired:           issAdvertised(oauthMeta),

		presentationConsented: opts.PresentationConsented,
		owner:                 opts.Owner,
	}
	issuance := authorizationCodeIssuance{
		offer:              offer,
		metadata:           metadata,
		tokenEndpoint:      tokenEndpoint,
		credentialEndpoint: credentialEndpoint,
		clientID:           clientID,
		codeVerifier:       codeVerifier,
		clientAuth:         clientAuth,
		dpopKey:            dpopKey,
		nonces:             nonces,
		configID:           configID,
	}

	// requestURI is empty when the request goes to the authorization endpoint
	// directly, and the parameters travel in the query string instead.
	var requestURI string

	if useInteractive {
		code, viaWeb, err := w.obtainInteractiveAuthorizationCode(challengeEndpoint, setup, offer)
		switch {
		case err == nil:
			// A code from the challenge conversation had no redirect, so the
			// token request omits redirect_uri (first-party-apps §6). One from
			// the auth_via_web browser redirect came through an authorization
			// request that carried it, so the token request repeats it
			// (RFC 6749 §4.1.3).
			if viaWeb {
				issuance.redirectURI = redirectURI
			}
			return w.completeAuthorizationCodeIssuance(issuance, code)
		case isRedirectToWeb(err):
			// The server sent this exchange to a browser after all, so the
			// redirect flow below finishes it, with the pushed request the
			// server offered where it offered one.
			if err := w.noteRedirectToWeb(challengeEndpoint, redirectURI, authorizationEndpoint); err != nil {
				return nil, err
			}
			requestURI = redirectToWebRequestURI(err)
			issuance.redirectURI = redirectURI
		default:
			return nil, err
		}
	}

	if requestURI == "" && parEndpoint != "" {
		w.addProtocolLog("issuance", "par_request", fmt.Sprintf("Request PAR from %s", parEndpoint), true, formRequestLogDetails(parEndpoint, "par", parForm))
		parResp, err := postFormWithDPoP(parEndpoint, parForm, dpopKey, "", &nonces.authzServer, w.attestorFor(clientAuth))
		w.addProtocolLog("issuance", "par_response", fmt.Sprintf("PAR response from %s", parEndpoint), err == nil, responseMapLogDetails(parEndpoint, "par", parResp, err))
		if err != nil {
			return nil, fmt.Errorf("PAR request: %w", err)
		}
		requestURI, _ = parResp["request_uri"].(string)
		if requestURI == "" {
			return nil, fmt.Errorf("PAR response missing request_uri")
		}
	}

	w.addProtocolLog("issuance", "authorization_request", fmt.Sprintf("Start authorization request at %s", authorizationEndpoint), true, map[string]any{
		"direction":    "outbound",
		"method":       "GET",
		"url":          authorizationEndpoint,
		"endpoint":     "authorization",
		"client_id":    clientID,
		"request_uri":  requestURI,
		"redirect_uri": redirectURI,
		"state":        state,
	})
	callbackValues, err := runAuthorizationCodeRequest(w, authorizationEndpoint, clientID, requestURI, parForm, redirectURI, state, oauthIssuer(oauthMeta, ""), opts.Owner, issAdvertised(oauthMeta))
	authorizationResponseDetails := map[string]any{
		"direction": "inbound",
		"endpoint":  "authorization",
		"state":     state,
	}
	if callbackValues != nil {
		authorizationResponseDetails["callback_values"] = callbackValues
	}
	if err != nil {
		authorizationResponseDetails["error"] = err.Error()
	}
	w.addProtocolLog("issuance", "authorization_response", fmt.Sprintf("Authorization response for %s", authorizationEndpoint), err == nil, authorizationResponseDetails)
	if err != nil {
		return nil, fmt.Errorf("authorization request: %w", err)
	}
	code := callbackValues.Get("code")
	if code == "" {
		return nil, fmt.Errorf("authorization callback missing code in values %q", callbackValues.Encode())
	}

	issuance.redirectURI = redirectURI
	return w.completeAuthorizationCodeIssuance(issuance, code)
}

// authorizationCodeSetup is what both routes to an authorization code need:
// the client's identity to the authorization server, and the keys and nonces
// the exchange uses.
type authorizationCodeSetup struct {
	clientID      string
	redirectURI   string
	scope         string
	state         string
	codeVerifier  string
	codeChallenge string
	clientAuth    *ClientAuthentication
	dpopKey       *ecdsa.PrivateKey
	nonces        *dpopNonceState
	// authorizationEndpoint and issuer are what the auth_via_web interaction
	// of OpenID4VCI 1.1 §6.2.1.2 needs: the endpoint the request_uri is taken
	// to, and the issuer the redirect back is checked against.
	authorizationEndpoint string
	issuer                string
	// issRequired is whether the authorization server advertised
	// authorization_response_iss_parameter_supported, which makes iss REQUIRED
	// in the response (RFC 9207).
	issRequired bool
	// presentationConsented skips the consent for a presentation the issuer
	// asks for, because the caller already gave it.
	presentationConsented bool
	// owner is the browser the issuance belongs to.
	owner string
}

// authorizationCodeIssuance carries what the second half of an authorization
// code issuance needs, and nothing about how the code was obtained.
type authorizationCodeIssuance struct {
	offer              *oid4vc.CredentialOffer
	metadata           map[string]any
	tokenEndpoint      string
	credentialEndpoint string
	clientID           string
	// redirectURI is empty where the flow that produced the code had none, and
	// the token request then omits it (RFC 6749 §4.1.3).
	redirectURI  string
	codeVerifier string
	clientAuth   *ClientAuthentication
	dpopKey      *ecdsa.PrivateKey
	nonces       *dpopNonceState
	configID     string
}

// completeAuthorizationCodeIssuance exchanges an authorization code for an
// access token and takes the flow through to an imported credential.
func (w *Wallet) completeAuthorizationCodeIssuance(ctx authorizationCodeIssuance, code string) (*IssuanceResult, error) {
	offer := ctx.offer
	metadata := ctx.metadata
	tokenEndpoint := ctx.tokenEndpoint
	credentialEndpoint := ctx.credentialEndpoint
	clientID := ctx.clientID
	clientAuth := ctx.clientAuth
	dpopKey := ctx.dpopKey
	nonces := ctx.nonces
	configID := ctx.configID

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("client_id", clientID)
	if ctx.redirectURI != "" {
		tokenForm.Set("redirect_uri", ctx.redirectURI)
	}
	tokenForm.Set("code_verifier", ctx.codeVerifier)
	if err := applyClientAuthentication(tokenForm, clientAuth, w.HolderKey); err != nil {
		return nil, err
	}

	// The wallet attestation and the DPoP proof travel as headers, so the
	// log names them next to the form.
	attestor := w.attestorFor(clientAuth)
	tokenDetails := formRequestLogDetails(tokenEndpoint, "token", tokenForm)
	tokenDetails["client_attestation"] = attestor != nil
	tokenDetails["dpop"] = dpopKey != nil
	w.addProtocolLog("issuance", "token_request", fmt.Sprintf("Request token from %s", tokenEndpoint), true, tokenDetails)
	tokenResp, err := postFormWithDPoP(tokenEndpoint, tokenForm, dpopKey, "", &nonces.authzServer, attestor)
	w.addProtocolLog("issuance", "token_response", fmt.Sprintf("Token response from %s", tokenEndpoint), err == nil, responseMapLogDetails(tokenEndpoint, "token", tokenResp, err))
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	accessToken, _ := tokenResp["access_token"].(string)
	refreshToken, expiresIn := tokenGrantRenewal(tokenResp)
	if accessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}
	authScheme := accessTokenScheme(tokenResp, dpopKey != nil)

	if nonceEndpoint, _ := metadata["nonce_endpoint"].(string); nonceEndpoint != "" {
		w.addProtocolLog("issuance", "nonce_request", fmt.Sprintf("Request nonce from %s", nonceEndpoint), true, map[string]any{
			"direction": "outbound",
			"method":    "POST",
			"url":       nonceEndpoint,
			"endpoint":  "nonce",
		})
	}
	cNonce := w.issuanceChallenge(metadata, tokenResp, offer.CredentialIssuer, &nonces.resource)
	if nonceEndpoint, _ := metadata["nonce_endpoint"].(string); nonceEndpoint != "" {
		w.addProtocolLog("issuance", "nonce_response", fmt.Sprintf("Nonce response from %s", nonceEndpoint), cNonce != "", map[string]any{
			"direction": "inbound",
			"url":       nonceEndpoint,
			"endpoint":  "nonce",
			"c_nonce":   cNonce,
		})
	}

	proofKeys, err := issuanceProofKeys(w.HolderKey, metadata, configID)
	if err != nil {
		return nil, fmt.Errorf("preparing proof keys: %w", err)
	}

	credentialIdentifier := resolveCredentialIdentifier(tokenResp)
	credentialConfigurationID := ""
	if credentialIdentifier == "" && len(offer.CredentialConfigurationIDs) > 0 {
		credentialConfigurationID = offer.CredentialConfigurationIDs[0]
	}
	responseEncryption, err := buildCredentialResponseEncryptionRequest(w.Mode(), metadata, w.HolderKey)
	if err != nil {
		return nil, err
	}

	attempt := credentialRequestAttempt{
		metadata:                  metadata,
		endpoint:                  credentialEndpoint,
		issuer:                    offer.CredentialIssuer,
		configID:                  configID,
		accessToken:               accessToken,
		authScheme:                authScheme,
		credentialIdentifier:      credentialIdentifier,
		credentialConfigurationID: credentialConfigurationID,
		responseEncryption:        responseEncryption,
		dpopKey:                   dpopKey,
		proofKeys:                 proofKeys,
		// The authorization code flow always identifies the client, so the key
		// proof names it as iss for an issuer that binds the token to it.
		clientID: clientID,
		nonce:    &nonces.resource,
	}
	proofJWTs, err := w.buildCredentialProofs(attempt, cNonce)
	if err != nil {
		return nil, err
	}

	credResp, err := w.requestCredentialWithNonceRetry(attempt, proofJWTs)
	if err != nil {
		return nil, fmt.Errorf("requesting credential: %w", err)
	}

	credResp, pending, err := w.resolveDeferredCredential(credResp, deferredContext{
		metadata:      metadata,
		tokenEndpoint: tokenEndpoint,
		clientID:      clientID,
		clientAuth:    clientAuth,
		refreshToken:  refreshToken,
		expiresIn:     expiresIn,
		issuer:        offer.CredentialIssuer,
		configID:      configID,
		format:        resolveCredentialFormat(metadata, credentialConfigurationID),
		accessToken:   accessToken,
		authScheme:    authScheme,
		dpopKey:       dpopKey,
		proofKeys:     proofKeys,
		nonce:         &nonces.resource,
	})
	if err != nil {
		return nil, err
	}
	display := w.resolveCredentialDisplay(metadata, configID)
	if pending != nil {
		pending.Display = display
		return w.recordDeferredIssuance(pending), nil
	}

	credential, err := selectPrimaryCredential(credResp, proofKeys)
	if err != nil {
		return nil, err
	}

	imported, err := w.importPrimaryCredential(credential, proofKeys)
	if err != nil {
		return nil, fmt.Errorf("importing received credential: %w", err)
	}
	w.logCredentialImport(imported, credential, offer.CredentialIssuer)
	w.rememberRenewal(imported.ID, refreshToken, CredentialRenewal{
		Issuer:             offer.CredentialIssuer,
		TokenEndpoint:      tokenEndpoint,
		CredentialEndpoint: credentialEndpoint,
		ConfigurationID:    configID,
		ClientID:           clientID,
		UseDPoP:            dpopKey != nil,
		ClientAuth:         clientAuth,
	})
	w.rememberDisplay(imported, display)
	w.storeBatchSiblings(imported, credResp, proofKeys, display)

	w.notifyCredentialAccepted(metadata, credResp, accessToken, authScheme, dpopKey, &nonces.resource)

	credFormat := resolveCredentialFormat(metadata, credentialConfigurationID)
	if credFormat == "" {
		credFormat = imported.Format
	}
	verificationStatus, verificationDetail := verifyImportedJWTMetadataSignature(credential)
	return &IssuanceResult{
		CredentialID:       imported.ID,
		Format:             credFormat,
		Issuer:             offer.CredentialIssuer,
		VerificationStatus: verificationStatus,
		VerificationDetail: verificationDetail,
		Imported:           imported,
	}, nil
}

// detectTokenEndpointAuthMethod picks the client authentication method from
// the ones the authorization server offers. Attestation wins wherever it is
// offered, since the wallet can sign one itself and the counterparty decides
// what it is worth. The methods that ask nothing are read too, so a server
// offering only those stays usable.

// unauthenticatedClientMethod is the registered method of a client that does
// not authenticate (RFC 8414, via the IANA registry).
const unauthenticatedClientMethod = "none"

// unregisteredPublicClientMethod is a value some deployments publish for the
// same thing. It is not in the registry, so it is reported as a deviation
// before the wallet acts on what it evidently means.
const unregisteredPublicClientMethod = "public"

// noteDeclinedInteractiveAuthorization records an offer of Interactive
// Authorization (OpenID4VCI 1.1 §6) the wallet is not taking up, and names the
// flag that would.
func (w *Wallet) noteDeclinedInteractiveAuthorization(oauthMeta map[string]any, endpoint string) {
	if endpoint == "" {
		return
	}
	details := map[string]any{"authorization_challenge_endpoint": endpoint}
	required, _ := oauthMeta["require_interactive_authorization"].(bool)
	if required {
		details["require_interactive_authorization"] = true
	}
	detail := fmt.Sprintf("authorization server offers interactive authorization (OpenID4VCI 1.1 §6) at %s, and this wallet is set to OpenID4VCI 1.0, so the redirect flow is used; --vci-version 1.1 selects the challenge endpoint instead", endpoint)
	if required {
		detail = fmt.Sprintf("authorization server requires interactive authorization (OpenID4VCI 1.1 §6, require_interactive_authorization) at %s, and this wallet is set to OpenID4VCI 1.0, so the redirect flow is attempted and is likely to be refused; --vci-version 1.1 selects the challenge endpoint instead", endpoint)
	}
	w.addProtocolLog("issuance", "interactive_authorization_offered", detail, true, details)
	log.Printf("[VCI] %s", detail)
}

// reportServerDeviation records something the counterparty got wrong. Strict
// refuses to go on, debug names it and continues, which is the difference
// between the two modes everywhere else in the wallet.
func (w *Wallet) reportServerDeviation(detail string) error {
	details := map[string]any{"deviation": detail}
	if w.Mode() == ValidationModeStrict {
		w.addProtocolLog("issuance", "server_deviation", detail, false, details)
		return fmt.Errorf("%s", detail)
	}
	w.addProtocolWarning("issuance", "server_deviation", detail, details)
	log.Printf("[VCI] WARNING: %s", detail)
	return nil
}

func detectTokenEndpointAuthMethod(oauthMeta map[string]any) string {
	methods, ok := oauthMeta["token_endpoint_auth_methods_supported"].([]any)
	if !ok || len(methods) == 0 {
		return ""
	}
	for _, raw := range methods {
		method, _ := raw.(string)
		if method == "attest_jwt_client_auth" {
			return method
		}
	}
	// The combined method of draft-10 §5.2, where the DPoP proof is the
	// possession proof. Taken only where the dedicated-PoP method is not
	// offered, since the dedicated PoP works without DPoP being negotiated.
	for _, raw := range methods {
		method, _ := raw.(string)
		if method == "attest_jwt_client_auth_dpop" {
			return method
		}
	}
	for _, raw := range methods {
		method, _ := raw.(string)
		if method == "private_key_jwt" {
			return method
		}
	}
	// Last: a client that authenticates is preferred to one that does not.
	for _, raw := range methods {
		method, _ := raw.(string)
		if method == unauthenticatedClientMethod || method == unregisteredPublicClientMethod {
			return method
		}
	}
	if method, _ := methods[0].(string); method != "" {
		return method
	}
	return ""
}

func supportsDPoP(oauthMeta map[string]any) bool {
	values, ok := oauthMeta["dpop_signing_alg_values_supported"].([]any)
	return ok && len(values) > 0
}

func resolveCredentialScope(metadata map[string]any, configID string) string {
	configs, ok := metadata["credential_configurations_supported"].(map[string]any)
	if !ok {
		return ""
	}
	cfg, ok := configs[configID].(map[string]any)
	if !ok {
		return ""
	}
	scope, _ := cfg["scope"].(string)
	return scope
}

func oauthIssuer(oauthMeta map[string]any, fallback string) string {
	if issuer, _ := oauthMeta["issuer"].(string); issuer != "" {
		return issuer
	}
	return fallback
}

// issAdvertised reports whether the authorization server metadata advertises
// authorization_response_iss_parameter_supported, which makes iss REQUIRED in
// the authorization response (RFC 9207).
func issAdvertised(oauthMeta map[string]any) bool {
	supported, _ := oauthMeta["authorization_response_iss_parameter_supported"].(bool)
	return supported
}

// attestsClient reports whether to authenticate with the wallet attestation.
//
// It always attests when the server advertises it
// (draft-ietf-oauth-attestation-based-client-auth §8) or when
// ForceClientAttestation was set. HAIP 1.0 §4.4.1 goes further ("Wallets MUST
// use, and Issuers MUST require, an OAuth2 Client authentication mechanism"),
// so under HAIP the remaining cases turn on the metadata:
//
//   - No method advertised at all: attest anyway, since §10.1 makes
//     advertising only a SHOULD.
//   - Only unauthenticated access advertised: debug takes the server at its
//     word and does not attest, strict attests and lets the exchange fail.
func (w *Wallet) attestsClient(oauthMeta map[string]any) bool {
	if w == nil {
		return false
	}
	method := detectTokenEndpointAuthMethod(oauthMeta)
	if w.ForceClientAttestation || method == "attest_jwt_client_auth" || method == "attest_jwt_client_auth_dpop" {
		return true
	}
	if !w.RequireHAIP {
		return false
	}
	if w.Mode() == ValidationModeStrict {
		return true
	}
	// debug: attest a silent issuer, honor one that named an unauthenticated method.
	return method == ""
}

// clientAuthContext is what deciding, and re-deciding, client authentication
// needs: the authorization server's metadata, who the wallet says it is, and
// the token endpoint that stands in for a server that does not name itself.
type clientAuthContext struct {
	oauthMeta     map[string]any
	clientID      string
	tokenEndpoint string
}

// resolveClientAuthentication reads how this authorization server wants the
// client authenticated; nil means it asked for nothing. The answer is kept
// with the credential, since a refresh is another request to the same
// endpoint.
func (w *Wallet) resolveClientAuthentication(method string, ctx clientAuthContext) *ClientAuthentication {
	if method == ClientAuthPrivateKeyJWT {
		return &ClientAuthentication{
			Method:   ClientAuthPrivateKeyJWT,
			ClientID: ctx.clientID,
			Audience: oauthIssuer(ctx.oauthMeta, ctx.tokenEndpoint),
		}
	}
	if w.attestsClient(ctx.oauthMeta) {
		// §10.1 lets an issuer require attestation without advertising it, so
		// the wallet attests, but the missing advertisement is a deviation.
		if w != nil && w.RequireHAIP && w.Mode() != ValidationModeStrict &&
			!w.ForceClientAttestation &&
			detectTokenEndpointAuthMethod(ctx.oauthMeta) == "" {
			w.addProtocolWarning("issuance", "client_authentication_not_advertised",
				"The issuer's authorization server advertises no token endpoint client authentication method (draft-ietf-oauth-attestation-based-client-auth §10.1 recommends it). Attesting anyway, since HAIP requires client authentication.",
				map[string]any{"token_endpoint": ctx.tokenEndpoint})
		}
		return w.attestationClientAuth(ctx)
	}
	// The wallet is not attesting. HAIP wanted client authentication but this
	// issuer advertised only unauthenticated access, so debug proceeds without
	// it: record the profile violation so it is visible without failing.
	if w != nil && w.RequireHAIP && !w.ForceClientAttestation {
		w.addProtocolWarning("issuance", "haip_client_authentication_unavailable",
			"HAIP 1.0 §4.4.1 requires client authentication at the token endpoint, but this issuer's authorization server offers only unauthenticated access. Proceeding without it.",
			map[string]any{"token_endpoint": ctx.tokenEndpoint})
	}
	return nil
}

func (w *Wallet) attestationClientAuth(ctx clientAuthContext) *ClientAuthentication {
	challengeEndpoint, _ := ctx.oauthMeta["challenge_endpoint"].(string)
	auth := &ClientAuthentication{
		Method:            ClientAuthAttestation,
		ClientID:          ctx.clientID,
		Audience:          oauthIssuer(ctx.oauthMeta, ctx.tokenEndpoint),
		ChallengeEndpoint: challengeEndpoint,
		ABCADraft:         w.VCIFeatureVersion().ABCADraft(),
	}
	if usesCombinedPoP(ctx.oauthMeta) {
		auth.CombinedPoP = true
		if auth.ABCADraft < ABCALatestDraft {
			w.addProtocolWarning("issuance", "abca_draft_feature",
				fmt.Sprintf("This authorization server takes the DPoP proof as the attestation's possession proof (dpop_combined), a draft-10 mechanism, while the configured OpenID4VCI version pins attestation-based client authentication draft-0%d. Using it, since the server offers nothing earlier.", auth.ABCADraft),
				map[string]any{"token_endpoint": ctx.tokenEndpoint})
		}
	}
	return auth
}

// usesCombinedPoP reports whether the DPoP proof serves as the possession
// proof for the attestation (draft-10 §5.2): the server offers only the
// attest_jwt_client_auth_dpop method, or its
// client_attestation_pop_methods_supported (a draft-10 parameter the earlier
// drafts' servers omit) names dpop_combined without attestation_pop_jwt.
func usesCombinedPoP(oauthMeta map[string]any) bool {
	if detectTokenEndpointAuthMethod(oauthMeta) == "attest_jwt_client_auth_dpop" {
		return true
	}
	values, ok := oauthMeta["client_attestation_pop_methods_supported"].([]any)
	if !ok {
		return false
	}
	combined, dedicated := false, false
	for _, raw := range values {
		switch raw {
		case "dpop_combined":
			combined = true
		case "attestation_pop_jwt":
			dedicated = true
		}
	}
	return combined && !dedicated
}

// usesDPoP reports whether requests to this authorization server carry a DPoP
// proof: it advertises DPoP (RFC 9449 §5.1), or it demands the combined
// attestation possession proof, whose proof is a DPoP proof (draft-10 §5.2).
func usesDPoP(oauthMeta map[string]any) bool {
	return supportsDPoP(oauthMeta) || usesCombinedPoP(oauthMeta)
}

// dpopKeyFor is the key requests to this authorization server sign their DPoP
// proofs with, nil where the server neither advertises DPoP nor demands the
// combined possession proof. RFC 9449 leaves the metadata optional, so a
// server naming no algorithms and no combined method issues bearer tokens.
func (w *Wallet) dpopKeyFor(oauthMeta map[string]any) *ecdsa.PrivateKey {
	if usesDPoP(oauthMeta) {
		return w.HolderKey
	}
	return nil
}

// attestorFor builds the attestor a request carries its wallet
// attestation with, or nil when this authentication needs no headers.
func (w *Wallet) attestorFor(auth *ClientAuthentication) *clientAttestor {
	if auth == nil || auth.Method != ClientAuthAttestation {
		return nil
	}
	return &clientAttestor{wallet: w, auth: auth}
}

// clientAttestor puts the wallet attestation on requests and follows the
// challenge conversation the server may hold across responses: every
// supported ABCA draft lets a server hand out a fresh challenge in the
// OAuth-Client-Attestation-Challenge header of any response, and the client
// MUST carry it in the next PoP.
type clientAttestor struct {
	wallet *Wallet
	auth   *ClientAuthentication
	// challenge is the server-provided challenge the next PoP carries.
	challenge string
}

// headers mints the attestation headers for one request. In combined mode
// the challenge travels in the DPoP proof (dpopChallenge).
func (a *clientAttestor) headers() (map[string]string, error) {
	challenge := ""
	if !a.auth.CombinedPoP {
		var err error
		challenge, err = a.requestChallenge()
		if err != nil {
			return nil, err
		}
	}
	headers, err := createClientAttestationHeaders(a.wallet, a.auth, challenge)
	if err != nil {
		return nil, fmt.Errorf("creating client attestation headers: %w", err)
	}
	return headers, nil
}

// requestChallenge resolves the challenge one request carries: the one the
// server handed out in a response header, consumed here because challenges
// are single use, or a fresh one from the challenge endpoint the metadata
// names. Resolved per request, since a server that requires a challenge
// refuses a stale one.
func (a *clientAttestor) requestChallenge() (string, error) {
	challenge := a.challenge
	a.challenge = ""
	if challenge != "" {
		return challenge, nil
	}
	challenge, err := fetchAttestationChallenge(a.auth.ChallengeEndpoint)
	if err != nil {
		return "", fmt.Errorf("fetching client attestation challenge: %w", err)
	}
	return challenge, nil
}

// dpopChallenge resolves the challenge the DPoP proof carries in combined
// mode, where that proof is the attestation's possession proof and the
// challenge claim lives in it (draft-10 §5.2). Empty with a dedicated PoP,
// which carries the challenge itself.
func (a *clientAttestor) dpopChallenge() (string, error) {
	if !a.auth.CombinedPoP {
		return "", nil
	}
	return a.requestChallenge()
}

// observe reads the challenge a response hands out for the next PoP.
func (a *clientAttestor) observe(headers http.Header) {
	if value := strings.TrimSpace(headers.Get("OAuth-Client-Attestation-Challenge")); value != "" {
		a.challenge = value
	}
}

// retryAfterRefusal reports whether the refusal asks for another attempt with
// fresh attestation material: use_attestation_challenge arrives together with
// the challenge the retry has to carry (§6.2 requires the header alongside
// it), and use_fresh_attestation asks for a newer attestation, which this
// wallet mints per request anyway.
func (a *clientAttestor) retryAfterRefusal(body []byte) bool {
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	switch parsed.Error {
	case "use_attestation_challenge":
		return a.challenge != ""
	case "use_fresh_attestation":
		return true
	}
	return false
}

// applyClientAuthentication puts into the form what belongs in the form.
// private_key_jwt authenticates there, an attestation in the headers.
func applyClientAuthentication(form url.Values, auth *ClientAuthentication, holderKey *ecdsa.PrivateKey) error {
	if auth == nil || auth.Method != ClientAuthPrivateKeyJWT {
		return nil
	}
	assertion, err := createClientAssertionJWT(holderKey, auth.ClientID, auth.Audience)
	if err != nil {
		return fmt.Errorf("creating client assertion: %w", err)
	}
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	return nil
}

// createClientAttestationHeaders mints the attestation and, outside combined
// mode, the PoP that proves possession of the attested key. Both carry the
// union of the claims the supported drafts define, which is the draft-07
// shape: the later drafts only stopped requiring claims, and every one of
// them lets a JWT carry claims it does not define itself (§5.1 and §5.2 rule
// 1), so this one shape verifies under all of them.
func createClientAttestationHeaders(w *Wallet, auth *ClientAuthentication, challenge string) (map[string]string, error) {
	if w == nil || w.IssuerKey == nil || len(w.CertChain) == 0 {
		return nil, fmt.Errorf("wallet issuer signing material is not configured")
	}

	x5c := buildJWSX5C(w.CertChain)
	holderJWK := mock.SigningJWKMap(&w.HolderKey.PublicKey)
	clientAttestationHeader := map[string]any{
		"alg": "ES256",
		"typ": "oauth-client-attestation+jwt",
		"x5c": x5c,
	}
	if kid := mock.KeyIDForPublicKey(&w.IssuerKey.PublicKey); kid != "" {
		clientAttestationHeader["kid"] = kid
	}
	clientAttestationPayload := map[string]any{
		"sub": auth.ClientID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"cnf": map[string]any{"jwk": holderJWK},
		// Draft-07 §5.1 requires iss and defines nbf, and draft-08 dropped
		// both from the claims it defines while keeping the rule that a JWT
		// MAY carry further claims (§5.1 rule 1). Naming the attester and the
		// validity window in every shape is what a draft-07 server needs and
		// a later one ignores.
		"iss": w.IssuerURL,
		"nbf": time.Now().Unix(),
	}
	clientAttestationJWT, err := signJWT(clientAttestationHeader, clientAttestationPayload, w.IssuerKey)
	if err != nil {
		return nil, err
	}
	if auth.CombinedPoP {
		// The DPoP proof on the request is the possession proof (draft-10
		// §5.2), so the attestation travels alone.
		return map[string]string{"OAuth-Client-Attestation": clientAttestationJWT}, nil
	}

	popHeader := map[string]any{
		"alg": "ES256",
		"typ": "oauth-client-attestation-pop+jwt",
		"jwk": holderJWK,
	}
	popPayload := map[string]any{
		"aud": auth.Audience,
		"iat": time.Now().Unix(),
		"jti": randomBase64URL(18),
		// Draft-07 §5.2 requires iss and defines nbf, and draft-08 dropped
		// both from the claims it defines while keeping the rule that a JWT
		// MAY carry further claims (§5.2 rule 1). Naming the client and the
		// validity window in every shape is what a draft-07 server needs and
		// a later one ignores.
		"iss": auth.ClientID,
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	if challenge != "" {
		popPayload["challenge"] = challenge
	}
	clientAttestationPoP, err := signJWT(popHeader, popPayload, w.HolderKey)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"OAuth-Client-Attestation":     clientAttestationJWT,
		"OAuth-Client-Attestation-PoP": clientAttestationPoP,
	}, nil
}

func fetchAttestationChallenge(endpoint string) (string, error) {
	if endpoint == "" {
		return "", nil
	}
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("creating challenge request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := doIssuanceRequest(req)
	if err != nil {
		return "", fmt.Errorf("challenge request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := format.ReadRemoteBody(resp.Body, "issuer response")
		return "", fmt.Errorf("challenge endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("parsing challenge response: %w", err)
	}
	challenge, _ := payload["attestation_challenge"].(string)
	if challenge == "" {
		challenge, _ = payload["challenge"].(string)
	}
	return challenge, nil
}

func createCredentialProofHeader(w *Wallet, metadata map[string]any, configID, cNonce string, proofKeys []*ecdsa.PrivateKey) (map[string]any, error) {
	requirement, required := credentialKeyAttestationRequirement(metadata, configID)
	if !required {
		return nil, nil
	}
	if w == nil || w.IssuerKey == nil || len(w.CertChain) == 0 {
		return nil, fmt.Errorf("wallet issuer signing material is not configured")
	}
	if len(proofKeys) == 0 {
		proofKeys = []*ecdsa.PrivateKey{w.HolderKey}
	}
	attestedKeys := make([]any, 0, len(proofKeys))
	for _, key := range proofKeys {
		attestedKeys = append(attestedKeys, mock.SigningJWKMap(&key.PublicKey))
	}
	header := map[string]any{
		"alg": "ES256",
		"typ": "key-attestation+jwt",
		"x5c": buildJWSX5C(w.CertChain),
	}
	if kid := mock.KeyIDForPublicKey(&w.IssuerKey.PublicKey); kid != "" {
		header["kid"] = kid
	}
	payload := map[string]any{
		"iat":           time.Now().Unix(),
		"nbf":           time.Now().Unix(),
		"exp":           time.Now().Add(5 * time.Minute).Unix(),
		"attested_keys": attestedKeys,
	}
	// OID4VCI 1.0 Appendix D: the attestation states how well key storage and
	// user authentication resist attack. An issuer naming values in
	// key_attestations_required rejects an attestation claiming nothing, so
	// mirror what it asks for. This is a test wallet with a software key, so
	// it only ever repeats the issuer's own requirement.
	for _, claim := range []string{"key_storage", "user_authentication"} {
		if values, ok := requirement[claim].([]any); ok && len(values) > 0 {
			payload[claim] = values
		}
	}
	if cNonce != "" {
		payload["nonce"] = cNonce
	}
	keyAttestationJWT, err := signJWT(header, payload, w.IssuerKey)
	if err != nil {
		return nil, fmt.Errorf("creating key attestation JWT: %w", err)
	}
	return map[string]any{"key_attestation": keyAttestationJWT}, nil
}

// credentialKeyAttestationRequirement reports whether a credential
// configuration requires a key attestation, and what it requires. The presence
// of key_attestations_required alone makes it mandatory, so an empty one (or a
// non-object, which some issuers send) still gets an attestation.
func credentialKeyAttestationRequirement(metadata map[string]any, configID string) (map[string]any, bool) {
	if configID == "" {
		return nil, false
	}
	configs, ok := metadata["credential_configurations_supported"].(map[string]any)
	if !ok {
		return nil, false
	}
	cfg, ok := configs[configID].(map[string]any)
	if !ok {
		return nil, false
	}
	proofTypes, ok := cfg["proof_types_supported"].(map[string]any)
	if !ok {
		return nil, false
	}
	jwtProof, ok := proofTypes["jwt"].(map[string]any)
	if !ok {
		return nil, false
	}
	raw, ok := jwtProof["key_attestations_required"]
	if !ok {
		return nil, false
	}
	requirement, _ := raw.(map[string]any)
	return requirement, true
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return format.EncodeBase64URL(sum[:])
}

func randomBase64URL(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return format.EncodeBase64URL(buf)
}

func createClientAssertionJWT(key *ecdsa.PrivateKey, clientID, audience string) (string, error) {
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"kid": mock.KeyIDForPublicKey(&key.PublicKey),
	}
	payload := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"jti": randomBase64URL(18),
	}
	return signJWT(header, payload, key)
}

func createDPoPProofJWT(key *ecdsa.PrivateKey, method, targetURL, nonce, accessToken, challenge string) (string, error) {
	jwk := mock.SigningJWKMap(&key.PublicKey)
	header := map[string]any{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": jwk,
	}
	payload := map[string]any{
		"jti": randomBase64URL(18),
		"htm": strings.ToUpper(method),
		"htu": dpopTargetURI(targetURL),
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	// The attestation challenge of combined-mode attestation-based client
	// authentication (draft-10 §5.2), where this proof is the possession proof.
	if challenge != "" {
		payload["challenge"] = challenge
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		payload["ath"] = format.EncodeBase64URL(sum[:])
	}
	return signJWT(header, payload, key)
}

// dpopTargetURI is the htu claim of a DPoP proof. RFC 9449 §4.2: "The HTTP
// target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is
// attached, without query and fragment parts." An issuer is free to publish an
// endpoint carrying a query (a tenant, an API version), and a server that
// compares htu against its own target URI refuses a proof that kept it.
func dpopTargetURI(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.Fragment = ""
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	return parsed.String()
}

func formRequestLogDetails(endpoint, endpointName string, form url.Values) map[string]any {
	return map[string]any{
		"direction": "outbound",
		"method":    "POST",
		"url":       endpoint,
		"endpoint":  endpointName,
		"request":   form,
	}
}

func responseMapLogDetails(endpoint, endpointName string, response map[string]any, err error) map[string]any {
	details := map[string]any{
		"direction": "inbound",
		"url":       endpoint,
		"endpoint":  endpointName,
	}
	if response != nil {
		details["response"] = response
	}
	if err != nil {
		details["error"] = err.Error()
		// What the server actually sent. The headline is the refusal's own
		// code, which a server answering outside the OAuth 2.0 error format
		// fills with its HTTP status text, and then the reason is only here.
		var refusal *serverRefusal
		if errors.As(err, &refusal) {
			if refusal.StatusCode != 0 {
				details["status_code"] = refusal.StatusCode
			}
			// Only when the message does not already carry it: a body that is
			// not an error response at all is reported whole, and repeating it
			// here would put a second copy in the stored log.
			if refusal.Body != "" && !strings.Contains(refusal.Message, refusal.Body) {
				details["response_body"] = refusal.Body
			}
		}
	}
	return details
}

// accessTokenScheme picks the HTTP authorization scheme for an access token.
// RFC 9449 §5 returns token_type "DPoP" for a DPoP-bound token, so a proof
// answered with "Bearer" yields a plain bearer token. A server omitting
// token_type after accepting a proof is taken at the flow's word.
func accessTokenScheme(tokenResp map[string]any, sentDPoP bool) string {
	tokenType, _ := tokenResp["token_type"].(string)
	if strings.EqualFold(tokenType, "DPoP") {
		return "DPoP"
	}
	if tokenType == "" && sentDPoP {
		return "DPoP"
	}
	return "Bearer"
}

// serverRefusal is an authorization server's refusal, kept whole. Message is
// what the flow reports, so an entry stays on a line, and the status and body
// travel with it for the log details: a server that does not answer in the
// OAuth 2.0 error format states its reason where only the body shows it, and
// then the code alone says nothing worth reading.
type serverRefusal struct {
	StatusCode int
	Body       string
	Message    string
}

func (e *serverRefusal) Error() string { return e.Message }

func postFormWithDPoP(target string, form url.Values, key *ecdsa.PrivateKey, accessToken string, nonce *string, attestor *clientAttestor) (map[string]any, error) {
	body := []byte(form.Encode())
	respBody, status, err := doDPoPRequest("POST", target, "application/x-www-form-urlencoded", "", body, "", accessToken, key, nonce, attestor)
	if err != nil {
		// A refusal states its reason in the response, in the two fields
		// RFC 6749 §5.2 defines for it. Reporting those beats handing the
		// caller the raw body and the status code a second time.
		message := oauthErrorMessage(respBody)
		if message == "" {
			message = err.Error()
		}
		return nil, &serverRefusal{StatusCode: status, Body: string(respBody), Message: message}
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parsing JSON response: %w", err)
	}
	// Some servers answer 200 with an error document, so the body decides
	// rather than the status.
	if refusal := oauthErrorMessage(respBody); refusal != "" {
		return nil, &serverRefusal{StatusCode: status, Body: string(respBody), Message: refusal}
	}
	return out, nil
}

// oauthErrorMessage renders an OAuth 2.0 error response as "code: what it
// says", or empty when the body is not one.
//
// RFC 6749 §5.2 defines error and error_description, and a server that says
// why in neither leaves its reason behind: a NestJS handler answers
// {"error":"Bad Request","message":"Invalid grant_type, ..."}, whose error is
// the HTTP status phrase, so reporting that alone turns a named refusal into
// "Bad Request". A message next to the error is read for that reason. An
// error is still what makes the body an error response, because this also
// decides whether a 200 carries a refusal, and a success body carrying a
// message is not one.
func oauthErrorMessage(body []byte) string {
	var doc struct {
		Error       string          `json:"error"`
		Description string          `json:"error_description"`
		Message     json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Error == "" {
		return ""
	}
	reason := doc.Description
	if reason == "" {
		reason = errorBodyMessage(doc.Message)
	}
	if reason == "" || reason == doc.Error {
		return doc.Error
	}
	return doc.Error + ": " + reason
}

// errorBodyMessage reads the message member of an error body, which servers
// write as one string or as the list of things that were wrong with the
// request.
func errorBodyMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return strings.TrimSpace(single)
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return strings.TrimSpace(strings.Join(many, "; "))
	}
	return ""
}

func requestCredentialWithDPoP(mode ValidationMode, metadata map[string]any, endpoint, accessToken, authScheme string, proofJWTs []string, credentialIdentifier, credentialConfigurationID string, credentialResponseEncryption map[string]any, dpopKey, holderKey *ecdsa.PrivateKey, nonce *string) (map[string]any, error) {
	reqBody := map[string]any{
		"proofs": map[string]any{
			"jwt": proofJWTs,
		},
	}
	if credentialIdentifier != "" {
		reqBody["credential_identifier"] = credentialIdentifier
	} else if credentialConfigurationID != "" {
		reqBody["credential_configuration_id"] = credentialConfigurationID
	}
	if credentialResponseEncryption != nil {
		reqBody["credential_response_encryption"] = credentialResponseEncryption
	}
	body, contentType, err := prepareCredentialRequestBody(mode, metadata, reqBody)
	if err != nil {
		return nil, err
	}
	respBody, _, reqErr := doDPoPRequest("POST", endpoint, contentType, credentialAccept(credentialResponseEncryption), body, authScheme, accessToken, dpopKey, nonce, nil)
	out, parseErr := parseCredentialResponseBody(respBody, holderKey)
	if parseErr == nil {
		// The code decides what happens next, so it is reported instead of the
		// HTTP failure: §8.3.1.2 retries on invalid_nonce and stops on
		// credential_request_denied.
		if code, _ := out["error"].(string); code != "" {
			desc, _ := out["error_description"].(string)
			return out, credentialErrorResponse{code: code, description: desc}
		}
	}
	if reqErr != nil {
		return out, reqErr
	}
	if parseErr != nil {
		return nil, parseErr
	}
	return out, nil
}

// credentialErrorResponse is a Credential Error Response as defined in
// §8.3.1.2. The code is kept apart from the message because the wallet acts on
// it rather than only reporting it.
type credentialErrorResponse struct {
	code        string
	description string
}

func (e credentialErrorResponse) Error() string {
	if e.description == "" {
		return "credential error: " + e.code
	}
	return "credential error: " + e.code + ": " + e.description
}

// isInvalidNonceError reports whether the issuer refused the request for the
// challenge its key proofs carried.
func isInvalidNonceError(err error) bool {
	var credErr credentialErrorResponse
	return errors.As(err, &credErr) && credErr.code == "invalid_nonce"
}

// deferredContext carries what a deferred credential request needs, both for
// the poll that happens inside the issuance flow and for the record left
// behind when the issuer wants more time than the flow can wait.
type deferredContext struct {
	metadata         map[string]any
	tokenEndpoint    string
	clientID         string
	clientAuth       *ClientAuthentication
	refreshToken     string
	expiresIn        int
	issuer           string
	configID         string
	format           string
	deferredEndpoint string
	accessToken      string
	authScheme       string
	dpopKey          *ecdsa.PrivateKey
	proofKeys        []*ecdsa.PrivateKey
	nonce            *string
}

// resolveDeferredCredential completes an issuance the issuer deferred. A
// response with a transaction_id and no credential is not ready yet; one that
// already carries the credential is returned untouched, so both flows can call
// this unconditionally.
//
// A short deferral is waited out here. A longer one returns a DeferredIssuance
// for the background poller.
func (w *Wallet) resolveDeferredCredential(credResp map[string]any, ctx deferredContext) (map[string]any, *DeferredIssuance, error) {
	txID, _ := credResp["transaction_id"].(string)
	if txID == "" {
		return credResp, nil, nil
	}
	ctx.deferredEndpoint, _ = ctx.metadata["deferred_credential_endpoint"].(string)
	if ctx.deferredEndpoint == "" {
		return nil, nil, fmt.Errorf("issuer deferred the credential but published no deferred_credential_endpoint")
	}

	// Hand it to the poller rather than holding the caller (a consent dialog,
	// a CLI run) for the issuer's interval.
	interval := deferredPollInterval
	if seconds, ok := numericValue(credResp["interval"]); ok && seconds >= 1 {
		interval = time.Duration(seconds) * time.Second
	}
	pending, err := newDeferredIssuance(ctx, txID, interval)
	if err != nil {
		return nil, nil, err
	}
	return nil, pending, nil
}

// deferredPollInterval is used when the issuer names no interval of its own.
const deferredPollInterval = 5 * time.Second

// stillPendingError says the issuer has not finished the credential yet. Not a
// failure: the transaction is good and the interval says when to come back.
type stillPendingError struct {
	transactionID string
	interval      time.Duration
}

func (e stillPendingError) Error() string {
	return fmt.Sprintf("credential is not ready yet: retry in %s with transaction_id %s",
		e.interval, e.transactionID)
}

// deferredCredentialAttempt makes exactly one deferred credential request. A
// still-working issuer comes back as a stillPendingError carrying its
// interval, because whether to wait is the caller's decision.
//
// The request is held to the same encryption rules as the one that started the
// issuance. §9.1: "The Client MAY encrypt the request when encryption_required
// is false and MUST do so when encryption_required is true", and the wallet
// "MAY request encrypted responses by providing its encryption parameters in
// the Deferred Credential Request when encryption_required is false and MUST do
// so when encryption_required is true. Note that this object will be used for
// encrypting the response, regardless of what was sent in the initial
// Credential Request. If it is not included encryption will not be performed."
func deferredCredentialAttempt(mode ValidationMode, metadata map[string]any, endpoint, accessToken, authScheme, transactionID string, responseEncryption map[string]any, dpopKey, holderKey *ecdsa.PrivateKey, nonce *string) (map[string]any, error) {
	reqBody := map[string]any{"transaction_id": transactionID}
	if responseEncryption != nil {
		reqBody["credential_response_encryption"] = responseEncryption
	}
	body, contentType, err := prepareCredentialRequestBody(mode, metadata, reqBody)
	if err != nil {
		return nil, err
	}
	respBody, _, reqErr := doDPoPRequest("POST", endpoint, contentType, credentialAccept(responseEncryption), body, authScheme, accessToken, dpopKey, nonce, nil)
	out, parseErr := parseCredentialResponseBody(respBody, holderKey)
	if parseErr != nil {
		if reqErr != nil {
			return nil, reqErr
		}
		return nil, fmt.Errorf("parsing deferred credential response: %w", parseErr)
	}

	if pending, interval := deferredIssuancePending(out); pending {
		return nil, stillPendingError{transactionID: transactionID, interval: interval}
	}
	if errMsg, _ := out["error"].(string); errMsg != "" {
		desc, _ := out["error_description"].(string)
		return nil, fmt.Errorf("deferred credential error: %s: %s", errMsg, desc)
	}
	if reqErr != nil {
		return nil, reqErr
	}
	return out, nil
}

// deferredIssuancePending reports whether a deferred credential response says
// the credential is not ready yet, and how long to wait. OpenID4VCI 1.0 §9.2
// makes that a 202 carrying interval and transaction_id, not an error.
func deferredIssuancePending(out map[string]any) (bool, time.Duration) {
	interval := deferredPollInterval
	if seconds, ok := numericValue(out["interval"]); ok && seconds >= 1 {
		interval = time.Duration(seconds) * time.Second
	}
	if txID, _ := out["transaction_id"].(string); txID != "" && len(credentialStringsFromResponse(out)) == 0 {
		return true, interval
	}
	return false, 0
}

// notifyCredentialAccepted reports a stored credential to the issuer's
// Notification Endpoint. §11: "Support for this endpoint is OPTIONAL. The
// Issuer cannot assume that a notification will be sent for every issued
// Credential since the use of this Endpoint is not mandatory for the Wallet."
// The credential is stored by the time it is sent, so a notification the
// issuer does not answer is reported and left at that. Failing the issuance
// over it would throw away a credential the user already holds.
func (w *Wallet) notifyCredentialAccepted(metadata, credResp map[string]any, accessToken, authScheme string, dpopKey *ecdsa.PrivateKey, nonce *string) {
	notificationID, _ := credResp["notification_id"].(string)
	notificationEndpoint, _ := metadata["notification_endpoint"].(string)
	if notificationID == "" || notificationEndpoint == "" {
		return
	}
	w.addProtocolLog("issuance", "notification_request", fmt.Sprintf("Send credential notification to %s", notificationEndpoint), true, map[string]any{
		"direction":          "outbound",
		"method":             "POST",
		"url":                notificationEndpoint,
		"endpoint":           "notification",
		"notification_id":    notificationID,
		"notification_event": "credential_accepted",
	})
	status, respBody, err := sendNotificationWithDPoP(notificationEndpoint, accessToken, authScheme, notificationID, dpopKey, nonce)
	if err != nil {
		w.addProtocolLog("issuance", "notification_response", fmt.Sprintf("Notification response from %s", notificationEndpoint), false, map[string]any{
			"direction": "inbound",
			"url":       notificationEndpoint,
			"endpoint":  "notification",
			"error":     err.Error(),
		})
		reading, code := readNotificationRefusal(status, respBody)
		details := map[string]any{
			"url":             notificationEndpoint,
			"notification_id": notificationID,
			"status":          status,
			"error":           err.Error(),
		}
		if code != "" {
			details["error_code"] = code
		}
		w.addProtocolWarning("issuance", "notification_failed",
			"The issuer did not accept the notification for this credential, which is stored either way. "+reading,
			details)
		return
	}
	w.addProtocolLog("issuance", "notification_response", fmt.Sprintf("Notification response from %s", notificationEndpoint), true, map[string]any{
		"direction": "inbound",
		"url":       notificationEndpoint,
		"endpoint":  "notification",
	})
}

// readNotificationRefusal says what an answer from the Notification Endpoint
// is against §11.3, which defines two: an Authorization Error Response
// (RFC 6750 §3) when the Access Token is missing or invalid, and 400 with a
// JSON error whose value SHOULD be invalid_notification_id or
// invalid_notification_request.
// An issuer answering outside those is worth naming, because a developer
// reading a bare status has no way to tell a refusal from a wiring mistake.
// It returns the reading and the error code the issuer sent, if any.
func readNotificationRefusal(status int, body []byte) (string, string) {
	var parsed struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	code := strings.TrimSpace(parsed.Error)

	switch {
	case status < 100:
		return "Nothing was answered, so this is the endpoint being unreachable rather than the issuer refusing.", code
	case status >= 200 && status < 300:
		return "The status says the issuer took it (§11.2 makes any 2xx a success), so what failed is reading the response.", code
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return "That is the Authorization Error Response §11.3 points at (RFC 6750 §3): the endpoint did not accept the access token this issuance was granted.", code
	// RFC 6750 §3.1 gives invalid_request a 400, so that one is the
	// Authorization Error Response too rather than a notification error.
	case status == http.StatusBadRequest && code == "invalid_request":
		return "That is the Authorization Error Response §11.3 points at (RFC 6750 §3.1 gives invalid_request a 400).", code
	case status == http.StatusBadRequest && (code == "invalid_notification_id" || code == "invalid_notification_request"):
		return "That is a Notification Error Response of §11.3 (" + code + ").", code
	case status == http.StatusBadRequest && code != "":
		return "§11.3 lists invalid_notification_id and invalid_notification_request for a 400, and this names " + code + " instead.", code
	case status == http.StatusBadRequest:
		return "§11.3 requires a 400 to carry a JSON error, whose value SHOULD be invalid_notification_id or invalid_notification_request. This one carries no error at all.", code
	default:
		return fmt.Sprintf("§11.3 defines no response with status %d for this endpoint: an invalid access token is answered per RFC 6750 §3, an invalid notification_id with 400.", status), code
	}
}

func sendNotificationWithDPoP(endpoint, accessToken, authScheme, notificationID string, dpopKey *ecdsa.PrivateKey, nonce *string) (int, []byte, error) {
	body, err := json.Marshal(map[string]any{
		"notification_id": notificationID,
		"event":           "credential_accepted",
	})
	if err != nil {
		return 0, nil, fmt.Errorf("marshaling notification request: %w", err)
	}
	// §11.2 requires a 2xx and only RECOMMENDS 204, so the whole range is a
	// success.
	respBody, statusCode, err := doDPoPRequest("POST", endpoint, "application/json", "", body, authScheme, accessToken, dpopKey, nonce, nil)
	if err != nil {
		return statusCode, respBody, err
	}
	if statusCode < 200 || statusCode >= 300 {
		return statusCode, respBody, fmt.Errorf("notification endpoint returned HTTP %d", statusCode)
	}
	return statusCode, respBody, nil
}

// fetchNonce asks the Nonce Endpoint for a challenge. Nothing is presented
// with it: §7.1 says "The Nonce Endpoint is not a protected resource". The
// DPoP nonce state is still carried in, since §7.2 lets the issuer hand out a
// DPoP nonce here.
func fetchNonce(metadata map[string]any, nonce *string) string {
	ep, _ := metadata["nonce_endpoint"].(string)
	if ep == "" {
		return ""
	}
	respBody, _, err := doDPoPRequest("POST", ep, "", "", nil, "", "", nil, nonce, nil)
	if err != nil {
		return ""
	}
	var resp map[string]any
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return ""
	}
	value, _ := resp["c_nonce"].(string)
	return value
}

// credentialAccept returns the Accept header for a credential request.
// Advertise application/jwt only for encrypted responses: Keycloak 26.6's
// credential endpoint returns signed issuer *metadata* (a JWT string) when it
// sees application/jwt in Accept and then fails on it internally.
func credentialAccept(credentialResponseEncryption map[string]any) string {
	if credentialResponseEncryption != nil {
		return "application/json, application/jwt"
	}
	return "application/json"
}

// doDPoPRequest sends one issuance request, optionally DPoP-bound. A nil key
// sends no DPoP proof, which is what an issuer that does not advertise
// dpop_signing_alg_values_supported expects. A refusal that comes with the
// material to do better is answered once: a DPoP nonce (RFC 9449 §8), and an
// attestation challenge or freshness demand (ABCA §6.2), each with its own
// retry so one does not spend the other's.
func doDPoPRequest(method, target, contentType, accept string, body []byte, authScheme, token string, key *ecdsa.PrivateKey, nonce *string, attestor *clientAttestor) ([]byte, int, error) {
	if accept == "" {
		accept = "application/json, application/jwt"
	}
	dpopRetried := false
	attestationRetried := false
	for {
		reqBody := bytes.NewReader(body)
		req, err := http.NewRequest(method, target, reqBody)
		if err != nil {
			return nil, 0, fmt.Errorf("creating request: %w", err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Accept", accept)
		if token != "" && authScheme != "" {
			req.Header.Set("Authorization", authScheme+" "+token)
		}
		if attestor != nil {
			headers, err := attestor.headers()
			if err != nil {
				return nil, 0, err
			}
			for headerName, headerValue := range headers {
				req.Header.Set(headerName, headerValue)
			}
		}
		if key != nil {
			challenge := ""
			if attestor != nil {
				var err error
				challenge, err = attestor.dpopChallenge()
				if err != nil {
					return nil, 0, err
				}
			}
			dpopJWT, err := createDPoPProofJWT(key, method, target, derefString(nonce), token, challenge)
			if err != nil {
				return nil, 0, fmt.Errorf("creating DPoP proof: %w", err)
			}
			req.Header.Set("DPoP", dpopJWT)
		}

		resp, err := doIssuanceRequest(req)
		if err != nil {
			return nil, 0, fmt.Errorf("request: %w", err)
		}
		respBody, readErr := format.ReadRemoteBody(resp.Body, "issuer response")
		resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, fmt.Errorf("reading response: %w", readErr)
		}
		updateDPoPNonce(nonce, resp.Header)
		if attestor != nil {
			attestor.observe(resp.Header)
		}
		if needsDPoPRetry(resp.StatusCode, resp.Header, respBody) && !dpopRetried {
			dpopRetried = true
			continue
		}
		if resp.StatusCode >= 400 && attestor != nil && attestor.retryAfterRefusal(respBody) && !attestationRetried {
			attestationRetried = true
			continue
		}
		if resp.StatusCode >= 400 {
			// The body travels with the error: a Credential Error Response
			// (§8.3.1.2) carries the code the caller acts on, such as the
			// invalid_nonce that asks for a fresh challenge and another attempt.
			return respBody, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		return respBody, resp.StatusCode, nil
	}
}

func updateDPoPNonce(target *string, headers http.Header) {
	if target == nil {
		return
	}
	if value := strings.TrimSpace(headers.Get("DPoP-Nonce")); value != "" {
		*target = value
	}
}

func needsDPoPRetry(statusCode int, headers http.Header, body []byte) bool {
	if statusCode < 400 {
		return false
	}
	if strings.TrimSpace(headers.Get("DPoP-Nonce")) != "" {
		return true
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	errCode, _ := parsed["error"].(string)
	return errCode == "use_dpop_nonce"
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// runAuthorizationCodeRequest takes the authorization request to whoever can
// answer it. A browser does where it can reach the wallet's redirect URI, and
// the wallet itself where no browser can. RFC 9126 §4 says "the client MUST
// only use a request_uri value once", so only one of them requests the
// endpoint.
func runAuthorizationCodeRequest(w *Wallet, endpoint, clientID, requestURI string, params url.Values, redirectURI, expectedState, expectedIssuer, owner string, issRequired bool) (url.Values, error) {
	authURL, err := authorizationRequestURL(endpoint, clientID, requestURI, params)
	if err != nil {
		return nil, err
	}

	if canUseInteractiveAuthorizationCallback(w, redirectURI) {
		callbackCh, unregister := w.RegisterAuthorizationCodeCallback(expectedState)
		defer unregister()

		// The wallet never opens a browser itself: a hosted wallet opening one
		// on its own server reaches nobody. It hands the URL to whoever holds
		// the user's attention and waits.
		if !w.NotifyAuthorization(AuthorizationPrompt{URL: authURL, Owner: owner}) {
			return nil, fmt.Errorf("this offer needs an interactive sign-in at %s, and nothing is attached to this wallet that can open it", authURL)
		}
		select {
		case values := <-callbackCh:
			if err := w.validateAuthorizationCodeResponse(values, expectedState, expectedIssuer, issRequired); err != nil {
				return nil, err
			}
			return values, nil
		case <-time.After(config.AuthorizationCallbackWait):
			return nil, fmt.Errorf("timed out waiting for authorization callback at %s", redirectURI)
		}
	}

	location, body, err := callAuthorizationEndpoint(authURL)
	if err != nil {
		return nil, err
	}
	if location != "" {
		valuesOut, err := parseRedirectQuery(location)
		if err == nil {
			// auth_session is what an auth_via_web redirect carries when the
			// authorization continues at the challenge endpoint (OpenID4VCI
			// 1.1 §6.2.1.2).
			if valuesOut.Get("code") != "" || valuesOut.Get("error") != "" || valuesOut.Get("auth_session") != "" {
				if err := w.validateAuthorizationCodeResponse(valuesOut, expectedState, expectedIssuer, issRequired); err != nil {
					return nil, err
				}
				return valuesOut, nil
			}
		}
	}

	if location != "" {
		return nil, fmt.Errorf("authorization requires interactive browser login at %q, but redirect_uri %q is not handled by the running wallet server", location, redirectURI)
	}
	return nil, fmt.Errorf("authorization requires interactive browser login, but redirect_uri %q is not handled by the running wallet server (body: %s)", redirectURI, truncateBody(body))
}

// validateAuthorizationCodeResponse checks the state and issuer of an
// authorization response. Each deviation is worked around in debug (a warning)
// and refused in strict, through reportServerDeviation. A missing iss is a
// deviation only when the authorization server advertised iss support
// (RFC 9207): otherwise iss is optional and its absence says nothing.
func (w *Wallet) validateAuthorizationCodeResponse(values url.Values, expectedState, expectedIssuer string, issRequired bool) error {
	if values == nil {
		return fmt.Errorf("authorization response is empty")
	}
	if expectedState = strings.TrimSpace(expectedState); expectedState != "" {
		switch state := values.Get("state"); {
		case state == "":
			if err := w.reportServerDeviation("the authorization response omitted state, which RFC 6749 §4.1.2 returns when the request carried one"); err != nil {
				return err
			}
		case state != expectedState:
			if err := w.reportServerDeviation(fmt.Sprintf("the authorization response state %q does not match the request's %q", state, expectedState)); err != nil {
				return err
			}
		}
	}

	expectedIssuer = normalizeIssuerURL(expectedIssuer)
	issuer := normalizeIssuerURL(values.Get("iss"))
	switch {
	case issuer == "" && issRequired:
		return w.reportServerDeviation("the authorization response omitted iss, which RFC 9207 requires when the authorization server advertises authorization_response_iss_parameter_supported")
	case issuer != "" && expectedIssuer != "" && issuer != expectedIssuer:
		return w.reportServerDeviation(fmt.Sprintf("the authorization response iss %q does not match the expected issuer %q", values.Get("iss"), expectedIssuer))
	}
	return nil
}

// authorizationRequestURL builds the authorization request: by request_uri
// after PAR, which RFC 9126 §4 sends with the client_id and nothing else, or
// with the parameters in the query string (RFC 6749 §4.1.1).
func authorizationRequestURL(endpoint, clientID, requestURI string, params url.Values) (string, error) {
	values := url.Values{}
	if requestURI != "" {
		values.Set("client_id", clientID)
		values.Set("request_uri", requestURI)
	} else {
		for key, entries := range params {
			for _, entry := range entries {
				values.Add(key, entry)
			}
		}
		values.Set("client_id", clientID)
	}
	// A javascript: or data: endpoint from issuer metadata would run in the
	// wallet's own origin.
	authURL := endpoint + "?" + values.Encode()
	if err := validateAbsoluteURI("authorization_endpoint", authURL); err != nil {
		return "", err
	}
	return authURL, nil
}

// callAuthorizationEndpoint makes the request no browser is there to make,
// and reports where it was sent.
func callAuthorizationEndpoint(authURL string) (string, string, error) {
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("creating authorization request: %w", err)
	}

	baseClient := format.HTTPClientForURL(req.URL.String())
	if httpClient != defaultHTTPClient {
		if overridden, ok := httpClient.(*http.Client); ok && overridden != nil {
			baseClient = overridden
		}
	}
	client := *baseClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("authorization request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := format.ReadRemoteBody(resp.Body, "issuer response")
	if resp.StatusCode == http.StatusOK {
		return "", string(body), nil
	}
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", "", fmt.Errorf("authorization endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return "", "", fmt.Errorf("authorization response missing Location header")
	}
	return location, string(body), nil
}

func parseRedirectQuery(location string) (url.Values, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parsing redirect URL: %w", err)
	}
	return parsed.Query(), nil
}

func canUseInteractiveAuthorizationCallback(w *Wallet, redirectURI string) bool {
	if w == nil {
		return false
	}
	// A wallet started without --base-url still serves /callback: the serve
	// command records the origin it answers on, which is also where it
	// derived the default redirect URI from.
	base := strings.TrimSpace(w.BaseURL)
	if base == "" {
		base = strings.TrimSpace(w.ServingOrigin)
	}
	if base == "" {
		return false
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return false
	}
	if !sameLoopbackHost(redirectURL.Hostname(), baseURL.Hostname()) {
		return false
	}
	if redirectURL.Port() != baseURL.Port() {
		return false
	}
	return strings.HasSuffix(strings.TrimRight(redirectURL.Path, "/"), "/callback")
}

func sameLoopbackHost(a, b string) bool {
	a = strings.TrimSpace(strings.ToLower(a))
	b = strings.TrimSpace(strings.ToLower(b))
	if a == b {
		return true
	}
	loopback := map[string]bool{
		"localhost": true,
		"127.0.0.1": true,
		"::1":       true,
	}
	return loopback[a] && loopback[b]
}

func truncateBody(body string) string {
	body = strings.TrimSpace(body)
	if len(body) <= 200 {
		return body
	}
	return body[:200] + "..."
}

// tokenGrantRenewal reads what a token response offers for renewing the
// access token later. Both issuance flows need it, and a deferred credential
// collected an hour from now depends on it being read the same way in each.
func tokenGrantRenewal(tokenResp map[string]any) (refreshToken string, expiresIn int) {
	refreshToken, _ = tokenResp["refresh_token"].(string)
	if seconds, ok := tokenResp["expires_in"].(float64); ok && seconds > 0 {
		expiresIn = int(seconds)
	}
	return refreshToken, expiresIn
}
