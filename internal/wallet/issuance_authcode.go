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
) (*IssuanceResult, error) {
	if w == nil {
		return nil, fmt.Errorf("wallet is nil")
	}
	clientID := strings.TrimSpace(w.VCIClientID)
	redirectURI := strings.TrimSpace(w.VCIRedirectURI)
	if clientID == "" || redirectURI == "" {
		return nil, fmt.Errorf("OID4VCI authorization_code flow requires configured wallet client_id and redirect_uri")
	}

	// Pushed Authorization Requests are used where the Authorization Server
	// offers them and skipped where it does not. RFC 9126 §2 asks a server
	// that supports PAR to publish the endpoint ("Authorization servers
	// supporting PAR SHOULD include the URL of their pushed authorization
	// request endpoint in their authorization server metadata document"), so
	// its absence is the server saying it takes the request at the
	// authorization endpoint instead. OpenID4VCI requires neither, and HAIP
	// asks for PAR through FAPI 2.0, which the profile checks separately.
	parEndpoint, _ := oauthMeta["pushed_authorization_request_endpoint"].(string)
	authorizationEndpoint, _ := oauthMeta["authorization_endpoint"].(string)
	if authorizationEndpoint == "" {
		return nil, fmt.Errorf("authorization server metadata did not include authorization_endpoint")
	}

	clientAuthMethod := detectTokenEndpointAuthMethod(oauthMeta)
	switch clientAuthMethod {
	case "", unauthenticatedClientMethod, "private_key_jwt", "attest_jwt_client_auth":
	case unregisteredPublicClientMethod:
		// RFC 8414 takes the values of token_endpoint_auth_methods_supported
		// from the IANA "OAuth Token Endpoint Authentication Methods" registry,
		// where a client that does not authenticate is "none". "public" is not
		// registered, so a server naming it is describing itself in a value no
		// client is obliged to understand.
		if err := w.reportServerDeviation(fmt.Sprintf("authorization server advertises the unregistered token endpoint auth method %q; RFC 8414 takes these values from the OAuth Token Endpoint Authentication Methods registry, where an unauthenticated client is %q", unregisteredPublicClientMethod, unauthenticatedClientMethod)); err != nil {
			return nil, err
		}
	default:
		// Everything else needs a credential the wallet was never issued, such
		// as the client secret the client_secret_* methods sign or send.
		return nil, fmt.Errorf("unsupported token endpoint auth method %q", clientAuthMethod)
	}
	// A sender-constrained token is used where the server advertises DPoP.
	// RFC 9449 leaves the metadata optional, and an Authorization Server that
	// names no signing algorithms is one that issues bearer tokens, which is
	// what the request then carries.
	var dpopKey *ecdsa.PrivateKey
	if supportsDPoP(oauthMeta) {
		dpopKey = w.HolderKey
	}

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

	// requestURI is empty when the request goes to the authorization endpoint
	// directly, and the parameters travel in the query string instead.
	var requestURI string
	if parEndpoint != "" {
		w.addProtocolLog("issuance", "par_request", fmt.Sprintf("Request PAR from %s", parEndpoint), true, formRequestLogDetails(parEndpoint, "par", parForm))
		parResp, err := postFormWithDPoP(parEndpoint, parForm, dpopKey, "", &nonces.authzServer, w.clientAttestationHeaders(clientAuth))
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
	callbackValues, err := runAuthorizationCodeRequest(w, authorizationEndpoint, clientID, requestURI, parForm, redirectURI, state, oauthIssuer(oauthMeta, ""), w.ValidationMode)
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

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("client_id", clientID)
	tokenForm.Set("redirect_uri", redirectURI)
	tokenForm.Set("code_verifier", codeVerifier)
	if err := applyClientAuthentication(tokenForm, clientAuth, w.HolderKey); err != nil {
		return nil, err
	}

	w.addProtocolLog("issuance", "token_request", fmt.Sprintf("Request token from %s", tokenEndpoint), true, formRequestLogDetails(tokenEndpoint, "token", tokenForm))
	tokenResp, err := postFormWithDPoP(tokenEndpoint, tokenForm, dpopKey, "", &nonces.authzServer, w.clientAttestationHeaders(clientAuth))
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

	credentialIdentifier := resolveCredentialIdentifier(tokenResp, offer.CredentialConfigurationIDs)
	credentialConfigurationID := ""
	if credentialIdentifier == "" && len(offer.CredentialConfigurationIDs) > 0 {
		credentialConfigurationID = offer.CredentialConfigurationIDs[0]
	}
	responseEncryption, err := buildCredentialResponseEncryptionRequest(w.ValidationMode, metadata, w.HolderKey)
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
		nonce:                     &nonces.resource,
	}
	proofJWTs, err := w.buildCredentialProofs(attempt, cNonce)
	if err != nil {
		return nil, err
	}

	credResp, err := w.requestCredentialWithNonceRetry(attempt, proofJWTs)
	if err != nil {
		return nil, fmt.Errorf("requesting credential: %w", err)
	}

	// This flow always sends DPoP: it refuses issuer metadata without it.
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
	if pending != nil {
		return w.recordDeferredIssuance(pending), nil
	}

	credential, err := selectHolderBoundCredential(credResp, proofKeys)
	if err != nil {
		return nil, err
	}

	imported, err := w.ImportCredential(credential)
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

	if err := w.notifyCredentialAccepted(metadata, credResp, accessToken, authScheme, dpopKey, &nonces.resource); err != nil {
		return nil, err
	}

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

// detectTokenEndpointAuthMethod picks the client authentication method to use
// from the ones the authorization server offers.
//
// A server that also accepts an unauthenticated client is taken up on it,
// ahead of attestation. A wallet attestation is only worth anything to a server
// that trusts the attester who signed it, and this wallet signs its own with a
// certificate authority it generated locally, which no deployment has any
// reason to trust: an issuer that checks the attestation answers "no trusted
// attester matched" and the flow ends, though the same server would have issued
// to an unauthenticated client. Where attestation is the only method offered it
// is used, and --haip and ForceClientAttestation still ask for it outright,
// because that is the case the wallet is there to exercise.
// unauthenticatedClientMethod is the registered token endpoint authentication
// method of a client that does not authenticate. RFC 8414 takes the values of
// token_endpoint_auth_methods_supported from the IANA "OAuth Token Endpoint
// Authentication Methods" registry, and this is the one that appears there.
const unauthenticatedClientMethod = "none"

// unregisteredPublicClientMethod is a value some deployments publish for the
// same thing. It is not in the registry, so it is reported as a deviation
// before the wallet acts on what it evidently means.
const unregisteredPublicClientMethod = "public"

// reportServerDeviation records something the counterparty got wrong. Strict
// refuses to go on, debug names it and continues, which is the difference
// between the two modes everywhere else in the wallet.
func (w *Wallet) reportServerDeviation(detail string) error {
	w.addProtocolLog("issuance", "server_deviation", detail, false, map[string]any{
		"deviation": detail,
	})
	if w.ValidationMode == ValidationModeStrict {
		return fmt.Errorf("%s", detail)
	}
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
		if method == unauthenticatedClientMethod || method == unregisteredPublicClientMethod {
			return method
		}
	}
	for _, raw := range methods {
		method, _ := raw.(string)
		if method == "attest_jwt_client_auth" {
			return method
		}
	}
	for _, raw := range methods {
		method, _ := raw.(string)
		if method == "private_key_jwt" {
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

// attestsClient reports whether to authenticate with the wallet attestation
// against this authorization server.
//
// HAIP 1.0 §4.4.1 puts it plainly: "Wallets MUST use, and Issuers MUST
// require, an OAuth2 Client authentication mechanism at OAuth2 Endpoints that
// support client authentication (such as the PAR and Token Endpoints)." That
// is unconditional, so a wallet enforcing HAIP attests without asking the
// metadata first.
//
// Outside HAIP the metadata is the signal, which
// draft-ietf-oauth-attestation-based-client-auth §8 has a client read.
// Advertising it there is only a SHOULD, so an issuer may check an attestation
// without announcing it, and ForceClientAttestation covers that.
func (w *Wallet) attestsClient(oauthMeta map[string]any) bool {
	if w == nil {
		return false
	}
	return w.RequireHAIP ||
		detectTokenEndpointAuthMethod(oauthMeta) == "attest_jwt_client_auth" ||
		w.ForceClientAttestation
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
// client authenticated. Nil means it asked for nothing. The answer is kept
// with the credential, because a refresh is another request to the same
// endpoint long after this metadata is gone.
func (w *Wallet) resolveClientAuthentication(method string, ctx clientAuthContext) *ClientAuthentication {
	if method == ClientAuthPrivateKeyJWT {
		return &ClientAuthentication{
			Method:   ClientAuthPrivateKeyJWT,
			ClientID: ctx.clientID,
			Audience: oauthIssuer(ctx.oauthMeta, ctx.tokenEndpoint),
		}
	}
	if !w.attestsClient(ctx.oauthMeta) {
		return nil
	}
	return attestationClientAuth(ctx)
}

func attestationClientAuth(ctx clientAuthContext) *ClientAuthentication {
	challengeEndpoint, _ := ctx.oauthMeta["challenge_endpoint"].(string)
	return &ClientAuthentication{
		Method:            ClientAuthAttestation,
		ClientID:          ctx.clientID,
		Audience:          oauthIssuer(ctx.oauthMeta, ctx.tokenEndpoint),
		ChallengeEndpoint: challengeEndpoint,
	}
}

// clientAttestationHeaders builds the wallet attestation a request has to
// carry, or nil when this authentication needs no headers. The challenge is
// fetched per request: a server that requires one refuses a stale one.
func (w *Wallet) clientAttestationHeaders(auth *ClientAuthentication) func() (map[string]string, error) {
	if auth == nil || auth.Method != ClientAuthAttestation {
		return nil
	}
	return func() (map[string]string, error) {
		challenge, err := fetchAttestationChallenge(auth.ChallengeEndpoint)
		if err != nil {
			return nil, fmt.Errorf("fetching client attestation challenge: %w", err)
		}
		headers, err := createClientAttestationHeaders(w, auth.ClientID, auth.Audience, challenge)
		if err != nil {
			return nil, fmt.Errorf("creating client attestation headers: %w", err)
		}
		return headers, nil
	}
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

func createClientAttestationHeaders(w *Wallet, clientID, audience, challenge string) (map[string]string, error) {
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
		"iss": w.IssuerURL,
		"sub": clientID,
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"cnf": map[string]any{"jwk": holderJWK},
	}
	clientAttestationJWT, err := signJWT(clientAttestationHeader, clientAttestationPayload, w.IssuerKey)
	if err != nil {
		return nil, err
	}

	popHeader := map[string]any{
		"alg": "ES256",
		"typ": "oauth-client-attestation-pop+jwt",
		"jwk": holderJWK,
	}
	popPayload := map[string]any{
		"iss": clientID,
		"aud": audience,
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"jti": randomBase64URL(18),
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
	// OID4VCI 1.0 Appendix D has the attestation state how well the key
	// storage and the user authentication resist attack. An issuer that names
	// the values it wants in key_attestations_required checks them, and
	// rejects an attestation that claims nothing, so mirror what it asks for.
	// This is a test wallet: the claim describes a software key, not a
	// certified secure element, which is why it only ever repeats the
	// issuer's own requirement.
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
// configuration requires a key attestation in the proof, and returns what it
// requires. key_attestations_required is an object in OID4VCI 1.0, but its
// presence alone is what makes the attestation mandatory, so an issuer that
// sends an empty one (or a non-object, which some do) still gets an
// attestation, just without claims it never asked for.
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

func createDPoPProofJWT(key *ecdsa.PrivateKey, method, targetURL, nonce, accessToken string) (string, error) {
	jwk := mock.SigningJWKMap(&key.PublicKey)
	header := map[string]any{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": jwk,
	}
	payload := map[string]any{
		"jti": randomBase64URL(18),
		"htm": strings.ToUpper(method),
		"htu": stripURLFragment(targetURL),
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		payload["ath"] = format.EncodeBase64URL(sum[:])
	}
	return signJWT(header, payload, key)
}

func stripURLFragment(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.Fragment = ""
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
	}
	return details
}

// accessTokenScheme picks the HTTP authorization scheme for an access token.
// RFC 9449 §5 has an authorization server return token_type "DPoP" for a
// DPoP-bound token, so a wallet that sent a proof and got "Bearer" back holds
// a plain bearer token and has to say so. A server that omits token_type
// after accepting a proof is taken at the flow's word.
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

func postFormWithDPoP(target string, form url.Values, key *ecdsa.PrivateKey, accessToken string, nonce *string, extraHeaders func() (map[string]string, error)) (map[string]any, error) {
	body := []byte(form.Encode())
	respBody, _, err := doDPoPRequest("POST", target, "application/x-www-form-urlencoded", "", body, "", accessToken, key, nonce, extraHeaders)
	if err != nil {
		// A refusal states its reason in the response, in the two fields
		// RFC 6749 §5.2 defines for it. Reporting those beats handing the
		// caller the raw body and the status code a second time.
		if refusal := oauthErrorMessage(respBody); refusal != "" {
			return nil, errors.New(refusal)
		}
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parsing JSON response: %w", err)
	}
	// Some servers answer 200 with an error document, so the body decides
	// rather than the status.
	if refusal := oauthErrorMessage(respBody); refusal != "" {
		return nil, errors.New(refusal)
	}
	return out, nil
}

// oauthErrorMessage renders an OAuth 2.0 error response as "code: what it
// says", or empty when the body is not one.
func oauthErrorMessage(body []byte) string {
	var doc struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Error == "" {
		return ""
	}
	if doc.Description == "" {
		return doc.Error
	}
	return doc.Error + ": " + doc.Description
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
		// A Credential Error Response is reported by its code rather than as an
		// HTTP failure, because the code decides what happens next: §8.3.1.2
		// asks for another attempt on invalid_nonce and for none at all on
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
// response carrying a transaction_id and no credential means it is not ready,
// and that transaction_id claims it later from the deferred endpoint. A
// response that already has the credential is returned untouched, so both
// issuance flows can call this unconditionally.
//
// A short deferral is waited out here, so the caller gets its credential from
// the call it made. A longer one returns a DeferredIssuance for the background
// poller: not finished, but not failed either.
func (w *Wallet) resolveDeferredCredential(credResp map[string]any, ctx deferredContext) (map[string]any, *DeferredIssuance, error) {
	txID, _ := credResp["transaction_id"].(string)
	if txID == "" {
		return credResp, nil, nil
	}
	ctx.deferredEndpoint, _ = ctx.metadata["deferred_credential_endpoint"].(string)
	if ctx.deferredEndpoint == "" {
		return nil, nil, fmt.Errorf("issuer deferred the credential but published no deferred_credential_endpoint")
	}

	// Hand it straight to the poller rather than waiting here. Whoever started
	// the issuance is waiting on this call (a consent dialog, a CLI run), and
	// holding them for the issuer's interval tells them nothing they cannot be
	// told now: the credential is coming, and here is the ticket for it.
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
// the credential is not ready yet, and how long to wait before asking again.
//
// OpenID4VCI 1.0 §9.2: "If the Credential Issuer still requires more time, the
// Deferred Credential Response MUST use the interval and transaction_id
// parameters as defined in Section 8.3 and it MUST respond with the HTTP status
// code 202". Not ready is therefore a successful response carrying the
// transaction back with no credentials, not an error code.
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

// notifyCredentialAccepted reports a stored credential back to the issuer's
// Notification Endpoint. OpenID4VCI 1.0 §11.1 leaves this to the wallet ("the
// Wallet MAY send one or more Notification Requests per notification_id value
// received"); this wallet sends one whenever the issuer offers the endpoint and
// the Credential Response carries a notification_id, on every grant type.
func (w *Wallet) notifyCredentialAccepted(metadata, credResp map[string]any, accessToken, authScheme string, dpopKey *ecdsa.PrivateKey, nonce *string) error {
	notificationID, _ := credResp["notification_id"].(string)
	notificationEndpoint, _ := metadata["notification_endpoint"].(string)
	if notificationID == "" || notificationEndpoint == "" {
		return nil
	}
	w.addProtocolLog("issuance", "notification_request", fmt.Sprintf("Send credential notification to %s", notificationEndpoint), true, map[string]any{
		"direction":          "outbound",
		"method":             "POST",
		"url":                notificationEndpoint,
		"endpoint":           "notification",
		"notification_id":    notificationID,
		"notification_event": "credential_accepted",
	})
	if err := sendNotificationWithDPoP(notificationEndpoint, accessToken, authScheme, notificationID, dpopKey, nonce); err != nil {
		w.addProtocolLog("issuance", "notification_response", fmt.Sprintf("Notification response from %s", notificationEndpoint), false, map[string]any{
			"direction": "inbound",
			"url":       notificationEndpoint,
			"endpoint":  "notification",
			"error":     err.Error(),
		})
		return fmt.Errorf("sending notification: %w", err)
	}
	w.addProtocolLog("issuance", "notification_response", fmt.Sprintf("Notification response from %s", notificationEndpoint), true, map[string]any{
		"direction": "inbound",
		"url":       notificationEndpoint,
		"endpoint":  "notification",
	})
	return nil
}

func sendNotificationWithDPoP(endpoint, accessToken, authScheme, notificationID string, dpopKey *ecdsa.PrivateKey, nonce *string) error {
	body, err := json.Marshal(map[string]any{
		"notification_id": notificationID,
		"event":           "credential_accepted",
	})
	if err != nil {
		return fmt.Errorf("marshaling notification request: %w", err)
	}
	_, statusCode, err := doDPoPRequest("POST", endpoint, "application/json", "", body, authScheme, accessToken, dpopKey, nonce, nil)
	if err != nil {
		return err
	}
	if statusCode != http.StatusNoContent && (statusCode < 200 || statusCode >= 300) {
		return fmt.Errorf("notification endpoint returned HTTP %d", statusCode)
	}
	return nil
}

// fetchNonce asks the Nonce Endpoint for a challenge.
//
// Nothing is presented with the request: §7.1 says "The Nonce Endpoint is not a
// protected resource, meaning the Wallet does not need to supply an access
// token to access it", so neither the access token nor a DPoP proof belongs on
// it. The DPoP nonce state is still carried in, because §7.2 lets the issuer
// hand out a DPoP nonce here for the Credential Endpoint to use.
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
// dpop_signing_alg_values_supported expects.
func doDPoPRequest(method, target, contentType, accept string, body []byte, authScheme, token string, key *ecdsa.PrivateKey, nonce *string, extraHeaders func() (map[string]string, error)) ([]byte, int, error) {
	if accept == "" {
		accept = "application/json, application/jwt"
	}
	for attempt := 0; attempt < 2; attempt++ {
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
		if extraHeaders != nil {
			headers, err := extraHeaders()
			if err != nil {
				return nil, 0, err
			}
			for headerName, headerValue := range headers {
				req.Header.Set(headerName, headerValue)
			}
		}
		if key != nil {
			dpopJWT, err := createDPoPProofJWT(key, method, target, derefString(nonce), token)
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
		if needsDPoPRetry(resp.StatusCode, resp.Header, respBody) && attempt == 0 {
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
	return nil, 0, fmt.Errorf("DPoP request failed after retry")
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

func runAuthorizationCodeRequest(w *Wallet, endpoint, clientID, requestURI string, params url.Values, redirectURI, expectedState, expectedIssuer string, mode ValidationMode) (url.Values, error) {
	location, body, err := callAuthorizationEndpoint(endpoint, clientID, requestURI, params)
	if err != nil {
		return nil, err
	}
	if location != "" {
		valuesOut, err := parseRedirectQuery(location)
		if err == nil {
			if valuesOut.Get("code") != "" || valuesOut.Get("error") != "" {
				if err := validateAuthorizationCodeResponse(mode, valuesOut, expectedState, expectedIssuer); err != nil {
					return nil, err
				}
				return valuesOut, nil
			}
		}
	}

	if !canUseInteractiveAuthorizationCallback(w, redirectURI) {
		if location != "" {
			return nil, fmt.Errorf("authorization requires interactive browser login at %q, but redirect_uri %q is not handled by the running wallet server", location, redirectURI)
		}
		return nil, fmt.Errorf("authorization requires interactive browser login, but redirect_uri %q is not handled by the running wallet server (body: %s)", redirectURI, truncateBody(body))
	}

	callbackCh, unregister := w.RegisterAuthorizationCodeCallback(expectedState)
	defer unregister()

	authURL := endpoint + "?" + url.Values{
		"client_id":   {clientID},
		"request_uri": {requestURI},
	}.Encode()
	// The authorization endpoint comes from an issuer's metadata, and this
	// URL is about to be navigated to. A javascript: or data: endpoint would
	// run in the wallet's own origin, so refuse anything but http(s) before
	// handing it anywhere. (The call above would already have failed on such
	// a scheme. This does not depend on that ordering.)
	if err := validateAbsoluteURI("authorization_endpoint", authURL); err != nil {
		return nil, err
	}

	// The user authenticates at the issuer as part of this flow, which only a
	// browser can do. The wallet never opens one itself: the browser that
	// matters belongs to the user, and a hosted wallet opening a browser on
	// its own server reaches nobody. It hands the URL to whoever is holding
	// the user's attention (an open UI tab, or the API caller) and waits.
	//
	// The callback that resumes this flow is matched by state alone, so it
	// does not matter which browser performs the sign-in.
	if !w.NotifyAuthorization(authURL) {
		return nil, fmt.Errorf("this offer needs an interactive sign-in at %s, and nothing is attached to this wallet that can open it", authURL)
	}

	select {
	case values := <-callbackCh:
		if err := validateAuthorizationCodeResponse(mode, values, expectedState, expectedIssuer); err != nil {
			return nil, err
		}
		return values, nil
	case <-time.After(config.AuthorizationCallbackWait):
		return nil, fmt.Errorf("timed out waiting for authorization callback at %s", redirectURI)
	}
}

func validateAuthorizationCodeResponse(mode ValidationMode, values url.Values, expectedState, expectedIssuer string) error {
	if values == nil {
		return fmt.Errorf("authorization response is empty")
	}
	expectedState = strings.TrimSpace(expectedState)
	if expectedState != "" {
		state := values.Get("state")
		if mode == ValidationModeStrict && state == "" {
			return fmt.Errorf("authorization response missing state")
		}
		if state != "" && state != expectedState {
			return fmt.Errorf("authorization response state %q did not match %q", state, expectedState)
		}
	}

	if mode != ValidationModeStrict {
		return nil
	}

	expectedIssuer = normalizeIssuerURL(expectedIssuer)
	if expectedIssuer == "" {
		return nil
	}
	issuer := values.Get("iss")
	actualIssuer := normalizeIssuerURL(issuer)
	if actualIssuer == "" {
		return fmt.Errorf("authorization response missing issuer")
	}
	if actualIssuer != expectedIssuer {
		return fmt.Errorf("authorization response issuer %q did not match %q", issuer, expectedIssuer)
	}
	return nil
}

// callAuthorizationEndpoint starts the authorization request.
//
// A request that went through PAR is referred to by its request_uri, and the
// Authorization Server already holds everything else. Without PAR the same
// parameters travel in the query string, which is the plain authorization
// request of RFC 6749 §4.1.1.
func callAuthorizationEndpoint(endpoint, clientID, requestURI string, params url.Values) (string, string, error) {
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
	req, err := http.NewRequest("GET", endpoint+"?"+values.Encode(), nil)
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
	if w == nil || strings.TrimSpace(w.BaseURL) == "" {
		return false
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	baseURL, err := url.Parse(w.BaseURL)
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
