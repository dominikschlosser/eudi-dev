package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

var openAuthorizationBrowser = openAuthorizationBrowserImpl

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

	parEndpoint, _ := oauthMeta["pushed_authorization_request_endpoint"].(string)
	if parEndpoint == "" {
		return nil, fmt.Errorf("authorization server metadata did not include pushed_authorization_request_endpoint")
	}
	authorizationEndpoint, _ := oauthMeta["authorization_endpoint"].(string)
	if authorizationEndpoint == "" {
		return nil, fmt.Errorf("authorization server metadata did not include authorization_endpoint")
	}

	clientAuthMethod := detectTokenEndpointAuthMethod(oauthMeta)
	if clientAuthMethod != "" && clientAuthMethod != "private_key_jwt" && clientAuthMethod != "attest_jwt_client_auth" {
		return nil, fmt.Errorf("unsupported token endpoint auth method %q", clientAuthMethod)
	}
	useDPoP := supportsDPoP(oauthMeta)
	if !useDPoP {
		return nil, fmt.Errorf("authorization_code flow currently requires DPoP-capable issuer metadata")
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
	if clientAuthMethod == "private_key_jwt" {
		aud := oauthIssuer(oauthMeta, tokenEndpoint)
		assertion, err := createClientAssertionJWT(w.HolderKey, clientID, aud)
		if err != nil {
			return nil, fmt.Errorf("creating client assertion: %w", err)
		}
		parForm.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		parForm.Set("client_assertion", assertion)
	}
	buildClientAttestationHeaders := func() (map[string]string, error) {
		if clientAuthMethod != "attest_jwt_client_auth" {
			return nil, nil
		}
		challenge, err := fetchAttestationChallenge(oauthMeta)
		if err != nil {
			return nil, fmt.Errorf("fetching client attestation challenge: %w", err)
		}
		headers, err := createClientAttestationHeaders(w, clientID, oauthIssuer(oauthMeta, tokenEndpoint), challenge)
		if err != nil {
			return nil, fmt.Errorf("creating client attestation headers: %w", err)
		}
		return headers, nil
	}

	w.addProtocolLog("issuance", "par_request", fmt.Sprintf("Request PAR from %s", parEndpoint), true, formRequestLogDetails(parEndpoint, "par", parForm))
	parResp, err := postFormWithDPoP(parEndpoint, parForm, w.HolderKey, "", &nonces.authzServer, buildClientAttestationHeaders)
	w.addProtocolLog("issuance", "par_response", fmt.Sprintf("PAR response from %s", parEndpoint), err == nil, responseMapLogDetails(parEndpoint, "par", parResp, err))
	if err != nil {
		return nil, fmt.Errorf("PAR request: %w", err)
	}
	requestURI, _ := parResp["request_uri"].(string)
	if requestURI == "" {
		return nil, fmt.Errorf("PAR response missing request_uri")
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
	callbackValues, err := runAuthorizationCodeRequest(w, authorizationEndpoint, clientID, requestURI, redirectURI, state, oauthIssuer(oauthMeta, ""), w.ValidationMode)
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
	if clientAuthMethod == "private_key_jwt" {
		aud := oauthIssuer(oauthMeta, tokenEndpoint)
		assertion, err := createClientAssertionJWT(w.HolderKey, clientID, aud)
		if err != nil {
			return nil, fmt.Errorf("creating token client assertion: %w", err)
		}
		tokenForm.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		tokenForm.Set("client_assertion", assertion)
	}

	w.addProtocolLog("issuance", "token_request", fmt.Sprintf("Request token from %s", tokenEndpoint), true, formRequestLogDetails(tokenEndpoint, "token", tokenForm))
	tokenResp, err := postFormWithDPoP(tokenEndpoint, tokenForm, w.HolderKey, "", &nonces.authzServer, buildClientAttestationHeaders)
	w.addProtocolLog("issuance", "token_response", fmt.Sprintf("Token response from %s", tokenEndpoint), err == nil, responseMapLogDetails(tokenEndpoint, "token", tokenResp, err))
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	accessToken, _ := tokenResp["access_token"].(string)
	cNonce, _ := tokenResp["c_nonce"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}

	proofKeys, err := issuanceProofKeys(w.HolderKey, metadata)
	if err != nil {
		return nil, fmt.Errorf("preparing proof keys: %w", err)
	}
	proofHeader, err := createCredentialProofHeader(w, metadata, configID, cNonce, proofKeys)
	if err != nil {
		return nil, fmt.Errorf("building credential proof header: %w", err)
	}
	proofJWTs, err := createProofJWTs(proofKeys, offer.CredentialIssuer, cNonce, proofHeader)
	if err != nil {
		return nil, fmt.Errorf("creating proof JWT: %w", err)
	}

	credentialIdentifier := resolveCredentialIdentifier(tokenResp, offer.CredentialConfigurationIDs)
	credentialConfigurationID := ""
	if credentialIdentifier == "" && len(offer.CredentialConfigurationIDs) > 0 {
		credentialConfigurationID = offer.CredentialConfigurationIDs[0]
	}
	responseEncryption := buildCredentialResponseEncryptionRequest(metadata, w.HolderKey)

	if cNonce == "" {
		if nonceEndpoint, _ := metadata["nonce_endpoint"].(string); nonceEndpoint != "" {
			w.addProtocolLog("issuance", "nonce_request", fmt.Sprintf("Request nonce from %s", nonceEndpoint), true, map[string]any{
				"direction": "outbound",
				"method":    "POST",
				"url":       nonceEndpoint,
				"endpoint":  "nonce",
			})
		}
		cNonce = fetchNonceWithDPoP(metadata, accessToken, w.HolderKey, &nonces.resource)
		if nonceEndpoint, _ := metadata["nonce_endpoint"].(string); nonceEndpoint != "" {
			w.addProtocolLog("issuance", "nonce_response", fmt.Sprintf("Nonce response from %s", nonceEndpoint), cNonce != "", map[string]any{
				"direction": "inbound",
				"url":       nonceEndpoint,
				"endpoint":  "nonce",
				"c_nonce":   cNonce,
			})
		}
		if cNonce != "" {
			proofHeader, err = createCredentialProofHeader(w, metadata, configID, cNonce, proofKeys)
			if err != nil {
				return nil, fmt.Errorf("building credential proof header with nonce: %w", err)
			}
			proofJWTs, err = createProofJWTs(proofKeys, offer.CredentialIssuer, cNonce, proofHeader)
			if err != nil {
				return nil, fmt.Errorf("creating proof JWT with nonce: %w", err)
			}
		}
	}

	w.addProtocolLog("issuance", "credential_request", fmt.Sprintf("Request credential from %s", credentialEndpoint), true, credentialRequestLogDetails(credentialEndpoint, accessToken, proofJWTs, credentialIdentifier, credentialConfigurationID, responseEncryption))
	credResp, err := requestCredentialWithDPoP(
		metadata,
		credentialEndpoint,
		accessToken,
		proofJWTs,
		credentialIdentifier,
		credentialConfigurationID,
		responseEncryption,
		w.HolderKey,
		&nonces.resource,
	)
	w.addProtocolLog("issuance", "credential_response", fmt.Sprintf("Credential response from %s", credentialEndpoint), err == nil, credentialResponseLogDetails(credentialEndpoint, credResp, err))
	if err != nil {
		return nil, fmt.Errorf("requesting credential: %w", err)
	}

	if txID, _ := credResp["transaction_id"].(string); txID != "" {
		deferredEndpoint, _ := metadata["deferred_credential_endpoint"].(string)
		if deferredEndpoint == "" {
			return nil, fmt.Errorf("deferred credential response missing deferred_credential_endpoint metadata")
		}
		w.addProtocolLog("issuance", "deferred_credential_request", fmt.Sprintf("Request deferred credential from %s", deferredEndpoint), true, map[string]any{
			"direction":      "outbound",
			"method":         "POST",
			"url":            deferredEndpoint,
			"endpoint":       "deferred_credential",
			"transaction_id": txID,
		})
		credResp, err = requestDeferredCredentialWithDPoP(deferredEndpoint, accessToken, txID, w.HolderKey, &nonces.resource)
		w.addProtocolLog("issuance", "deferred_credential_response", fmt.Sprintf("Deferred credential response from %s", deferredEndpoint), err == nil, responseMapLogDetails(deferredEndpoint, "deferred_credential", credResp, err))
		if err != nil {
			return nil, fmt.Errorf("requesting deferred credential: %w", err)
		}
	}

	credential, err := selectHolderBoundCredential(credResp, proofKeys)
	if err != nil {
		return nil, err
	}

	imported, err := w.ImportCredential(credential)
	if err != nil {
		return nil, fmt.Errorf("importing received credential: %w", err)
	}
	importDetails := credentialImportLogDetails(imported, credential)
	importDetails["issuer"] = offer.CredentialIssuer
	w.addProtocolLog("issuance", "credential_imported", fmt.Sprintf("Imported credential %s", imported.ID), true, importDetails)

	if notificationID, _ := credResp["notification_id"].(string); notificationID != "" {
		if notificationEndpoint, _ := metadata["notification_endpoint"].(string); notificationEndpoint != "" {
			w.addProtocolLog("issuance", "notification_request", fmt.Sprintf("Send credential notification to %s", notificationEndpoint), true, map[string]any{
				"direction":          "outbound",
				"method":             "POST",
				"url":                notificationEndpoint,
				"endpoint":           "notification",
				"notification_id":    notificationID,
				"notification_event": "credential_accepted",
			})
			if err := sendNotificationWithDPoP(notificationEndpoint, accessToken, notificationID, w.HolderKey, &nonces.resource); err != nil {
				w.addProtocolLog("issuance", "notification_response", fmt.Sprintf("Notification response from %s", notificationEndpoint), false, map[string]any{
					"direction": "inbound",
					"url":       notificationEndpoint,
					"endpoint":  "notification",
					"error":     err.Error(),
				})
				return nil, fmt.Errorf("sending notification: %w", err)
			}
			w.addProtocolLog("issuance", "notification_response", fmt.Sprintf("Notification response from %s", notificationEndpoint), true, map[string]any{
				"direction": "inbound",
				"url":       notificationEndpoint,
				"endpoint":  "notification",
			})
		}
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
	}, nil
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

func fetchAttestationChallenge(oauthMeta map[string]any) (string, error) {
	endpoint, _ := oauthMeta["challenge_endpoint"].(string)
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
		body, _ := io.ReadAll(resp.Body)
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
	if !credentialRequiresKeyAttestation(metadata, configID) {
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
	if cNonce != "" {
		payload["nonce"] = cNonce
	}
	keyAttestationJWT, err := signJWT(header, payload, w.IssuerKey)
	if err != nil {
		return nil, fmt.Errorf("creating key attestation JWT: %w", err)
	}
	return map[string]any{"key_attestation": keyAttestationJWT}, nil
}

func credentialRequiresKeyAttestation(metadata map[string]any, configID string) bool {
	if configID == "" {
		return false
	}
	configs, ok := metadata["credential_configurations_supported"].(map[string]any)
	if !ok {
		return false
	}
	cfg, ok := configs[configID].(map[string]any)
	if !ok {
		return false
	}
	proofTypes, ok := cfg["proof_types_supported"].(map[string]any)
	if !ok {
		return false
	}
	jwtProof, ok := proofTypes["jwt"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = jwtProof["key_attestations_required"]
	return ok
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

func postFormWithDPoP(target string, form url.Values, key *ecdsa.PrivateKey, accessToken string, nonce *string, extraHeaders func() (map[string]string, error)) (map[string]any, error) {
	body := []byte(form.Encode())
	respBody, _, err := doDPoPRequest("POST", target, "application/x-www-form-urlencoded", body, "", accessToken, key, nonce, extraHeaders)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parsing JSON response: %w", err)
	}
	if errMsg, _ := out["error"].(string); errMsg != "" {
		desc, _ := out["error_description"].(string)
		return nil, fmt.Errorf("server error: %s: %s", errMsg, desc)
	}
	return out, nil
}

func requestCredentialWithDPoP(metadata map[string]any, endpoint, accessToken string, proofJWTs []string, credentialIdentifier, credentialConfigurationID string, credentialResponseEncryption map[string]any, key *ecdsa.PrivateKey, nonce *string) (map[string]any, error) {
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
	body, contentType, err := prepareCredentialRequestBody(metadata, reqBody)
	if err != nil {
		return nil, err
	}
	respBody, _, err := doDPoPRequest("POST", endpoint, contentType, body, "DPoP", accessToken, key, nonce, nil)
	if err != nil {
		return nil, err
	}
	out, err := parseCredentialResponseBody(respBody, key)
	if err != nil {
		return nil, err
	}
	if errMsg, _ := out["error"].(string); errMsg != "" {
		desc, _ := out["error_description"].(string)
		return nil, fmt.Errorf("credential error: %s: %s", errMsg, desc)
	}
	return out, nil
}

func requestDeferredCredentialWithDPoP(endpoint, accessToken, transactionID string, key *ecdsa.PrivateKey, nonce *string) (map[string]any, error) {
	body, err := json.Marshal(map[string]any{"transaction_id": transactionID})
	if err != nil {
		return nil, fmt.Errorf("marshaling deferred credential request: %w", err)
	}
	for {
		respBody, _, err := doDPoPRequest("POST", endpoint, "application/json", body, "DPoP", accessToken, key, nonce, nil)
		if err != nil {
			return nil, err
		}
		out, err := parseCredentialResponseBody(respBody, key)
		if err != nil {
			return nil, fmt.Errorf("parsing deferred credential response: %w", err)
		}
		if txID, _ := out["transaction_id"].(string); txID != "" {
			interval := 1
			if raw, ok := out["interval"].(float64); ok && raw >= 1 {
				interval = int(raw)
			}
			time.Sleep(time.Duration(interval) * time.Second)
			continue
		}
		if errMsg, _ := out["error"].(string); errMsg != "" {
			desc, _ := out["error_description"].(string)
			return nil, fmt.Errorf("deferred credential error: %s: %s", errMsg, desc)
		}
		return out, nil
	}
}

func sendNotificationWithDPoP(endpoint, accessToken, notificationID string, key *ecdsa.PrivateKey, nonce *string) error {
	body, err := json.Marshal(map[string]any{
		"notification_id": notificationID,
		"event":           "credential_accepted",
	})
	if err != nil {
		return fmt.Errorf("marshaling notification request: %w", err)
	}
	_, statusCode, err := doDPoPRequest("POST", endpoint, "application/json", body, "DPoP", accessToken, key, nonce, nil)
	if err != nil {
		return err
	}
	if statusCode != http.StatusNoContent && (statusCode < 200 || statusCode >= 300) {
		return fmt.Errorf("notification endpoint returned HTTP %d", statusCode)
	}
	return nil
}

func fetchNonceWithDPoP(metadata map[string]any, accessToken string, key *ecdsa.PrivateKey, nonce *string) string {
	ep, _ := metadata["nonce_endpoint"].(string)
	if ep == "" {
		return ""
	}
	respBody, _, err := doDPoPRequest("POST", ep, "application/x-www-form-urlencoded", nil, "DPoP", accessToken, key, nonce, nil)
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

func doDPoPRequest(method, target, contentType string, body []byte, authScheme, token string, key *ecdsa.PrivateKey, nonce *string, extraHeaders func() (map[string]string, error)) ([]byte, int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		reqBody := bytes.NewReader(body)
		req, err := http.NewRequest(method, target, reqBody)
		if err != nil {
			return nil, 0, fmt.Errorf("creating request: %w", err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Accept", "application/json, application/jwt")
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
		dpopJWT, err := createDPoPProofJWT(key, method, target, derefString(nonce), token)
		if err != nil {
			return nil, 0, fmt.Errorf("creating DPoP proof: %w", err)
		}
		req.Header.Set("DPoP", dpopJWT)

		resp, err := doIssuanceRequest(req)
		if err != nil {
			return nil, 0, fmt.Errorf("request: %w", err)
		}
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, fmt.Errorf("reading response: %w", readErr)
		}
		updateDPoPNonce(nonce, resp.Header)
		if needsDPoPRetry(resp.StatusCode, resp.Header, respBody) && attempt == 0 {
			continue
		}
		if resp.StatusCode >= 400 {
			return nil, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
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

func runAuthorizationCodeRequest(w *Wallet, endpoint, clientID, requestURI, redirectURI, expectedState, expectedIssuer string, mode ValidationMode) (url.Values, error) {
	location, body, err := callAuthorizationEndpoint(endpoint, clientID, requestURI)
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
	if err := openAuthorizationBrowser(authURL); err != nil {
		return nil, fmt.Errorf("opening browser for authorization request: %w", err)
	}

	select {
	case values := <-callbackCh:
		if err := validateAuthorizationCodeResponse(mode, values, expectedState, expectedIssuer); err != nil {
			return nil, err
		}
		return values, nil
	case <-time.After(5 * time.Minute):
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

func callAuthorizationEndpoint(endpoint, clientID, requestURI string) (string, string, error) {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("request_uri", requestURI)
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
	body, _ := io.ReadAll(resp.Body)
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

func openAuthorizationBrowserImpl(rawURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "linux":
		cmd = exec.Command("xdg-open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		return fmt.Errorf("opening browser is not supported on %s", runtime.GOOS)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return nil
}
