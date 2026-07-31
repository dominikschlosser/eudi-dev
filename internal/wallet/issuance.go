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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
	"github.com/dominikschlosser/oid4vc-dev/internal/validate"
)

var preferredCredentialResponseEncryptionAlgs = []string{"ECDH-ES"}
var preferredCredentialResponseEncryptionEncs = []string{"A128GCM", "A256GCM", "A128CBC-HS256"}
var preferredCredentialRequestEncryptionEncs = []string{"A256GCM", "A128GCM", "A128CBC-HS256"}

// HTTPClient is the interface used for HTTP requests during issuance flows.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

var defaultHTTPClient HTTPClient = http.DefaultClient

// httpClient is the HTTP client used by the issuance functions. Override in
// tests to inject mock servers.
var httpClient HTTPClient = defaultHTTPClient

func doIssuanceRequest(req *http.Request) (*http.Response, error) {
	if httpClient == defaultHTTPClient {
		return format.HTTPClientForURL(req.URL.String()).Do(req)
	}
	return httpClient.Do(req)
}

// IssuanceResult captures the result of an OID4VCI flow.
type IssuanceResult struct {
	CredentialID       string `json:"credential_id"`
	Format             string `json:"format"`
	Issuer             string `json:"issuer"`
	VerificationStatus string `json:"verification_status,omitempty"`
	VerificationDetail string `json:"verification_detail,omitempty"`
	Error              string `json:"error,omitempty"`
}

// ProcessCredentialOffer processes an OID4VCI credential offer URI.
func (w *Wallet) ProcessCredentialOffer(offerURI string) (*IssuanceResult, error) {
	// Parse the credential offer
	reqType, result, err := oid4vc.Parse(offerURI)
	if err != nil {
		return nil, fmt.Errorf("parsing credential offer: %w", err)
	}
	if reqType != oid4vc.TypeVCI {
		return nil, fmt.Errorf("expected VCI credential offer, got VP")
	}

	offer, ok := result.(*oid4vc.CredentialOffer)
	if !ok {
		return nil, fmt.Errorf("unexpected result type")
	}

	w.addProtocolLog("issuance", "credential_offer", fmt.Sprintf("Received credential offer from %s", offer.CredentialIssuer), true, map[string]any{
		"direction":                    "inbound",
		"offer_uri":                    offerURI,
		"issuer":                       offer.CredentialIssuer,
		"credential_configuration_ids": offer.CredentialConfigurationIDs,
		"grants":                       offer.Grants,
	})

	// Fetch issuer metadata
	metadataURL, _ := wellKnownURL(offer.CredentialIssuer, "openid-credential-issuer")
	w.addProtocolLog("issuance", "issuer_metadata_request", fmt.Sprintf("Fetch issuer metadata from %s", offer.CredentialIssuer), true, map[string]any{
		"direction": "outbound",
		"method":    "GET",
		"url":       metadataURL,
		"issuer":    offer.CredentialIssuer,
	})
	metadata, err := fetchIssuerMetadata(offer.CredentialIssuer)
	if err != nil {
		w.addProtocolLog("issuance", "issuer_metadata_response", fmt.Sprintf("Issuer metadata response from %s", offer.CredentialIssuer), false, map[string]any{
			"direction": "inbound",
			"url":       metadataURL,
			"issuer":    offer.CredentialIssuer,
			"error":     err.Error(),
		})
		return nil, fmt.Errorf("fetching issuer metadata: %w", err)
	}
	w.addProtocolLog("issuance", "issuer_metadata_response", fmt.Sprintf("Issuer metadata response from %s", offer.CredentialIssuer), true, map[string]any{
		"direction": "inbound",
		"url":       metadataURL,
		"issuer":    offer.CredentialIssuer,
		"metadata":  metadata,
	})

	authServer := getAuthorizationServer(metadata, offer.CredentialIssuer)
	oauthURL, _ := wellKnownURL(authServer, "oauth-authorization-server")
	w.addProtocolLog("issuance", "oauth_metadata_request", fmt.Sprintf("Fetch OAuth metadata from %s", authServer), true, map[string]any{
		"direction": "outbound",
		"method":    "GET",
		"url":       oauthURL,
		"issuer":    authServer,
	})
	oauthMeta, oauthErr := fetchOAuthMetadata(authServer)
	oauthResponseDetails := map[string]any{
		"direction": "inbound",
		"url":       oauthURL,
		"issuer":    authServer,
	}
	if oauthErr != nil {
		oauthResponseDetails["error"] = oauthErr.Error()
	} else {
		oauthResponseDetails["metadata"] = oauthMeta
	}
	w.addProtocolLog("issuance", "oauth_metadata_response", fmt.Sprintf("OAuth metadata response from %s", authServer), oauthErr == nil, oauthResponseDetails)
	tokenEndpoint := getTokenEndpoint(metadata, oauthMeta, offer.CredentialIssuer)
	credentialEndpoint := getCredentialEndpoint(metadata, offer.CredentialIssuer)
	if offer.Grants.PreAuthorizedCode == "" {
		if w.ValidationMode == ValidationModeStrict {
			if oauthErr != nil {
				return nil, fmt.Errorf("fetching authorization server metadata: %w", oauthErr)
			}
			if err := validateAuthorizationServerIssuer(authServer, oauthMeta); err != nil {
				return nil, err
			}
		}
		return w.processAuthorizationCodeOffer(offer, metadata, oauthMeta, tokenEndpoint, credentialEndpoint)
	}

	// Token exchange (pre-authorized code flow)
	w.mu.Lock()
	txCode := w.TxCode
	w.TxCode = "" // clear after use
	w.mu.Unlock()
	w.addProtocolLog("issuance", "token_request", fmt.Sprintf("Request token from %s", tokenEndpoint), true, map[string]any{
		"direction":           "outbound",
		"method":              "POST",
		"url":                 tokenEndpoint,
		"endpoint":            "token",
		"grant_type":          "urn:ietf:params:oauth:grant-type:pre-authorized_code",
		"pre-authorized_code": offer.Grants.PreAuthorizedCode,
		"tx_code":             txCode,
	})
	tokenResp, err := exchangePreAuthorizedToken(tokenEndpoint, offer, txCode)
	if err != nil {
		w.addProtocolLog("issuance", "token_response", fmt.Sprintf("Token response from %s", tokenEndpoint), false, map[string]any{
			"direction": "inbound",
			"url":       tokenEndpoint,
			"endpoint":  "token",
			"error":     err.Error(),
		})
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	w.addProtocolLog("issuance", "token_response", fmt.Sprintf("Token response from %s", tokenEndpoint), true, map[string]any{
		"direction": "inbound",
		"url":       tokenEndpoint,
		"endpoint":  "token",
		"response":  tokenResp,
	})

	accessToken, _ := tokenResp["access_token"].(string)
	cNonce, _ := tokenResp["c_nonce"].(string)

	log.Printf("[VCI] Token endpoint: %s", tokenEndpoint)
	log.Printf("[VCI] Credential endpoint: %s", credentialEndpoint)
	log.Printf("[VCI] c_nonce: %q", cNonce)
	if tokenJSON, err := json.MarshalIndent(tokenResp, "", "  "); err == nil {
		log.Printf("[VCI] Token response:\n%s", tokenJSON)
	}

	// Create proof of possession JWTs (multiple when the issuer advertises
	// batch credential issuance)
	proofKeys, err := issuanceProofKeys(w.HolderKey, metadata)
	if err != nil {
		return nil, fmt.Errorf("preparing proof keys: %w", err)
	}
	proofJWTs, err := createProofJWTs(proofKeys, offer.CredentialIssuer, cNonce, nil)
	if err != nil {
		return nil, fmt.Errorf("creating proof JWT: %w", err)
	}
	log.Printf("[VCI] Proof JWT: %s", proofJWTs[0])

	// Request credential
	credFormat := ""
	if len(offer.CredentialConfigurationIDs) > 0 {
		credFormat = resolveCredentialFormat(metadata, offer.CredentialConfigurationIDs[0])
	}
	responseEncryption := buildCredentialResponseEncryptionRequest(metadata, w.HolderKey)

	// Extract credential_identifiers from authorization_details in token response
	credentialIdentifier := resolveCredentialIdentifier(tokenResp, offer.CredentialConfigurationIDs)
	credentialConfigurationID := ""
	if credentialIdentifier == "" && len(offer.CredentialConfigurationIDs) > 0 {
		credentialConfigurationID = offer.CredentialConfigurationIDs[0]
	}

	// If no c_nonce in token response, try a nonce endpoint or send without
	// proof first to get a c_nonce from the error response.
	if cNonce == "" {
		cNonce = fetchNonce(metadata, offer.CredentialIssuer)
		if cNonce != "" {
			proofJWTs, err = createProofJWTs(proofKeys, offer.CredentialIssuer, cNonce, nil)
			if err != nil {
				return nil, fmt.Errorf("creating proof JWT with nonce: %w", err)
			}
			log.Printf("[VCI] Recreated proof JWT with nonce from nonce endpoint")
		}
	}

	if cNonce == "" {
		// Try credential request without proof to get c_nonce from error response
		log.Printf("[VCI] No c_nonce available, attempting credential request to obtain one")
		w.addProtocolLog("issuance", "credential_request", fmt.Sprintf("Request credential from %s", credentialEndpoint), true, credentialRequestLogDetails(credentialEndpoint, accessToken, proofJWTs, credentialIdentifier, credentialConfigurationID, responseEncryption))
		nonceResp, nonceErr := requestCredential(
			metadata,
			credentialEndpoint,
			accessToken,
			proofJWTs,
			credentialIdentifier,
			credentialConfigurationID,
			responseEncryption,
			w.HolderKey,
		)
		w.addProtocolLog("issuance", "credential_response", fmt.Sprintf("Credential response from %s", credentialEndpoint), nonceErr == nil, credentialResponseLogDetails(credentialEndpoint, nonceResp, nonceErr))
		if nonceErr != nil {
			// Check if the error response contained a c_nonce
			if n, ok := nonceResp["c_nonce"].(string); ok && n != "" {
				cNonce = n
				log.Printf("[VCI] Got c_nonce from error response: %s", cNonce)
				// Recreate proofs with the real nonce
				proofJWTs, err = createProofJWTs(proofKeys, offer.CredentialIssuer, cNonce, nil)
				if err != nil {
					return nil, fmt.Errorf("creating proof JWT with nonce: %w", err)
				}
			} else {
				return nil, fmt.Errorf("requesting credential: %w", nonceErr)
			}
		} else {
			// First request succeeded without nonce — use the response directly
			credential, err := selectHolderBoundCredential(nonceResp, proofKeys)
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
	}

	w.addProtocolLog("issuance", "credential_request", fmt.Sprintf("Request credential from %s", credentialEndpoint), true, credentialRequestLogDetails(credentialEndpoint, accessToken, proofJWTs, credentialIdentifier, credentialConfigurationID, responseEncryption))
	credResp, err := requestCredential(
		metadata,
		credentialEndpoint,
		accessToken,
		proofJWTs,
		credentialIdentifier,
		credentialConfigurationID,
		responseEncryption,
		w.HolderKey,
	)
	w.addProtocolLog("issuance", "credential_response", fmt.Sprintf("Credential response from %s", credentialEndpoint), err == nil, credentialResponseLogDetails(credentialEndpoint, credResp, err))
	if err != nil {
		return nil, fmt.Errorf("requesting credential: %w", err)
	}

	if credJSON, err := json.MarshalIndent(credResp, "", "  "); err == nil {
		log.Printf("[VCI] Credential response:\n%s", credJSON)
	}

	credential, err := selectHolderBoundCredential(credResp, proofKeys)
	if err != nil {
		return nil, err
	}

	// Import the received credential
	imported, err := w.ImportCredential(credential)
	if err != nil {
		return nil, fmt.Errorf("importing received credential: %w", err)
	}
	importDetails := credentialImportLogDetails(imported, credential)
	importDetails["issuer"] = offer.CredentialIssuer
	w.addProtocolLog("issuance", "credential_imported", fmt.Sprintf("Imported credential %s", imported.ID), true, importDetails)

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

func verifyImportedJWTMetadataSignature(raw string) (string, string) {
	token, err := sdjwt.Parse(raw)
	if err != nil {
		return "", ""
	}
	result, source, err := validate.VerifyJWTSignature(token, nil, nil)
	if err != nil {
		return "fail", err.Error()
	}
	if result == nil {
		return "skipped", "Issuer metadata verification unavailable"
	}
	if result.SignatureValid {
		if source != "" {
			return "pass", fmt.Sprintf("Signature valid (%s, via %s)", result.Algorithm, source)
		}
		return "pass", fmt.Sprintf("Signature valid (%s)", result.Algorithm)
	}
	if source != "" {
		return "fail", fmt.Sprintf("Signature invalid via %s", source)
	}
	return "fail", "Signature invalid"
}

// fetchIssuerMetadata fetches the OpenID Credential Issuer metadata.
func fetchIssuerMetadata(issuer string) (map[string]any, error) {
	metadataURL, err := wellKnownURL(issuer, "openid-credential-issuer")
	if err != nil {
		return nil, fmt.Errorf("building issuer metadata URL: %w", err)
	}

	req, err := http.NewRequest("GET", metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating metadata request: %w", err)
	}
	// Some issuers (e.g. Procivis One) reject requests without an Accept header.
	req.Header.Set("Accept", "application/json, application/openidvci-issuer-metadata+jwt")
	resp, err := doIssuanceRequest(req)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("metadata request failed (%d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading metadata: %w", err)
	}
	return parseIssuerMetadataResponse(body, resp.Header.Get("Content-Type"))
}

func wellKnownURL(issuerOrServer, wellKnownType string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(issuerOrServer))
	if err != nil {
		return "", fmt.Errorf("parsing issuer URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("issuer URL must be absolute")
	}
	path := parsed.EscapedPath()
	if wellKnownType == "oauth-authorization-server" {
		// RFC 8414 §3.1: remove a terminating "/" from the issuer path before
		// inserting the well-known segment. OID4VCI 1.0 §12.2.2 preserves the
		// Credential Issuer Identifier path verbatim, so only the OAuth AS
		// metadata URL strips it.
		path = strings.TrimSuffix(path, "/")
	}
	return fmt.Sprintf("%s://%s/.well-known/%s%s", parsed.Scheme, parsed.Host, wellKnownType, path), nil
}

func parseIssuerMetadataResponse(body []byte, contentType string) (map[string]any, error) {
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil, fmt.Errorf("issuer metadata response was empty")
	}

	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if strings.Contains(mediaType, "openidvci-issuer-metadata+jwt") || isLikelyCompactJWT(raw) {
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing signed issuer metadata: %w", err)
		}
		if err := verifySignedIssuerMetadata(token); err != nil {
			return nil, err
		}
		return token.Payload, nil
	}

	var metadata map[string]any
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("parsing metadata JSON: %w", err)
	}
	return metadata, nil
}

func isLikelyCompactJWT(raw string) bool {
	if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
		return false
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return false
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func verifySignedIssuerMetadata(token *sdjwt.Token) error {
	if token == nil {
		return fmt.Errorf("signed issuer metadata token is nil")
	}
	x5cRaw, ok := token.Header["x5c"]
	if !ok {
		return nil
	}
	entries, err := normalizeMetadataX5CEntries(x5cRaw)
	if err != nil {
		return fmt.Errorf("parsing issuer metadata x5c: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}
	der, err := format.DecodeBase64Std(entries[0])
	if err != nil {
		return fmt.Errorf("decoding issuer metadata x5c leaf: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parsing issuer metadata x5c leaf: %w", err)
	}
	result := sdjwt.Verify(token, cert.PublicKey)
	if result == nil || !result.SignatureValid {
		return fmt.Errorf("issuer metadata signature is invalid")
	}
	return nil
}

func normalizeMetadataX5CEntries(raw any) ([]string, error) {
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, entry := range v {
			s, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("x5c entry is not a string")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("x5c is not an array")
	}
}

func getAuthorizationServer(metadata map[string]any, issuer string) string {
	authServer := issuer
	if servers, ok := metadata["authorization_servers"].([]any); ok && len(servers) > 0 {
		if s, ok := servers[0].(string); ok && s != "" {
			authServer = s
		}
	}
	return authServer
}

func validateAuthorizationServerIssuer(authServer string, oauthMeta map[string]any) error {
	expected := normalizeIssuerURL(authServer)
	issuer, _ := oauthMeta["issuer"].(string)
	actual := normalizeIssuerURL(issuer)
	if expected == "" {
		return fmt.Errorf("authorization server issuer cannot be validated without authorization server URL")
	}
	if actual == "" {
		return fmt.Errorf("authorization server metadata missing issuer")
	}
	if actual != expected {
		return fmt.Errorf("authorization server issuer %q did not match authorization server %q", issuer, authServer)
	}
	return nil
}

func normalizeIssuerURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func getTokenEndpoint(metadata map[string]any, oauthMeta map[string]any, issuer string) string {
	// OID4VCI: token_endpoint may be directly in credential issuer metadata
	if ep, ok := metadata["token_endpoint"].(string); ok {
		return ep
	}

	if ep, ok := oauthMeta["token_endpoint"].(string); ok {
		return ep
	}

	authServer := getAuthorizationServer(metadata, issuer)
	return authServer + "/token"
}

// fetchOAuthMetadata fetches the OAuth 2.0 Authorization Server metadata.
// Tries /.well-known/openid-configuration first, falls back to
// /.well-known/oauth-authorization-server.
func fetchOAuthMetadata(authServer string) (map[string]any, error) {
	oauthURL, err := wellKnownURL(authServer, "oauth-authorization-server")
	if err != nil {
		return nil, err
	}
	urls := []string{oauthURL}

	for _, u := range urls {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		resp, err := doIssuanceRequest(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		var meta map[string]any
		err = json.NewDecoder(resp.Body).Decode(&meta)
		resp.Body.Close()
		if err != nil {
			continue
		}
		return meta, nil
	}

	return nil, fmt.Errorf("no OAuth metadata found at %s", authServer)
}

func getCredentialEndpoint(metadata map[string]any, issuer string) string {
	if ep, ok := metadata["credential_endpoint"].(string); ok {
		return ep
	}
	return strings.TrimRight(issuer, "/") + "/credential"
}

func resolveCredentialFormat(metadata map[string]any, configID string) string {
	configs, ok := metadata["credential_configurations_supported"].(map[string]any)
	if !ok {
		return ""
	}
	cfg, ok := configs[configID].(map[string]any)
	if !ok {
		return ""
	}
	f, _ := cfg["format"].(string)
	return f
}

// exchangePreAuthorizedToken performs the pre-authorized code token exchange.
func exchangePreAuthorizedToken(tokenEndpoint string, offer *oid4vc.CredentialOffer, txCode string) (map[string]any, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	form.Set("pre-authorized_code", offer.Grants.PreAuthorizedCode)
	if txCode != "" {
		form.Set("tx_code", txCode)
	}

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := doIssuanceRequest(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	if errMsg, ok := tokenResp["error"].(string); ok {
		desc, _ := tokenResp["error_description"].(string)
		return nil, fmt.Errorf("token error: %s: %s", errMsg, desc)
	}

	return tokenResp, nil
}

// createProofJWT creates an OID4VCI proof of possession JWT.
func createProofJWT(holderKey *ecdsa.PrivateKey, audience, cNonce string, extraHeader map[string]any) (string, error) {
	// Build JWK for holder public key
	jwkJSON := mock.PublicKeyJWK(&holderKey.PublicKey)
	var jwk map[string]any
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		return "", fmt.Errorf("parsing holder JWK: %w", err)
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "openid4vci-proof+jwt",
		"jwk": jwk,
	}
	for key, value := range extraHeader {
		header[key] = value
	}

	payload := map[string]any{
		"aud":   audience,
		"iat":   time.Now().Unix(),
		"nonce": cNonce,
	}

	return signJWT(header, payload, holderKey)
}

// resolveCredentialIdentifier extracts a credential_identifier from the token
// response's authorization_details. Per OID4VCI 1.0 final, the token response
// may contain credential_identifiers that should be used instead of the
// credential_configuration_id from the offer.
func resolveCredentialIdentifier(tokenResp map[string]any, configIDs []string) string {
	if authDetails, ok := tokenResp["authorization_details"].([]any); ok {
		for _, detail := range authDetails {
			d, ok := detail.(map[string]any)
			if !ok {
				continue
			}
			if ids, ok := d["credential_identifiers"].([]any); ok && len(ids) > 0 {
				if id, ok := ids[0].(string); ok {
					return id
				}
			}
		}
	}

	return ""
}

func buildCredentialResponseEncryptionRequest(metadata map[string]any, holderKey *ecdsa.PrivateKey) map[string]any {
	if holderKey == nil {
		return nil
	}
	raw, ok := metadata["credential_response_encryption"].(map[string]any)
	if !ok {
		return nil
	}

	alg := firstSupportedString(raw["alg_values_supported"], preferredCredentialResponseEncryptionAlgs)
	enc := firstSupportedString(raw["enc_values_supported"], preferredCredentialResponseEncryptionEncs)
	if alg == "" || enc == "" {
		return nil
	}

	return map[string]any{
		"jwk": publicCredentialResponseEncryptionJWK(&holderKey.PublicKey, alg),
		"enc": enc,
	}
}

func publicCredentialResponseEncryptionJWK(key *ecdsa.PublicKey, alg string) map[string]any {
	jwk := mock.PublicKeyJWKMap(key)
	return map[string]any{
		"kty": jwk["kty"],
		"crv": jwk["crv"],
		"x":   jwk["x"],
		"y":   jwk["y"],
		"kid": mock.KeyIDForPublicKey(key),
		"use": "enc",
		"alg": alg,
	}
}

func firstSupportedString(raw any, preferred []string) string {
	values := supportedStringValues(raw)
	if len(values) == 0 {
		return ""
	}
	for _, want := range preferred {
		for _, got := range values {
			if got == want {
				return got
			}
		}
	}
	return ""
}

func supportedStringValues(raw any) []string {
	switch values := raw.(type) {
	case []any:
		out := make([]string, 0, len(values))
		for _, candidate := range values {
			if got, _ := candidate.(string); got != "" {
				out = append(out, got)
			}
		}
		return out
	case []string:
		return values
	default:
		return nil
	}
}

type credentialRequestEncryptionParams struct {
	key *ecdsa.PublicKey
	kid string
	alg string
	enc string
}

func prepareCredentialRequestBody(metadata map[string]any, reqBody map[string]any) ([]byte, string, error) {
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling request: %w", err)
	}
	encryption, err := selectCredentialRequestEncryption(metadata)
	if err != nil {
		return nil, "", err
	}
	if encryption == nil {
		return bodyJSON, "application/json", nil
	}
	jwe, _, err := EncryptJWEWithContentType(bodyJSON, encryption.key, encryption.kid, encryption.alg, encryption.enc, "json", nil, nil)
	if err != nil {
		return nil, "", fmt.Errorf("encrypting credential request: %w", err)
	}
	return []byte(jwe), "application/jwt", nil
}

func selectCredentialRequestEncryption(metadata map[string]any) (*credentialRequestEncryptionParams, error) {
	raw, ok := metadata["credential_request_encryption"].(map[string]any)
	if !ok {
		return nil, nil
	}
	enc := firstSupportedString(raw["enc_values_supported"], preferredCredentialRequestEncryptionEncs)
	if enc == "" {
		if credentialRequestEncryptionRequired(raw) {
			return nil, fmt.Errorf("credential request encryption is required but no supported enc value was advertised")
		}
		return nil, nil
	}
	jwks, ok := raw["jwks"].(map[string]any)
	if !ok {
		if credentialRequestEncryptionRequired(raw) {
			return nil, fmt.Errorf("credential request encryption is required but jwks is missing")
		}
		return nil, nil
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		if credentialRequestEncryptionRequired(raw) {
			return nil, fmt.Errorf("credential request encryption is required but jwks.keys is missing")
		}
		return nil, nil
	}
	for _, keyRaw := range keys {
		jwk, ok := keyRaw.(map[string]any)
		if !ok {
			continue
		}
		if use, _ := jwk["use"].(string); use != "" && use != "enc" {
			continue
		}
		alg, _ := jwk["alg"].(string)
		if alg != "ECDH-ES" {
			continue
		}
		kid, _ := jwk["kid"].(string)
		if kid == "" {
			continue
		}
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		key, err := ecdsaPublicKeyFromJWK(x, y)
		if err != nil {
			continue
		}
		return &credentialRequestEncryptionParams{
			key: key,
			kid: kid,
			alg: alg,
			enc: enc,
		}, nil
	}
	if credentialRequestEncryptionRequired(raw) {
		return nil, fmt.Errorf("credential request encryption is required but no usable ECDH-ES encryption key was advertised")
	}
	return nil, nil
}

func credentialRequestEncryptionRequired(raw map[string]any) bool {
	required, _ := raw["encryption_required"].(bool)
	return required
}

// extractCredential extracts the credential string from a credential response.
// Supports both the single "credential" field and the "credentials" array format.
func extractCredential(resp map[string]any) string {
	// Single credential field (OID4VCI draft 13 and earlier)
	if c, ok := resp["credential"].(string); ok && c != "" {
		return c
	}

	// Credentials array (OID4VCI draft 14+)
	if creds, ok := resp["credentials"].([]any); ok && len(creds) > 0 {
		if entry, ok := creds[0].(map[string]any); ok {
			if c, ok := entry["credential"].(string); ok {
				return c
			}
		}
		// Array of raw strings
		if c, ok := creds[0].(string); ok {
			return c
		}
	}

	return ""
}

func parseCredentialResponseBody(body []byte, holderKey *ecdsa.PrivateKey) (map[string]any, error) {
	trimmed := strings.TrimSpace(string(body))
	var out map[string]any
	if err := json.Unmarshal([]byte(trimmed), &out); err == nil {
		return out, nil
	}
	if holderKey == nil {
		return nil, fmt.Errorf("credential response is not valid JSON")
	}
	decrypted, err := DecryptCompactJWE(trimmed, holderKey)
	if err != nil {
		return nil, fmt.Errorf("credential response is neither valid JSON nor decryptable compact JWE: %w", err)
	}
	if err := json.Unmarshal([]byte(decrypted), &out); err != nil {
		return nil, fmt.Errorf("parsing decrypted credential response JSON: %w", err)
	}
	return out, nil
}

// fetchNonce tries to obtain a c_nonce from a dedicated nonce endpoint.
// OID4VCI draft 15+ defines an optional nonce_endpoint in issuer metadata.
func fetchNonce(metadata map[string]any, issuer string) string {
	ep, ok := metadata["nonce_endpoint"].(string)
	if !ok || ep == "" {
		return ""
	}

	req, err := http.NewRequest("POST", ep, nil)
	if err != nil {
		log.Printf("[VCI] Nonce endpoint request creation failed: %v", err)
		return ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := doIssuanceRequest(req)
	if err != nil {
		log.Printf("[VCI] Nonce endpoint request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var nonceResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&nonceResp); err != nil {
		return ""
	}

	if n, ok := nonceResp["c_nonce"].(string); ok {
		log.Printf("[VCI] Got c_nonce from nonce endpoint: %s", n)
		return n
	}
	return ""
}

func credentialRequestLogDetails(endpoint, accessToken string, proofJWTs []string, credentialIdentifier, credentialConfigurationID string, credentialResponseEncryption map[string]any) map[string]any {
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
	details := map[string]any{
		"direction": "outbound",
		"method":    "POST",
		"url":       endpoint,
		"endpoint":  "credential",
		"request":   reqBody,
	}
	addStringDetail(details, "access_token", accessToken)
	if len(proofJWTs) > 0 {
		addStringDetail(details, "proof_jwt", proofJWTs[0])
	}
	addStringDetail(details, "credential_identifier", credentialIdentifier)
	addStringDetail(details, "credential_configuration_id", credentialConfigurationID)
	return details
}

func credentialResponseLogDetails(endpoint string, response map[string]any, err error) map[string]any {
	details := map[string]any{
		"direction": "inbound",
		"url":       endpoint,
		"endpoint":  "credential",
	}
	if response != nil {
		details["response"] = response
	}
	if err != nil {
		details["error"] = err.Error()
	}
	return details
}

// requestCredential sends a credential request to the issuer.
func requestCredential(
	metadata map[string]any,
	credentialEndpoint,
	accessToken string,
	proofJWTs []string,
	credentialIdentifier string,
	credentialConfigurationID string,
	credentialResponseEncryption map[string]any,
	holderKey *ecdsa.PrivateKey,
) (map[string]any, error) {
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

	reqBodyBytes, contentType, err := prepareCredentialRequestBody(metadata, reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", credentialEndpoint, strings.NewReader(string(reqBodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	// Advertise application/jwt only for encrypted responses: Keycloak 26.6's
	// credential endpoint returns signed issuer *metadata* (a JWT string) when
	// it sees application/jwt in Accept and then fails on it internally.
	if credentialResponseEncryption != nil {
		req.Header.Set("Accept", "application/json, application/jwt")
	} else {
		req.Header.Set("Accept", "application/json")
	}

	resp, err := doIssuanceRequest(req)
	if err != nil {
		return nil, fmt.Errorf("credential request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading credential response: %w", err)
	}

	credResp, err := parseCredentialResponseBody(body, holderKey)
	if err != nil {
		return nil, err
	}

	if errMsg, ok := credResp["error"].(string); ok {
		desc, _ := credResp["error_description"].(string)
		// Return the response map alongside the error so callers can extract c_nonce
		return credResp, fmt.Errorf("credential error: %s: %s", errMsg, desc)
	}

	return credResp, nil
}
