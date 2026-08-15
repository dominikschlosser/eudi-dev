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
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/validate"
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

// metadataFetchAttempts is how many times a metadata document is asked for
// before the wallet gives up on it.
//
// Metadata is read from somebody else's server at the start of every flow, and
// a single slow answer there is not evidence that the issuer cannot be talked
// to. Giving up on the first one ends the flow with a message about what the
// metadata did not contain, which points at the issuer's configuration rather
// than at the read that never completed.
const metadataFetchAttempts = 3

// metadataRetryDelay spaces the attempts out enough to outlast a moment of
// unresponsiveness without holding a flow up for long.
var metadataRetryDelay = 500 * time.Millisecond

// fetchMetadataDocument performs a metadata GET, retrying a request that could
// not be completed or that the server could not answer.
//
// Only the transport failing and the 5xx range are retried. A 404 is the
// server saying it publishes nothing there, which is an answer, and every
// other 4xx is about the request rather than the moment it was made.
func fetchMetadataDocument(newRequest func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= metadataFetchAttempts; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, err
		}
		resp, err := doIssuanceRequest(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("%s answered HTTP %d", req.URL, resp.StatusCode)
		}
		if attempt < metadataFetchAttempts {
			log.Printf("[VCI] metadata read from %s did not complete (%v), retrying", req.URL, lastErr)
			time.Sleep(metadataRetryDelay)
		}
	}
	return nil, lastErr
}

// IssuanceResult captures the result of an OID4VCI flow.
type IssuanceResult struct {
	CredentialID       string `json:"credential_id"`
	Format             string `json:"format"`
	Issuer             string `json:"issuer"`
	VerificationStatus string `json:"verification_status,omitempty"`
	VerificationDetail string `json:"verification_detail,omitempty"`
	Error              string `json:"error,omitempty"`
	// Pending marks an issuance the issuer deferred. The credential is not in
	// the wallet yet and nothing went wrong: TransactionID identifies the
	// deferred issuance and RetryInterval is how often the wallet retries it.
	Pending       bool   `json:"pending,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	RetryInterval string `json:"retry_interval,omitempty"`
	// Imported is the credential this flow stored. The server keeps it so it
	// can put the credential back if a concurrent store reload dropped it
	// before the save, which an authorization code flow invites: it stays
	// open across the user's login while the UI keeps polling.
	Imported *StoredCredential `json:"-"`
}

// ProcessCredentialOffer processes an OID4VCI credential offer URI. An offer
// delivered by reference is dereferenced here even when the consent dialog
// already fetched it once to show the user what they were approving: fetching
// a credential_offer_uri more than once is allowed, and it keeps this the
// single entry point to the flow.
func (w *Wallet) ProcessCredentialOffer(offerURI string) (*IssuanceResult, error) {
	reqType, result, err := oid4vc.Parse(offerURI)
	if err != nil {
		return nil, fmt.Errorf("parsing credential offer: %w", err)
	}
	if reqType != oid4vc.TypeVCI {
		return nil, fmt.Errorf("expected VCI credential offer, got VP")
	}
	offer, ok := result.(*oid4vc.CredentialOffer)
	if !ok {
		return nil, fmt.Errorf("unexpected credential offer type")
	}
	w.addProtocolLog("issuance", "credential_offer", fmt.Sprintf("Received credential offer from %s", offer.CredentialIssuer), true, map[string]any{
		"direction":                    "inbound",
		"offer_uri":                    offerURI,
		"issuer":                       offer.CredentialIssuer,
		"credential_configuration_ids": offer.CredentialConfigurationIDs,
		"grants":                       offer.Grants,
	})

	metadata, err := w.fetchLoggedMetadata(metadataFetch{
		event:         "issuer_metadata",
		fetchLabel:    "issuer metadata",
		responseLabel: "Issuer metadata",
		wellKnown:     "openid-credential-issuer",
		issuer:        offer.CredentialIssuer,
		fetch:         fetchIssuerMetadata,
	})
	if err != nil {
		return nil, fmt.Errorf("fetching issuer metadata: %w", err)
	}

	// A missing authorization server document is not fatal here: the
	// endpoints fall back to the issuer's own metadata below, so the error is
	// carried rather than returned.
	authServer, err := selectAuthorizationServer(metadata, offer)
	if err != nil {
		return nil, err
	}
	oauthMeta, oauthErr := w.fetchLoggedMetadata(metadataFetch{
		event:         "oauth_metadata",
		fetchLabel:    "OAuth metadata",
		responseLabel: "OAuth metadata",
		wellKnown:     "oauth-authorization-server",
		issuer:        authServer,
		fetch:         fetchOAuthMetadata,
	})
	tokenEndpoint := getTokenEndpoint(metadata, oauthMeta, offer.CredentialIssuer)
	credentialEndpoint := getCredentialEndpoint(metadata, offer.CredentialIssuer)

	// The profile decides how many checks run, the mode decides what a
	// violation does. Strict refuses the offer, debug reports every violation
	// and collects the credential anyway, which is what makes a run against a
	// counterparty that does not follow the profile worth watching.
	if w.RequireHAIP {
		if violations := ValidateHAIPIssuanceCompliance(offer, oauthMeta); len(violations) > 0 {
			detail := fmt.Sprintf("Credential offer does not follow HAIP 1.0: %s", strings.Join(violations, "; "))
			details := map[string]any{
				"issuer":     offer.CredentialIssuer,
				"violations": violations,
			}
			if w.Mode() == ValidationModeStrict {
				w.addProtocolLog("issuance", "haip_violation", detail, false, details)
				return nil, fmt.Errorf("HAIP 1.0 compliance check failed: %s", strings.Join(violations, "; "))
			}
			w.addProtocolWarning("issuance", "haip_violation", detail, details)
			for _, v := range violations {
				log.Printf("[VCI] WARNING: HAIP violation: %s", v)
			}
		}
	}

	if offer.Grants.PreAuthorizedCode == "" {
		if w.Mode() == ValidationModeStrict {
			if oauthErr != nil {
				return nil, fmt.Errorf("fetching authorization server metadata: %w", oauthErr)
			}
			if err := validateAuthorizationServerIssuer(authServer, oauthMeta); err != nil {
				return nil, err
			}
		}
		return w.processAuthorizationCodeOffer(offer, metadata, oauthMeta, tokenEndpoint, credentialEndpoint)
	}

	// Token exchange (pre-authorized code flow).
	//
	// An issuer may protect this flow like the authorization code flow:
	// DPoP-bound tokens (RFC 9449), client authentication by wallet attestation
	// (OAuth 2.0 Attestation-Based Client Authentication), and key attestation
	// in the proof. Each follows the issuer's metadata, so an issuer that asks
	// for none of them sees the same plain request as before.
	nonces := &dpopNonceState{}
	var dpopKey *ecdsa.PrivateKey
	if supportsDPoP(oauthMeta) {
		dpopKey = w.HolderKey
	}
	// A pre-authorized offer carries no client_id, and the wallet is not
	// registered with the issuer. The attestation names the wallet itself, so
	// its own identifier is the subject.
	attestationClientID := strings.TrimSpace(w.VCIClientID)
	if attestationClientID == "" {
		attestationClientID = strings.TrimSpace(w.BaseURL)
	}
	authCtx := clientAuthContext{oauthMeta: oauthMeta, clientID: attestationClientID, tokenEndpoint: tokenEndpoint}
	clientAuth := w.resolveClientAuthentication("", authCtx)

	w.mu.Lock()
	txCode := w.TxCode
	w.TxCode = "" // clear after use
	w.mu.Unlock()
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	tokenForm.Set("pre-authorized_code", offer.Grants.PreAuthorizedCode)
	if txCode != "" {
		tokenForm.Set("tx_code", txCode)
	}
	w.addProtocolLog("issuance", "token_request", fmt.Sprintf("Request token from %s", tokenEndpoint), true, map[string]any{
		"direction":           "outbound",
		"method":              "POST",
		"url":                 tokenEndpoint,
		"endpoint":            "token",
		"grant_type":          "urn:ietf:params:oauth:grant-type:pre-authorized_code",
		"pre-authorized_code": offer.Grants.PreAuthorizedCode,
		"tx_code":             txCode,
	})
	tokenResp, err := postFormWithDPoP(tokenEndpoint, tokenForm, dpopKey, "", &nonces.authzServer, w.clientAttestationHeaders(clientAuth))
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
	refreshToken, expiresIn := tokenGrantRenewal(tokenResp)
	authScheme := accessTokenScheme(tokenResp, dpopKey != nil)

	cNonce := w.issuanceChallenge(metadata, tokenResp, offer.CredentialIssuer, &nonces.resource)

	log.Printf("[VCI] Token endpoint: %s", tokenEndpoint)
	log.Printf("[VCI] Credential endpoint: %s", credentialEndpoint)
	log.Printf("[VCI] c_nonce: %q", cNonce)
	if tokenJSON, err := json.MarshalIndent(tokenResp, "", "  "); err == nil {
		log.Printf("[VCI] Token response:\n%s", tokenJSON)
	}

	// Create proof of possession JWTs (multiple when the issuer advertises
	// batch credential issuance)
	configID := ""
	if len(offer.CredentialConfigurationIDs) > 0 {
		configID = offer.CredentialConfigurationIDs[0]
	}
	proofKeys, err := issuanceProofKeys(w.HolderKey, metadata, configID)
	if err != nil {
		return nil, fmt.Errorf("preparing proof keys: %w", err)
	}

	// Request credential
	credFormat := ""
	if configID != "" {
		credFormat = resolveCredentialFormat(metadata, configID)
	}
	responseEncryption, err := buildCredentialResponseEncryptionRequest(w.Mode(), metadata, w.HolderKey)
	if err != nil {
		return nil, err
	}

	// Extract credential_identifiers from authorization_details in token response
	credentialIdentifier := resolveCredentialIdentifier(tokenResp, offer.CredentialConfigurationIDs)
	credentialConfigurationID := ""
	if credentialIdentifier == "" && len(offer.CredentialConfigurationIDs) > 0 {
		credentialConfigurationID = offer.CredentialConfigurationIDs[0]
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
	log.Printf("[VCI] Proof JWT: %s", proofJWTs[0])

	credResp, err := w.requestCredentialWithNonceRetry(attempt, proofJWTs)
	if err != nil {
		return nil, fmt.Errorf("requesting credential: %w", err)
	}

	if credJSON, err := json.MarshalIndent(credResp, "", "  "); err == nil {
		log.Printf("[VCI] Credential response:\n%s", credJSON)
	}

	credResp, pending, err := w.resolveDeferredCredential(credResp, deferredContext{
		metadata:      metadata,
		tokenEndpoint: tokenEndpoint,
		clientID:      "",
		clientAuth:    clientAuth,
		refreshToken:  refreshToken,
		expiresIn:     expiresIn,
		issuer:        offer.CredentialIssuer,
		configID:      configID,
		format:        credFormat,
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

	// The profile decides whether this runs, the mode decides what it does,
	// as with the offer above. A credential whose issuer the certificate does
	// not name is one a verifier holding the issuer to HAIP will refuse, so
	// saying so here is what turns a rejection later into a finding now.
	if w.RequireHAIP {
		if violations := w.haipCredentialIssuerViolations(credential); len(violations) > 0 {
			detail := fmt.Sprintf("Credential does not follow HAIP 1.0: %s", strings.Join(violations, "; "))
			details := map[string]any{
				"issuer":     offer.CredentialIssuer,
				"violations": violations,
			}
			if w.Mode() == ValidationModeStrict {
				w.addProtocolLog("issuance", "haip_violation", detail, false, details)
				return nil, fmt.Errorf("HAIP 1.0 compliance check failed: %s", strings.Join(violations, "; "))
			}
			w.addProtocolWarning("issuance", "haip_violation", detail, details)
			for _, v := range violations {
				log.Printf("[VCI] WARNING: HAIP violation: %s", v)
			}
		}
	}

	// Import the received credential
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
		UseDPoP:            dpopKey != nil,
		ClientAuth:         clientAuth,
	})

	if err := w.notifyCredentialAccepted(metadata, credResp, accessToken, authScheme, dpopKey, &nonces.resource); err != nil {
		return nil, err
	}

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

// metadataFetch describes one well-known metadata document to fetch and how
// to name it in the activity log.
type metadataFetch struct {
	event         string // log event prefix, e.g. "issuer_metadata"
	fetchLabel    string // reads as "Fetch <fetchLabel> from <issuer>"
	responseLabel string // reads as "<responseLabel> response from <issuer>"
	wellKnown     string // the .well-known suffix, for the logged URL
	issuer        string
	fetch         func(string) (map[string]any, error)
}

// fetchLoggedMetadata fetches a metadata document and records the request and
// whichever response it produced.
//
// Both callers wrote this out inline, twenty lines each of the same three
// log calls with the details map spelled out per branch, which is how a field
// comes to be recorded on one fetch and not the other. The error is returned
// rather than acted on: one caller gives up on it and the other carries on
// with what the issuer's own metadata says.
func (w *Wallet) fetchLoggedMetadata(f metadataFetch) (map[string]any, error) {
	url, _ := wellKnownURL(f.issuer, f.wellKnown)
	w.addProtocolLog("issuance", f.event+"_request", fmt.Sprintf("Fetch %s from %s", f.fetchLabel, f.issuer), true, map[string]any{
		"direction": "outbound",
		"method":    "GET",
		"url":       url,
		"issuer":    f.issuer,
	})

	metadata, err := f.fetch(f.issuer)

	details := map[string]any{
		"direction": "inbound",
		"url":       url,
		"issuer":    f.issuer,
	}
	if err != nil {
		details["error"] = err.Error()
	} else {
		details["metadata"] = metadata
	}
	w.addProtocolLog("issuance", f.event+"_response", fmt.Sprintf("%s response from %s", f.responseLabel, f.issuer), err == nil, details)

	return metadata, err
}

// fetchIssuerMetadata fetches the OpenID Credential Issuer metadata.
func fetchIssuerMetadata(issuer string) (map[string]any, error) {
	metadataURL, err := wellKnownURL(issuer, "openid-credential-issuer")
	if err != nil {
		return nil, fmt.Errorf("building issuer metadata URL: %w", err)
	}

	resp, err := fetchMetadataDocument(func() (*http.Request, error) {
		req, err := http.NewRequest("GET", metadataURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating metadata request: %w", err)
		}
		// OpenID4VCI 1.0 §12.2.2 gives the issuer two forms to answer in: "an
		// unsigned JSON document using the media type application/json, or a
		// signed JSON Web Token (JWT) containing the Credential Issuer Metadata
		// in its payload using the media type application/jwt". Naming both
		// signals that signed metadata is supported. There is no
		// application/openidvci-issuer-metadata+jwt media type: that string is
		// the typ header value of the signed form (§12.2.3).
		req.Header.Set("Accept", "application/json, application/jwt")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("fetching metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := format.ReadRemoteBody(resp.Body, "issuer response")
		return nil, fmt.Errorf("metadata request failed (%d): %s", resp.StatusCode, string(body))
	}

	body, err := format.ReadRemoteBody(resp.Body, "issuer response")
	if err != nil {
		return nil, fmt.Errorf("reading metadata: %w", err)
	}
	return parseIssuerMetadataResponse(body, resp.Header.Get("Content-Type"), issuer)
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

// parseIssuerMetadataResponse decodes a Credential Issuer Metadata response in
// either of the two forms §12.2.2 allows. issuer is the Credential Issuer
// Identifier the metadata URL was built from, which both the signature check
// and the identity check below are made against.
func parseIssuerMetadataResponse(body []byte, contentType, issuer string) (map[string]any, error) {
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil, fmt.Errorf("issuer metadata response was empty")
	}

	var metadata map[string]any
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if mediaType == "application/jwt" || strings.Contains(mediaType, "openidvci-issuer-metadata+jwt") || isLikelyCompactJWT(raw) {
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing signed issuer metadata: %w", err)
		}
		if err := verifySignedIssuerMetadata(token, issuer); err != nil {
			return nil, err
		}
		metadata = token.Payload
	} else if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("parsing metadata JSON: %w", err)
	}

	if err := checkCredentialIssuerIdentifier(metadata, issuer); err != nil {
		return nil, err
	}
	return metadata, nil
}

// checkCredentialIssuerIdentifier holds the metadata to the identifier it was
// fetched for.
//
// OpenID4VCI 1.0 §12.2.4 on credential_issuer: "The value MUST be identical to
// the Credential Issuer's identifier value into which the well-known URI string
// was inserted to create the URL used to retrieve the metadata. If these values
// are not identical (when compared using a simple string comparison with no
// normalization), the data contained in the response MUST NOT be used."
func checkCredentialIssuerIdentifier(metadata map[string]any, issuer string) error {
	declared, _ := metadata["credential_issuer"].(string)
	if declared == issuer {
		return nil
	}
	if declared == "" {
		return fmt.Errorf("issuer metadata for %q carries no credential_issuer identifier", issuer)
	}
	return fmt.Errorf("issuer metadata declares credential_issuer %q but was fetched for %q, so it cannot be used", declared, issuer)
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

// issuerMetadataTrustAnchors are the roots a signed Credential Issuer Metadata
// certificate chain has to end in. nil selects the host's own root store, which
// is what a wallet with no separately provisioned anchors has to go on. Tests
// point it at the certificate authority they signed with.
var issuerMetadataTrustAnchors *x509.CertPool

// signedIssuerMetadataTyp is the typ header value §12.2.3 requires on signed
// Credential Issuer Metadata. It is a JWT type, not a media type.
const signedIssuerMetadataTyp = "openidvci-issuer-metadata+jwt"

// verifySignedIssuerMetadata checks signed Credential Issuer Metadata against
// §12.2.3 before any of it is read.
//
// The section requires typ to be openidvci-issuer-metadata+jwt, an alg that is
// neither none nor a symmetric algorithm, and a sub "matching the Credential
// Issuer Identifier". It also requires more than a valid signature: "When
// requesting signed metadata, the Wallet MUST establish trust in the signer of
// the metadata. Otherwise, the Wallet MUST reject the signed metadata." The
// mechanism is out of scope of the specification, so this wallet takes the one
// the header can carry: an x5c chain ending in a trusted root.
//
// Rejecting a signer it cannot place would make every ecosystem issuer
// unreachable: an issuer CA is not a WebPKI root, and this wallet has no way to
// be given one. A check that nothing can satisfy is not enforcement, so the
// signer that anchors nowhere is named in the log and the metadata is read.
// That is no weaker than the unsigned form the same issuer serves on request,
// which carries no signature at all. What the wallet can check without being
// given anything is enforced: the typ, an asymmetric alg, a sub matching the
// Credential Issuer Identifier, and the signature itself.
func verifySignedIssuerMetadata(token *sdjwt.Token, issuer string) error {
	if token == nil {
		return fmt.Errorf("signed issuer metadata token is nil")
	}
	if typ, _ := token.Header["typ"].(string); typ != signedIssuerMetadataTyp {
		return fmt.Errorf("signed issuer metadata has typ %q, want %q", typ, signedIssuerMetadataTyp)
	}
	alg, _ := token.Header["alg"].(string)
	if alg == "" || strings.EqualFold(alg, "none") || strings.HasPrefix(strings.ToUpper(alg), "HS") {
		return fmt.Errorf("signed issuer metadata alg %q is not an asymmetric digital signature algorithm", alg)
	}
	sub, _ := token.Payload["sub"].(string)
	if sub != issuer {
		return fmt.Errorf("signed issuer metadata sub %q does not match the credential issuer identifier %q", sub, issuer)
	}

	certs, err := signedIssuerMetadataChain(token)
	if err != nil {
		return err
	}
	result := sdjwt.Verify(token, certs[0].PublicKey)
	if result == nil || !result.SignatureValid {
		return fmt.Errorf("issuer metadata signature is invalid")
	}
	if err := verifyIssuerMetadataChainTrust(certs); err != nil {
		log.Printf("[VCI] signed issuer metadata signer could not be anchored (%v); the wallet holds no issuer trust anchors, so the metadata is read as signed but unplaced", err)
	}
	return nil
}

// signedIssuerMetadataChain returns the certificates of a signed metadata x5c
// chain, leaf first.
func signedIssuerMetadataChain(token *sdjwt.Token) ([]*x509.Certificate, error) {
	x5cRaw, ok := token.Header["x5c"]
	if !ok {
		return nil, fmt.Errorf("signed issuer metadata carries no x5c, so its signer cannot be trusted")
	}
	entries, err := normalizeMetadataX5CEntries(x5cRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer metadata x5c: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("signed issuer metadata x5c is empty, so its signer cannot be trusted")
	}
	certs := make([]*x509.Certificate, 0, len(entries))
	for i, entry := range entries {
		der, err := format.DecodeBase64Std(entry)
		if err != nil {
			return nil, fmt.Errorf("decoding issuer metadata x5c entry %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing issuer metadata x5c entry %d: %w", i, err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// verifyIssuerMetadataChainTrust reports whether a signed metadata chain ends
// in one of the anchors the wallet holds. issuerMetadataTrustAnchors is nil in
// normal operation, which selects the host's root store.
func verifyIssuerMetadataChainTrust(certs []*x509.Certificate) error {
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         issuerMetadataTrustAnchors,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
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
	servers := authorizationServersFromMetadata(metadata)
	if len(servers) == 0 {
		return issuer
	}
	return servers[0]
}

// authorizationServersFromMetadata lists the authorization_servers entries of
// the Credential Issuer Metadata. §12.2.4 makes the parameter optional: "If
// this parameter is omitted, the entity providing the Credential Issuer is also
// acting as the Authorization Server".
func authorizationServersFromMetadata(metadata map[string]any) []string {
	raw, ok := metadata["authorization_servers"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		if s, _ := entry.(string); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// offerAuthorizationServer reads the authorization_server hint the offer's
// grant may carry. §12.2.4 defines it as "OPTIONAL string that the Wallet can
// use to identify the Authorization Server to use with this grant type when
// authorization_servers parameter in the Credential Issuer metadata has
// multiple entries."
func offerAuthorizationServer(offer *oid4vc.CredentialOffer) string {
	if offer == nil {
		return ""
	}
	grants, ok := offer.FullJSON["grants"].(map[string]any)
	if !ok {
		return ""
	}
	for _, grantType := range []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code", "authorization_code"} {
		grant, ok := grants[grantType].(map[string]any)
		if !ok {
			continue
		}
		if server, _ := grant["authorization_server"].(string); server != "" {
			return server
		}
	}
	return ""
}

// selectAuthorizationServer picks the authorization server this offer is to be
// redeemed at.
//
// §12.2.4: "When the Wallet is using authorization_server parameter in the
// Credential Offer as a hint to determine which Authorization Server to use out
// of multiple, the Wallet MUST NOT proceed with the flow if the
// authorization_server Credential Offer parameter value does not match any of
// the entries in the authorization_servers array." A hint that matches nothing
// is therefore an error rather than something to fall back from: the issuer
// named a server this metadata does not vouch for.
func selectAuthorizationServer(metadata map[string]any, offer *oid4vc.CredentialOffer) (string, error) {
	servers := authorizationServersFromMetadata(metadata)
	hint := offerAuthorizationServer(offer)
	issuer := ""
	if offer != nil {
		issuer = offer.CredentialIssuer
	}
	if hint == "" {
		if len(servers) == 0 {
			return issuer, nil
		}
		return servers[0], nil
	}
	for _, candidate := range servers {
		if candidate == hint {
			return hint, nil
		}
	}
	return "", fmt.Errorf("credential offer names authorization server %q, which the issuer metadata of %s does not list", hint, issuer)
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

// getTokenEndpoint resolves the token endpoint of the authorization server.
//
// token_endpoint is an authorization server metadata parameter (RFC 8414 §2),
// and OpenID4VCI 1.0 §12.2.4 defines no such Credential Issuer Metadata
// parameter, so the authorization server document is what decides. An issuer
// that publishes one in its own metadata anyway is read only when no
// authorization server metadata was reachable, which is the case the URL guess
// below also covers.
func getTokenEndpoint(metadata map[string]any, oauthMeta map[string]any, issuer string) string {
	if ep, ok := oauthMeta["token_endpoint"].(string); ok && ep != "" {
		return ep
	}
	if ep, ok := metadata["token_endpoint"].(string); ok && ep != "" {
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
		resp, err := fetchMetadataDocument(func() (*http.Request, error) {
			req, err := http.NewRequest("GET", u, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/json")
			return req, nil
		})
		if err != nil {
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
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	// The nonce claim echoes a c_nonce the issuer provided. An issuer that
	// provided none expects the claim to be absent, and an empty string is not
	// the same thing: it reads as a nonce that does not match.
	if cNonce != "" {
		payload["nonce"] = cNonce
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

// buildCredentialResponseEncryptionRequest builds the
// credential_response_encryption object of §8.2, or nil when the wallet must
// not ask for an encrypted response.
//
// The parameter never travels on its own: §8.2 says "Credential Request
// encryption MUST be used if the credential_response_encryption parameter is
// included, to prevent it being substituted by an attacker." An issuer that
// offers no usable request encryption key therefore gets no encryption request
// either, and one that requires an encrypted response while offering no way to
// encrypt the request cannot be satisfied at all.
func buildCredentialResponseEncryptionRequest(mode ValidationMode, metadata map[string]any, holderKey *ecdsa.PrivateKey) (map[string]any, error) {
	if holderKey == nil {
		return nil, nil
	}
	raw, ok := metadata["credential_response_encryption"].(map[string]any)
	if !ok {
		return nil, nil
	}
	required, _ := raw["encryption_required"].(bool)

	alg := firstSupportedString(raw["alg_values_supported"], preferredCredentialResponseEncryptionAlgs)
	enc := firstSupportedString(raw["enc_values_supported"], preferredCredentialResponseEncryptionEncs)
	if alg == "" || enc == "" {
		if required {
			return nil, fmt.Errorf("issuer requires an encrypted credential response but advertised no alg or enc value the wallet supports")
		}
		return nil, nil
	}

	requestEncryption, err := selectCredentialRequestEncryption(mode, metadata)
	if err != nil {
		return nil, err
	}
	if requestEncryption == nil {
		if required {
			return nil, fmt.Errorf("issuer requires an encrypted credential response but published no usable credential_request_encryption key, and the credential request must be encrypted whenever credential_response_encryption is sent")
		}
		log.Printf("[VCI] Not requesting credential response encryption: the credential request itself cannot be encrypted")
		return nil, nil
	}

	return map[string]any{
		"jwk": publicCredentialResponseEncryptionJWK(&holderKey.PublicKey, alg),
		"enc": enc,
	}, nil
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

func prepareCredentialRequestBody(mode ValidationMode, metadata map[string]any, reqBody map[string]any) ([]byte, string, error) {
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling request: %w", err)
	}
	encryption, err := selectCredentialRequestEncryption(mode, metadata)
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

func selectCredentialRequestEncryption(mode ValidationMode, metadata map[string]any) (*credentialRequestEncryptionParams, error) {
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
		key, finding, err := ecdsaPublicKeyFromJWK(mode, x, y)
		if err != nil {
			continue
		}
		// Debug mode read past a specification violation to get here. No
		// wallet is in scope this deep to reach the activity log, so it goes
		// where the rest of this flow's diagnostics go.
		if finding != "" {
			log.Printf("[VCI] WARNING: %s", finding)
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

// issuanceChallenge obtains the c_nonce the key proofs of this flow are signed
// over.
//
// §8.2 leaves one source: "The c_nonce value is retrieved from the Nonce
// Endpoint as defined in Section 7." A c_nonce in the token response is a
// pre-1.0 issuer showing through, and a wallet that reads it signs its proof
// over a challenge the specification does not define. Strict mode therefore
// ignores it outright, and debug mode says whose issuer is behind the times
// before using it, because being able to complete the flow is what the mode is
// for.
func (w *Wallet) issuanceChallenge(metadata, tokenResp map[string]any, issuer string, dpopNonce *string) string {
	if cNonce := fetchNonce(metadata, dpopNonce); cNonce != "" {
		return cNonce
	}
	cNonce, _ := tokenResp["c_nonce"].(string)
	if cNonce == "" {
		return ""
	}
	if w.Mode() == ValidationModeStrict {
		log.Printf("[VCI] WARNING: ignoring the c_nonce in the token response of %s: OpenID4VCI 1.0 defines the Nonce Endpoint as its only source", issuer)
		w.AddWarning("issuance", fmt.Sprintf("Ignored the c_nonce %s returned in its token response: OpenID4VCI 1.0 has no such parameter and defines the Nonce Endpoint as the only source of a challenge", issuer), nil)
		return ""
	}
	log.Printf("[VCI] WARNING: %s returned a c_nonce in its token response, which OpenID4VCI 1.0 does not define; this issuer is pre-1.0", issuer)
	w.AddWarning("issuance", fmt.Sprintf("Using the c_nonce %s returned in its token response: OpenID4VCI 1.0 defines no such parameter, so this issuer is pre-1.0. Strict mode refuses it", issuer), nil)
	return cNonce
}

// credentialRequestAttempt is one credential request in every detail it takes
// to send it again. §8.3.1.2 answers a stale challenge with invalid_nonce and
// expects another attempt, and the retry has to reproduce the request down to
// the proof keys it is bound to.
type credentialRequestAttempt struct {
	metadata                  map[string]any
	endpoint                  string
	issuer                    string
	configID                  string
	accessToken               string
	authScheme                string
	credentialIdentifier      string
	credentialConfigurationID string
	responseEncryption        map[string]any
	dpopKey                   *ecdsa.PrivateKey
	proofKeys                 []*ecdsa.PrivateKey
	// nonce is the DPoP nonce state of the resource server, not the c_nonce.
	nonce *string
}

// buildCredentialProofs signs one key proof per proof key over one challenge. A
// key attestation covers the challenge too, so the header is rebuilt with them.
func (w *Wallet) buildCredentialProofs(a credentialRequestAttempt, cNonce string) ([]string, error) {
	header, err := createCredentialProofHeader(w, a.metadata, a.configID, cNonce, a.proofKeys)
	if err != nil {
		return nil, fmt.Errorf("building credential proof header: %w", err)
	}
	proofs, err := createProofJWTs(a.proofKeys, a.issuer, cNonce, header)
	if err != nil {
		return nil, fmt.Errorf("creating proof JWT: %w", err)
	}
	return proofs, nil
}

// requestCredentialWithNonceRetry sends a credential request and, when the
// issuer says the challenge was no good, fetches a fresh one and sends it once
// more.
//
// §8.3.1.2 on invalid_nonce: "The proofs parameter in the Credential Request
// uses an invalid nonce: at least one of the key proofs contains an invalid
// c_nonce value. The wallet should retrieve a new c_nonce value (refer to
// Section 7)." One retry: a second rejection of a challenge the issuer just
// handed out is the issuer disagreeing with itself, and asking again would loop.
func (w *Wallet) requestCredentialWithNonceRetry(a credentialRequestAttempt, proofJWTs []string) (map[string]any, error) {
	credResp, err := w.sendCredentialRequest(a, proofJWTs)
	if err == nil || !isInvalidNonceError(err) {
		return credResp, err
	}
	cNonce := fetchNonce(a.metadata, a.nonce)
	if cNonce == "" {
		return nil, err
	}
	retryProofs, buildErr := w.buildCredentialProofs(a, cNonce)
	if buildErr != nil {
		return nil, buildErr
	}
	log.Printf("[VCI] Issuer rejected the proof nonce, retrying once with a fresh nonce from the Nonce Endpoint")
	return w.sendCredentialRequest(a, retryProofs)
}

func (w *Wallet) sendCredentialRequest(a credentialRequestAttempt, proofJWTs []string) (map[string]any, error) {
	w.addProtocolLog("issuance", "credential_request", fmt.Sprintf("Request credential from %s", a.endpoint), true,
		credentialRequestLogDetails(a.endpoint, a.accessToken, proofJWTs, a.credentialIdentifier, a.credentialConfigurationID, a.responseEncryption))
	credResp, err := requestCredentialWithDPoP(
		w.Mode(),
		a.metadata,
		a.endpoint,
		a.accessToken,
		a.authScheme,
		proofJWTs,
		a.credentialIdentifier,
		a.credentialConfigurationID,
		a.responseEncryption,
		a.dpopKey,
		w.HolderKey,
		a.nonce,
	)
	w.addProtocolLog("issuance", "credential_response", fmt.Sprintf("Credential response from %s", a.endpoint), err == nil,
		credentialResponseLogDetails(a.endpoint, credResp, err))
	return credResp, err
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
