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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jwe"
)

// BuildWalletMetadata builds the wallet_metadata JSON object per OID4VP 1.0 §10.
func BuildWalletMetadata(w *Wallet) map[string]any {
	meta := map[string]any{
		// Appendix B names the members of each format profile. For dc+sd-jwt
		// they are sd-jwt_alg_values and kb-jwt_alg_values, and for mso_mdoc
		// they are issuerauth_alg_values and deviceauth_alg_values, whose
		// values are COSE algorithm identifiers rather than the JOSE names
		// used for JWTs (-7 is ECDSA with SHA-256).
		"vp_formats_supported": map[string]any{
			"dc+sd-jwt": map[string]any{
				"sd-jwt_alg_values": []string{"ES256"},
				"kb-jwt_alg_values": []string{"ES256"},
			},
			"mso_mdoc": map[string]any{
				"issuerauth_alg_values": []int{-7},
				"deviceauth_alg_values": []int{-7},
			},
		},
		// §10.1: "A non-empty array of strings containing the values of the
		// Client Identifier Prefixes that the Wallet supports ... If omitted,
		// the default value is pre-registered." A Verifier reads this to
		// choose a prefix (§5.9.1), so a wallet that says nothing is taken to
		// support only pre-registered clients and cannot be sent x509_hash.
		//
		// Only the prefixes whose requests this wallet can actually verify
		// are listed. Request Object signatures are checked against the leaf
		// of an x5c chain, so verifier_attestation and
		// decentralized_identifier, which carry their key elsewhere, would
		// name a prefix whose signature nothing here can confirm. Naming one
		// invites a Verifier to choose it and have its request refused in
		// strict mode, or accepted unverified in debug mode.
		"client_id_prefixes_supported": []string{
			"pre-registered",
			"redirect_uri",
			"x509_san_dns",
			"x509_hash",
		},
		"request_object_signing_alg_values_supported": []string{"ES256"},
	}

	if w.RequireEncryptedRequest && w.RequestEncryptionKey != nil {
		pub := &w.RequestEncryptionKey.PublicKey
		x := pub.X.Bytes()
		y := pub.Y.Bytes()
		// Pad to 32 bytes for P-256
		xPad := make([]byte, 32)
		yPad := make([]byte, 32)
		copy(xPad[32-len(x):], x)
		copy(yPad[32-len(y):], y)

		meta["jwks"] = map[string]any{
			"keys": []any{
				map[string]any{
					"kty": "EC",
					"crv": "P-256",
					"x":   format.EncodeBase64URL(xPad),
					"y":   format.EncodeBase64URL(yPad),
					"use": "enc",
					"alg": "ECDH-ES",
				},
			},
		}
		meta["authorization_encryption_alg_values_supported"] = []string{"ECDH-ES"}
		meta["authorization_encryption_enc_values_supported"] = []string{"A128GCM", "A256GCM"}
	}

	return meta
}

// GenerateWalletNonce generates a base64url-encoded 16-byte cryptographic nonce
// for replay attack mitigation per OID4VP 1.0 §5.10.
func GenerateWalletNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating wallet nonce: %w", err)
	}
	return format.EncodeBase64URL(b), nil
}

// MakeFetchRequestURI returns a FetchRequestURI callback for oid4vc.ParseOptions.
// When method is "post", it POSTs wallet_metadata and wallet_nonce to the request_uri.
// When method is "get" or empty, it performs a plain GET.
// If the response is a JWE (encrypted request object) and the wallet has an encryption key, it decrypts it.
func MakeFetchRequestURI(w *Wallet, logFn func(string, ...any)) func(url string, method string) (string, error) {
	return func(requestURI string, method string) (string, error) {
		if method == "post" {
			return fetchRequestURIPOST(w, requestURI, logFn)
		}
		return fetchRequestURIGET(w, requestURI)
	}
}

func fetchRequestURIGET(w *Wallet, requestURI string) (string, error) {
	logRequestObjectFetchRequest(w, "GET", requestURI, nil)
	resp, err := format.HTTPClientForURL(requestURI).Get(requestURI)
	if err != nil {
		logRequestObjectFetchResponse(w, "GET", requestURI, nil, err)
		return "", fmt.Errorf("fetching %s: %w", requestURI, err)
	}
	defer resp.Body.Close()

	body, readErr := format.ReadRemoteBody(resp.Body, "request object")
	details := map[string]any{
		"content_type": resp.Header.Get("Content-Type"),
	}
	if readErr == nil {
		addStringDetail(details, "response_body", strings.TrimSpace(string(body)))
	}
	logRequestObjectFetchResponse(w, "GET", requestURI, responseLogResult(resp.StatusCode, details), readErr)
	if readErr != nil {
		return "", fmt.Errorf("reading response from %s: %w", requestURI, readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching %s: HTTP %d", requestURI, resp.StatusCode)
	}
	return strings.TrimSpace(string(body)), nil
}

// fetchRequestURIPOST implements the request_uri_method=post flow per OID4VP 1.0 §5.10.
func fetchRequestURIPOST(w *Wallet, requestURI string, logFn func(string, ...any)) (string, error) {
	walletMeta := BuildWalletMetadata(w)
	walletMetaJSON, err := json.Marshal(walletMeta)
	if err != nil {
		return "", fmt.Errorf("marshaling wallet_metadata: %w", err)
	}

	walletNonce, err := GenerateWalletNonce()
	if err != nil {
		return "", err
	}

	if logFn != nil {
		logFn("  request_uri_method: post")
		logFn("  wallet_nonce:       %s", walletNonce)
		if w.RequireEncryptedRequest {
			logFn("  wallet_metadata:    includes encryption keys (require encrypted request object)")
		} else {
			logFn("  wallet_metadata:    sent (no encryption keys)")
		}
	}

	form := url.Values{}
	form.Set("wallet_metadata", string(walletMetaJSON))
	form.Set("wallet_nonce", walletNonce)

	logRequestObjectFetchRequest(w, "POST", requestURI, map[string]any{
		"wallet_metadata": walletMeta,
		"wallet_nonce":    walletNonce,
	})

	req, err := http.NewRequest("POST", requestURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/oauth-authz-req+jwt")

	resp, err := format.HTTPClientForURL(requestURI).Do(req)
	if err != nil {
		logRequestObjectFetchResponse(w, "POST", requestURI, nil, err)
		return "", fmt.Errorf("POSTing to request_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := format.ReadRemoteBody(resp.Body, "request object")
	if err != nil {
		logRequestObjectFetchResponse(w, "POST", requestURI, responseLogResult(resp.StatusCode, map[string]any{
			"content_type": resp.Header.Get("Content-Type"),
		}), err)
		return "", fmt.Errorf("reading request_uri response: %w", err)
	}
	result := strings.TrimSpace(string(body))
	logRequestObjectFetchResponse(w, "POST", requestURI, responseLogResult(resp.StatusCode, map[string]any{
		"content_type":  resp.Header.Get("Content-Type"),
		"response_body": result,
	}), nil)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST to request_uri returned HTTP %d", resp.StatusCode)
	}
	if err := validateRequestURIResponse(resp.Header.Get("Content-Type")); err != nil {
		return "", err
	}

	if !isJWT(result) && !isJWE(result) {
		return "", fmt.Errorf("request_uri response must be a compact JWT or JWE")
	}
	if w.RequireEncryptedRequest && !isJWE(result) {
		return "", fmt.Errorf("request_uri response must be a compact JWE when encrypted request objects are required")
	}

	// If response is JWE (5 parts), try to decrypt to get the JWT
	if isJWE(result) {
		if w.RequestEncryptionKey == nil {
			return "", fmt.Errorf("received encrypted request object (JWE) but wallet has no decryption key")
		}
		if logFn != nil {
			logFn("  Request object is encrypted (JWE), decrypting...")
		}
		decrypted, err := DecryptRequestObjectJWE(result, w.RequestEncryptionKey)
		if err != nil {
			return "", fmt.Errorf("decrypting request object JWE: %w", err)
		}
		result = decrypted
	}
	if !isJWT(result) {
		return "", fmt.Errorf("request_uri response did not resolve to a compact JWT")
	}

	// wallet_nonce is optional in the returned request object. If the verifier
	// echoes it back, it must match the value sent in the POST body.
	// The returned request object itself may be either signed or unsecured,
	// depending on the request_uri variant under test.
	if header, payload, _, err := format.ParseJWTParts(result); err == nil {
		if returnedNonce, ok := payload["wallet_nonce"].(string); ok {
			if returnedNonce != walletNonce {
				return "", fmt.Errorf("wallet_nonce mismatch in request object: expected %s, got %s", walletNonce, returnedNonce)
			}
			if logFn != nil {
				logFn("  wallet_nonce validated in request object")
			}
		} else if logFn != nil {
			if alg, _ := header["alg"].(string); alg != "" {
				logFn("  request object alg:      %s", alg)
			}
			logFn("  request object did not include wallet_nonce")
		}
	}

	return result, nil
}

func logRequestObjectFetchRequest(w *Wallet, method, requestURI string, details map[string]any) {
	if w == nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	details["direction"] = "outbound"
	details["method"] = method
	details["url"] = requestURI
	w.addProtocolLog("presentation", "request_object_fetch_request", fmt.Sprintf("Fetch request object %s %s", method, requestURI), true, details)
}

func logRequestObjectFetchResponse(w *Wallet, method, requestURI string, result map[string]any, err error) {
	if w == nil {
		return
	}
	details := map[string]any{
		"direction": "inbound",
		"method":    method,
		"url":       requestURI,
	}
	for key, value := range result {
		details[key] = value
	}
	if err != nil {
		details["error"] = err.Error()
	}
	success := err == nil
	if statusCode, ok := details["status_code"].(int); ok && (statusCode < 200 || statusCode >= 300) {
		success = false
	}
	w.addProtocolLog("presentation", "request_object_fetch_response", fmt.Sprintf("Request object fetch response %s %s", method, requestURI), success, details)
}

func responseLogResult(statusCode int, details map[string]any) map[string]any {
	if details == nil {
		details = map[string]any{}
	}
	details["status_code"] = statusCode
	return details
}

func validateRequestURIResponse(contentType string) error {
	if contentType == "" {
		return fmt.Errorf("request_uri response missing Content-Type application/oauth-authz-req+jwt")
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("invalid request_uri response Content-Type: %w", err)
	}
	if mediaType != "application/oauth-authz-req+jwt" {
		return fmt.Errorf("request_uri response Content-Type must be application/oauth-authz-req+jwt")
	}
	return nil
}

// isJWT checks if a string looks like a JWT (3 dot-separated parts).
func isJWT(s string) bool {
	parts := strings.SplitN(s, ".", 4)
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0
}

// isJWE checks if a string looks like a JWE compact serialization (5 dot-separated parts).
func isJWE(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 5 && len(parts[0]) > 0
}

// DecryptCompactJWE decrypts a compact JWE using the wallet's EC private key
// via ECDH-ES key agreement and returns the plaintext.
func DecryptCompactJWE(compact string, key *ecdsa.PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("decryption requires a private key")
	}
	ecdhKey, err := key.ECDH()
	if err != nil {
		return "", fmt.Errorf("converting private key to ECDH: %w", err)
	}
	plaintext, err := jwe.Decrypt(compact, ecdhKey)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(plaintext)), nil
}

// DecryptRequestObjectJWE decrypts a JWE-encrypted request object using the wallet's
// EC private key via ECDH-ES key agreement. Returns the decrypted JWT string.
func DecryptRequestObjectJWE(jwe string, key *ecdsa.PrivateKey) (string, error) {
	return DecryptCompactJWE(jwe, key)
}
