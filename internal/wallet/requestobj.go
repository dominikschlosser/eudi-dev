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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

// BuildWalletMetadata builds the wallet_metadata JSON object per OID4VP 1.0 §10.
func BuildWalletMetadata(w *Wallet) map[string]any {
	meta := map[string]any{
		"vp_formats_supported": map[string]any{
			"dc+sd-jwt": map[string]any{
				"alg_values_supported": []string{"ES256"},
			},
			"mso_mdoc": map[string]any{
				"alg_values_supported": []int{-7},
			},
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

	body, readErr := io.ReadAll(resp.Body)
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

	body, err := io.ReadAll(resp.Body)
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
func DecryptCompactJWE(jwe string, key *ecdsa.PrivateKey) (string, error) {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return "", fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}

	// Parse protected header
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return "", fmt.Errorf("decoding JWE header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("parsing JWE header: %w", err)
	}

	enc, _ := header["enc"].(string)
	if enc == "" {
		return "", fmt.Errorf("missing enc in JWE header")
	}

	// Parse ephemeral public key from header
	epkMap, ok := header["epk"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("missing epk in JWE header")
	}

	epkPub, err := parseECPublicKeyFromEPK(epkMap)
	if err != nil {
		return "", fmt.Errorf("parsing epk: %w", err)
	}

	// Convert our ECDSA private key to ECDH
	ecdhPriv, err := key.ECDH()
	if err != nil {
		return "", fmt.Errorf("converting private key to ECDH: %w", err)
	}

	// ECDH key agreement
	z, err := ecdhPriv.ECDH(epkPub)
	if err != nil {
		return "", fmt.Errorf("ECDH key agreement: %w", err)
	}

	// Decode apu/apv from header
	var apu, apv []byte
	if apuB64, ok := header["apu"].(string); ok {
		apu, _ = format.DecodeBase64URL(apuB64)
	}
	if apvB64, ok := header["apv"].(string); ok {
		apv, _ = format.DecodeBase64URL(apvB64)
	}

	// Derive CEK via Concat KDF (reuse the wallet's existing concatKDF)
	keyBitLen, err := encKeyBitLen(enc)
	if err != nil {
		return "", err
	}
	cek := concatKDF(z, enc, apu, apv, keyBitLen)

	// Decrypt
	ivBytes, err := format.DecodeBase64URL(parts[2])
	if err != nil {
		return "", fmt.Errorf("decoding IV: %w", err)
	}
	ciphertext, err := format.DecodeBase64URL(parts[3])
	if err != nil {
		return "", fmt.Errorf("decoding ciphertext: %w", err)
	}
	tag, err := format.DecodeBase64URL(parts[4])
	if err != nil {
		return "", fmt.Errorf("decoding tag: %w", err)
	}

	var plaintext []byte
	switch enc {
	case "A128GCM", "A256GCM":
		plaintext, err = decryptAESGCM(cek, ivBytes, ciphertext, tag, []byte(parts[0]))
	default:
		return "", fmt.Errorf("unsupported enc algorithm for request object: %s", enc)
	}
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

// parseECPublicKeyFromEPK parses an EC public key from a JWK map (epk field).
func parseECPublicKeyFromEPK(m map[string]any) (*ecdh.PublicKey, error) {
	crv, _ := m["crv"].(string)
	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}
	xB64, _ := m["x"].(string)
	yB64, _ := m["y"].(string)
	if xB64 == "" || yB64 == "" {
		return nil, fmt.Errorf("missing x or y coordinate")
	}

	xBytes, err := format.DecodeBase64URL(xB64)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	yBytes, err := format.DecodeBase64URL(yB64)
	if err != nil {
		return nil, fmt.Errorf("decoding y: %w", err)
	}

	pub := make([]byte, 1+32+32)
	pub[0] = 0x04
	copy(pub[1:33], padTo32(xBytes))
	copy(pub[33:65], padTo32(yBytes))

	return ecdh.P256().NewPublicKey(pub)
}

// padTo32 left-pads b with zeros to 32 bytes (P-256 coordinate size).
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// decryptAESGCM decrypts with AES-GCM.
func decryptAESGCM(key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	sealed := append(ciphertext, tag...)
	return aead.Open(nil, iv, sealed, aad)
}
