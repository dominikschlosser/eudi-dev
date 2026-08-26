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
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"

	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// extractJWKThumbprint extracts the encryption JWK from the request object
// and computes its RFC 7638 thumbprint (SHA-256).
// Returns nil if no encryption key is found.
func extractJWKThumbprint(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) []byte {
	jwk := findEncryptionJWK(reqObj, clientMetadata)
	if jwk == nil {
		return nil
	}
	return computeJWKThumbprint(jwk)
}

// findEncryptionJWK locates the first encryption JWK from client_metadata.jwks
// per OID4VP 1.0. No fallback to other locations. The wallet enforces strict
// spec compliance so verifiers can detect misconfigurations.
func findEncryptionJWK(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) map[string]any {
	return firstJWK(encryptionJWKS(reqObj, clientMetadata))
}

// encryptionJWKS returns the verifier's jwks value, preferring the request
// object's client_metadata when it carries one.
func encryptionJWKS(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) any {
	if reqObj != nil && reqObj.Payload != nil {
		if clientMeta, ok := reqObj.Payload["client_metadata"].(map[string]any); ok {
			return clientMeta["jwks"]
		}
	}
	if clientMetadata != nil {
		return clientMetadata["jwks"]
	}
	return nil
}

// firstSigningOnlyEncryptionJWK returns the first key marked "use":"sig" whose
// material the wallet could still encrypt to. It is the debug-mode fallback when
// the verifier published no encryption-marked key at all.
func firstSigningOnlyEncryptionJWK(jwksVal any) map[string]any {
	jwks, ok := jwksVal.(map[string]any)
	if !ok {
		return nil
	}
	keysSlice, ok := jwks["keys"].([]any)
	if !ok {
		return nil
	}
	for _, entry := range keysSlice {
		jwk, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if use, _ := jwk["use"].(string); use == "sig" && encryptableKeyMaterial(jwk) {
			return jwk
		}
	}
	return nil
}

// firstJWK extracts the first usable encryption key from a JWKS value
// ({"keys": [...]}). Keys the wallet cannot use (unsupported kty, unsupported
// curve, or a signing-only use) are ignored per RFC 7517 §5, so verifiers can
// advertise e.g. post-quantum keys ahead of wallet support without breaking
// encryption to the usable key.
func firstJWK(jwksVal any) map[string]any {
	jwks, ok := jwksVal.(map[string]any)
	if !ok {
		return nil
	}
	keysSlice, ok := jwks["keys"].([]any)
	if !ok || len(keysSlice) == 0 {
		return nil
	}
	// Prefer an EC key: ECDH-ES on P-256 is the OID4VP baseline and the only
	// option HAIP allows, so it is chosen over an RSA key when the verifier
	// offers both. A usable RSA-OAEP key is the fallback when it is all there is.
	var fallback map[string]any
	for _, entry := range keysSlice {
		jwk, ok := entry.(map[string]any)
		if !ok || !usableEncryptionJWK(jwk) {
			continue
		}
		if kty, _ := jwk["kty"].(string); kty == "EC" {
			return jwk
		}
		if fallback == nil {
			fallback = jwk
		}
	}
	return fallback
}

// usableEncryptionJWK reports whether the wallet can encrypt to the given JWK:
// an EC key on P-256 (ECDH-ES) or an RSA key (RSA-OAEP), not marked signing-only.
func usableEncryptionJWK(jwk map[string]any) bool {
	if use, ok := jwk["use"].(string); ok && use != "enc" {
		return false
	}
	return encryptableKeyMaterial(jwk)
}

// encryptableKeyMaterial reports whether a JWK holds a key the wallet can
// encrypt to (an EC key on P-256, or an RSA key), ignoring its declared use.
func encryptableKeyMaterial(jwk map[string]any) bool {
	switch kty, _ := jwk["kty"].(string); kty {
	case "EC":
		if crv, ok := jwk["crv"].(string); ok && crv != "P-256" {
			return false
		}
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		return x != "" && y != ""
	case "RSA":
		n, _ := jwk["n"].(string)
		e, _ := jwk["e"].(string)
		return n != "" && e != ""
	default:
		return false
	}
}

// computeJWKThumbprint computes the RFC 7638 JWK Thumbprint using SHA-256.
// For EC keys, the required members in lexicographic order are: crv, kty, x, y.
// For RSA keys: e, kty, n.
func computeJWKThumbprint(jwk map[string]any) []byte {
	kty, _ := jwk["kty"].(string)

	var canonical map[string]string
	switch kty {
	case "EC":
		crv, _ := jwk["crv"].(string)
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		if crv == "" || x == "" || y == "" {
			return nil
		}
		canonical = map[string]string{"crv": crv, "kty": kty, "x": x, "y": y}
	case "RSA":
		e, _ := jwk["e"].(string)
		n, _ := jwk["n"].(string)
		if e == "" || n == "" {
			return nil
		}
		canonical = map[string]string{"e": e, "kty": kty, "n": n}
	default:
		return nil
	}

	// RFC 7638: JSON must have members in lexicographic order, no whitespace
	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		return nil
	}

	hash := sha256.Sum256(canonicalJSON)
	return hash[:]
}

// encryptionKeyInfo holds the extracted encryption key parameters from a JWK.
// Exactly one of Key (ECDH-ES) or RSAKey (RSA-OAEP) is set.
type encryptionKeyInfo struct {
	Key    *ecdsa.PublicKey
	RSAKey *rsa.PublicKey
	Kid    string
	Alg    string // JWE algorithm (e.g. "ECDH-ES" or "RSA-OAEP") — MUST be present per OID4VP 1.0
	// Finding records a specification violation the debug path read past.
	// Strict mode never produces one: it refuses the document instead.
	Finding string
}

// extractEncryptionKey reads the verifier's public key, kid, and alg from
// client_metadata.jwks per OID4VP 1.0. An EC key is used with ECDH-ES, an RSA
// key with RSA-OAEP. ECDH-ES on P-256 is the OID4VP baseline (and the only key
// HAIP allows), so findEncryptionJWK prefers it when the verifier offers both.
func extractEncryptionKey(mode ValidationMode, reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) (*encryptionKeyInfo, error) {
	jwk := findEncryptionJWK(reqObj, clientMetadata)
	selectionFinding := ""
	if jwk == nil && mode == ValidationModeDebug {
		// The verifier published no encryption-marked key. Debug answers where it
		// can, so a signing-marked key of a usable type is encrypted to anyway,
		// with a finding: a direct_post.jwt response needs an encryption key here.
		if cand := firstSigningOnlyEncryptionJWK(encryptionJWKS(reqObj, clientMetadata)); cand != nil {
			jwk = cand
			selectionFinding = `verifier's key in client_metadata.jwks is marked "use":"sig" (signing only); OID4VP 1.0 needs an encryption key for a direct_post.jwt response, so it was used for encryption`
		}
	}
	if jwk == nil {
		return nil, fmt.Errorf("no encryption JWK found in client_metadata.jwks")
	}

	kid, _ := jwk["kid"].(string)
	alg, _ := jwk["alg"].(string)
	if alg == "" {
		return nil, fmt.Errorf("JWK missing required 'alg' parameter (OID4VP 1.0 requires alg in each JWK)")
	}

	switch kty, _ := jwk["kty"].(string); kty {
	case "RSA":
		rsaKey, err := rsaPublicKeyFromJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("constructing RSA key: %w", err)
		}
		return &encryptionKeyInfo{RSAKey: rsaKey, Kid: kid, Alg: alg, Finding: selectionFinding}, nil
	case "EC", "":
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		if x == "" || y == "" {
			return nil, fmt.Errorf("missing x or y in JWK")
		}
		pubKey, finding, err := ecdsaPublicKeyFromJWK(mode, x, y)
		if err != nil {
			return nil, fmt.Errorf("constructing EC key: %w", err)
		}
		return &encryptionKeyInfo{Key: pubKey, Kid: kid, Alg: alg, Finding: joinFindings(selectionFinding, finding)}, nil
	default:
		return nil, fmt.Errorf("unsupported encryption key type %q in client_metadata.jwks", kty)
	}
}

// joinFindings combines the non-empty findings into one line.
func joinFindings(findings ...string) string {
	out := ""
	for _, f := range findings {
		if f == "" {
			continue
		}
		if out != "" {
			out += "; "
		}
		out += f
	}
	return out
}

// HasEncryptionKey checks if the request object contains a valid encryption JWK.
func HasEncryptionKey(reqObj *oid4vc.RequestObjectJWT) bool {
	_, err := extractEncryptionKey(ValidationModeDebug, reqObj, nil)
	return err == nil
}

// HasEncryptionKeyForParams checks if the verifier metadata contains a valid
// encryption JWK, preferring Request Object metadata when present.
func HasEncryptionKeyForParams(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) bool {
	_, err := extractEncryptionKey(ValidationModeDebug, reqObj, clientMetadata)
	return err == nil
}

// encryptDirectPostJWTPayload encrypts a direct_post.jwt response payload.
// The caller is responsible for providing top-level JSON members as required
// by OID4VP 1.0 for both success and error responses.
func (w *Wallet) encryptDirectPostJWTPayload(payload map[string]any, mdocNonce string, params PresentationParams) (string, []byte, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling response payload: %w", err)
	}

	keyInfo, err := extractEncryptionKey(w.Mode(), params.RequestObject, params.ClientMetadata)
	if err != nil {
		return "", nil, fmt.Errorf("extracting encryption key: %w", err)
	}
	// Debug mode read past a specification violation to get here. Recording it
	// is the whole reason the repair is allowed: an unreported repair leaves
	// strict mode rejecting what debug mode accepts with nothing said either
	// way.
	if keyInfo.Finding != "" {
		w.AddLog("presentation", keyInfo.Finding, false)
	}

	// Determine enc algorithm from client_metadata
	// OID4VP 1.0: encrypted_response_enc_values_supported (array)
	enc := detectEncAlgorithm(params.RequestObject, params.ClientMetadata, "A128GCM")

	// An RSA verifier key is wrapped with RSA-OAEP, which has no key agreement
	// and so no ephemeral key, apu or apv.
	if keyInfo.RSAKey != nil {
		return EncryptJWERSA(payloadJSON, keyInfo.RSAKey, keyInfo.Kid, keyInfo.Alg, enc)
	}

	// For ISO mode with mdoc_generated_nonce, set apu and apv per ISO 18013-7 Annex B.
	var apu, apv []byte
	if mdocNonce != "" {
		apu = []byte(mdocNonce)
		if params.Nonce != "" {
			apv = []byte(params.Nonce)
		}
	}

	return EncryptJWE(payloadJSON, keyInfo.Key, keyInfo.Kid, keyInfo.Alg, enc, apu, apv)
}

// EncryptResponse encrypts vp_token, optional id_token, and state as a JWE, for
// the response modes that carry an encrypted response. Returns the JWE and the
// derived content encryption key (CEK) for debugging.
func (w *Wallet) EncryptResponse(vpToken any, idToken, state string, mdocNonce string, params PresentationParams) (string, []byte, error) {
	log.Printf("[VP] Encrypting response: response_mode=%s", params.ResponseMode)
	payload := map[string]any{}
	// OID4VP 1.0 Appendix A.2: "since the state parameter is not defined for
	// the DC API, the Verifier cannot expect it to be included in the
	// response". Over the redirect flows it binds the response to the request
	// and is carried whenever the request supplied one.
	if state != "" && !isDCAPIResponseMode(params.ResponseMode) {
		payload["state"] = state
	}
	if vpToken != nil {
		payload["vp_token"] = vpToken
	}
	if idToken != "" {
		payload["id_token"] = idToken
	}
	return w.encryptDirectPostJWTPayload(payload, mdocNonce, params)
}

// EncryptErrorResponse encrypts an authorization error response. The payload
// carries error, optional error_description, and state as top-level members per
// OID4VP 1.0.
func (w *Wallet) EncryptErrorResponse(errorCode, errorDescription, state string, params PresentationParams) (string, []byte, error) {
	log.Printf("[VP] Encrypting error response: response_mode=%s error=%s", params.ResponseMode, errorCode)
	payload := map[string]any{
		"error": errorCode,
	}
	if errorDescription != "" {
		payload["error_description"] = errorDescription
	}
	if state != "" && !isDCAPIResponseMode(params.ResponseMode) {
		payload["state"] = state
	}
	return w.encryptDirectPostJWTPayload(payload, "", params)
}

// detectEncAlgorithm finds the content encryption algorithm from
// client_metadata.encrypted_response_enc_values_supported per OID4VP 1.0.
// No fallback to legacy field names. Strict spec compliance.
func detectEncAlgorithm(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any, fallback string) string {
	clientMeta := clientMetadata
	if reqObj != nil && reqObj.Payload != nil {
		if reqClientMeta, ok := reqObj.Payload["client_metadata"].(map[string]any); ok {
			clientMeta = reqClientMeta
		}
	}
	if len(clientMeta) == 0 {
		return fallback
	}

	if arr, ok := clientMeta["encrypted_response_enc_values_supported"].([]any); ok && len(arr) > 0 {
		if v, ok := arr[0].(string); ok && v != "" {
			return v
		}
	}

	return fallback
}
