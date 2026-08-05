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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
)

// PresentationParams holds parameters for VP token creation.
type PresentationParams struct {
	Nonce          string
	ClientID       string
	RequestOrigin  string
	ResponseURI    string
	RedirectURI    string // used for fragment response mode
	ResponseMode   string // e.g. "direct_post.jwt", "direct_post", "fragment"
	ClientMetadata map[string]any
	RequestObject  *oid4vc.RequestObjectJWT // optional, used to extract JWK thumbprint for mDoc
}

// VPTokenResult holds the result of VP token creation.
type VPTokenResult struct {
	Token     string
	MDocNonce string // only set for ISO mode mDoc
}

// CreateVPToken creates a VP token for the given credential match.
func (w *Wallet) CreateVPToken(match CredentialMatch, params PresentationParams) (VPTokenResult, error) {
	cred, ok := w.GetCredential(match.CredentialID)
	if !ok {
		return VPTokenResult{}, fmt.Errorf("credential %s not found", match.CredentialID)
	}

	// Renew on the way out when the credential is about to expire. The
	// background task only runs on a wallet server, and a credential that
	// lapses between two presentations would otherwise be sent for the
	// verifier to reject. A renewal that fails is not fatal: the credential in
	// hand may still be accepted, and refusing to present it certainly is not
	// better.
	if cred.CanRenew() && CredentialNeedsRenewal(cred, time.Now()) {
		if renewed, err := w.RefreshCredential(cred.ID); err != nil {
			log.Printf("[VP] renewing %s before presenting it failed, sending the credential as it is: %v", cred.ID, err)
		} else {
			log.Printf("[VP] renewed %s before presenting it", cred.ID)
			cred = *renewed
		}
	}

	typeLabel := cred.VCT
	if typeLabel == "" {
		typeLabel = cred.DocType
	}
	log.Printf("[VP] Creating VP token: format=%s type=%s claims=%v", cred.Format, typeLabel, match.SelectedKeys)

	switch cred.Format {
	case "dc+sd-jwt":
		audience := sdJWTAudience(params)
		token, err := w.createSDJWTPresentation(cred, match.SelectedKeys, params.Nonce, audience)
		if err != nil {
			return VPTokenResult{}, err
		}
		log.Printf("[VP] SD-JWT presentation created: %d disclosures selected, aud=%s", len(match.SelectedKeys), audience)
		return VPTokenResult{Token: token}, nil
	case "jwt_vc_json":
		log.Printf("[VP] Plain JWT presentation (no selective disclosure)")
		return VPTokenResult{Token: cred.Raw}, nil
	case "mso_mdoc":
		result, err := w.createMDocPresentation(cred, match.SelectedKeys, params)
		if err != nil {
			return VPTokenResult{}, err
		}
		log.Printf("[VP] mDoc presentation created: docType=%s transcript=%s", cred.DocType, w.SessionTranscript)
		return result, nil
	default:
		return VPTokenResult{}, fmt.Errorf("unsupported credential format: %s", cred.Format)
	}
}

func sdJWTAudience(params PresentationParams) string {
	if (params.ResponseMode == "dc_api" || params.ResponseMode == "dc_api.jwt") && params.RequestOrigin != "" {
		return "origin:" + params.RequestOrigin
	}
	return params.ClientID
}

// createSDJWTPresentation creates an SD-JWT presentation with selective disclosure and KB-JWT.
func (w *Wallet) createSDJWTPresentation(cred StoredCredential, selectedKeys []string, nonce, clientID string) (string, error) {
	// Parse the raw SD-JWT to get the issuer JWT part
	parts := strings.Split(cred.Raw, "~")
	if len(parts) < 1 {
		return "", fmt.Errorf("invalid SD-JWT format")
	}
	issuerJWT := parts[0]

	payload, err := parseIssuerJWTPayload(issuerJWT)
	if err != nil {
		return "", fmt.Errorf("parsing issuer JWT payload: %w", err)
	}

	digestMap := make(map[string]*sdjwt.Disclosure, len(cred.Disclosures))
	for i := range cred.Disclosures {
		digestMap[cred.Disclosures[i].Digest] = &cred.Disclosures[i]
	}

	topLevel := topLevelDisclosureMap(payload, digestMap)
	includedDigests := make(map[string]bool)

	for _, selector := range selectedKeys {
		path, ok := parseSDJWTSelector(selector)
		if !ok || len(path) == 0 {
			continue
		}
		root, ok := path[0].(string)
		if !ok {
			continue
		}
		disc := topLevel[root]
		if disc == nil {
			continue
		}
		includedDigests[disc.Digest] = true
		if len(path) == 1 {
			collectAllNestedDisclosureDigests(disc.Value, digestMap, includedDigests)
			continue
		}
		collectPathDisclosureDigests(disc.Value, path[1:], digestMap, includedDigests)
	}

	// Preserve the original disclosure order from the credential.
	var selectedDisclosures []string
	for _, d := range cred.Disclosures {
		if includedDigests[d.Digest] {
			selectedDisclosures = append(selectedDisclosures, d.Raw)
		}
	}

	// Build the SD-JWT without KB-JWT: issuer_jwt~disc1~disc2~...~
	withoutKB := issuerJWT + "~"
	if len(selectedDisclosures) > 0 {
		withoutKB += strings.Join(selectedDisclosures, "~") + "~"
	}

	// Compute sd_hash = base64url(SHA-256(sd-jwt-without-kb))
	sdHash := sha256.Sum256([]byte(withoutKB))
	sdHashB64 := format.EncodeBase64URL(sdHash[:])

	// Create Key Binding JWT
	kbJWT, err := w.createKBJWT(nonce, clientID, sdHashB64)
	if err != nil {
		return "", fmt.Errorf("creating KB-JWT: %w", err)
	}

	// Final: issuer_jwt~disc1~disc2~...~kb_jwt
	return withoutKB + kbJWT, nil
}

// createKBJWT creates a Key Binding JWT.
func (w *Wallet) createKBJWT(nonce, audience, sdHash string) (string, error) {
	header := map[string]any{
		"alg": "ES256",
		"typ": "kb+jwt",
	}

	payload := map[string]any{
		"iat":     time.Now().Unix(),
		"aud":     audience,
		"nonce":   nonce,
		"sd_hash": sdHash,
	}

	return signJWT(header, payload, w.HolderKey)
}

// signJWT creates and signs a JWT with the given header, payload, and key.
func signJWT(header, payload map[string]any, key *ecdsa.PrivateKey) (string, error) {
	return jws.Sign(header, payload, key)
}

// VPTokenMapResult holds the result of creating VP tokens for all matches.
type VPTokenMapResult struct {
	TokenMap  map[string]string
	MDocNonce string // set if any mDoc credential produced a nonce (ISO mode)
}

// CreateVPTokenMap creates a vp_token as a JSON object for DCQL responses.
// Maps query credential ID → presentation string.
func (w *Wallet) CreateVPTokenMap(matches []CredentialMatch, params PresentationParams) (*VPTokenMapResult, error) {
	log.Printf("[VP] Creating VP token map: %d credentials, client=%s, response_mode=%s", len(matches), params.ClientID, params.ResponseMode)
	result := &VPTokenMapResult{
		TokenMap: make(map[string]string),
	}

	for _, match := range matches {
		tokenResult, err := w.CreateVPToken(match, params)
		if err != nil {
			return nil, fmt.Errorf("creating VP token for %s: %w", match.QueryID, err)
		}
		result.TokenMap[match.QueryID] = tokenResult.Token
		if tokenResult.MDocNonce != "" {
			result.MDocNonce = tokenResult.MDocNonce
		}
	}

	log.Printf("[VP] VP token map created: queries=%v", mapKeys(result.TokenMap))
	return result, nil
}

// VPToken builds the spec-compliant vp_token JSON object.
// Per OID4VP 1.0: values are arrays of one or more presentations.
func (r *VPTokenMapResult) VPToken() map[string][]string {
	vpToken := make(map[string][]string, len(r.TokenMap))
	for k, v := range r.TokenMap {
		vpToken[k] = []string{v}
	}
	return vpToken
}

// QueryIDs returns the credential query IDs in the token map.
func (r *VPTokenMapResult) QueryIDs() []string {
	return mapKeys(r.TokenMap)
}

func buildPlainAuthorizationResponse(vpToken any, idToken, state string) map[string]any {
	payload := map[string]any{}
	if state != "" {
		payload["state"] = state
	}
	if vpToken != nil {
		payload["vp_token"] = vpToken
	}
	if idToken != "" {
		payload["id_token"] = idToken
	}
	return payload
}

func buildPlainAuthorizationErrorResponse(errorCode, errorDescription, state string) map[string]any {
	payload := map[string]any{
		"error": errorCode,
	}
	if errorDescription != "" {
		payload["error_description"] = errorDescription
	}
	if state != "" {
		payload["state"] = state
	}
	return payload
}

// BuildAuthorizationResponse constructs the authorization response without
// submitting it to the verifier. The result can then be delivered via
// direct_post, fragment, or a Browser API wrapper.
func (w *Wallet) BuildAuthorizationResponse(vpResult *VPTokenMapResult, idToken, state string, params PresentationParams) (*AuthorizationResponseEnvelope, error) {
	var vpToken any
	if vpResult != nil {
		vpToken = vpResult.VPToken()
	}
	var mdocNonce string
	if vpResult != nil {
		mdocNonce = vpResult.MDocNonce
	}

	responseMode := params.ResponseMode
	if responseMode == "" {
		responseMode = "direct_post"
	}

	plain := buildPlainAuthorizationResponse(vpToken, idToken, state)

	switch responseMode {
	case "direct_post.jwt", "dc_api.jwt":
		if !HasEncryptionKeyForParams(params.RequestObject, params.ClientMetadata) {
			return nil, fmt.Errorf("response_mode is %s but no encryption key found in client_metadata.jwks — verifier must provide JWK per OID4VP 1.0", responseMode)
		}
		jwe, cek, err := w.EncryptResponse(vpToken, idToken, state, mdocNonce, params)
		if err != nil {
			return nil, fmt.Errorf("encrypting response: %w", err)
		}
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			ResponseJWT:  jwe,
			CEK:          cek,
		}, nil
	case "fragment":
		redirectURI := params.RedirectURI
		if redirectURI == "" {
			redirectURI = params.ResponseURI
		}
		redirectURL, err := BuildFragmentRedirect(redirectURI, state, vpToken, idToken)
		if err != nil {
			return nil, fmt.Errorf("building fragment redirect: %w", err)
		}
		log.Printf("[VP] Fragment response mode: redirect to %s", format.Truncate(redirectURL, 120))
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			RedirectURI:  redirectURL,
		}, nil
	case "direct_post", "dc_api":
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			Plain:        plain,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported response_mode %q", responseMode)
	}
}

// BuildAuthorizationErrorResponse constructs an authorization error response
// without submitting it to the verifier.
func (w *Wallet) BuildAuthorizationErrorResponse(errorCode, errorDescription, state string, params PresentationParams) (*AuthorizationResponseEnvelope, error) {
	responseMode := params.ResponseMode
	if responseMode == "" {
		responseMode = "direct_post"
	}

	switch responseMode {
	case "direct_post.jwt", "dc_api.jwt":
		if !HasEncryptionKeyForParams(params.RequestObject, params.ClientMetadata) {
			return nil, fmt.Errorf("response_mode is %s but no encryption key found in client_metadata.jwks — verifier must provide JWK per OID4VP 1.0", responseMode)
		}
		jwe, cek, err := w.EncryptErrorResponse(errorCode, errorDescription, state, params)
		if err != nil {
			return nil, fmt.Errorf("encrypting error response: %w", err)
		}
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			ResponseJWT:  jwe,
			CEK:          cek,
		}, nil
	case "fragment":
		redirectURI := params.RedirectURI
		if redirectURI == "" {
			redirectURI = params.ResponseURI
		}
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			RedirectURI:  BuildFragmentErrorRedirect(redirectURI, state, errorCode, errorDescription),
		}, nil
	case "direct_post", "dc_api":
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			Plain:        buildPlainAuthorizationErrorResponse(errorCode, errorDescription, state),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported response_mode %q", responseMode)
	}
}

// SubmitPresentation builds the vp_token, optionally encrypts it, and submits to the verifier.
// If idToken is non-empty, it is included alongside vp_token in the response.
func (w *Wallet) SubmitPresentation(vpResult *VPTokenMapResult, idToken, state, responseURI string, params PresentationParams) (*DirectPostResult, error) {
	response, err := w.BuildAuthorizationResponse(vpResult, idToken, state, params)
	if err != nil {
		return nil, err
	}
	switch response.ResponseMode {
	case "direct_post.jwt":
		return SubmitDirectPostJWT(responseURI, response.ResponseJWT, response.CEK)
	case "fragment":
		return &DirectPostResult{
			StatusCode:  302,
			RedirectURI: response.RedirectURI,
		}, nil
	case "direct_post":
		return SubmitDirectPostObject(responseURI, response.Plain)
	case "dc_api", "dc_api.jwt":
		return nil, fmt.Errorf("response_mode %q must be returned via Browser API, not direct submission", response.ResponseMode)
	default:
		return nil, fmt.Errorf("unsupported response_mode %q", response.ResponseMode)
	}
}

// SubmitAuthorizationError submits an authorization error response to the verifier.
func (w *Wallet) SubmitAuthorizationError(errorCode, errorDescription, state, responseURI string, params PresentationParams) (*DirectPostResult, error) {
	response, err := w.BuildAuthorizationErrorResponse(errorCode, errorDescription, state, params)
	if err != nil {
		return nil, err
	}
	switch response.ResponseMode {
	case "direct_post.jwt":
		return SubmitDirectPostJWT(responseURI, response.ResponseJWT, response.CEK)
	case "fragment":
		return &DirectPostResult{
			StatusCode:  302,
			RedirectURI: response.RedirectURI,
		}, nil
	case "direct_post":
		return SubmitDirectPostObject(responseURI, response.Plain)
	case "dc_api", "dc_api.jwt":
		return nil, fmt.Errorf("response_mode %q must be returned via Browser API, not direct submission", response.ResponseMode)
	default:
		return nil, fmt.Errorf("unsupported response_mode %q", response.ResponseMode)
	}
}

func parseIssuerJWTPayload(issuerJWT string) (map[string]any, error) {
	parts := strings.Split(issuerJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid issuer JWT format")
	}

	rawPayload, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshaling payload: %w", err)
	}

	return payload, nil
}

func topLevelDisclosureMap(payload map[string]any, digestMap map[string]*sdjwt.Disclosure) map[string]*sdjwt.Disclosure {
	topLevel := make(map[string]*sdjwt.Disclosure)
	sdArr, _ := payload["_sd"].([]any)
	for _, rawDigest := range sdArr {
		digest, ok := rawDigest.(string)
		if !ok {
			continue
		}
		disc := digestMap[digest]
		if disc == nil || disc.IsArrayEntry || disc.Name == "" {
			continue
		}
		topLevel[disc.Name] = disc
	}
	return topLevel
}

func collectAllNestedDisclosureDigests(value any, digestMap map[string]*sdjwt.Disclosure, digests map[string]bool) {
	switch v := value.(type) {
	case map[string]any:
		if sdArr, ok := v["_sd"].([]any); ok {
			for _, item := range sdArr {
				digest, ok := item.(string)
				if !ok {
					continue
				}
				digests[digest] = true
				if disc := digestMap[digest]; disc != nil {
					collectAllNestedDisclosureDigests(disc.Value, digestMap, digests)
				}
			}
		}
		for k, item := range v {
			if k == "_sd" {
				continue
			}
			collectAllNestedDisclosureDigests(item, digestMap, digests)
		}
	case []any:
		for _, item := range v {
			if obj, ok := item.(map[string]any); ok {
				if digest, ok := obj["..."].(string); ok {
					digests[digest] = true
					if disc := digestMap[digest]; disc != nil {
						collectAllNestedDisclosureDigests(disc.Value, digestMap, digests)
					}
					continue
				}
			}
			collectAllNestedDisclosureDigests(item, digestMap, digests)
		}
	}
}

// collectArrayDigests extracts array entry digests from {"...": digest} objects.
// It is kept as a narrow helper for tests.
func collectArrayDigests(value any, digests map[string]bool) {
	arr, ok := value.([]any)
	if !ok {
		return
	}
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if digest, ok := obj["..."].(string); ok {
			digests[digest] = true
		}
	}
}

func collectPathDisclosureDigests(value any, path []any, digestMap map[string]*sdjwt.Disclosure, digests map[string]bool) {
	if len(path) == 0 {
		collectAllNestedDisclosureDigests(value, digestMap, digests)
		return
	}

	switch segment := path[0].(type) {
	case string:
		obj, ok := value.(map[string]any)
		if !ok {
			return
		}
		if next, ok := obj[segment]; ok {
			collectPathDisclosureDigests(next, path[1:], digestMap, digests)
			return
		}
		if sdArr, ok := obj["_sd"].([]any); ok {
			for _, item := range sdArr {
				digest, ok := item.(string)
				if !ok {
					continue
				}
				disc := digestMap[digest]
				if disc == nil || disc.IsArrayEntry || disc.Name != segment {
					continue
				}
				digests[digest] = true
				collectPathDisclosureDigests(disc.Value, path[1:], digestMap, digests)
			}
		}
	case int:
		arr, ok := value.([]any)
		if !ok || segment < 0 || segment >= len(arr) {
			return
		}
		collectArrayItemDisclosureDigests(arr[segment], path[1:], digestMap, digests)
	case nil:
		arr, ok := value.([]any)
		if !ok {
			return
		}
		for _, item := range arr {
			collectArrayItemDisclosureDigests(item, path[1:], digestMap, digests)
		}
	}
}

func collectArrayItemDisclosureDigests(item any, path []any, digestMap map[string]*sdjwt.Disclosure, digests map[string]bool) {
	if ref, ok := item.(map[string]any); ok {
		if digest, ok := ref["..."].(string); ok {
			digests[digest] = true
			if disc := digestMap[digest]; disc != nil {
				collectPathDisclosureDigests(disc.Value, path, digestMap, digests)
			}
			return
		}
	}
	collectPathDisclosureDigests(item, path, digestMap, digests)
}
