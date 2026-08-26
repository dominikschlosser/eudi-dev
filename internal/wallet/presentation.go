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
	"errors"
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
	// InteractiveAuthorizationEndpoint is the Authorization Challenge Endpoint
	// the presentation is bound to (OpenID4VCI 1.1 §6.2.1.1). Empty for every
	// other flow, and always the endpoint the wallet called rather than a
	// value read out of the request.
	InteractiveAuthorizationEndpoint string
}

// isInteractiveAuthorizationResponseMode reports whether a response mode is
// one of the two of OpenID4VCI 1.1 §6.2.1.1, which go back to the
// Authorization Challenge Endpoint rather than to a response_uri.
func isInteractiveAuthorizationResponseMode(mode string) bool {
	return mode == "ia_post" || mode == "ia_post.jwt"
}

// VPTokenResult holds the result of VP token creation.
type VPTokenResult struct {
	Token     string
	MDocNonce string // only set for ISO mode mDoc
}

// CreateVPToken creates a VP token for the given credential match.
func (w *Wallet) CreateVPToken(match CredentialMatch, params PresentationParams) (VPTokenResult, error) {
	return w.createVPToken(match, params, "")
}

// createVPToken builds one presentation. mdocNonce is the mdoc generated
// nonce the whole response shares (ISO 18013-7); an empty one lets an mdoc
// presentation generate its own, which is what a response holding a single
// presentation needs.
func (w *Wallet) createVPToken(match CredentialMatch, params PresentationParams, mdocNonce string) (VPTokenResult, error) {
	cred, ok := w.GetCredential(match.CredentialID)
	if !ok {
		return VPTokenResult{}, fmt.Errorf("credential %s not found", match.CredentialID)
	}

	// Renew on the way out when the credential is about to expire: the
	// background task only runs on a wallet server. A failed renewal is not
	// fatal, since the credential in hand may still be accepted.
	if cred.CanRenew() && CredentialNeedsRenewal(cred, time.Now()) {
		if renewed, err := w.RefreshCredential(cred.ID); err != nil {
			log.Printf("[VP] renewing %s before presenting it failed, sending the credential as it is: %v", cred.ID, err)
		} else {
			log.Printf("[VP] renewed %s before presenting it", cred.ID)
			cred = *renewed
		}
	}

	if err := w.checkPresentableKeyBinding(cred); err != nil {
		return VPTokenResult{}, err
	}

	// The signing key is the copy's own key for a batch copy bound to one, and
	// the wallet holder key otherwise, so a rotated batch copy signs its key
	// binding with the key it was issued against.
	signingKey, err := w.batchSigningKey(cred)
	if err != nil {
		return VPTokenResult{}, err
	}

	typeLabel := cred.VCT
	if typeLabel == "" {
		typeLabel = cred.DocType
	}
	log.Printf("[VP] Creating VP token: format=%s type=%s claims=%v", cred.Format, typeLabel, match.SelectedKeys)

	switch cred.Format {
	case "dc+sd-jwt":
		audience := sdJWTAudience(params)
		token, err := w.createSDJWTPresentation(cred, match.SelectedKeys, params.Nonce, audience, signingKey)
		if err != nil {
			return VPTokenResult{}, err
		}
		log.Printf("[VP] SD-JWT presentation created: %d disclosures selected, aud=%s", len(match.SelectedKeys), audience)
		return VPTokenResult{Token: token}, nil
	case "jwt_vc_json":
		log.Printf("[VP] Plain JWT presentation (no selective disclosure)")
		return VPTokenResult{Token: cred.Raw}, nil
	case "mso_mdoc":
		result, err := w.createMDocPresentation(cred, match.SelectedKeys, params, mdocNonce, signingKey)
		if err != nil {
			return VPTokenResult{}, err
		}
		log.Printf("[VP] mDoc presentation created: docType=%s transcript=%s", cred.DocType, w.SessionTranscript)
		return result, nil
	default:
		return VPTokenResult{}, fmt.Errorf("unsupported credential format: %s", cred.Format)
	}
}

// checkPresentableKeyBinding reports a credential whose key binding this
// wallet cannot sign. RFC 9901 §4.3 has the KB-JWT signed by the key the
// credential's cnf names and ISO 18013-5 §9.1.3 the DeviceSigned by the MSO's
// deviceKey, and this wallet signs both with the one holder key it has, so a
// credential bound to another key produces a signature every verifier
// refuses. Strict mode stops before the nonce is spent, debug mode sends it
// and lets the refusal be the finding, as it does with every other deviation
// ([ADR-0001]). A plain JWT VC signs no key binding at all and is not in
// scope.
//
// [ADR-0001]: docs/adr/0001-debug-by-default-validation-with-opt-in-strict-mode.md
func (w *Wallet) checkPresentableKeyBinding(cred StoredCredential) error {
	if cred.Format != "dc+sd-jwt" && cred.Format != "mso_mdoc" {
		return nil
	}
	if !w.keyBindingNotHeld(&cred) {
		return nil
	}
	detail := fmt.Sprintf(
		"Credential %s is bound to a holder key this wallet does not hold, so the key binding signature of this presentation comes from the wrong key and the verifier refuses it.",
		credentialLabel(cred))
	details := map[string]any{
		"credential_id": cred.ID,
		"format":        cred.Format,
	}
	addStringDetail(details, "vct", cred.VCT)
	addStringDetail(details, "doctype", cred.DocType)
	if w.Mode() == ValidationModeStrict {
		w.addProtocolLog("presentation", "key_binding_cannot_be_signed", detail, false, details)
		return errors.New(detail)
	}
	w.addProtocolWarning("presentation", "key_binding_cannot_be_signed", detail, details)
	log.Printf("[VP] WARNING: %s", detail)
	return nil
}

func sdJWTAudience(params PresentationParams) string {
	if isInteractiveAuthorizationResponseMode(params.ResponseMode) && params.InteractiveAuthorizationEndpoint != "" {
		return interactiveAuthorizationAudience(params.InteractiveAuthorizationEndpoint)
	}
	if (params.ResponseMode == "dc_api" || params.ResponseMode == "dc_api.jwt") && params.RequestOrigin != "" {
		return "origin:" + params.RequestOrigin
	}
	return params.ClientID
}

// interactiveAuthorizationAudience binds a Key Binding JWT to the
// Authorization Challenge Endpoint (Appendix A.3.5).
//
// A.3.5 is the one binding section that says "the derived Origin ... of the
// Authorization Challenge Endpoint". A.1.1.5, A.1.2.5 and A.2.5 all bind the
// endpoint itself, and §6.2.1.5 names the mechanism as "binding the
// Authorization Challenge Endpoint to the Verifiable Presentation", which an
// origin cannot do between two endpoints sharing a host. So the endpoint is
// sent. A.3.5's own example agrees.
func interactiveAuthorizationAudience(endpoint string) string {
	return "ia:" + endpoint
}

// createSDJWTPresentation creates an SD-JWT presentation with selective
// disclosure and KB-JWT, signing the key binding with signingKey.
func (w *Wallet) createSDJWTPresentation(cred StoredCredential, selectedKeys []string, nonce, clientID string, signingKey *ecdsa.PrivateKey) (string, error) {
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

	includedDigests := make(map[string]bool)

	for _, selector := range selectedKeys {
		path, ok := parseSDJWTSelector(selector)
		if !ok || len(path) == 0 {
			continue
		}
		// Resolve the whole path from the payload root: at each level it
		// descends a cleartext structural object and matches an SD claim by
		// name. So a claim under a cleartext parent (address.street_address,
		// where address is a plain object carrying its children in _sd) is
		// disclosed the same as a top-level SD claim.
		collectPathDisclosureDigests(payload, path, digestMap, includedDigests)
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

	// A credential with no cnf names no holder key, so RFC 9901 §3.3 (key
	// binding is optional) has it presented without a KB-JWT: issuer_jwt~disc~.
	if !credentialHolderBinding(cred.Raw).Bound {
		return withoutKB, nil
	}

	// Compute sd_hash = base64url(SHA-256(sd-jwt-without-kb))
	sdHash := sha256.Sum256([]byte(withoutKB))
	sdHashB64 := format.EncodeBase64URL(sdHash[:])

	// Create Key Binding JWT
	kbJWT, err := w.createKBJWT(nonce, clientID, sdHashB64, signingKey)
	if err != nil {
		return "", fmt.Errorf("creating KB-JWT: %w", err)
	}

	// Final: issuer_jwt~disc1~disc2~...~kb_jwt
	return withoutKB + kbJWT, nil
}

// createKBJWT creates a Key Binding JWT signed with signingKey (the copy's
// holder key).
func (w *Wallet) createKBJWT(nonce, audience, sdHash string, signingKey *ecdsa.PrivateKey) (string, error) {
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

	return signJWT(header, payload, signingKey)
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

	// ISO 18013-7 Annex B carries one mdoc generated nonce per response, in
	// the apu of the encrypted response, and every document's session
	// transcript hashes it. Generating one per document would leave every
	// document but the reported one unverifiable, so the response settles it
	// once and hands it to each presentation.
	var mdocNonce string
	if w.SessionTranscript == SessionTranscriptISO {
		var err error
		if mdocNonce, err = newMDocGeneratedNonce(); err != nil {
			return nil, err
		}
	}

	for _, match := range matches {
		tokenResult, err := w.createVPToken(match, params, mdocNonce)
		if err != nil {
			return nil, fmt.Errorf("creating VP token for %s: %w", match.QueryID, err)
		}
		result.TokenMap[match.QueryID] = tokenResult.Token
		if tokenResult.MDocNonce != "" {
			result.MDocNonce = tokenResult.MDocNonce
		}
		// The copy has now been sent, so the next presentation of the batch
		// prefers a copy used fewer times (a no-op outside a batch).
		w.recordBatchPresentation(match.CredentialID)
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
	case "direct_post.jwt", "dc_api.jwt", "ia_post.jwt":
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
	case "direct_post", "dc_api", "ia_post":
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

	// A Digital Credentials API error is never encrypted, whichever response
	// mode was asked for: Appendix A.4 has it returned "as an object within
	// the data property". A JWE there reads as a response, not a refusal.
	if isDCAPIResponseMode(responseMode) {
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			Plain:        map[string]any{"error": errorCode},
		}, nil
	}

	switch responseMode {
	case "direct_post.jwt", "ia_post.jwt":
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
	case "direct_post", "dc_api", "ia_post":
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
	case "ia_post", "ia_post.jwt":
		return nil, fmt.Errorf("response_mode %q goes back to the Authorization Challenge Endpoint, not to a response_uri", response.ResponseMode)
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
	case "ia_post", "ia_post.jwt":
		return nil, fmt.Errorf("response_mode %q goes back to the Authorization Challenge Endpoint, not to a response_uri", response.ResponseMode)
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
