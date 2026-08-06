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

package oid4vc

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jsonutil"
)

// Parse detects and parses an OID4VCI credential offer or OID4VP authorization request.
// It returns the request type, the parsed object (CredentialOffer or AuthorizationRequest), and any error.
func Parse(raw string) (RequestType, any, error) {
	return ParseWithOptions(raw, ParseOptions{})
}

// ParseWithOptions is like Parse but accepts options to customize behavior
// (e.g. a custom request_uri fetcher for request_uri_method=post support).
func ParseWithOptions(raw string, opts ParseOptions) (RequestType, any, error) {
	raw = strings.TrimSpace(raw)

	// 1. URI scheme detection
	if strings.HasPrefix(raw, "openid-credential-offer://") || strings.HasPrefix(raw, "haip-vci://") {
		return parseVCIURI(raw)
	}
	if strings.HasPrefix(raw, "openid4vp://") || strings.HasPrefix(raw, "haip-vp://") || strings.HasPrefix(raw, "eudi-openid4vp://") {
		return parseVPURI(raw, opts)
	}

	// 2. HTTPS/HTTP URL
	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
		return parseHTTPURL(raw, opts)
	}

	// 3. JWT (3 dot-separated base64url parts)
	if isJWT(raw) {
		return parseJWTInput(raw)
	}

	// 4. JSON object
	if strings.HasPrefix(raw, "{") {
		return parseJSONInput(raw)
	}

	return 0, nil, fmt.Errorf("unable to detect OpenID4VCI/VP format: not a recognized URI, URL, JWT, or JSON")
}

func isJWT(s string) bool {
	parts := strings.SplitN(s, ".", 4)
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0
}

// parseVCIURI parses an openid-credential-offer:// or haip-vci:// URI.
func parseVCIURI(raw string) (RequestType, any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return TypeVCI, nil, fmt.Errorf("parsing VCI URI: %w", err)
	}
	return parseVCIParams(u.Query())
}

// parseVPURI parses an openid4vp://, haip-vp://, or eudi-openid4vp:// URI.
func parseVPURI(raw string, opts ParseOptions) (RequestType, any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return TypeVP, nil, fmt.Errorf("parsing VP URI: %w", err)
	}
	return parseVPParams(u.Query(), opts)
}

// parseHTTPURL parses an HTTPS/HTTP URL by checking query params.
func parseHTTPURL(raw string, opts ParseOptions) (RequestType, any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("parsing URL: %w", err)
	}
	q := u.Query()
	if q.Has("credential_offer") || q.Has("credential_offer_uri") {
		return parseVCIParams(q)
	}
	return parseVPParams(q, opts)
}

// parseVCIParams extracts a credential offer from URL query parameters.
func parseVCIParams(q url.Values) (RequestType, any, error) {
	var offerJSON []byte

	if inline := q.Get("credential_offer"); inline != "" {
		offerJSON = []byte(inline)
	} else if uri := q.Get("credential_offer_uri"); uri != "" {
		fetched, err := format.FetchURL(uri)
		if err != nil {
			return TypeVCI, nil, fmt.Errorf("fetching credential_offer_uri: %w", err)
		}
		offerJSON = []byte(fetched)
	} else {
		return TypeVCI, nil, fmt.Errorf("VCI URI has no credential_offer or credential_offer_uri parameter")
	}

	return parseVCIJSON(offerJSON)
}

// parseVCIJSON parses a credential offer JSON blob.
func parseVCIJSON(data []byte) (RequestType, any, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return TypeVCI, nil, fmt.Errorf("parsing credential offer JSON: %w", err)
	}

	offer := &CredentialOffer{FullJSON: m}

	offer.CredentialIssuer = jsonutil.GetString(m, "credential_issuer")

	if ids := jsonutil.GetArray(m, "credential_configuration_ids"); ids != nil {
		for _, id := range ids {
			if s, ok := id.(string); ok {
				offer.CredentialConfigurationIDs = append(offer.CredentialConfigurationIDs, s)
			}
		}
	}

	if grants := jsonutil.GetMap(m, "grants"); grants != nil {
		if preAuth := jsonutil.GetMap(grants, "urn:ietf:params:oauth:grant-type:pre-authorized_code"); preAuth != nil {
			offer.Grants.PreAuthorizedCode = jsonutil.GetString(preAuth, "pre-authorized_code")
			if txCode := jsonutil.GetMap(preAuth, "tx_code"); txCode != nil {
				offer.Grants.TxCode = txCode
			}
		}
		if authCode := jsonutil.GetMap(grants, "authorization_code"); authCode != nil {
			offer.Grants.IssuerState = jsonutil.GetString(authCode, "issuer_state")
			offer.Grants.AuthorizationCode = jsonutil.GetString(authCode, "authorization_code")
		}
	}

	return TypeVCI, offer, nil
}

// parseVPParams extracts an authorization request from URL query parameters.
func parseVPParams(q url.Values, opts ParseOptions) (RequestType, any, error) {
	req := &AuthorizationRequest{
		FullParams: make(map[string]string),
	}

	for key := range q {
		req.FullParams[key] = q.Get(key)
	}

	req.ClientID = q.Get("client_id")
	req.ResponseType = q.Get("response_type")
	req.ResponseMode = q.Get("response_mode")
	req.Nonce = q.Get("nonce")
	req.State = q.Get("state")
	req.RedirectURI = q.Get("redirect_uri")
	req.ResponseURI = q.Get("response_uri")
	req.Scope = q.Get("scope")
	req.RequestURIMethod = q.Get("request_uri_method") // OID4VP 1.0 §5.10
	if cm := q.Get("client_metadata"); cm != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(cm), &m); err == nil {
			req.ClientMetadata = m
		}
	}

	// Resolve request_uri (fetch and parse JWT)
	if requestURI := q.Get("request_uri"); requestURI != "" {
		req.RequestURI = requestURI
		method := req.RequestURIMethod
		if method == "" {
			method = "get"
		}

		var fetched string
		var err error
		if opts.FetchRequestURI != nil {
			fetched, err = opts.FetchRequestURI(requestURI, method)
		} else {
			fetched, err = format.FetchURL(requestURI)
		}
		if err != nil {
			return TypeVP, nil, fmt.Errorf("fetching request_uri: %w", err)
		}
		if isJWT(fetched) {
			header, payload, _, err := format.ParseJWTParts(fetched)
			if err != nil {
				return TypeVP, nil, fmt.Errorf("parsing request object JWT: %w", err)
			}
			req.RequestObject = &RequestObjectJWT{Raw: fetched, Header: header, Payload: payload}
			if err := applyRequestObjectPayload(req, payload); err != nil {
				return TypeVP, nil, err
			}
		}
	}

	if requestJWT := q.Get("request"); requestJWT != "" {
		header, payload, _, err := format.ParseJWTParts(requestJWT)
		if err != nil {
			return TypeVP, nil, fmt.Errorf("parsing request JWT: %w", err)
		}
		req.RequestObject = &RequestObjectJWT{Raw: requestJWT, Header: header, Payload: payload}
		if err := applyRequestObjectPayload(req, payload); err != nil {
			return TypeVP, nil, err
		}
	}

	// Parse dcql_query
	if dq := q.Get("dcql_query"); dq != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(dq), &m); err == nil {
			req.DCQLQuery = m
		}
	}

	return TypeVP, req, nil
}

// applyRequestObjectPayload applies Request Object claims authoritatively per OID4VP 1.0.
func applyRequestObjectPayload(req *AuthorizationRequest, payload map[string]any) error {
	if outerClientID := req.ClientID; outerClientID != "" {
		if innerClientID, ok := payload["client_id"].(string); ok && innerClientID != "" && innerClientID != outerClientID {
			return fmt.Errorf("request object client_id %q does not match outer client_id %q", innerClientID, outerClientID)
		}
	}

	setString := func(target *string, key string) {
		if v, ok := payload[key].(string); ok && v != "" {
			*target = v
		}
	}
	setString(&req.ClientID, "client_id")
	setString(&req.ResponseType, "response_type")
	setString(&req.ResponseMode, "response_mode")
	setString(&req.Nonce, "nonce")
	setString(&req.State, "state")
	setString(&req.RedirectURI, "redirect_uri")
	setString(&req.ResponseURI, "response_uri")
	setString(&req.Scope, "scope")

	if dq, ok := payload["dcql_query"].(map[string]any); ok {
		req.DCQLQuery = dq
	}
	if clientMetadata, ok := payload["client_metadata"].(map[string]any); ok {
		req.ClientMetadata = clientMetadata
	}

	return nil
}

// parseJWTInput decodes a JWT and auto-detects VCI vs VP.
func parseJWTInput(raw string) (RequestType, any, error) {
	header, payload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("parsing JWT: %w", err)
	}

	// VCI: has credential_issuer
	if _, ok := payload["credential_issuer"]; ok {
		data, err := json.Marshal(payload)
		if err != nil {
			return TypeVCI, nil, fmt.Errorf("marshaling JWT payload: %w", err)
		}
		_, offer, err := parseVCIJSON(data)
		return TypeVCI, offer, err
	}

	// VP: has client_id or response_type
	if _, ok := payload["client_id"]; ok {
		rt, req := buildVPFromJWT(raw, header, payload)
		return rt, req, nil
	}
	if _, ok := payload["response_type"]; ok {
		rt, req := buildVPFromJWT(raw, header, payload)
		return rt, req, nil
	}

	return 0, nil, fmt.Errorf("JWT payload does not contain VCI or VP markers (credential_issuer, client_id, response_type)")
}

func buildVPFromJWT(raw string, header, payload map[string]any) (RequestType, *AuthorizationRequest) {
	req := &AuthorizationRequest{
		RequestObject: &RequestObjectJWT{Raw: raw, Header: header, Payload: payload},
		FullParams:    make(map[string]string),
	}
	_ = applyRequestObjectPayload(req, payload)
	return TypeVP, req
}

// parseJSONInput parses a raw JSON object and auto-detects VCI vs VP.
func parseJSONInput(raw string) (RequestType, any, error) {
	// VCI: has credential_issuer
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return 0, nil, fmt.Errorf("parsing JSON: %w", err)
	}

	if _, ok := m["credential_issuer"]; ok {
		return parseVCIJSON([]byte(raw))
	}

	if _, ok := m["client_id"]; ok {
		rt, req := buildVPFromJSON(m)
		return rt, req, nil
	}

	return 0, nil, fmt.Errorf("JSON does not contain VCI or VP markers (credential_issuer, client_id)")
}

func buildVPFromJSON(m map[string]any) (RequestType, *AuthorizationRequest) {
	req := &AuthorizationRequest{
		FullJSON:   m,
		FullParams: make(map[string]string),
	}

	req.ClientID = jsonutil.GetString(m, "client_id")
	req.ResponseType = jsonutil.GetString(m, "response_type")
	req.ResponseMode = jsonutil.GetString(m, "response_mode")
	req.Nonce = jsonutil.GetString(m, "nonce")
	req.State = jsonutil.GetString(m, "state")
	req.RedirectURI = jsonutil.GetString(m, "redirect_uri")
	req.ResponseURI = jsonutil.GetString(m, "response_uri")
	req.Scope = jsonutil.GetString(m, "scope")
	if cm := jsonutil.GetMap(m, "client_metadata"); cm != nil {
		req.ClientMetadata = cm
	}

	if dq := jsonutil.GetMap(m, "dcql_query"); dq != nil {
		req.DCQLQuery = dq
	}

	return TypeVP, req
}
