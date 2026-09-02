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

	if strings.HasPrefix(raw, "openid-credential-offer://") || strings.HasPrefix(raw, "haip-vci://") {
		return parseVCIURI(raw)
	}
	if strings.HasPrefix(raw, "openid4vp://") || strings.HasPrefix(raw, "haip-vp://") || strings.HasPrefix(raw, "eudi-openid4vp://") {
		return parseVPURI(raw, opts)
	}

	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
		return parseHTTPURL(raw, opts)
	}

	if isJWT(raw) {
		return parseJWTInput(raw)
	}

	if strings.HasPrefix(raw, "{") {
		return parseJSONInput(raw)
	}

	return 0, nil, fmt.Errorf("unable to detect OpenID4VCI/VP format: not a recognized URI, URL, JWT, or JSON")
}

func isJWT(s string) bool {
	parts := strings.SplitN(s, ".", 4)
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0
}

// URIQueryValues parses a request URI's query with RFC 3986 semantics:
// percent escapes are decoded and "+" stays a literal plus. Authorization
// requests and credential offers travel as links and QR codes, not as
// submitted forms, and their values carry literal plus signs ("dc+sd-jwt"
// in a dcql_query, vct URNs).
func URIQueryValues(u *url.URL) url.Values {
	values := url.Values{}
	for _, part := range strings.Split(u.RawQuery, "&") {
		if part == "" {
			continue
		}
		key, value, _ := strings.Cut(part, "=")
		if decoded, err := url.PathUnescape(key); err == nil {
			key = decoded
		}
		if decoded, err := url.PathUnescape(value); err == nil {
			value = decoded
		}
		values.Add(key, value)
	}
	return values
}

// DeriveResponseURI fills an absent response_uri for the redirect_uri client
// id prefix: OID4VP 1.0 §5.9.3 makes the prefix value the response endpoint,
// so a verifier may omit the parameter for the direct_post response modes and
// the wallet derives it from the client_id.
func DeriveResponseURI(clientID, responseMode, responseURI string) string {
	if responseURI != "" {
		return responseURI
	}
	if responseMode != "direct_post" && responseMode != "direct_post.jwt" {
		return ""
	}
	if value, ok := strings.CutPrefix(clientID, "redirect_uri:"); ok && value != "" {
		return value
	}
	return ""
}

// EncodeURIQuery encodes values for a request URI's query component with RFC
// 3986 semantics, the counterpart of URIQueryValues: a space becomes %20, so
// a receiver reading "+" as a literal plus sees the original text.
func EncodeURIQuery(values url.Values) string {
	return strings.ReplaceAll(values.Encode(), "+", "%20")
}

// parseVCIURI parses an openid-credential-offer:// or haip-vci:// URI.
func parseVCIURI(raw string) (RequestType, any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return TypeVCI, nil, fmt.Errorf("parsing VCI URI: %w", err)
	}
	return parseVCIParams(URIQueryValues(u))
}

// parseVPURI parses an openid4vp://, haip-vp://, or eudi-openid4vp:// URI.
func parseVPURI(raw string, opts ParseOptions) (RequestType, any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return TypeVP, nil, fmt.Errorf("parsing VP URI: %w", err)
	}
	return parseVPParams(URIQueryValues(u), opts)
}

// parseHTTPURL parses an HTTPS/HTTP URL by checking query params.
func parseHTTPURL(raw string, opts ParseOptions) (RequestType, any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("parsing URL: %w", err)
	}
	q := URIQueryValues(u)
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
	req.ResponseURI = DeriveResponseURI(req.ClientID, req.ResponseMode, q.Get("response_uri"))
	req.Scope = q.Get("scope")
	req.RequestURIMethod = q.Get("request_uri_method") // OID4VP 1.0 §5.10
	if cm := q.Get("client_metadata"); cm != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(cm), &m); err == nil {
			req.ClientMetadata = m
		}
	}

	// Read before any Request Object is resolved. A signed object replaces the
	// whole parameter set, so anything taken from the query string afterwards
	// would outrank what the Verifier signed.
	if dq := q.Get("dcql_query"); dq != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(dq), &m); err == nil {
			req.DCQLQuery = m
		}
	}

	if requestURI := q.Get("request_uri"); requestURI != "" {
		req.RequestURI = requestURI
		method := req.RequestURIMethod
		if method == "" {
			method = "get"
		}

		var fetched string
		var err error
		if opts.FetchRequestURI != nil {
			fetched, err = opts.FetchRequestURI(requestURI, method, req.ClientID)
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

	return TypeVP, req, nil
}

// applyRequestObjectPayload replaces the request parameters with the claims of
// the Request Object. OID4VP 1.0 §5.10.1: "The Wallet MUST only use the
// parameters in this Request Object, even if the same parameter was provided
// in an Authorization Request query parameter", so a parameter the signed
// object omits is absent rather than inherited. Merging would let anyone who
// can append to the invocation URL decide what the wallet discloses.
//
// request_uri and request_uri_method stay outside: they describe the
// transport, not the request.
func applyRequestObjectPayload(req *AuthorizationRequest, payload map[string]any) error {
	innerClientID, _ := payload["client_id"].(string)
	// "The Client Identifier value in the client_id Authorization Request
	// parameter and the Request Object client_id claim value MUST be
	// identical, including the Client Identifier Prefix."
	if req.ClientID != "" && innerClientID != req.ClientID {
		return fmt.Errorf("request object client_id %q does not match outer client_id %q", innerClientID, req.ClientID)
	}

	str := func(key string) string {
		v, _ := payload[key].(string)
		return v
	}
	req.ClientID = innerClientID
	req.ResponseType = str("response_type")
	req.ResponseMode = str("response_mode")
	req.Nonce = str("nonce")
	req.State = str("state")
	req.RedirectURI = str("redirect_uri")
	req.ResponseURI = DeriveResponseURI(req.ClientID, req.ResponseMode, str("response_uri"))
	req.Scope = str("scope")

	req.DCQLQuery, _ = payload["dcql_query"].(map[string]any)
	req.ClientMetadata, _ = payload["client_metadata"].(map[string]any)

	return nil
}

// parseJWTInput decodes a JWT and auto-detects VCI vs VP.
func parseJWTInput(raw string) (RequestType, any, error) {
	header, payload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("parsing JWT: %w", err)
	}

	if _, ok := payload["credential_issuer"]; ok {
		data, err := json.Marshal(payload)
		if err != nil {
			return TypeVCI, nil, fmt.Errorf("marshaling JWT payload: %w", err)
		}
		_, offer, err := parseVCIJSON(data)
		return TypeVCI, offer, err
	}

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
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return 0, nil, fmt.Errorf("parsing JSON: %w", err)
	}

	if _, ok := m["credential_issuer"]; ok {
		return parseVCIJSON([]byte(raw))
	}

	// An unsigned request over the Digital Credentials API carries no
	// client_id at all (OID4VP 1.0 Appendix A.2), so the request is
	// recognised by what it asks for rather than by who is asking.
	for _, marker := range []string{"client_id", "dcql_query", "response_type"} {
		if _, ok := m[marker]; ok {
			rt, req := buildVPFromJSON(m)
			return rt, req, nil
		}
	}

	return 0, nil, fmt.Errorf("JSON does not contain VCI or VP markers (credential_issuer, client_id, dcql_query, response_type)")
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
	req.ResponseURI = DeriveResponseURI(req.ClientID, req.ResponseMode, jsonutil.GetString(m, "response_uri"))
	req.Scope = jsonutil.GetString(m, "scope")
	if cm := jsonutil.GetMap(m, "client_metadata"); cm != nil {
		req.ClientMetadata = cm
	}

	if dq := jsonutil.GetMap(m, "dcql_query"); dq != nil {
		req.DCQLQuery = dq
	}

	return TypeVP, req
}
