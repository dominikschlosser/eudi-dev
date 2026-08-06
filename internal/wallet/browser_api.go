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
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/dominikschlosser/eudi-dev/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

const (
	BrowserAPIProtocolOpenID4VPUnsigned = "openid4vp-v1-unsigned"
	BrowserAPIProtocolOpenID4VPSigned   = "openid4vp-v1-signed"
	BrowserAPIProtocolOpenID4VPMulti    = "openid4vp-v1-multisigned"
)

type BrowserAPIRequestEnvelope struct {
	Digital BrowserAPIDigitalRequest `json:"digital"`
}

type BrowserAPIDigitalRequest struct {
	Requests []BrowserAPICredentialRequest `json:"requests"`
}

type BrowserAPICredentialRequest struct {
	Protocol string `json:"protocol"`
	Data     any    `json:"data"`
}

type BrowserAPIResult struct {
	Protocol string `json:"protocol"`
	Data     any    `json:"data"`
}

type AuthorizationResponseEnvelope struct {
	ResponseMode string
	Plain        map[string]any
	ResponseJWT  string
	CEK          []byte
	RedirectURI  string
}

func ParseBrowserAPIRequest(body BrowserAPIRequestEnvelope, opts oid4vc.ParseOptions, requestOrigin string) (string, *AuthorizationRequestParams, error) {
	for _, req := range body.Digital.Requests {
		switch req.Protocol {
		case BrowserAPIProtocolOpenID4VPUnsigned, BrowserAPIProtocolOpenID4VPSigned, BrowserAPIProtocolOpenID4VPMulti:
			params, err := parseBrowserAuthorizationRequest(req.Protocol, req.Data, opts, requestOrigin)
			if err != nil {
				return "", nil, err
			}
			return req.Protocol, params, nil
		}
	}
	return "", nil, fmt.Errorf("browser request did not contain a supported OpenID4VP protocol")
}

func parseBrowserAuthorizationRequest(protocol string, data any, opts oid4vc.ParseOptions, requestOrigin string) (*AuthorizationRequestParams, error) {
	var raw string

	switch protocol {
	case BrowserAPIProtocolOpenID4VPSigned:
		switch typed := data.(type) {
		case string:
			raw = typed
		case map[string]any:
			if requestJWT, ok := typed["request"].(string); ok && requestJWT != "" {
				raw = requestJWT
				break
			}
			if requestURI, ok := typed["request_uri"].(string); ok && requestURI != "" {
				params := url.Values{}
				for key, value := range typed {
					if text, ok := value.(string); ok {
						params.Set(key, text)
					}
				}
				raw = "openid4vp://authorize?" + params.Encode()
				break
			}
			return nil, fmt.Errorf("signed browser request must contain request or request_uri")
		default:
			return nil, fmt.Errorf("signed browser request data must be a JWT string or object")
		}
	case BrowserAPIProtocolOpenID4VPMulti:
		requestMap, ok := data.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("multisigned browser request data must be an object")
		}
		requestObject, ok := requestMap["request"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("multisigned browser request must contain a request object")
		}
		return parseMultiSignedBrowserAuthorizationRequest(requestObject, opts, requestOrigin)
	case BrowserAPIProtocolOpenID4VPUnsigned:
		payload := data
		if requestMap, ok := data.(map[string]any); ok {
			if _, ok := requestMap["client_id"].(string); !ok || requestMap["client_id"] == "" {
				if requestOrigin != "" {
					cloned := make(map[string]any, len(requestMap)+1)
					for key, value := range requestMap {
						cloned[key] = value
					}
					cloned["client_id"] = "web-origin:" + requestOrigin
					payload = cloned
				}
			}
		}

		bytes, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshaling unsigned browser request: %w", err)
		}
		raw = string(bytes)
	default:
		return nil, fmt.Errorf("unsupported browser protocol %q", protocol)
	}

	parsed, err := ParseAuthorizationRequestWithOptions(raw, opts)
	if err != nil {
		return nil, err
	}

	return &AuthorizationRequestParams{
		ClientID:         parsed.ClientID,
		ResponseType:     parsed.ResponseType,
		ResponseMode:     parsed.ResponseMode,
		Nonce:            parsed.Nonce,
		State:            parsed.State,
		RequestOrigin:    requestOrigin,
		RedirectURI:      parsed.RedirectURI,
		ResponseURI:      parsed.ResponseURI,
		RequestURIMethod: parsed.RequestURIMethod,
		RequestURI:       parsed.RequestURI,
		ClientMetadata:   parsed.ClientMetadata,
		DCQLQuery:        parsed.DCQLQuery,
		RequestObject:    parsed.RequestObject,
		RequestPayload:   requestPayload(parsed.RequestObject, parsed.FullJSON),
	}, nil
}

func parseMultiSignedBrowserAuthorizationRequest(requestObject map[string]any, opts oid4vc.ParseOptions, requestOrigin string) (*AuthorizationRequestParams, error) {
	payload, _ := requestObject["payload"].(string)
	signatures, ok := requestObject["signatures"].([]any)
	if payload == "" || !ok || len(signatures) == 0 {
		return nil, fmt.Errorf("multisigned browser request must contain payload and signatures")
	}

	var firstCandidate *AuthorizationRequestParams
	for _, item := range signatures {
		signatureMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		protected, _ := signatureMap["protected"].(string)
		signature, _ := signatureMap["signature"].(string)
		if protected == "" || signature == "" {
			continue
		}

		raw := protected + "." + payload + "." + signature
		parsed, err := ParseAuthorizationRequestWithOptions(raw, opts)
		if err != nil {
			continue
		}

		clientID := parsed.ClientID
		if clientID == "" && parsed.RequestObject != nil {
			clientID = jsonutil.GetString(parsed.RequestObject.Header, "client_id")
		}

		candidate := &AuthorizationRequestParams{
			ClientID:         clientID,
			ResponseType:     parsed.ResponseType,
			ResponseMode:     parsed.ResponseMode,
			Nonce:            parsed.Nonce,
			State:            parsed.State,
			RequestOrigin:    requestOrigin,
			RedirectURI:      parsed.RedirectURI,
			ResponseURI:      parsed.ResponseURI,
			RequestURIMethod: parsed.RequestURIMethod,
			RequestURI:       parsed.RequestURI,
			ClientMetadata:   parsed.ClientMetadata,
			DCQLQuery:        parsed.DCQLQuery,
			RequestObject:    parsed.RequestObject,
			RequestPayload:   requestPayload(parsed.RequestObject, parsed.FullJSON),
		}
		if firstCandidate == nil {
			firstCandidate = candidate
		}

		if parsed.RequestObject != nil && clientID != "" && VerifyRequestObjectSignature(parsed.RequestObject) == "" {
			return candidate, nil
		}
	}

	if firstCandidate != nil {
		return firstCandidate, nil
	}
	return nil, fmt.Errorf("multisigned browser request did not contain a parseable signature")
}

func BuildBrowserAPIResult(protocol string, response *AuthorizationResponseEnvelope) (*BrowserAPIResult, error) {
	if response == nil {
		return nil, fmt.Errorf("authorization response is missing")
	}

	switch response.ResponseMode {
	case "dc_api.jwt":
		if response.ResponseJWT == "" {
			return nil, fmt.Errorf("dc_api.jwt response is missing response JWT")
		}
		return &BrowserAPIResult{
			Protocol: protocol,
			Data: map[string]any{
				"response": response.ResponseJWT,
			},
		}, nil
	case "dc_api", "":
		return &BrowserAPIResult{
			Protocol: protocol,
			Data:     response.Plain,
		}, nil
	default:
		return nil, fmt.Errorf("response_mode %q cannot be returned via Browser API", response.ResponseMode)
	}
}
