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
	"fmt"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// ParseAuthorizationRequest parses an OID4VP authorization request from a URI or query params.
func ParseAuthorizationRequest(raw string) (*oid4vc.AuthorizationRequest, error) {
	return ParseAuthorizationRequestWithOptions(raw, oid4vc.ParseOptions{})
}

// ParseAuthorizationRequestWithOptions is like ParseAuthorizationRequest but accepts
// ParseOptions for custom behavior (e.g. request_uri_method=post with wallet_metadata).
func ParseAuthorizationRequestWithOptions(raw string, opts oid4vc.ParseOptions) (*oid4vc.AuthorizationRequest, error) {
	raw = strings.TrimSpace(raw)

	reqType, result, err := oid4vc.ParseWithOptions(raw, opts)
	if err != nil {
		return nil, fmt.Errorf("parsing authorization request: %w", err)
	}

	if reqType != oid4vc.TypeVP {
		return nil, fmt.Errorf("expected VP authorization request, got VCI")
	}

	authReq, ok := result.(*oid4vc.AuthorizationRequest)
	if !ok {
		return nil, fmt.Errorf("unexpected result type")
	}

	return authReq, nil
}

// ParseAuthorizationRequestFromParams parses an authorization request from URL query parameters.
func ParseAuthorizationRequestFromParams(params url.Values) (*oid4vc.AuthorizationRequest, error) {
	// Build a synthetic URI for the oid4vc parser
	u := url.URL{
		Scheme:   "openid4vp",
		Host:     "authorize",
		RawQuery: params.Encode(),
	}
	return ParseAuthorizationRequest(u.String())
}

// GetResponseURI returns the URI where the VP response should be posted.
func GetResponseURI(authReq *oid4vc.AuthorizationRequest) string {
	if authReq.ResponseURI != "" {
		return authReq.ResponseURI
	}
	return authReq.RedirectURI
}

// GetResponseMode returns the response mode from the auth request.
func GetResponseMode(authReq *oid4vc.AuthorizationRequest) string {
	if authReq.ResponseMode != "" {
		return authReq.ResponseMode
	}
	return "direct_post"
}
