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

// Package oid4vc parses OID4VCI credential offers and OID4VP authorization requests.
package oid4vc

// RequestType identifies whether a request is VCI or VP.
type RequestType int

const (
	TypeVCI RequestType = iota
	TypeVP
)

// CredentialOffer represents a parsed OID4VCI credential offer.
type CredentialOffer struct {
	CredentialIssuer           string
	CredentialConfigurationIDs []string
	Grants                     OfferGrants
	FullJSON                   map[string]any
}

// OfferGrants holds the grant types in a credential offer.
type OfferGrants struct {
	PreAuthorizedCode string
	TxCode            map[string]any // input_mode, length, description
	AuthorizationCode string
	IssuerState       string
}

// AuthorizationRequest represents a parsed OID4VP authorization request.
type AuthorizationRequest struct {
	ClientID         string
	ResponseType     string
	ResponseMode     string
	Nonce            string
	State            string
	RedirectURI      string
	ResponseURI      string
	Scope            string
	RequestURIMethod string // "get" (default) or "post" per OID4VP 1.0 §5.10
	// RequestURI is the request_uri the request object was fetched from, empty
	// when the request carried its parameters directly or passed the object
	// inline. HAIP 1.0 §5.1 requires the object to be delivered this way, so
	// the difference has to survive parsing.
	RequestURI     string
	ClientMetadata map[string]any
	DCQLQuery      map[string]any
	RequestObject  *RequestObjectJWT
	FullParams     map[string]string
	FullJSON       map[string]any
}

// RequestObjectJWT holds the decoded header and payload of a JWT request object.
type RequestObjectJWT struct {
	Raw     string
	Header  map[string]any
	Payload map[string]any
}

// ParseOptions configures optional behavior for the OID4VP/VCI parser.
type ParseOptions struct {
	// FetchRequestURI is called to retrieve the request object from request_uri.
	// url is the request_uri value, method is "get" or "post".
	// If nil, format.FetchURL (HTTP GET) is used regardless of method.
	FetchRequestURI func(url string, method string) (string, error)
}
