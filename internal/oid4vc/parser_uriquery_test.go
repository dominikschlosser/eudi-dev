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
	"net/url"
	"testing"
)

// TestURIQueryValues_PlusStaysLiteral checks the RFC 3986 reading of a
// request URI query: "+" is a plus sign, so a dcql_query naming the
// dc+sd-jwt format survives even when the sender does not percent-encode it.
func TestURIQueryValues_PlusStaysLiteral(t *testing.T) {
	u, err := url.Parse(`openid4vp://?dcql_query={"credentials":[{"format":"dc+sd-jwt"}]}&nonce=a%2Bb%20c`)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	values := URIQueryValues(u)
	if got := values.Get("dcql_query"); got != `{"credentials":[{"format":"dc+sd-jwt"}]}` {
		t.Errorf("dcql_query = %q, want the literal plus preserved", got)
	}
	if got := values.Get("nonce"); got != "a+b c" {
		t.Errorf("nonce = %q, want percent escapes decoded", got)
	}
}

// TestParseVPURI_UnencodedPlusInDCQL checks the whole VP URI parse path with
// an unencoded plus, the form the OIDF conformance suite's url_query request
// method sends.
func TestParseVPURI_UnencodedPlusInDCQL(t *testing.T) {
	raw := `openid4vp://?client_id=redirect_uri:https://verifier.example/cb&response_type=vp_token&response_mode=direct_post&nonce=n-0` +
		`&response_uri=https://verifier.example/cb&dcql_query={"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}`
	reqType, parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("request type = %v, want TypeVP", reqType)
	}
	authReq := parsed.(*AuthorizationRequest)
	credentials, ok := authReq.DCQLQuery["credentials"].([]any)
	if !ok || len(credentials) != 1 {
		t.Fatalf("dcql credentials = %#v, want one entry", authReq.DCQLQuery["credentials"])
	}
	format := credentials[0].(map[string]any)["format"]
	if format != "dc+sd-jwt" {
		t.Errorf("format = %v, want dc+sd-jwt", format)
	}
}

// TestParseVPURI_ResponseURIDerivedFromRedirectURIClientID checks OID4VP 1.0
// §5.9.3: with the redirect_uri client id prefix the prefix value is the
// response endpoint, so a request omitting response_uri still names one.
func TestParseVPURI_ResponseURIDerivedFromRedirectURIClientID(t *testing.T) {
	raw := `openid4vp://?client_id=redirect_uri:https://verifier.example/cb&response_type=vp_token&response_mode=direct_post.jwt&nonce=n-0` +
		`&dcql_query={"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}`
	_, parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	authReq := parsed.(*AuthorizationRequest)
	if authReq.ResponseURI != "https://verifier.example/cb" {
		t.Errorf("response_uri = %q, want it derived from the client_id", authReq.ResponseURI)
	}
}
