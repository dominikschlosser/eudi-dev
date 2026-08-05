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

package format

import "testing"

func TestDetect_SDJWT(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  CredentialFormat
	}{
		{"with disclosures", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig~disc1~disc2~", FormatSDJWT},
		{"single disclosure", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig~disc1~", FormatSDJWT},
		{"trailing tilde only", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig~", FormatSDJWT},
		{"plain JWT no tilde", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig", FormatJWT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.input)
			if got != tt.want {
				t.Errorf("Detect(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestDetect_MDOC(t *testing.T) {
	// 0xa2 = CBOR map(2). A valid CBOR start byte
	hexMDOC := "a26a6e616d65537061636573a0"
	got := Detect(hexMDOC)
	if got != FormatMDOC {
		t.Errorf("Detect(hex mDOC) = %q, want %q", got, FormatMDOC)
	}
}

func TestDetect_Unknown(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"random text", "hello world"},
		{"just dots", "a.b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.input)
			if got != FormatUnknown {
				t.Errorf("Detect(%q) = %q, want %q", tt.input, got, FormatUnknown)
			}
		})
	}
}

func TestDetect_OID4VCI_URIScheme(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"basic", "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%7D"},
		{"haip-vci", "haip-vci://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%7D"},
		{"uppercase", "OpenID-Credential-Offer://?credential_offer=test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.input)
			if got != FormatOID4VCI {
				t.Errorf("Detect(%q) = %q, want %q", tt.name, got, FormatOID4VCI)
			}
		})
	}
}

func TestDetect_OID4VP_URIScheme(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"openid4vp", "openid4vp://?client_id=did:example:123&response_type=vp_token"},
		{"haip-vp", "haip-vp://?client_id=did:example:123&response_type=vp_token"},
		{"eudi", "eudi-openid4vp://?client_id=did:example:123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.input)
			if got != FormatOID4VP {
				t.Errorf("Detect(%q) = %q, want %q", tt.name, got, FormatOID4VP)
			}
		})
	}
}

func TestDetect_RejectsLegacyHAIPScheme(t *testing.T) {
	if got := Detect("haip://?client_id=did:example:123&response_type=vp_token"); got != FormatUnknown {
		t.Fatalf("Detect(legacy haip://) = %q, want %q", got, FormatUnknown)
	}
}

func TestDetect_OID4_HTTPURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  CredentialFormat
	}{
		{"vci credential_offer", "https://issuer.example.com/offer?credential_offer=%7B%7D", FormatOID4VCI},
		{"vci credential_offer_uri", "https://issuer.example.com/offer?credential_offer_uri=https://example.com/offer.json", FormatOID4VCI},
		{"vp client_id", "https://verifier.example.com/auth?client_id=did:example:123&response_type=vp_token", FormatOID4VP},
		{"vp request_uri", "https://verifier.example.com/auth?request_uri=https://example.com/req.jwt", FormatOID4VP},
		{"plain url no params", "https://example.com/some/path", FormatUnknown},
		{"url with unrelated params", "https://example.com/?foo=bar", FormatUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.input)
			if got != tt.want {
				t.Errorf("Detect(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestDetect_OID4_JWT(t *testing.T) {
	// Build JWTs with specific payload keys
	encHeader := EncodeBase64URL([]byte(`{"alg":"ES256"}`))

	vciPayload := EncodeBase64URL([]byte(`{"credential_issuer":"https://issuer.example.com"}`))
	vciJWT := encHeader + "." + vciPayload + ".sig"

	vpPayload := EncodeBase64URL([]byte(`{"client_id":"did:example:123","response_type":"vp_token"}`))
	vpJWT := encHeader + "." + vpPayload + ".sig"

	plainPayload := EncodeBase64URL([]byte(`{"iss":"test","sub":"user"}`))
	plainJWT := encHeader + "." + plainPayload + ".sig"

	tests := []struct {
		name  string
		input string
		want  CredentialFormat
	}{
		{"vci jwt", vciJWT, FormatOID4VCI},
		{"vp jwt", vpJWT, FormatOID4VP},
		{"plain jwt", plainJWT, FormatJWT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.input)
			if got != tt.want {
				t.Errorf("Detect(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestDetect_OID4_JSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  CredentialFormat
	}{
		{"vci json", `{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["pid"]}`, FormatOID4VCI},
		{"vp json", `{"client_id":"did:example:123","response_type":"vp_token"}`, FormatOID4VP},
		{"plain json", `{"foo":"bar"}`, FormatUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.input)
			if got != tt.want {
				t.Errorf("Detect(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestDetect_TrustList_JWT(t *testing.T) {
	// Build a JWT with the ETSI LoTE wrapper in the payload.
	encHeader := EncodeBase64URL([]byte(`{"alg":"ES256"}`))
	payload := EncodeBase64URL([]byte(`{"LoTE":{"TrustedEntitiesList":[{"TrustedEntityInformation":{"TEName":[{"value":"Test"}]}}]}}`))
	jwt := encHeader + "." + payload + ".sig"

	got := Detect(jwt)
	if got != FormatTrustList {
		t.Errorf("Detect(trust list JWT) = %q, want %q", got, FormatTrustList)
	}
}

func TestDetect_TrustList_JSON(t *testing.T) {
	payload := `{"LoTE":{"ListAndSchemeInformation":{"LoTEType":"http://uri.etsi.org/19602/LoTEType/local"}}}`
	if got := Detect(payload); got != FormatTrustList {
		t.Errorf("Detect(trust list JSON) = %q, want %q", got, FormatTrustList)
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"abcdef01", true},
		{"ABCDEF01", true},
		{"0123456789abcdef", true},
		{"abc", false},    // odd length
		{"xyz123", false}, // non-hex chars
		{"", false},       // empty
		{"a", false},      // too short
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isHex(tt.input)
			if got != tt.want {
				t.Errorf("isHex(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsCBORStart(t *testing.T) {
	tests := []struct {
		b    byte
		want bool
	}{
		{0xa0, true},  // empty CBOR map
		{0xa2, true},  // CBOR map(2)
		{0xbf, true},  // CBOR map indefinite
		{0xd8, true},  // CBOR tag
		{0x80, true},  // CBOR array(0)
		{0x00, false}, // CBOR unsigned int
		{0x60, false}, // CBOR text string
	}
	for _, tt := range tests {
		got := isCBORStart(tt.b)
		if got != tt.want {
			t.Errorf("isCBORStart(0x%02x) = %v, want %v", tt.b, got, tt.want)
		}
	}
}
