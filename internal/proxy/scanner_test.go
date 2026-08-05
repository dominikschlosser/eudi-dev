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

package proxy

import (
	"testing"
)

func TestScanCEK(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantCEK string
	}{
		{
			name:    "wallet-style CEK log",
			line:    `2026/01/15 14:32:05 [VP] JWE content encryption key for proxy debugging: dGhpcyBpcyBhIHRlc3Qga2V5MTIz`,
			wantCEK: "dGhpcyBpcyBhIHRlc3Qga2V5MTIz",
		},
		{
			name:    "generic CEK log",
			line:    `CEK: abcdef0123456789ABCDEF`,
			wantCEK: "abcdef0123456789ABCDEF",
		},
		{
			name:    "content encryption key label",
			line:    `Content Encryption Key derived: AAAAAAAAAAAAAAAA_-test`,
			wantCEK: "AAAAAAAAAAAAAAAA_-test",
		},
		{
			name:    "no CEK",
			line:    `2026/01/15 14:32:05 Starting server on port 8080`,
			wantCEK: "",
		},
		{
			name:    "case insensitive cek",
			line:    `cek value: AAAAAAAAAAAAAAAA`,
			wantCEK: "AAAAAAAAAAAAAAAA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewOutputScanner()
			s.Scan(tt.line)
			if got := s.LastCEK(); got != tt.wantCEK {
				t.Errorf("LastCEK() = %q, want %q", got, tt.wantCEK)
			}
		})
	}
}

func TestScanCEKLastWins(t *testing.T) {
	s := NewOutputScanner()
	s.Scan(`CEK: firstkey1234567890`)
	s.Scan(`CEK: secondkey123456789`)
	if got := s.LastCEK(); got != "secondkey123456789" {
		t.Errorf("LastCEK() = %q, want last key", got)
	}
}

func TestScanCredentials(t *testing.T) {
	// A realistic-looking JWT (header.payload.signature, each part base64url)
	jwt := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	tests := []struct {
		name      string
		line      string
		wantCount int
		wantLabel string
	}{
		{
			name:      "vp_token line",
			line:      `Received vp_token: ` + jwt,
			wantCount: 1,
			wantLabel: "vp_token",
		},
		{
			name:      "credential line",
			line:      `Issued credential: ` + jwt,
			wantCount: 1,
			wantLabel: "credential",
		},
		{
			name:      "sd-jwt with disclosures",
			line:      `SD-JWT: ` + jwt + `~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~`,
			wantCount: 1,
			wantLabel: "sd-jwt",
		},
		{
			name:      "no credentials",
			line:      `Server started on port 8080`,
			wantCount: 0,
		},
		{
			name:      "generic jwt",
			line:      `Token: ` + jwt,
			wantCount: 1,
			wantLabel: "jwt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewOutputScanner()
			s.Scan(tt.line)
			creds := s.Credentials()
			if len(creds) != tt.wantCount {
				t.Fatalf("got %d credentials, want %d", len(creds), tt.wantCount)
			}
			if tt.wantCount > 0 && creds[0].Label != tt.wantLabel {
				t.Errorf("label = %q, want %q", creds[0].Label, tt.wantLabel)
			}
		})
	}
}

func TestScanJWK(t *testing.T) {
	s := NewOutputScanner()
	// A line containing a JWK with private key "d" parameter
	line := `Verifier key: {"kty":"EC","crv":"P-256","x":"abc","y":"def","d":"privatekeyvalue"}`
	s.Scan(line)

	jwk := s.LastJWK()
	if jwk == "" {
		t.Fatal("expected JWK to be stored")
	}
	if !contains(jwk, `"d":"privatekeyvalue"`) {
		t.Errorf("expected JWK to contain private key, got %q", jwk)
	}
}

func TestScanJWKKeycloakFormat(t *testing.T) {
	s := NewOutputScanner()
	// Realistic keycloak log line
	line := `2026-03-02 10:15:59,849 TRACE [de.arbeitsagentur.keycloak.oid4vp.service] Generated ephemeral encryption key: kid=9eabcc30, jwk={"kty":"EC","d":"soZ-J57DCNYJZ5k_0aUQopc7ehTAhab0da6-Cs4jRr0","crv":"P-256","kid":"9eabcc30","x":"TAEcOVsZF8NTgBoJoTSZlaFU_RTHcJZni63UiyB4_vQ","y":"1g_bke-8_ZPWtPFohNeBM0hHqX69oSu_yUE4Sfp5AFk","alg":"ECDH-ES"}`
	s.Scan(line)

	jwk := s.LastJWK()
	if jwk == "" {
		t.Fatal("expected JWK to be stored from keycloak log line")
	}
	if !contains(jwk, `"d":"soZ-J57DCNYJZ5k_0aUQopc7ehTAhab0da6-Cs4jRr0"`) {
		t.Errorf("expected JWK to contain private key d, got %q", jwk)
	}
}

func TestScanJWKLastWins(t *testing.T) {
	s := NewOutputScanner()
	s.Scan(`Key1: {"kty":"EC","crv":"P-256","x":"a","y":"b","d":"first"}`)
	s.Scan(`Key2: {"kty":"EC","crv":"P-256","x":"c","y":"d","d":"second"}`)
	if !contains(s.LastJWK(), `"d":"second"`) {
		t.Errorf("expected last JWK to win, got %q", s.LastJWK())
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}
func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestScanVPTokenJSON(t *testing.T) {
	s := NewOutputScanner()
	// Simulate keycloak log with mDoc CBOR data in VP token
	mdocData := "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBld2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xbGlzc3VlclNpZ25lZKJqbmFtZVNwYWNlc6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGG"
	line := `Processing VP token (length=3600): {"cred2":["` + mdocData + `"]}`
	s.Scan(line)

	creds := s.Credentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Raw != mdocData {
		t.Errorf("expected mDoc data, got %q", creds[0].Raw)
	}
	if creds[0].Label != "vp_token.cred2[0]" {
		t.Errorf("expected label vp_token.cred2[0], got %q", creds[0].Label)
	}
}

func TestScanVPTokenJSONMultipleCredentials(t *testing.T) {
	s := NewOutputScanner()
	mdoc1 := "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBld2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xbGlzc3VlclNpZ25lZKJqbmFtZVNwYWNlc6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGG"
	mdoc2 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	line := `VP token received: {"cred1":"` + mdoc1 + `","cred2":["` + mdoc2 + `"]}`
	s.Scan(line)

	creds := s.Credentials()
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d: %v", len(creds), creds)
	}
}

func TestScanVPTokenJSONSkipsJWTs(t *testing.T) {
	s := NewOutputScanner()
	// JWT-shaped tokens starting with eyJ should not be double-counted
	jwt := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	line := `VP token: {"cred1":"` + jwt + `"}`
	s.Scan(line)

	// The JWT should be picked up by scanCredentials, not by scanVPTokenJSON
	creds := s.Credentials()
	for _, c := range creds {
		if c.Label == "vp_token.cred1" {
			t.Error("JWT should not be detected by scanVPTokenJSON (starts with eyJ)")
		}
	}
}

func TestScanVPTokenJSONIgnoresNonVPLines(t *testing.T) {
	s := NewOutputScanner()
	line := `Some other data: {"key":"` + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + `"}`
	s.Scan(line)

	// scanVPTokenJSON should not trigger on lines without vp_token/VP token
	creds := s.Credentials()
	for _, c := range creds {
		if c.Label == "vp_token.key" {
			t.Error("should not detect credentials on non-VP-token lines")
		}
	}
}

func TestDrainCredentials(t *testing.T) {
	jwt := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	s := NewOutputScanner()
	s.Scan("Token: " + jwt)

	drained := s.DrainCredentials()
	if len(drained) != 1 {
		t.Fatalf("DrainCredentials() returned %d, want 1", len(drained))
	}

	// After drain, credentials should be empty
	if remaining := s.Credentials(); len(remaining) != 0 {
		t.Errorf("after drain, Credentials() returned %d, want 0", len(remaining))
	}
}

func TestScanSkipsOAuthAuthzReqJWT(t *testing.T) {
	// oauth-authz-req+jwt header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
	reqObj := "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	s := NewOutputScanner()
	s.Scan("Request Object: " + reqObj)
	if len(s.Credentials()) != 0 {
		t.Error("oauth-authz-req+jwt should not be detected as a credential")
	}
}

func TestScanShortTokenIgnored(t *testing.T) {
	s := NewOutputScanner()
	// eyJ followed by very short content. Should be ignored
	s.Scan("eyJhbGci.eyJz.abc")
	if len(s.Credentials()) != 0 {
		t.Error("short token should be ignored")
	}
}
