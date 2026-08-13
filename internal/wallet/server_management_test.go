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
	"net/http"
	"strings"
	"testing"
)

func TestGetCredentialByID(t *testing.T) {
	srv := newTestServer(t, true)
	creds := srv.wallet.GetCredentials()
	if len(creds) == 0 {
		t.Fatal("expected test credentials")
	}

	resp := serverRequest(t, srv, http.MethodGet, "/api/credentials/"+creds[0].ID, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	if result["id"] != creds[0].ID {
		t.Errorf("expected id %q, got %v", creds[0].ID, result["id"])
	}
	if result["format"] != creds[0].Format {
		t.Errorf("expected format %q, got %v", creds[0].Format, result["format"])
	}
	if result["raw"] != creds[0].Raw {
		t.Error("expected raw credential in response")
	}
}

func TestGetCredentialByIDNotFound(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodGet, "/api/credentials/nonexistent", "")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.Code)
	}
}

func TestDeleteAllCredentials(t *testing.T) {
	srv := newTestServer(t, true)
	before := len(srv.wallet.GetCredentials())
	if before == 0 {
		t.Fatal("expected test credentials")
	}

	resp := serverRequest(t, srv, http.MethodDelete, "/api/credentials", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	if int(result["deleted"].(float64)) != before {
		t.Errorf("expected %d deleted, got %v", before, result["deleted"])
	}
	if remaining := len(srv.wallet.GetCredentials()); remaining != 0 {
		t.Errorf("expected empty wallet, got %d credentials", remaining)
	}
}

func TestIssueCredentialAPI(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantFormat string
	}{
		{"sdjwt with defaults", `{"format": "sdjwt"}`, "dc+sd-jwt"},
		{"sdjwt with pid claims", `{"format": "sdjwt", "pid": true, "omit": ["place_of_birth"]}`, "dc+sd-jwt"},
		{"jwt with custom claims", `{"format": "jwt", "claims": {"given_name": "Erika"}, "vct": "urn:example:vct"}`, "jwt_vc_json"},
		{"mdoc with defaults", `{"format": "mdoc", "exp": "24h", "nbf": "-1h"}`, "mso_mdoc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, true)
			resp := serverRequest(t, srv, http.MethodPost, "/api/issue", tt.body)
			if resp.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
			}
			result := decodeJSON(t, resp)
			if result["format"] != tt.wantFormat {
				t.Errorf("expected format %q, got %v", tt.wantFormat, result["format"])
			}
			raw, _ := result["raw"].(string)
			if raw == "" {
				t.Fatal("expected raw credential in response")
			}
			id, _ := result["id"].(string)
			if _, ok := srv.wallet.GetCredential(id); !ok {
				t.Errorf("expected credential %q stored in wallet", id)
			}
		})
	}
}

// A JWT VC carries the PID claim set plainly, so a PID request in that format
// has to work. It used to fail with a template-format error, because the
// template the PID flag picks for the caller was held to the same format rule
// as one they named themselves.
func TestIssueCredentialAPIPIDAsJWT(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", `{"format": "jwt", "pid": true}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	if result["format"] != "jwt_vc_json" {
		t.Errorf("expected format jwt_vc_json, got %v", result["format"])
	}
	claims, ok := result["claims"].(map[string]any)
	if !ok {
		t.Fatalf("expected claims object, got %v", result["claims"])
	}
	for _, name := range []string{"family_name", "given_name", "birthdate", "place_of_birth"} {
		if _, ok := claims[name]; !ok {
			t.Errorf("the issued JWT VC is missing the PID claim %q", name)
		}
	}
}

func TestIssueCredentialAPICustomClaims(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue",
		`{"format": "sdjwt", "claims": {"given_name": "Erika", "family_name": "Mustermann"}}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	claims, ok := result["claims"].(map[string]any)
	if !ok {
		t.Fatalf("expected claims object, got %v", result["claims"])
	}
	if claims["given_name"] != "Erika" {
		t.Errorf("expected given_name claim, got %v", claims["given_name"])
	}
}

func TestIssueCredentialAPINamespacedMDOCClaims(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue",
		`{"format": "mdoc", "claims": {"given_name": "Erika", "org.example.custom:loyalty_tier": "gold"}}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	claims, ok := result["claims"].(map[string]any)
	if !ok {
		t.Fatalf("expected claims object, got %v", result["claims"])
	}
	if claims["eu.europa.ec.eudi.pid.1:given_name"] != "Erika" {
		t.Errorf("expected given_name in default namespace, got claims %v", claims)
	}
	if claims["org.example.custom:loyalty_tier"] != "gold" {
		t.Errorf("expected loyalty_tier in custom namespace, got claims %v", claims)
	}
}

func TestIssueCredentialAPIInvalidRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"missing format", `{}`},
		{"unknown format", `{"format": "x509"}`},
		{"invalid json", `{`},
		{"invalid exp", `{"format": "sdjwt", "exp": "tomorrow"}`},
		{"invalid nbf", `{"format": "sdjwt", "nbf": "tomorrow"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, true)
			resp := serverRequest(t, srv, http.MethodPost, "/api/issue", tt.body)
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestGeneratePIDAPI(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.ClearCredentials()

	resp := serverRequest(t, srv, http.MethodPost, "/api/generate-pid", `{"claims": {"given_name": "Erika"}}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	creds := decodeJSONArray(t, resp)
	if len(creds) != 2 {
		t.Fatalf("expected 2 PID credentials, got %d", len(creds))
	}
	formats := map[string]bool{}
	for _, c := range creds {
		cred := c.(map[string]any)
		format := cred["format"].(string)
		formats[format] = true
		claims, _ := cred["claims"].(map[string]any)
		key := "given_name"
		if format == "mso_mdoc" {
			key = "eu.europa.ec.eudi.pid.1:given_name"
		}
		if claims[key] != "Erika" {
			t.Errorf("expected claim override applied for %s, got %v", format, claims[key])
		}
	}
	if !formats["dc+sd-jwt"] || !formats["mso_mdoc"] {
		t.Errorf("expected SD-JWT and mDoc PID credentials, got %v", formats)
	}
}

func TestGeneratePIDAPIEmptyBody(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodPost, "/api/generate-pid", "")
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestCertificateExportAPI(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.IssuerURL = "https://localhost:18086"
	store := NewWalletStore(t.TempDir())
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("initializing store: %v", err)
	}
	srv.SetStore(store)

	for _, path := range []string{"/api/certificates/ca", "/api/certificates/tls"} {
		t.Run(path, func(t *testing.T) {
			resp := serverRequest(t, srv, http.MethodGet, path, "")
			if resp.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
			}
			if !strings.HasPrefix(resp.Body.String(), "-----BEGIN CERTIFICATE-----") {
				t.Errorf("expected PEM certificate, got %q", resp.Body.String()[:40])
			}

			resp = serverRequest(t, srv, http.MethodGet, path+"?format=jwks", "")
			if resp.Code != http.StatusOK {
				t.Fatalf("expected 200 for jwks, got %d: %s", resp.Code, resp.Body.String())
			}
			jwks := decodeJSON(t, resp)
			if _, ok := jwks["keys"]; !ok {
				t.Errorf("expected JWKS document, got %v", jwks)
			}

			resp = serverRequest(t, srv, http.MethodGet, path+"?format=der", "")
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for unsupported format, got %d", resp.Code)
			}
		})
	}
}

func TestCertificateExportAPIWithoutStore(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodGet, "/api/certificates/ca", "")
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without store, got %d", resp.Code)
	}
}
