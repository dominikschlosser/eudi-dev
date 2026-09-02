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
	"net/http"
	"testing"
	"time"
)

// newTestServerWithStatusList creates a test server whose wallet has a
// configured status list, so issued credentials get managed status entries.
func newTestServerWithStatusList(t *testing.T) *Server {
	t.Helper()
	w := generateTestWallet(t)
	w.AutoAccept = true
	w.BaseURL = "https://wallet.test.example"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	return NewServer(w, 0, nil)
}

func TestCredentialListIncludesManagedStatus(t *testing.T) {
	srv := newTestServerWithStatusList(t)

	resp := serverRequest(t, srv, http.MethodGet, "/api/credentials", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	creds := decodeJSONArray(t, resp)
	if len(creds) == 0 {
		t.Fatal("expected credentials")
	}
	for _, item := range creds {
		cred := item.(map[string]any)
		status, ok := cred["status"].(map[string]any)
		if !ok {
			t.Fatalf("credential %v has no status info", cred["id"])
		}
		if status["managed"] != true {
			t.Errorf("expected managed status, got %v", status)
		}
		if status["status"] != float64(0) {
			t.Errorf("expected status 0 (valid), got %v", status["status"])
		}
		if status["uri"] == "" || status["uri"] == nil {
			t.Errorf("expected status list uri, got %v", status["uri"])
		}
	}
}

func TestCredentialListWithoutStatusListHasNoStatus(t *testing.T) {
	srv := newTestServer(t, true) // no BaseURL: no status list configured

	resp := serverRequest(t, srv, http.MethodGet, "/api/credentials", "")
	creds := decodeJSONArray(t, resp)
	for _, item := range creds {
		cred := item.(map[string]any)
		if _, ok := cred["status"]; ok {
			t.Errorf("credential %v should have no status info: %v", cred["id"], cred["status"])
		}
	}
}

func TestRevokeAndActivateCredential(t *testing.T) {
	srv := newTestServerWithStatusList(t)
	creds := srv.wallet.GetCredentials()
	id := creds[0].ID

	resp := serverRequest(t, srv, http.MethodPost, "/api/credentials/"+id+"/status", `{"status": 1}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	resp = serverRequest(t, srv, http.MethodGet, "/api/credentials/"+id+"/status", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("get status: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	status := decodeJSON(t, resp)
	if status["status"] != float64(1) || status["managed"] != true || status["source"] != "wallet" {
		t.Errorf("unexpected status after revoke: %v", status)
	}

	// The list reflects the revocation
	resp = serverRequest(t, srv, http.MethodGet, "/api/credentials/"+id, "")
	cred := decodeJSON(t, resp)
	if cred["status"].(map[string]any)["status"] != float64(1) {
		t.Errorf("summary status not updated: %v", cred["status"])
	}

	resp = serverRequest(t, srv, http.MethodPost, "/api/credentials/"+id+"/status", `{"status": 0}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("activate: expected 200, got %d", resp.Code)
	}
	resp = serverRequest(t, srv, http.MethodGet, "/api/credentials/"+id+"/status", "")
	status = decodeJSON(t, resp)
	if status["status"] != float64(0) {
		t.Errorf("unexpected status after activate: %v", status)
	}
}

func TestGetCredentialStatusWithoutReference(t *testing.T) {
	srv := newTestServer(t, true)
	creds := srv.wallet.GetCredentials()

	resp := serverRequest(t, srv, http.MethodGet, fmt.Sprintf("/api/credentials/%s/status", creds[0].ID), "")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for credential without status reference, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestCredentialStatusRefFormats(t *testing.T) {
	srv := newTestServerWithStatusList(t)
	for _, cred := range srv.wallet.GetCredentials() {
		ref := CredentialStatusRef(cred)
		if ref == nil {
			t.Errorf("expected status ref for %s credential", cred.Format)
			continue
		}
		if ref.URI == "" {
			t.Errorf("empty status uri for %s credential", cred.Format)
		}
	}
}

func TestGetConfigStatusListURL(t *testing.T) {
	srv := newTestServerWithStatusList(t)
	resp := serverRequest(t, srv, http.MethodGet, "/api/config", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	config := decodeJSON(t, resp)
	if config["status_list_url"] == "" || config["status_list_url"] == nil {
		t.Errorf("expected status_list_url, got %v", config["status_list_url"])
	}

	bare := NewServer(generateTestWallet(t), 0, nil)
	resp = serverRequest(t, bare, http.MethodGet, "/api/config", "")
	config = decodeJSON(t, resp)
	if config["status_list_url"] != "" {
		t.Errorf("expected empty status_list_url without base URL, got %v", config["status_list_url"])
	}
}

func TestGeneratePIDStatusWithIssuerURLOnly(t *testing.T) {
	// Only an issuer URL is set (no base URL), matching a wallet that has
	// served before. PID generation must still embed status references.
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8086"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	for _, cred := range w.GetCredentials() {
		info := w.CredentialStatusInfo(cred)
		if info == nil {
			t.Fatalf("%s credential has no status info", cred.Format)
		}
		if info["managed"] != true {
			t.Errorf("%s credential status not managed: %v", cred.Format, info)
		}
	}
}

func TestShutdownEndpoint(t *testing.T) {
	srv := newTestServer(t, true)
	done := make(chan struct{})
	srv.ShutdownFunc = func() { close(done) }

	resp := serverRequest(t, srv, http.MethodPost, "/api/shutdown", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	result := decodeJSON(t, resp)
	if result["shutting_down"] != true {
		t.Errorf("unexpected response: %v", result)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown func not called")
	}
}
