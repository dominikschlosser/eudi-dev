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
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Importing a credential from the UI must leave an activity-log entry, the same
// as issuing or deleting one.
func TestImportCredentialLogsActivity(t *testing.T) {
	srv := newTestServer(t, false)
	raw := generateTestCredential(t, srv.wallet)

	before := len(srv.wallet.GetLog())
	rec := serverRequest(t, srv, "POST", "/api/credentials", raw)
	if rec.Code != http.StatusCreated {
		t.Fatalf("import status = %d: %s", rec.Code, rec.Body.String())
	}

	for _, e := range srv.wallet.GetLog()[before:] {
		if strings.Contains(e.Detail, "Imported") {
			return
		}
	}
	t.Error("expected an activity-log entry for the manual credential import")
}

// A presentation submitted through /api/presentations used to be validated
// twice (once in handlePresentationAPI, once in handleAuthFlow), so every
// validation warning was logged twice for a single flow. It must appear
// once now.
func TestPresentationAPILogsEachValidationWarningOnce(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.RequireHAIP = true
	srv.wallet.ValidationMode = ValidationModeDebug

	uri := "openid4vp://authorize?" + url.Values{
		"client_id":     {"redirect_uri:http://localhost/nowhere"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {"http://localhost/nowhere"},
		"nonce":         {"n-0S6_WzA2Mj"},
		"dcql_query":    {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}`},
	}.Encode()
	body, _ := json.Marshal(map[string]any{"uri": uri, "interactive": false})
	serverRequest(t, srv, "POST", "/api/presentations", string(body))

	counts := map[string]int{}
	for _, e := range srv.wallet.GetLog() {
		if e.Severity == severityWarning && strings.Contains(e.Detail, "does not follow") {
			counts[e.Detail]++
		}
	}
	if len(counts) == 0 {
		t.Fatal("expected at least one validation warning")
	}
	for detail, n := range counts {
		if n != 1 {
			t.Errorf("validation warning logged %d times, want 1: %s", n, detail)
		}
	}
}

// A tester's request carrying parameters no specification defines leaves a
// warning naming them, in every mode.
func TestUndefinedRequestParametersAreWarned(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.ValidationMode = ValidationModeDebug

	uri := "openid4vp://authorize?" + url.Values{
		"client_id":     {"redirect_uri:http://localhost/nowhere"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {"http://localhost/nowhere"},
		"nonce":         {"n-0S6_WzA2Mj"},
		"dcql_query":    {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}`},
		"my_test_field": {"whatever"},
	}.Encode()
	body, _ := json.Marshal(map[string]any{"uri": uri, "interactive": false})
	serverRequest(t, srv, "POST", "/api/presentations", string(body))

	for _, e := range srv.wallet.GetLog() {
		if e.Severity == severityWarning && strings.Contains(e.Detail, `"my_test_field"`) {
			return
		}
	}
	t.Error("expected a warning naming the undefined parameter my_test_field")
}
