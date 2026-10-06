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

package demorp

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// The issuer metadata lists every credential template beside the ticket,
// named after the template, with the type the template carries.
func TestIssuerMetadataListsTheTemplates(t *testing.T) {
	d, _, _ := newDemoRP(t)
	code, doc := doJSON(t, d.IssuerHandler(), "GET", "/.well-known/openid-credential-issuer", "", nil)
	if code != http.StatusOK {
		t.Fatalf("metadata: %d %v", code, doc)
	}
	configs, _ := doc["credential_configurations_supported"].(map[string]any)
	for id, want := range map[string]map[string]string{
		ticketConfigurationID: {"format": "dc+sd-jwt", "vct": TicketVCT},
		"pid-sdjwt":           {"format": "dc+sd-jwt", "vct": mock.DefaultPIDVCT},
		"german-pid-sdjwt":    {"format": "dc+sd-jwt", "vct": mock.GermanPIDVCT},
		"pid-mdoc":            {"format": "mso_mdoc", "doctype": mock.PIDNamespace},
		"german-pid-mdoc":     {"format": "mso_mdoc", "doctype": mock.PIDNamespace},
	} {
		entry, _ := configs[id].(map[string]any)
		if entry == nil {
			t.Errorf("configuration %s is missing", id)
			continue
		}
		for key, value := range want {
			if entry[key] != value {
				t.Errorf("configuration %s %s = %v, want %s", id, key, entry[key], value)
			}
		}
	}
}

// A template's logo and card image reach the issuer metadata. The issuer
// serves bundled and uploaded images itself and links an https image directly.
func TestIssuerMetadataCarriesTheTemplateImages(t *testing.T) {
	d, w, _ := newDemoRP(t)
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`
	if _, err := credtemplate.Save(w.Templates, credtemplate.Template{
		Name: "uploaded-badge", Format: "sdjwt", VCT: "urn:example:badge", Claims: map[string]any{"name": "x"},
		Display: &credtemplate.TemplateDisplay{
			Logo:            "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg)),
			LogoAltText:     "Badge",
			BackgroundImage: "https://images.example/badge.png",
		},
	}); err != nil {
		t.Fatal(err)
	}
	_, doc := doJSON(t, d.IssuerHandler(), "GET", "/.well-known/openid-credential-issuer", "", nil)
	configs, _ := doc["credential_configurations_supported"].(map[string]any)
	issuer := d.issuerID()
	for id, want := range map[string][2]string{
		"pid-sdjwt":        {issuer + "/templates/pid-sdjwt/logo", ""},
		"german-pid-sdjwt": {issuer + "/templates/german-pid-sdjwt/logo", issuer + "/templates/german-pid-sdjwt/background_image"},
		"italian-pid-mdoc": {issuer + "/templates/italian-pid-mdoc/logo", issuer + "/templates/italian-pid-mdoc/background_image"},
		"uploaded-badge":   {issuer + "/templates/uploaded-badge/logo", "https://images.example/badge.png"},
	} {
		entry, _ := configs[id].(map[string]any)
		metadata, _ := entry["credential_metadata"].(map[string]any)
		displays, _ := metadata["display"].([]any)
		if len(displays) != 1 {
			t.Fatalf("configuration %s display %v", id, metadata["display"])
		}
		display := displays[0].(map[string]any)
		logo, _ := display["logo"].(map[string]any)
		if logo["uri"] != want[0] || logo["alt_text"] == "" {
			t.Errorf("configuration %s logo %v, want %s", id, logo, want[0])
		}
		background, _ := display["background_image"].(map[string]any)
		if want[1] == "" && background != nil || want[1] != "" && (background == nil || background["uri"] != want[1]) {
			t.Errorf("configuration %s background_image %v, want %q", id, background, want[1])
		}
	}

	for path, wantType := range map[string]string{
		"/templates/uploaded-badge/logo":               "image/svg+xml",
		"/templates/german-pid-sdjwt/logo":             "image/svg+xml",
		"/templates/german-pid-sdjwt/background_image": "image/jpeg",
	} {
		rec := httptest.NewRecorder()
		d.IssuerHandler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != wantType || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "sandbox") {
			t.Errorf("GET %s = %d %q %q", path, rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Content-Security-Policy"))
		}
	}
	for _, path := range []string{"/templates/uploaded-badge/background_image", "/templates/unknown/logo", "/templates/pid-sdjwt/other"} {
		rec := httptest.NewRecorder()
		d.IssuerHandler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}

// The eudi-dev wallet redeems a German PID offer into a German PID in each
// format, signed by the wallet's PID signer. Each format gets its own offer
// because the wallet redeems only the first configuration in an offer.
func TestOfferOfTemplatesIssuesThem(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	created := postJSONTo(t, ts.URL+"/issuer/api/offers?credential=german-pid-sdjwt&credential=german-pid-mdoc", "")
	offerURI, _ := created["offer_uri"].(string)
	if offerURI == "" {
		t.Fatalf("unexpected offer response: %v", created)
	}
	offer := getJSONFrom(t, offerURI)
	ids, _ := offer["credential_configuration_ids"].([]any)
	if len(ids) != 2 || ids[0] != "german-pid-sdjwt" || ids[1] != "german-pid-mdoc" {
		t.Fatalf("offer names %v, want the two German PID configurations", ids)
	}

	known := make(map[string]bool)
	for _, c := range w.GetCredentials() {
		known[c.ID] = true
	}
	for _, id := range []string{"german-pid-sdjwt", "german-pid-mdoc"} {
		created := postJSONTo(t, ts.URL+"/issuer/api/offers?credential="+id, "")
		schemeURI, _ := created["scheme_uri"].(string)
		result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
		if result["error"] != nil {
			t.Fatalf("accepting the %s offer failed: %v", id, result["error"])
		}
	}
	var sdjwt, mdoc int
	for _, c := range w.GetCredentials() {
		switch {
		case c.Format == "dc+sd-jwt" && c.VCT == mock.GermanPIDVCT:
			sdjwt++
		case c.Format == "mso_mdoc" && c.DocType == mock.PIDNamespace && !known[c.ID]:
			mdoc++
		}
	}
	if sdjwt == 0 || mdoc == 0 {
		t.Errorf("wallet holds %d German PID SD-JWT and %d demo-issued PID mdoc credentials, want one of each", sdjwt, mdoc)
	}
	// The wallet fetches the card images from the issuer metadata and keeps them.
	for _, c := range w.GetCredentials() {
		if c.Format == "dc+sd-jwt" && c.VCT == mock.GermanPIDVCT && !known[c.ID] {
			if c.Display == nil || !strings.HasPrefix(c.Display.LogoURI, "data:image/svg+xml") || !strings.HasPrefix(c.Display.BackgroundURI, "data:image/jpeg") {
				t.Errorf("issued German PID display %+v, want the flag logo and the specimen image", c.Display)
			}
		}
	}
}

// An offer for a configuration the issuer does not have is refused, and a
// credential request for a configuration the offer did not name is refused.
func TestOfferRefusesUnknownConfigurations(t *testing.T) {
	d, _, _ := newDemoRP(t)
	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/api/offers?credential=no-such-template", "", nil)
	if code != http.StatusBadRequest {
		t.Errorf("offer for an unknown configuration: %d %v, want 400", code, doc)
	}
	if status, errResp := d.checkRequestedCredential(credentialRequest{CredentialConfigurationID: "german-pid-sdjwt"}, []string{ticketConfigurationID}); status != http.StatusBadRequest || errResp["error"] != "unknown_credential_configuration" {
		t.Errorf("credential request outside the offer: %d %v", status, errResp)
	}
}
