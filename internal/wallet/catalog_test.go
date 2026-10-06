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
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

func diplomaCatalogEntry() CatalogAttestation {
	isLOTE := true
	return CatalogAttestation{
		Name: "University diploma",
		Credentials: []CatalogCredential{
			{Format: "dc+sd-jwt", Type: testDiplomaVCT, Claims: [][]any{{"degree"}, {"graduation_date"}}},
			{Format: "mso_mdoc", Type: "org.example.diploma.1", Claims: [][]any{{"org.example.diploma.1", "degree"}}},
		},
		Schema: AttestationSchema{
			RulebookURI:        "https://example.com/diploma-rulebook",
			AttestationLoS:     "iso_18045_moderate",
			TrustedAuthorities: []TrustAuthority{{FrameworkType: "etsi_tl", Value: "https://example.com/lote", IsLOTE: &isLOTE}},
		},
	}
}

func TestTheCatalogueListsThePIDTemplates(t *testing.T) {
	w := generateTestWallet(t)
	entries := w.CatalogAttestations("https://wallet.example")
	i := slices.IndexFunc(entries, func(e CatalogAttestation) bool { return e.Name == "EUDI PID" })
	if i < 0 {
		t.Fatalf("no EUDI PID entry in %d entries", len(entries))
	}
	pid := entries[i]
	if !pid.Template || len(pid.Credentials) != 2 || pid.Credentials[0].Type != mock.DefaultPIDVCT || pid.Credentials[1].Type != mock.PIDNamespace {
		t.Fatalf("EUDI PID %+v", pid)
	}
	s := pid.Schema
	if !strings.Contains(s.RulebookURI, "pid-rulebook.md") || s.AttestationLoS != "iso_18045_high" || s.BindingType != "key" {
		t.Errorf("schema %+v", s)
	}
	if len(s.TrustedAuthorities) != 1 || s.TrustedAuthorities[0].FrameworkType != "etsi_tl" ||
		s.TrustedAuthorities[0].Value != "https://wallet.example/api/trustlists/pid" || s.TrustedAuthorities[0].IsLOTE == nil || !*s.TrustedAuthorities[0].IsLOTE {
		t.Errorf("trusted authorities %+v, want the wallet's PID provider list", s.TrustedAuthorities)
	}
	if !slices.Equal(s.SupportedFormats, []string{"dc+sd-jwt", "mso_mdoc"}) || len(s.SchemaURIs) != 2 ||
		s.SchemaURIs[0].URI != "https://wallet.example/api/catalog/schemas/"+s.ID+"/dc+sd-jwt" {
		t.Errorf("formats %v, schema URIs %+v", s.SupportedFormats, s.SchemaURIs)
	}
	// The ids stay the same on every instance.
	if again := generateTestWallet(t).CatalogAttestations("https://other.example"); again[i].Schema.ID != s.ID {
		t.Errorf("template entry id changed: %s, then %s", s.ID, again[i].Schema.ID)
	}
}

// The schema of the TS11 API has exactly the members of the normative JSON
// schema (EC TS11 v1.0 Annex A.2, additionalProperties false).
func TestCatalogueSchemasFollowTheTS11DataModel(t *testing.T) {
	w := generateTestWallet(t)
	for _, entry := range w.CatalogAttestations("https://wallet.example") {
		encoded, err := json.Marshal(entry.Schema)
		if err != nil {
			t.Fatal(err)
		}
		var members map[string]any
		if err := json.Unmarshal(encoded, &members); err != nil {
			t.Fatal(err)
		}
		allowed := []string{"id", "version", "rulebookURI", "trustedAuthorities", "attestationLoS", "bindingType", "supportedFormats", "schemaURIs"}
		for name := range members {
			if !slices.Contains(allowed, name) {
				t.Errorf("%s: member %q is not in the TS11 schema", entry.Name, name)
			}
		}
		for _, required := range []string{"version", "rulebookURI", "attestationLoS", "bindingType", "supportedFormats", "schemaURIs"} {
			if members[required] == nil {
				t.Errorf("%s: required member %q is missing", entry.Name, required)
			}
		}
	}
}

func TestAddingToTheCatalogue(t *testing.T) {
	w := generateTestWallet(t)
	added, err := w.AddCatalogAttestation(diplomaCatalogEntry(), "https://wallet.example")
	if err != nil {
		t.Fatal(err)
	}
	if added.Schema.ID == "" || added.Schema.Version != "1.0.0" || added.Schema.BindingType != "key" || added.Template {
		t.Fatalf("added %+v, want an assigned id and the defaults", added.Schema)
	}
	sdjwt, ok := added.FormatSchema("dc+sd-jwt")
	if !ok || sdjwt["vct"] != testDiplomaVCT {
		t.Errorf("SD-JWT VC type metadata %v", sdjwt)
	}
	mdoc, ok := added.FormatSchema("mso_mdoc")
	if !ok || mdoc["docType"] != "org.example.diploma.1" {
		t.Errorf("mdoc schema %v", mdoc)
	}

	updated := added.Schema
	updated.Version = "1.1.0"
	if got, err := w.UpdateCatalogSchema(added.Schema.ID, updated, "https://wallet.example"); err != nil || got.Schema.Version != "1.1.0" {
		t.Fatalf("update: %v %+v", err, got.Schema)
	}
	updated.SchemaURIs = []SchemaURI{{FormatIdentifier: "dc+sd-jwt", URI: "https://elsewhere.example/schema"}}
	if _, err := w.UpdateCatalogSchema(added.Schema.ID, updated, "https://wallet.example"); err == nil {
		t.Error("an update changed the schema URIs")
	}

	fromTemplate := w.CatalogAttestations("https://wallet.example")[0].Schema.ID
	if err := w.DeleteCatalogAttestation(fromTemplate, "https://wallet.example"); err == nil {
		t.Error("an entry of a template was deleted")
	}
	if err := w.DeleteCatalogAttestation(added.Schema.ID, "https://wallet.example"); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.CatalogAttestation(added.Schema.ID, "https://wallet.example"); ok {
		t.Error("the deleted entry is still listed")
	}
}

func TestCatalogueEntriesAreChecked(t *testing.T) {
	w := generateTestWallet(t)
	for _, tc := range []struct {
		name   string
		change func(*CatalogAttestation)
		want   string
	}{
		{"no name", func(e *CatalogAttestation) { e.Name = " " }, "needs a name"},
		{"no formats", func(e *CatalogAttestation) { e.Credentials = nil }, "at least one format"},
		{"a format twice", func(e *CatalogAttestation) { e.Credentials[1].Format = "dc+sd-jwt" }, "listed twice"},
		{"another format", func(e *CatalogAttestation) { e.Credentials[0].Format = "ldp_vc" }, "not dc+sd-jwt or mso_mdoc"},
		{"no type", func(e *CatalogAttestation) { e.Credentials[0].Type = "" }, "needs its type"},
		{"an mdoc claim without namespace", func(e *CatalogAttestation) { e.Credentials[1].Claims = [][]any{{"degree"}} }, "namespace and an element"},
		{"an unknown level of security", func(e *CatalogAttestation) { e.Schema.AttestationLoS = "high" }, "attestationLoS"},
		{"an unknown binding type", func(e *CatalogAttestation) { e.Schema.BindingType = "device" }, "bindingType"},
		{"a version that is not semantic", func(e *CatalogAttestation) { e.Schema.Version = "v1" }, "semantic versioning"},
		{"isLOTE on another framework", func(e *CatalogAttestation) { e.Schema.TrustedAuthorities[0].FrameworkType = "aki" }, "isLOTE"},
		{"a relative rulebook", func(e *CatalogAttestation) { e.Schema.RulebookURI = "rulebook.md" }, "not an http or https URL"},
		{"a script rulebook", func(e *CatalogAttestation) { e.Schema.RulebookURI = "javascript:alert(1)" }, "not an http or https URL"},
		{"a script trusted list", func(e *CatalogAttestation) { e.Schema.TrustedAuthorities[0].Value = "javascript:alert(1)" }, "not an http or https URL"},
		{"the name of a template entry", func(e *CatalogAttestation) { e.Name = "eudi pid" }, "already lists"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := diplomaCatalogEntry()
			tc.change(&entry)
			if _, err := w.AddCatalogAttestation(entry, "https://wallet.example"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestTheCatalogueAPI(t *testing.T) {
	srv, ts := registrarServer(t)
	resp := serverRequest(t, srv, "POST", "/api/catalog/attestations", mustJSON(t, diplomaCatalogEntry()))
	if resp.Code != http.StatusCreated {
		t.Fatalf("POST: %d %s", resp.Code, resp.Body.String())
	}
	var added CatalogAttestation
	if err := json.Unmarshal(resp.Body.Bytes(), &added); err != nil {
		t.Fatal(err)
	}

	// GET /schemas is a signed, paginated list (TS11 v1.0 §5.3.1).
	list := serverRequest(t, srv, "GET", "/api/catalog/schemas?supportedFormats=dc%2Bsd-jwt,mso_mdoc&attestationLoS=iso_18045_moderate", "")
	if list.Code != http.StatusOK || list.Header().Get("Content-Type") != "application/jwt" {
		t.Fatalf("GET /schemas: %d %s", list.Code, list.Header().Get("Content-Type"))
	}
	var page struct {
		Iss  string `json:"iss"`
		Iat  int64  `json:"iat"`
		Data struct {
			Total  int                 `json:"total"`
			Limit  int                 `json:"limit"`
			Offset int                 `json:"offset"`
			Data   []AttestationSchema `json:"data"`
		} `json:"data"`
	}
	decodeCompactJWTPayload(t, list.Body.String(), &page)
	if page.Iss == "" || page.Iat == 0 || page.Data.Total != 1 || page.Data.Limit != 20 || len(page.Data.Data) != 1 || page.Data.Data[0].ID != added.Schema.ID {
		t.Fatalf("page %+v", page)
	}
	if bad := serverRequest(t, srv, "GET", "/api/catalog/schemas?limit=0", ""); bad.Code != http.StatusBadRequest {
		t.Errorf("limit=0: %d", bad.Code)
	}
	if huge := serverRequest(t, srv, "GET", "/api/catalog/schemas?offset=1&limit=9223372036854775807", ""); huge.Code != http.StatusOK {
		t.Errorf("a huge limit: %d", huge.Code)
	}
	if past := serverRequest(t, srv, "GET", "/api/catalog/schemas?offset=1000", ""); past.Code != http.StatusOK {
		t.Errorf("an offset past the end: %d", past.Code)
	}

	// The schema URI serves the format-specific schema.
	schemaURL := added.Schema.SchemaURIs[0].URI
	if !strings.HasPrefix(schemaURL, ts.URL) {
		t.Fatalf("schema URI %s is not on the wallet %s", schemaURL, ts.URL)
	}
	typeMetadata := serverRequest(t, srv, "GET", strings.TrimPrefix(schemaURL, ts.URL), "")
	if typeMetadata.Code != http.StatusOK || !strings.Contains(typeMetadata.Body.String(), `"vct":"`+testDiplomaVCT+`"`) {
		t.Fatalf("type metadata: %d %s", typeMetadata.Code, typeMetadata.Body.String())
	}

	// PUT replaces the SchemaMeta, DELETE removes it (§5.3.2, §5.3.3).
	updated := added.Schema
	updated.Version = "2.0.0"
	if put := serverRequest(t, srv, "PUT", "/api/catalog/schemas/"+added.Schema.ID, mustJSON(t, updated)); put.Code != http.StatusOK || !strings.Contains(put.Body.String(), `"version":"2.0.0"`) {
		t.Fatalf("PUT: %d %s", put.Code, put.Body.String())
	}
	fromTemplate := srv.wallet.CatalogAttestations(srv.wallet.RegistrarBase())[0].Schema.ID
	if del := serverRequest(t, srv, "DELETE", "/api/catalog/schemas/"+fromTemplate, ""); del.Code != http.StatusForbidden {
		t.Errorf("DELETE of a template entry: %d", del.Code)
	}
	if del := serverRequest(t, srv, "DELETE", "/api/catalog/schemas/"+added.Schema.ID, ""); del.Code != http.StatusNoContent {
		t.Fatalf("DELETE: %d %s", del.Code, del.Body.String())
	}
	if del := serverRequest(t, srv, "DELETE", "/api/catalog/schemas/"+added.Schema.ID, ""); del.Code != http.StatusNotFound {
		t.Errorf("DELETE again: %d", del.Code)
	}
}

func TestTheCatalogueIsStored(t *testing.T) {
	for name, open := range map[string]func(t *testing.T) *WalletStore{
		"file":   func(t *testing.T) *WalletStore { return NewWalletStore(t.TempDir()) },
		"entity": func(t *testing.T) *WalletStore { store, _ := entityStore(t); return store },
	} {
		t.Run(name, func(t *testing.T) {
			store := open(t)
			w, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.AddCatalogAttestation(diplomaCatalogEntry(), "https://wallet.example"); err != nil {
				t.Fatal(err)
			}
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if len(reloaded.Catalog) != 1 || reloaded.Catalog[0].Name != "University diploma" {
				t.Fatalf("stored catalogue %+v", reloaded.Catalog)
			}
			reloaded.ResetToBaseline()
			if len(reloaded.Catalog) != 0 {
				t.Error("a demo reset kept the added attestations")
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// A saved credential template is in the catalogue. Deleting the template
// removes it.
func TestASavedTemplateIsInTheCatalogue(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := credtemplate.Save(w.Templates, credtemplate.Template{
		Name: "library-card", Format: "sdjwt", VCT: "urn:example:library:1",
		Claims:  map[string]any{"member_id": "42", "address": map[string]any{"locality": "Utrecht"}},
		Display: &credtemplate.TemplateDisplay{Name: "Library card", Description: "Rulebook: https://library.example/rulebook"},
	}); err != nil {
		t.Fatal(err)
	}
	entries := w.CatalogAttestations("https://wallet.example")
	i := slices.IndexFunc(entries, func(e CatalogAttestation) bool { return e.Name == "Library card" })
	if i < 0 {
		t.Fatal("the saved template is not in the catalogue")
	}
	card := entries[i]
	want := [][]any{{"address"}, {"address", "locality"}, {"member_id"}}
	if !card.Template || card.Credentials[0].Type != "urn:example:library:1" || !reflect.DeepEqual(card.Credentials[0].Claims, want) {
		t.Errorf("entry %+v", card)
	}
	if card.Schema.RulebookURI != "https://library.example/rulebook" || card.Schema.AttestationLoS != "iso_18045_basic" || len(card.Schema.TrustedAuthorities) != 0 {
		t.Errorf("schema %+v, want the template's rulebook and the defaults of an attestation that is not a PID", card.Schema)
	}
	if err := w.DeleteCatalogAttestation(card.Schema.ID, "https://wallet.example"); err == nil || !strings.Contains(err.Error(), "credential template") {
		t.Errorf("deleting a template entry: %v", err)
	}
	if err := credtemplate.Delete(w.Templates, "library-card"); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.CatalogAttestation(card.Schema.ID, "https://wallet.example"); ok {
		t.Error("the entry stayed after the template was deleted")
	}
}
