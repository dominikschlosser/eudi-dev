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

package credtemplate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

func TestPredefinedTemplates(t *testing.T) {
	predefined := PredefinedTemplates()
	// A PID template per format, for the country-independent PID and the
	// German one that extends it.
	if len(predefined) != 4 {
		t.Fatalf("expected 4 pre-defined templates, got %d", len(predefined))
	}

	sdjwt, err := Load("pid-sdjwt", t.TempDir())
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if !sdjwt.Predefined {
		t.Error("expected Predefined=true")
	}
	if sdjwt.Format != "sdjwt" || sdjwt.VCT != mock.DefaultPIDVCT {
		t.Errorf("unexpected format/vct: %q %q", sdjwt.Format, sdjwt.VCT)
	}
	if len(sdjwt.Claims) != len(mock.SDJWTPIDClaims) {
		t.Errorf("expected %d claims, got %d", len(mock.SDJWTPIDClaims), len(sdjwt.Claims))
	}

	// Pre-defined template claims must be copies: mutating them must not touch the mock maps.
	sdjwt.Claims["family_name"] = "CHANGED"
	addr := sdjwt.Claims["address"].(map[string]any)
	addr["country"] = "XX"
	if mock.SDJWTPIDClaims["family_name"] != "'t Hart" {
		t.Error("built-in template shares top-level claims with mock.SDJWTPIDClaims")
	}
	if mock.SDJWTPIDClaims["address"].(map[string]any)["country"] != "NL" {
		t.Error("built-in template shares nested claims with mock.SDJWTPIDClaims")
	}
}

// The German PID is its own credential type, with its own claim set, and the
// templates are how anything in this tool reaches either of them.
func TestPredefinedGermanPIDTemplates(t *testing.T) {
	sdjwt, err := Load("german-pid-sdjwt", t.TempDir())
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if sdjwt.VCT != mock.GermanPIDVCT {
		t.Errorf("german-pid-sdjwt vct = %q, want %q", sdjwt.VCT, mock.GermanPIDVCT)
	}
	if len(sdjwt.Claims) != len(mock.SDJWTGermanPIDClaims) {
		t.Errorf("expected %d claims, got %d", len(mock.SDJWTGermanPIDClaims), len(sdjwt.Claims))
	}

	mdoc, err := Load("german-pid-mdoc", t.TempDir())
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	// ISO/IEC 18013-5 has no inheritance between document types, so the
	// German PID shares the doctype and differs by its second namespace.
	if mdoc.DocType != mock.PIDNamespace {
		t.Errorf("german-pid-mdoc doctype = %q, want %q", mdoc.DocType, mock.PIDNamespace)
	}
	if _, ok := mdoc.Claims[mock.GermanPIDNamespace+":birth_name"]; !ok {
		t.Errorf("german-pid-mdoc is missing %s:birth_name", mock.GermanPIDNamespace)
	}
}

func TestPIDTemplatesCarryDisplayDescription(t *testing.T) {
	cases := map[string]string{
		"pid-sdjwt":        "EUDI PID Rulebook",
		"pid-mdoc":         "EUDI PID Rulebook",
		"german-pid-sdjwt": "German PID provider",
		"german-pid-mdoc":  "German PID provider",
	}
	for name, want := range cases {
		tpl, err := Load(name, t.TempDir())
		if err != nil {
			t.Fatalf("loading %s: %v", name, err)
		}
		if tpl.Display == nil || tpl.Display.Description == "" {
			t.Fatalf("%s carries no display description", name)
		}
		if !strings.Contains(tpl.Display.Description, want) {
			t.Errorf("%s description %q does not mention %q", name, tpl.Display.Description, want)
		}
	}
}

// The claim sets are package variables, so their dates are those of the
// moment the process started. Materializing a template has to recompute them,
// or a server that stays up for a month hands out PIDs issued the day it
// booted.
func TestPredefinedTemplates_RecomputeDatedClaims(t *testing.T) {
	stale := "2000-01-01"
	original := mock.SDJWTPIDClaims["date_of_issuance"]
	mock.SDJWTPIDClaims["date_of_issuance"] = stale
	t.Cleanup(func() { mock.SDJWTPIDClaims["date_of_issuance"] = original })

	tpl, err := Load("pid-sdjwt", t.TempDir())
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if got := tpl.Claims["date_of_issuance"]; got == stale {
		t.Error("date_of_issuance was carried over from process start instead of recomputed")
	}
	if got, want := tpl.Claims["date_of_issuance"], mock.PIDIssuanceDate(); got != want {
		t.Errorf("date_of_issuance = %v, want %v", got, want)
	}
	// The German PID carries no issuance date, and refreshing must not invent one.
	german, err := Load("german-pid-sdjwt", t.TempDir())
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if _, ok := german.Claims["date_of_issuance"]; ok {
		t.Error("the German PID gained an issuance date its rulebook does not define")
	}
}

func TestPIDTemplateNames(t *testing.T) {
	tests := []struct {
		vct         string
		sdjwt, mdoc string
		known       bool
	}{
		{"", "pid-sdjwt", "pid-mdoc", true},
		{mock.DefaultPIDVCT, "pid-sdjwt", "pid-mdoc", true},
		{mock.GermanPIDVCT, "german-pid-sdjwt", "german-pid-mdoc", true},
		// A type nothing knows still gets a claim set, the
		// country-independent one, under the type it was asked for.
		{"urn:example:custom:1", "pid-sdjwt", "pid-mdoc", false},
	}
	for _, tt := range tests {
		sdjwt, mdoc, known := PIDTemplateNames(tt.vct)
		if sdjwt != tt.sdjwt || mdoc != tt.mdoc || known != tt.known {
			t.Errorf("PIDTemplateNames(%q) = %q, %q, %t; want %q, %q, %t",
				tt.vct, sdjwt, mdoc, known, tt.sdjwt, tt.mdoc, tt.known)
		}
	}
}

func TestLoadFromFileAndByName(t *testing.T) {
	dir := t.TempDir()
	content := `{"format": "sdjwt", "vct": "urn:example:test", "claims": {"a": 1}, "always_disclosed": ["a"]}`
	path := filepath.Join(dir, "my-cred.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	byName, err := Load("my-cred", dir)
	if err != nil {
		t.Fatalf("loading by name: %v", err)
	}
	if byName.Name != "my-cred" {
		t.Errorf("expected name from file name, got %q", byName.Name)
	}
	if byName.VCT != "urn:example:test" || len(byName.AlwaysDisclosed) != 1 {
		t.Errorf("unexpected template: %+v", byName)
	}

	byPath, err := Load(path, "")
	if err != nil {
		t.Fatalf("loading by path: %v", err)
	}
	if byPath.Name != "my-cred" {
		t.Errorf("expected name from file name, got %q", byPath.Name)
	}

	if _, err := Load("does-not-exist", dir); err == nil {
		t.Error("expected error for unknown template")
	}
}

func TestLoadTemplateExtension(t *testing.T) {
	dir := t.TempDir()
	content := `{"format": "mdoc", "claims": {"family_name": "TEST"}}`
	if err := os.WriteFile(filepath.Join(dir, "my-mdoc.template"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tpl, err := Load("my-mdoc", dir)
	if err != nil {
		t.Fatalf("loading .template file: %v", err)
	}
	if tpl.Name != "my-mdoc" || tpl.Format != "mdoc" {
		t.Errorf("unexpected template: %+v", tpl)
	}
}

func TestLoadRejectsInvalidFormat(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"format": "nope", "claims": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("bad", dir); err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestListUserOverridesPredefined(t *testing.T) {
	dir := t.TempDir()
	content := `{"format": "sdjwt", "vct": "urn:custom", "claims": {"a": 1}}`
	if err := os.WriteFile(filepath.Join(dir, "german-pid-sdjwt.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	templates, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found *Template
	for i := range templates {
		if templates[i].Name == "german-pid-sdjwt" {
			found = &templates[i]
		}
	}
	if found == nil {
		t.Fatal("german-pid-sdjwt missing from list")
	}
	if found.Predefined || found.VCT != "urn:custom" {
		t.Errorf("user template did not override the pre-defined one: %+v", found)
	}
}

func TestListMissingDir(t *testing.T) {
	templates, err := List(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("missing dir must not error: %v", err)
	}
	if len(templates) != len(PredefinedTemplates()) {
		t.Errorf("expected only built-ins, got %d", len(templates))
	}
}

func TestSaveAndDelete(t *testing.T) {
	dir := t.TempDir()
	tpl := Template{
		Name:            "test-cred",
		Format:          "sdjwt",
		VCT:             "urn:example:test",
		Claims:          map[string]any{"given_name": "ERIKA"},
		AlwaysDisclosed: []string{"given_name"},
		Predefined:      true, // must be cleared on save
	}
	path, err := Save(dir, tpl)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load("test-cred", dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Predefined {
		t.Error("saved template must not be marked pre-defined")
	}
	if loaded.VCT != tpl.VCT || len(loaded.AlwaysDisclosed) != 1 {
		t.Errorf("round trip mismatch: %+v", loaded)
	}

	if err := Delete(dir, "test-cred"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("template file still exists after delete")
	}
	if err := Delete(dir, "german-pid-sdjwt"); err == nil {
		t.Error("deleting a pre-defined template must fail")
	}
	if err := Delete(dir, "test-cred"); err == nil {
		t.Error("deleting a missing template must fail")
	}
}

func TestSaveRejectsBadNames(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"", "../escape", "a/b", ".hidden"} {
		if _, err := Save(dir, Template{Name: name}); err == nil {
			t.Errorf("expected error for name %q", name)
		}
	}
}

func TestMergeClaims(t *testing.T) {
	base := map[string]any{"a": 1, "nested": map[string]any{"x": 1}}
	merged := MergeClaims(base, map[string]any{"a": 2, "b": 3})
	if merged["a"] != 2 || merged["b"] != 3 {
		t.Errorf("override not applied: %+v", merged)
	}
	merged["nested"].(map[string]any)["x"] = 99
	if base["nested"].(map[string]any)["x"] != 1 {
		t.Error("MergeClaims must not share nested maps with base")
	}
}
