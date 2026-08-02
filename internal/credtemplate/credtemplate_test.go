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
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
)

func TestPredefinedTemplates(t *testing.T) {
	predefined := PredefinedTemplates()
	if len(predefined) != 2 {
		t.Fatalf("expected 2 pre-defined templates, got %d", len(predefined))
	}

	sdjwt, err := Load("german-pid-sdjwt", t.TempDir())
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
	if mock.SDJWTPIDClaims["family_name"] != "MUSTERMANN" {
		t.Error("built-in template shares top-level claims with mock.SDJWTPIDClaims")
	}
	if mock.SDJWTPIDClaims["address"].(map[string]any)["country"] != "DE" {
		t.Error("built-in template shares nested claims with mock.SDJWTPIDClaims")
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
