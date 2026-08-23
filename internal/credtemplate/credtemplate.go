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

// Package credtemplate manages credential templates: named, reusable claim
// sets with per-format defaults (VCT, doc type, namespace, expiry) and the
// claims embedded plainly instead of selectively disclosable. Pre-defined
// templates compiled into the binary cover the EUDI PID and the German PID
// that extends it. User templates are JSON files under the wallet directory's
// templates/, and one with the same name replaces a pre-defined template.
package credtemplate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// Template describes a reusable credential template. All fields except Claims
// are optional: an empty Format means the template works with any format, and
// empty VCT/DocType/Namespace/Exp fall back to the issuance defaults.
type Template struct {
	// Name identifies the template. For file-based templates it defaults to
	// the file name without extension.
	Name string `json:"name,omitempty"`
	// Description is free text shown in template listings.
	Description string `json:"description,omitempty"`
	// Format is "sdjwt", "jwt", or "mdoc" (aliases "dc+sd-jwt", "jwt_vc_json",
	// and "mso_mdoc" are accepted). Empty means any format.
	Format string `json:"format,omitempty"`
	// VCT applies to sdjwt/jwt.
	VCT string `json:"vct,omitempty"`
	// DocType and Namespace apply to mdoc.
	DocType   string `json:"doctype,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	// Exp is a Go duration string (e.g. "720h").
	Exp string `json:"exp,omitempty"`
	// Claims is the default claim set. Callers may override individual
	// top-level claims at issuance time.
	Claims map[string]any `json:"claims"`
	// AlwaysDisclosed lists claims (dotted paths for nested claims, e.g.
	// "address.country") that are embedded plainly in an SD-JWT payload
	// instead of becoming selective disclosures.
	AlwaysDisclosed []string `json:"always_disclosed,omitempty"`
	// Display sets the §12.2.4 appearance a credential issued from this template
	// carries. Its image fields are references the wallet resolves: an
	// "embedded:<file>" name for a template compiled into the binary, or a data
	// URI or https URL for a user template.
	Display *TemplateDisplay `json:"display,omitempty"`
	// Predefined is true for pre-defined templates compiled into the binary. It is set by
	// this package and ignored in template files.
	Predefined bool `json:"predefined,omitempty"`
}

// TemplateDisplay is the appearance a template gives the credentials issued from
// it. Colors are CSS colors. Logo and BackgroundImage are references the wallet
// resolves to card art.
type TemplateDisplay struct {
	Name            string `json:"name,omitempty"`
	Description     string `json:"description,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
	Logo            string `json:"logo,omitempty"`
	LogoAltText     string `json:"logo_alt_text,omitempty"`
	BackgroundImage string `json:"background_image,omitempty"`
}

// templateExtensions are the file extensions recognized in the template
// directory. Both hold the same JSON document format.
var templateExtensions = []string{".json", ".template"}

// DirForWallet returns the template directory inside the given wallet
// directory. An empty walletDir selects the default wallet directory inside
// the tool's state directory.
func DirForWallet(walletDir string) string {
	if walletDir == "" {
		walletDir = filepath.Join(config.BaseDir(), "wallet")
	}
	return filepath.Join(walletDir, "templates")
}

// DefaultDir returns the default user template directory.
func DefaultDir() string {
	return DirForWallet("")
}

// NormalizeFormat maps format aliases to "sdjwt", "jwt", or "mdoc". An empty
// input stays empty (meaning any format).
func NormalizeFormat(format string) (string, error) {
	switch strings.TrimSpace(format) {
	case "":
		return "", nil
	case "sdjwt", "sd-jwt", "dc+sd-jwt":
		return "sdjwt", nil
	case "jwt", "jwt_vc_json":
		return "jwt", nil
	case "mdoc", "mso_mdoc":
		return "mdoc", nil
	default:
		return "", fmt.Errorf("unsupported template format %q: expected sdjwt, jwt, or mdoc", format)
	}
}

// PredefinedTemplates returns the pre-defined templates compiled into the binary. Claims are deep
// copies, so callers may modify them freely, and their dated claims are
// recomputed per call so a long-running server does not keep issuing PIDs
// dated the day it started.
func PredefinedTemplates() []Template {
	// The eudi-dev look the demo baseline shows, resolved by the wallet from its
	// embedded assets. The German PID adds the public Personalausweis specimen
	// as its card art, which is what tells it apart from the country-independent
	// one.
	pidDisplay := func(name string) *TemplateDisplay {
		return &TemplateDisplay{
			Name:            name,
			Description:     "Generated by eudi-dev for development and testing",
			BackgroundColor: "#3d59a1",
			TextColor:       "#ffffff",
			Logo:            "embedded:logo.svg",
			LogoAltText:     "eudi-dev logo",
		}
	}
	germanDisplay := func() *TemplateDisplay {
		d := pidDisplay("German PID")
		d.BackgroundImage = "embedded:german-id-specimen.jpg"
		return d
	}
	return []Template{
		{
			Name:        "pid-sdjwt",
			Description: "EUDI PID (SD-JWT, EU rulebook sample data)",
			Format:      "sdjwt",
			VCT:         mock.DefaultPIDVCT,
			Exp:         "720h",
			Claims:      mock.RefreshPIDDates(deepCopyClaims(mock.SDJWTPIDClaims)),
			Display:     pidDisplay("EUDI PID"),
			Predefined:  true,
		},
		{
			Name:        "pid-mdoc",
			Description: "EUDI PID (mDoc, EU rulebook sample data)",
			Format:      "mdoc",
			DocType:     mock.PIDNamespace,
			Namespace:   mock.PIDNamespace,
			Exp:         "720h",
			Claims:      mock.RefreshPIDDates(deepCopyClaims(mock.MDOCPIDClaims)),
			Display:     pidDisplay("EUDI PID"),
			Predefined:  true,
		},
		{
			Name:        "german-pid-sdjwt",
			Description: "German PID (SD-JWT, extends the EUDI PID)",
			Format:      "sdjwt",
			VCT:         mock.GermanPIDVCT,
			Exp:         "720h",
			Claims:      mock.RefreshPIDDates(deepCopyClaims(mock.SDJWTGermanPIDClaims)),
			Display:     germanDisplay(),
			Predefined:  true,
		},
		{
			Name:        "german-pid-mdoc",
			Description: "German PID (mDoc, EUDI PID doctype plus the German namespace)",
			Format:      "mdoc",
			DocType:     mock.PIDNamespace,
			Namespace:   mock.PIDNamespace,
			Exp:         "720h",
			Claims:      mock.RefreshPIDDates(deepCopyClaims(mock.MDOCGermanPIDClaims)),
			Display:     germanDisplay(),
			Predefined:  true,
		},
	}
}

// PIDTemplateNames returns the SD-JWT and mdoc template names that hold the
// claim set of the PID type vct, and whether that type has pre-defined
// templates at all. Callers that generate a PID for an unknown type fall back
// to the country-independent claim set under the type they were given.
func PIDTemplateNames(vct string) (sdjwt, mdoc string, ok bool) {
	switch vct {
	case "", mock.DefaultPIDVCT:
		return "pid-sdjwt", "pid-mdoc", true
	case mock.GermanPIDVCT:
		return "german-pid-sdjwt", "german-pid-mdoc", true
	default:
		return "pid-sdjwt", "pid-mdoc", false
	}
}

// List returns all templates: pre-defined templates plus user templates from dir (the
// default directory when dir is empty). A user template with the same name as
// a built-in replaces it. The result is sorted by name.
func List(dir string) ([]Template, error) {
	if dir == "" {
		dir = DefaultDir()
	}

	byName := make(map[string]Template)
	for _, t := range PredefinedTemplates() {
		byName[t.Name] = t
	}

	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading template directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !hasTemplateExtension(entry.Name()) {
			continue
		}
		t, err := loadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		byName[t.Name] = *t
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	templates := make([]Template, 0, len(names))
	for _, name := range names {
		templates = append(templates, byName[name])
	}
	return templates, nil
}

// Load resolves a template by name or file path. Names are looked up in dir
// (the default directory when dir is empty) first, then in the pre-defined templates.
// Anything containing a path separator, or matching an existing file, is
// loaded as a file path.
func Load(nameOrPath, dir string) (*Template, error) {
	if strings.TrimSpace(nameOrPath) == "" {
		return nil, fmt.Errorf("template name is required")
	}
	if dir == "" {
		dir = DefaultDir()
	}

	if strings.ContainsRune(nameOrPath, os.PathSeparator) || strings.ContainsRune(nameOrPath, '/') || hasTemplateExtension(nameOrPath) {
		return loadFile(nameOrPath)
	}

	for _, ext := range templateExtensions {
		path := filepath.Join(dir, nameOrPath+ext)
		if _, err := os.Stat(path); err == nil {
			return loadFile(path)
		}
	}

	for _, t := range PredefinedTemplates() {
		if t.Name == nameOrPath {
			tpl := t
			return &tpl, nil
		}
	}

	return nil, fmt.Errorf("template %q not found (looked in %s and pre-defined templates; run `templates list`)", nameOrPath, dir)
}

// Save writes a user template to dir (the default directory when dir is
// empty) as <name>.json and returns the file path.
func Save(dir string, t Template) (string, error) {
	name := strings.TrimSpace(t.Name)
	if name == "" {
		return "", fmt.Errorf("template name is required")
	}
	if name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("invalid template name %q", name)
	}
	if _, err := NormalizeFormat(t.Format); err != nil {
		return "", err
	}
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating template directory: %w", err)
	}

	t.Name = name
	t.Predefined = false
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding template: %w", err)
	}
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("writing template: %w", err)
	}
	return path, nil
}

// Delete removes a user template from dir (the default directory when dir is
// empty). Pre-defined templates cannot be deleted.
func Delete(dir, name string) error {
	if dir == "" {
		dir = DefaultDir()
	}
	if name != filepath.Base(name) {
		return fmt.Errorf("invalid template name %q", name)
	}
	for _, ext := range templateExtensions {
		path := filepath.Join(dir, name+ext)
		if _, err := os.Stat(path); err == nil {
			return os.Remove(path)
		}
	}
	for _, t := range PredefinedTemplates() {
		if t.Name == name {
			return fmt.Errorf("template %q is pre-defined and cannot be deleted", name)
		}
	}
	return fmt.Errorf("template %q not found in %s", name, dir)
}

func hasTemplateExtension(name string) bool {
	for _, ext := range templateExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func loadFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading template: %w", err)
	}
	var t Template
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing template %s: %w", path, err)
	}
	if _, err := NormalizeFormat(t.Format); err != nil {
		return nil, fmt.Errorf("template %s: %w", path, err)
	}
	if strings.TrimSpace(t.Name) == "" {
		base := filepath.Base(path)
		t.Name = strings.TrimSuffix(base, filepath.Ext(base))
	}
	t.Predefined = false
	return &t, nil
}

func deepCopyClaims(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims))
	for k, v := range claims {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyClaims(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = deepCopyValue(item)
		}
		return out
	default:
		return v
	}
}

// MergeClaims returns the template claims with the given top-level overrides
// applied. The template claims are deep-copied first, so neither input is
// modified.
func MergeClaims(base, overrides map[string]any) map[string]any {
	merged := deepCopyClaims(base)
	for k, v := range overrides {
		merged[k] = v
	}
	return merged
}
