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
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
)

// AttestationSchema is the SchemaMeta of the catalogue of attestations (EC
// TS11 v1.0 §4.3.1 and the normative JSON schema of Annex A.2).
type AttestationSchema struct {
	ID                 string           `json:"id,omitempty"`
	Version            string           `json:"version"`
	RulebookURI        string           `json:"rulebookURI"`
	TrustedAuthorities []TrustAuthority `json:"trustedAuthorities,omitempty"`
	AttestationLoS     string           `json:"attestationLoS"`
	BindingType        string           `json:"bindingType"`
	SupportedFormats   []string         `json:"supportedFormats"`
	SchemaURIs         []SchemaURI      `json:"schemaURIs"`
}

// SchemaURI binds a format to its schema (TS11 v1.0 §4.3.2).
type SchemaURI struct {
	FormatIdentifier string `json:"formatIdentifier"`
	URI              string `json:"uri"`
}

// TrustAuthority names the trust framework of an attestation type (TS11 v1.0
// §4.3.3). The Annex A.2 schema spells the qualifier isLOTE.
type TrustAuthority struct {
	FrameworkType string `json:"frameworkType"`
	Value         string `json:"value"`
	IsLOTE        *bool  `json:"isLOTE,omitempty"`
}

// CatalogAttestation is a catalogue entry. Schema is the SchemaMeta of the TS11
// API. Name and Credentials fill the format-specific schemas at its schemaURIs
// (TS11 v1.0 §4.3.4).
type CatalogAttestation struct {
	Name        string              `json:"name"`
	Credentials []CatalogCredential `json:"credentials"`
	Schema      AttestationSchema   `json:"schema"`
	// Template marks an entry that comes from one of the wallet's credential
	// templates. It changes with the template, not in the catalogue.
	Template bool `json:"template,omitempty"`
}

// CatalogCredential is one format of an attestation: its vct or doctype and
// its claim paths. An mdoc claim path is namespace and element identifier.
type CatalogCredential struct {
	Format string  `json:"format"`
	Type   string  `json:"type"`
	Claims [][]any `json:"claims,omitempty"`
}

const (
	catalogSchemaPath = "/api/catalog/schemas"
	maxCatalogEntries = 200
)

var (
	errCatalogNotFound = errors.New("attestation not in the catalogue")
	errCatalogTemplate = errors.New("this entry belongs to a predefined credential template and can't be changed or deleted")
	errCatalogFull     = errors.New("the catalogue holds the maximum number of attestations")
	semanticVersion    = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)

	attestationLevels = []string{"iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"}
	bindingTypes      = []string{"claim", "key", "biometric", "none"}
	frameworkTypes    = []string{"aki", "etsi_tl", "openid_federation"}
)

// CatalogAttestations lists the entries of the credential templates followed
// by the added ones. base is the URL the schema URIs point to.
func (w *Wallet) CatalogAttestations(base string) []CatalogAttestation {
	entries := w.templateCatalog(base)
	w.mu.RLock()
	added := slices.Clone(w.Catalog)
	w.mu.RUnlock()
	sort.SliceStable(added, func(i, j int) bool { return strings.ToLower(added[i].Name) < strings.ToLower(added[j].Name) })
	for _, entry := range added {
		entries = append(entries, withSchemaURIs(cloneCatalogAttestation(entry), base))
	}
	return entries
}

// CatalogAttestation returns the entry with the schema id.
func (w *Wallet) CatalogAttestation(id, base string) (CatalogAttestation, bool) {
	for _, entry := range w.CatalogAttestations(base) {
		if entry.Schema.ID == id {
			return entry, true
		}
	}
	return CatalogAttestation{}, false
}

// AddCatalogAttestation stores a new entry. The catalogue assigns its id and
// its schema URIs (TS11 v1.0 §5.2.3).
func (w *Wallet) AddCatalogAttestation(entry CatalogAttestation, base string) (CatalogAttestation, error) {
	entry = cloneCatalogAttestation(entry)
	entry.Template = false
	entry.Schema.ID = uuid.NewString()
	if err := normalizeCatalogAttestation(&entry, base); err != nil {
		return CatalogAttestation{}, err
	}
	fromTemplates := w.templateCatalog(base)
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkNewCatalogEntryLocked(entry, fromTemplates); err != nil {
		return CatalogAttestation{}, err
	}
	w.Catalog = append(w.Catalog, entry)
	return withSchemaURIs(cloneCatalogAttestation(entry), base), nil
}

// CheckCatalogAttestation reports whether AddCatalogAttestation would accept
// entry, without adding it.
func (w *Wallet) CheckCatalogAttestation(entry CatalogAttestation, base string) error {
	entry = cloneCatalogAttestation(entry)
	if err := normalizeCatalogAttestation(&entry, base); err != nil {
		return err
	}
	fromTemplates := w.templateCatalog(base)
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.checkNewCatalogEntryLocked(entry, fromTemplates)
}

// checkNewCatalogEntryLocked keeps names and types unique. The wallet finds
// the trusted list of a received credential by its type.
func (w *Wallet) checkNewCatalogEntryLocked(entry CatalogAttestation, fromTemplates []CatalogAttestation) error {
	for _, existing := range append(fromTemplates, w.Catalog...) {
		if strings.EqualFold(existing.Name, entry.Name) {
			return fmt.Errorf("the catalogue already lists %q", existing.Name)
		}
		for _, c := range entry.Credentials {
			if slices.ContainsFunc(existing.Credentials, func(e CatalogCredential) bool { return e.Format == c.Format && e.Type == c.Type }) {
				return fmt.Errorf("the catalogue already lists %s (%s) under %q", c.Type, c.Format, existing.Name)
			}
		}
	}
	if len(w.Catalog) >= maxCatalogEntries {
		return errCatalogFull
	}
	return nil
}

// templateCatalogEntry builds the catalogue entry for template t from the
// catalogue fields in entry and checks it.
func (w *Wallet) templateCatalogEntry(t credtemplate.Template, entry CatalogAttestation) (CatalogAttestation, error) {
	entry, err := TemplateCatalogAttestation(t, entry)
	if err != nil {
		return CatalogAttestation{}, err
	}
	if err := w.CheckCatalogAttestation(entry, w.RegistrarBase()); err != nil {
		return CatalogAttestation{}, err
	}
	return entry, nil
}

// TemplateCatalogAttestation completes entry with the format, type and claims
// of t. An empty name becomes the template's display name or its name.
func TemplateCatalogAttestation(t credtemplate.Template, entry CatalogAttestation) (CatalogAttestation, error) {
	if _, err := credtemplate.NormalizeFormat(t.Format); err != nil {
		return CatalogAttestation{}, err
	}
	credential, ok := templateCatalogCredential(t)
	if !ok {
		return CatalogAttestation{}, fmt.Errorf("only an SD-JWT VC template with a vct or an mdoc template with a doctype can be added to the catalogue")
	}
	entry = cloneCatalogAttestation(entry)
	entry.Credentials = []CatalogCredential{credential}
	if strings.TrimSpace(entry.Name) == "" {
		entry.Name = t.Name
		if t.Display != nil && t.Display.Name != "" {
			entry.Name = t.Display.Name
		}
	}
	return entry, nil
}

// UpdateCatalogSchema replaces the SchemaMeta of an added entry (TS11 v1.0
// §5.3.2). The formats and schema URIs follow from the entry's credentials,
// so an update can't change them.
func (w *Wallet) UpdateCatalogSchema(id string, schema AttestationSchema, base string) (CatalogAttestation, error) {
	if w.isTemplateCatalogID(id, base) {
		return CatalogAttestation{}, errCatalogTemplate
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	i := slices.IndexFunc(w.Catalog, func(e CatalogAttestation) bool { return e.Schema.ID == id })
	if i < 0 {
		return CatalogAttestation{}, fmt.Errorf("%w: %s", errCatalogNotFound, id)
	}
	stored := withSchemaURIs(cloneCatalogAttestation(w.Catalog[i]), base)
	if (schema.SupportedFormats != nil && !slices.Equal(schema.SupportedFormats, stored.Schema.SupportedFormats)) ||
		(schema.SchemaURIs != nil && !slices.Equal(schema.SchemaURIs, stored.Schema.SchemaURIs)) {
		return CatalogAttestation{}, fmt.Errorf("supportedFormats and schemaURIs follow from the attestation's credentials and can't be changed")
	}
	if schema.ID != "" && schema.ID != id {
		return CatalogAttestation{}, fmt.Errorf("the id in the body is %q, not %q", schema.ID, id)
	}
	updated := cloneCatalogAttestation(w.Catalog[i])
	schema.ID = id
	updated.Schema = schema
	if err := normalizeCatalogAttestation(&updated, base); err != nil {
		return CatalogAttestation{}, err
	}
	w.Catalog[i] = updated
	return withSchemaURIs(cloneCatalogAttestation(updated), base), nil
}

// DeleteCatalogAttestation removes an added entry.
func (w *Wallet) DeleteCatalogAttestation(id, base string) error {
	if w.isTemplateCatalogID(id, base) {
		return errCatalogTemplate
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	i := slices.IndexFunc(w.Catalog, func(e CatalogAttestation) bool { return e.Schema.ID == id })
	if i < 0 {
		return fmt.Errorf("%w: %s", errCatalogNotFound, id)
	}
	w.Catalog = slices.Delete(w.Catalog, i, i+1)
	return nil
}

func (w *Wallet) isTemplateCatalogID(id, base string) bool {
	return slices.ContainsFunc(w.templateCatalog(base), func(e CatalogAttestation) bool { return e.Schema.ID == id })
}

// normalizeCatalogAttestation checks an entry against the TS11 v1.0 §4.3 data
// model and fills in defaults. The catalogue takes the two formats of the EUDI
// stack.
func normalizeCatalogAttestation(entry *CatalogAttestation, base string) error {
	entry.Name = strings.TrimSpace(entry.Name)
	if entry.Name == "" {
		return fmt.Errorf("an attestation needs a name")
	}
	if len(entry.Credentials) == 0 {
		return fmt.Errorf("an attestation needs at least one format with its type")
	}
	if len(entry.Credentials) > 2 {
		return fmt.Errorf("an attestation has at most one dc+sd-jwt and one mso_mdoc format")
	}
	formats := map[string]bool{}
	for i := range entry.Credentials {
		c := &entry.Credentials[i]
		c.Type = strings.TrimSpace(c.Type)
		if c.Format != "dc+sd-jwt" && c.Format != "mso_mdoc" {
			return fmt.Errorf("format %q is not dc+sd-jwt or mso_mdoc", c.Format)
		}
		if formats[c.Format] {
			return fmt.Errorf("format %s is listed twice. TS11 binds one schema URI to each format", c.Format)
		}
		formats[c.Format] = true
		if c.Type == "" {
			return fmt.Errorf("the %s format needs its type (vct or doctype)", c.Format)
		}
		if len(c.Claims) > maxRegisteredClaims {
			return fmt.Errorf("a format may list at most %d claims", maxRegisteredClaims)
		}
		c.Claims = slices.DeleteFunc(c.Claims, func(path []any) bool { return len(path) == 0 })
		if c.Format == "mso_mdoc" && slices.ContainsFunc(c.Claims, func(path []any) bool { return len(path) != 2 }) {
			return fmt.Errorf("an mdoc claim is a namespace and an element identifier")
		}
	}
	s := &entry.Schema
	s.Version = firstNonEmpty(s.Version, "1.0.0")
	if !semanticVersion.MatchString(s.Version) {
		return fmt.Errorf("version %q does not follow semantic versioning (TS11 v1.0 §4.5.1)", s.Version)
	}
	s.RulebookURI = firstNonEmpty(s.RulebookURI, base+"/rulebook")
	if !isWebURL(s.RulebookURI) {
		return fmt.Errorf("rulebookURI %q is not an http or https URL", s.RulebookURI)
	}
	s.AttestationLoS = firstNonEmpty(s.AttestationLoS, "iso_18045_basic")
	if !slices.Contains(attestationLevels, s.AttestationLoS) {
		return fmt.Errorf("attestationLoS %q is not one of %s", s.AttestationLoS, strings.Join(attestationLevels, ", "))
	}
	s.BindingType = firstNonEmpty(s.BindingType, "key")
	if !slices.Contains(bindingTypes, s.BindingType) {
		return fmt.Errorf("bindingType %q is not one of %s", s.BindingType, strings.Join(bindingTypes, ", "))
	}
	if len(s.TrustedAuthorities) > maxRegistrationItems {
		return fmt.Errorf("an attestation may list at most %d trusted authorities", maxRegistrationItems)
	}
	for _, a := range s.TrustedAuthorities {
		if !slices.Contains(frameworkTypes, a.FrameworkType) {
			return fmt.Errorf("frameworkType %q is not one of %s", a.FrameworkType, strings.Join(frameworkTypes, ", "))
		}
		if strings.TrimSpace(a.Value) == "" {
			return fmt.Errorf("a trusted authority needs a value")
		}
		if a.IsLOTE != nil && a.FrameworkType != "etsi_tl" {
			return fmt.Errorf("isLOTE applies only to the etsi_tl framework type (TS11 v1.0 §4.3.3)")
		}
		// An aki value is a key identifier. The other two name a list or an
		// entity by URI, and the UI links them.
		if a.FrameworkType != "aki" && !isWebURL(a.Value) {
			return fmt.Errorf("the %s value %q is not an http or https URL", a.FrameworkType, a.Value)
		}
	}
	s.SupportedFormats, s.SchemaURIs = nil, nil
	return nil
}

// withSchemaURIs fills in the formats and their schema URIs on the wallet
// for them.
func withSchemaURIs(entry CatalogAttestation, base string) CatalogAttestation {
	entry.Schema.SupportedFormats = nil
	entry.Schema.SchemaURIs = nil
	for _, c := range entry.Credentials {
		entry.Schema.SupportedFormats = append(entry.Schema.SupportedFormats, c.Format)
		entry.Schema.SchemaURIs = append(entry.Schema.SchemaURIs, SchemaURI{
			FormatIdentifier: c.Format,
			URI:              catalogSchemaURL(base, entry.Schema.ID, c.Format),
		})
	}
	return entry
}

func catalogSchemaURL(base, id, format string) string {
	return base + catalogSchemaPath + "/" + url.PathEscape(id) + "/" + url.PathEscape(format)
}

// FormatSchema is the format-specific schema behind a schema URI (TS11 v1.0
// §4.3.4). For dc+sd-jwt it is SD-JWT VC Type Metadata
// (draft-ietf-oauth-sd-jwt-vc-19 §5.2), with the claims of §5.6. For mso_mdoc
// TS11 names the DocType format of ISO 23220-2, which eudi-dev has not
// checked. It serves the doctype with its namespaces and element identifiers.
func (entry CatalogAttestation) FormatSchema(format string) (map[string]any, bool) {
	i := slices.IndexFunc(entry.Credentials, func(c CatalogCredential) bool { return c.Format == format })
	if i < 0 {
		return nil, false
	}
	c := entry.Credentials[i]
	if format == "dc+sd-jwt" {
		claims := make([]map[string]any, 0, len(c.Claims))
		for _, path := range c.Claims {
			claims = append(claims, map[string]any{"path": path})
		}
		return map[string]any{"vct": c.Type, "name": entry.Name, "claims": claims}, true
	}
	namespaces := map[string][]map[string]any{}
	for _, path := range c.Claims {
		namespace := fmt.Sprint(path[0])
		namespaces[namespace] = append(namespaces[namespace], map[string]any{"identifier": fmt.Sprint(path[1])})
	}
	return map[string]any{"docType": c.Type, "name": entry.Name, "namespaces": namespaces}, true
}

func cloneCatalogAttestation(entry CatalogAttestation) CatalogAttestation {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return entry
	}
	var clone CatalogAttestation
	if json.Unmarshal(encoded, &clone) != nil {
		return entry
	}
	return clone
}

// templateCatalogNamespace makes the ids of template entries stable across
// restarts and instances.
var templateCatalogNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/dominikschlosser/eudi-dev/catalog"))

// templateCatalog lists the attestations of the predefined credential
// templates, including a user template that replaces one. Other user templates
// are added only on request and are then added entries. Templates with the
// same display name are one attestation in two formats. The last URL in a
// template description is its rulebook or specification. A PID is issued at assurance level high, so its level of
// security is iso_18045_high, and it links to the wallet's PID provider list.
// Other templates get the same defaults as an added attestation.
func (w *Wallet) templateCatalog(base string) []CatalogAttestation {
	templates, err := credtemplate.List(w.Templates)
	if err != nil {
		templates = credtemplate.PredefinedTemplates()
	}
	predefined := map[string]bool{}
	for _, t := range credtemplate.PredefinedTemplates() {
		predefined[t.Name] = true
	}
	var entries []CatalogAttestation
	index := map[string]int{}
	for _, t := range templates {
		if !predefined[t.Name] {
			continue
		}
		credential, ok := templateCatalogCredential(t)
		if !ok {
			continue
		}
		name, description := t.Name, t.Description
		if t.Display != nil && t.Display.Name != "" {
			name, description = t.Display.Name, t.Display.Description
		}
		i, ok := index[name]
		if ok && slices.ContainsFunc(entries[i].Credentials, func(c CatalogCredential) bool { return c.Format == credential.Format }) {
			continue
		}
		if !ok {
			entry := CatalogAttestation{
				Name:     name,
				Template: true,
				Schema: AttestationSchema{
					ID:             uuid.NewSHA1(templateCatalogNamespace, []byte(name)).String(),
					Version:        "1.0.0",
					RulebookURI:    firstNonEmpty(lastURL(description), base+"/rulebook"),
					AttestationLoS: "iso_18045_basic",
					BindingType:    "key",
				},
			}
			if isPIDType(t.VCT) || isPIDType(t.DocType) {
				isLOTE := true
				entry.Schema.AttestationLoS = "iso_18045_high"
				entry.Schema.TrustedAuthorities = []TrustAuthority{{FrameworkType: "etsi_tl", Value: base + "/api/trustlists/pid", IsLOTE: &isLOTE}}
			}
			index[name] = len(entries)
			entries = append(entries, entry)
			i = len(entries) - 1
		}
		entries[i].Credentials = append(entries[i].Credentials, credential)
	}
	for i := range entries {
		sort.Slice(entries[i].Credentials, func(a, b int) bool { return entries[i].Credentials[a].Format < entries[i].Credentials[b].Format })
		entries[i] = withSchemaURIs(entries[i], base)
	}
	sort.SliceStable(entries, func(a, b int) bool { return strings.ToLower(entries[a].Name) < strings.ToLower(entries[b].Name) })
	return entries
}

// templateCatalogCredential lists a template's claims as paths. An SD-JWT
// object claim is listed with its members. An mdoc claim key is an element of
// the template's namespace, or namespace:element. A template without a type,
// or in the plain JWT format, has no entry.
func templateCatalogCredential(t credtemplate.Template) (CatalogCredential, bool) {
	t.Format, _ = credtemplate.NormalizeFormat(t.Format)
	switch {
	case t.Format == "mdoc" && t.DocType != "":
		c := CatalogCredential{Format: "mso_mdoc", Type: t.DocType}
		for _, key := range slices.Sorted(maps.Keys(t.Claims)) {
			namespace, element := firstNonEmpty(t.Namespace, t.DocType), key
			if at := strings.LastIndex(key, ":"); at > 0 {
				namespace, element = key[:at], key[at+1:]
			}
			c.Claims = append(c.Claims, []any{namespace, element})
		}
		return c, true
	case t.Format == "sdjwt" && t.VCT != "":
		c := CatalogCredential{Format: "dc+sd-jwt", Type: t.VCT}
		for _, key := range slices.Sorted(maps.Keys(t.Claims)) {
			c.Claims = append(c.Claims, []any{key})
			if members, ok := t.Claims[key].(map[string]any); ok {
				for _, member := range slices.Sorted(maps.Keys(members)) {
					c.Claims = append(c.Claims, []any{key, member})
				}
			}
		}
		return c, true
	}
	return CatalogCredential{}, false
}

var urlPattern = regexp.MustCompile(`https?://\S+`)

func lastURL(text string) string {
	urls := urlPattern.FindAllString(text, -1)
	if len(urls) == 0 {
		return ""
	}
	return strings.TrimRight(urls[len(urls)-1], ".,)")
}
