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
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// handleCatalogSchemas answers GET /schemas of the catalogue of attestations
// API (EC TS11 v1.0 §5.3.1) with a signed, paginated list of SchemaMeta
// objects.
func (s *Server) handleCatalogSchemas(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var matching []AttestationSchema
	for _, entry := range s.wallet.CatalogAttestations(s.wallet.RegistrarBase()) {
		if matchesSchemaQuery(entry.Schema, q) {
			matching = append(matching, entry.Schema)
		}
	}
	limit, offset := 20, 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = min(n, maxCatalogEntries)
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "offset must be a non-negative integer"})
			return
		}
		offset = n
	}
	start := min(offset, len(matching))
	end := start + min(limit, len(matching)-start)
	page := matching[start:end]
	if page == nil {
		page = []AttestationSchema{}
	}
	s.writeRegistrarResponse(w, r, map[string]any{"data": map[string]any{
		"total": len(matching), "limit": limit, "offset": offset, "data": page,
	}})
}

// matchesSchemaQuery applies the filters of TS11 v1.0 §5.3.1. supportedFormats
// takes a comma separated list, as the OpenAPI form style without explode
// does.
func matchesSchemaQuery(schema AttestationSchema, q map[string][]string) bool {
	get := func(name string) string {
		if values := q[name]; len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
		return ""
	}
	if v := get("id"); v != "" && v != schema.ID {
		return false
	}
	if v := get("supportedFormats"); v != "" {
		for _, format := range strings.Split(v, ",") {
			if !slices.Contains(schema.SupportedFormats, strings.TrimSpace(format)) {
				return false
			}
		}
	}
	if v := get("attestationLoS"); v != "" && v != schema.AttestationLoS {
		return false
	}
	if v := get("bindingType"); v != "" && v != schema.BindingType {
		return false
	}
	if v := get("trustedAuthoritiesFrameworkType"); v != "" && !slices.ContainsFunc(schema.TrustedAuthorities, func(a TrustAuthority) bool { return a.FrameworkType == v }) {
		return false
	}
	if v := get("trustedAuthoritiesValue"); v != "" && !slices.ContainsFunc(schema.TrustedAuthorities, func(a TrustAuthority) bool { return a.Value == v }) {
		return false
	}
	if v := get("schemaUri"); v != "" && !slices.ContainsFunc(schema.SchemaURIs, func(u SchemaURI) bool { return u.URI == v }) {
		return false
	}
	if v := get("rulebookUri"); v != "" && v != schema.RulebookURI {
		return false
	}
	return true
}

// handleCatalogSchema answers GET /schemas/{schemaId} (TS11 v1.0 §5.3.1).
func (s *Server) handleCatalogSchema(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.wallet.CatalogAttestation(r.PathValue("id"), s.wallet.RegistrarBase())
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "attestation schema not found"})
		return
	}
	s.writeRegistrarResponse(w, r, map[string]any{"data": entry.Schema})
}

// handleCatalogFormatSchema serves the format-specific schema a schema URI
// points to (TS11 v1.0 §4.3.4).
func (s *Server) handleCatalogFormatSchema(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.wallet.CatalogAttestation(r.PathValue("id"), s.wallet.RegistrarBase())
	var schema map[string]any
	if ok {
		schema, ok = entry.FormatSchema(r.PathValue("format"))
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "attestation schema not found"})
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, schema)
}

// handleUpdateCatalogSchema replaces a SchemaMeta (TS11 v1.0 §5.3.2).
func (s *Server) handleUpdateCatalogSchema(w http.ResponseWriter, r *http.Request) {
	var schema AttestationSchema
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&schema); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid attestation schema: " + err.Error()})
		return
	}
	var updated CatalogAttestation
	var err error
	s.saveMutation(func() bool {
		updated, err = s.wallet.UpdateCatalogSchema(r.PathValue("id"), schema, s.wallet.RegistrarBase())
		return err == nil
	})
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated.Schema)
}

// handleDeleteCatalogSchema deletes an attestation schema (TS11 v1.0 §5.3.3).
func (s *Server) handleDeleteCatalogSchema(w http.ResponseWriter, r *http.Request) {
	var err error
	s.saveMutation(func() bool {
		err = s.wallet.DeleteCatalogAttestation(r.PathValue("id"), s.wallet.RegistrarBase())
		return err == nil
	})
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCatalogAttestations lists the catalogue with the names and credential
// types the UI shows. TS11 has no such method, because its SchemaMeta leaves
// them to the format-specific schemas.
func (s *Server) handleCatalogAttestations(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.wallet.CatalogAttestations(s.wallet.RegistrarBase()))
}

// handleAddCatalogAttestation adds an attestation. TS11 v1.0 leaves
// registration to the European Commission's process (§4.5), so this method
// is the test catalogue's own.
func (s *Server) handleAddCatalogAttestation(w http.ResponseWriter, r *http.Request) {
	var entry CatalogAttestation
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid attestation: " + err.Error()})
		return
	}
	var stored CatalogAttestation
	var err error
	s.saveMutation(func() bool {
		stored, err = s.wallet.AddCatalogAttestation(entry, s.wallet.RegistrarBase())
		return err == nil
	})
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}

func writeCatalogError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, errCatalogNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errCatalogTemplate):
		status = http.StatusForbidden
	case errors.Is(err, errCatalogFull):
		status = http.StatusConflict
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
