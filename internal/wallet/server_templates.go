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

// Credential template API. Templates are JSON documents (see the
// credtemplate package). Pre-defined templates are compiled in and user templates
// live in the wallet directory's templates/ subdirectory. PUT accepts a full
// template document, which makes it double as an import endpoint for shared
// templates.

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
)

// handleListTemplates returns all credential templates (pre-defined and user),
// including their claims so clients can pre-fill issuance forms without a
// second request.
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := credtemplate.List(s.wallet.TemplatesDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, templates)
}

// handleGetTemplate returns a single template by name.
func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	tpl, err := credtemplate.Load(r.PathValue("name"), s.wallet.TemplatesDir)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, tpl)
}

// handlePutTemplate creates or replaces a user template. The body is a full
// template document. A name in the body is overridden by the URL name.
func (s *Server) handlePutTemplate(w http.ResponseWriter, r *http.Request) {
	var tpl credtemplate.Template
	if err := json.NewDecoder(r.Body).Decode(&tpl); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parsing request body: " + err.Error()})
		return
	}
	tpl.Name = strings.TrimSpace(r.PathValue("name"))
	if _, err := credtemplate.Save(s.wallet.TemplatesDir, tpl); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	saved, err := credtemplate.Load(tpl.Name, s.wallet.TemplatesDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// handleDeleteTemplate removes a user template. Pre-defined templates cannot be
// deleted. Deleting a user template that overrides a pre-defined one restores the
// pre-defined version.
func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	if err := credtemplate.Delete(s.wallet.TemplatesDir, r.PathValue("name")); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": r.PathValue("name")})
}
