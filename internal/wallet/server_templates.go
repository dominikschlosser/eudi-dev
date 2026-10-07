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

// User templates are stored under templates/ in the wallet directory. PUT accepts a
// complete document, including templates shared by other users.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

// Include claims so clients can populate issuance forms without another request.
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := credtemplate.List(s.wallet.Templates)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// On a demo the templates it started with are fixed like the built-in ones.
	if s.demo != nil {
		for i := range templates {
			templates[i].Predefined = templates[i].Predefined || s.demo.fixedTemplates[templates[i].Name]
		}
	}
	writeJSON(w, http.StatusOK, templates)
}

// Accept only a bare name. credtemplate.Load also accepts paths for the CLI. Through
// this endpoint a path would allow arbitrary file reads.
func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !credtemplate.IsBareName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid template name %q", name)})
		return
	}

	tpl, err := credtemplate.Load(name, s.wallet.Templates)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, tpl)
}

// templateSaveRequest is a template document. With catalog set, the template
// also joins the attestation catalogue as an entry of its own.
type templateSaveRequest struct {
	credtemplate.Template
	Catalog *registrar.CatalogAttestation `json:"catalog,omitempty"`
}

// The URL name overrides the name in the document.
func (s *Server) handlePutTemplate(w http.ResponseWriter, r *http.Request) {
	var req templateSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parsing request body: " + err.Error()})
		return
	}
	tpl := req.Template
	tpl.Name = strings.TrimSpace(r.PathValue("name"))
	if !credtemplate.IsBareName(tpl.Name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid template name %q", tpl.Name)})
		return
	}
	if err := s.checkDemoTemplate(tpl); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	var entry registrar.CatalogAttestation
	if req.Catalog != nil {
		var err error
		if entry, err = s.wallet.Registrar().TemplateCatalogEntry(tpl, *req.Catalog); err != nil {
			registrar.WriteCatalogError(w, err)
			return
		}
		tpl.Category = entry.Category
	}
	// The entry is added first, because the catalogue can refuse it and a
	// stored template is hard to take back when it replaced another one.
	var added registrar.CatalogAttestation
	if req.Catalog != nil {
		var err error
		s.saveMutation(func() bool {
			added, err = s.wallet.Registrar().AddCatalogAttestation(entry)
			return err == nil
		})
		if err != nil {
			registrar.WriteCatalogError(w, err)
			return
		}
	}
	if _, err := credtemplate.Save(s.wallet.Templates, tpl); err != nil {
		if req.Catalog != nil {
			s.saveMutation(func() bool {
				return s.wallet.Registrar().DeleteCatalogAttestation(added.Schema.ID) == nil
			})
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.syncDemoRegistrations(); err != nil {
		s.log("  WARNING: updating the demo registrations: %v", err)
	}
	saved, err := credtemplate.Load(tpl.Name, s.wallet.Templates)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// Deleting an override restores the bundled template. Bundled templates themselves
// cannot be deleted.
func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	if !credtemplate.IsBareName(r.PathValue("name")) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid template name %q", r.PathValue("name"))})
		return
	}
	if err := s.checkDemoTemplateDelete(r.PathValue("name")); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	if err := credtemplate.Delete(s.wallet.Templates, r.PathValue("name")); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if err := s.syncDemoRegistrations(); err != nil {
		s.log("  WARNING: updating the demo registrations: %v", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": r.PathValue("name")})
}
