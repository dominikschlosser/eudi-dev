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

// The stored credential collection: listing, importing, deleting, and
// setting revocation status.

package wallet

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// handleListCredentials serves the stored credentials, optionally windowed
// with ?limit= and ?offset=. The response stays a plain array so existing
// clients keep working. The full count travels in X-Total-Count, which a
// paging UI needs to know how many pages there are.
func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	// A batch counts once, so paging matches what the window returns.
	total := len(s.wallet.ListedCredentials())
	limit, err := intParam(r, "limit", 0)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid limit: " + err.Error()})
		return
	}
	offset, err := intParam(r, "offset", 0)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid offset: " + err.Error()})
		return
	}

	data, err := s.wallet.CredentialsJSONWindow(offset, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// intParam reads a non-negative integer query parameter.
func intParam(r *http.Request, name string, fallback int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", raw)
	}
	if value < 0 {
		return 0, fmt.Errorf("must not be negative")
	}
	return value, nil
}

// handleImportCredential imports a credential from the request body.
func (s *Server) handleImportCredential(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}

	raw := strings.TrimSpace(string(body))
	if raw == "" {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	imported, err := s.wallet.ImportCredential(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.wallet.AddLog("management", fmt.Sprintf("Imported %s credential %s", imported.Format, credentialLabel(*imported)), true)

	s.triggerSave()
	writeJSON(w, http.StatusCreated, s.wallet.CredentialSummaryWithStatus(*imported))
}

// handleDeleteCredential removes a credential by ID.
func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	label := id
	if cred, ok := s.wallet.GetCredential(id); ok {
		if cred.VCT != "" {
			label = cred.VCT
		} else if cred.DocType != "" {
			label = cred.DocType
		}
	}
	if s.wallet.IsProtected(id) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "credential is protected and can only be removed through the wallet file",
		})
		return
	}
	if !s.wallet.RemoveCredential(id) {
		http.Error(w, "credential not found", http.StatusNotFound)
		return
	}
	s.wallet.AddLog("management", fmt.Sprintf("Deleted credential %s", label), true)
	s.triggerSave()
	w.WriteHeader(http.StatusNoContent)
}

// handleSetCredentialStatus sets the revocation status for a credential.
func (s *Server) handleSetCredentialStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Resolve a short id prefix to the full id so the protection gate and the
	// status write below act on the same credential.
	if cred, ok := s.wallet.GetCredential(id); ok {
		id = cred.ID
	}

	var body struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if s.wallet.IsProtected(id) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "credential is protected and its status can only be changed through the wallet file",
		})
		return
	}
	// draft-ietf-oauth-status-list §7: "Status Types MUST have a numeric value
	// between 0 and 255." A value outside it cannot be published, and saying
	// so is a different answer from not knowing the credential.
	if body.Status < 0 || body.Status > 255 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("status %d is outside the range 0 to 255 that a status type may take", body.Status),
		})
		return
	}
	entry, ok := s.wallet.SetCredentialStatus(id, body.Status)
	if !ok {
		http.Error(w, "credential has no status entry", http.StatusNotFound)
		return
	}

	verb := fmt.Sprintf("Set status %d on", body.Status)
	switch body.Status {
	case 0:
		verb = "Activated"
	case 1:
		verb = "Revoked"
	}
	s.wallet.AddLog("management", fmt.Sprintf("%s credential %s", verb, id), true)
	s.triggerSave()
	writeJSON(w, http.StatusOK, entry)
}

// handleRefreshCredential re-requests a credential from its issuer now,
// rather than waiting for the background task to notice it nearing expiry.
func (s *Server) handleRefreshCredential(w http.ResponseWriter, r *http.Request) {
	renewed, err := s.RefreshCredential(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, CredentialSummary(*renewed))
}
