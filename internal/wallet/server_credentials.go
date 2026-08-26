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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// resolveDisplayImage turns a stored display image value into bytes: an
// "asset:" reference reads the file beside wallet.json, and an embedded data URI
// (as older wallets and freshly issued, not-yet-saved credentials carry) is
// decoded in place.
func (s *Server) resolveDisplayImage(uri string) (contentType string, data []byte, ok bool) {
	if strings.HasPrefix(uri, "asset:") {
		if s.store == nil {
			return "", nil, false
		}
		return s.store.ReadDisplayAsset(uri)
	}
	return dataURIImage(uri)
}

// handleCredentialDisplayImage serves a stored credential's display logo or
// background image, referenced by the credential listing instead of inlined as
// a data URI. The bytes are fixed for the credential, so the response is cached
// hard (immutable) with a content ETag.
func (s *Server) handleCredentialDisplayImage(w http.ResponseWriter, r *http.Request) {
	cred, ok := s.wallet.GetCredential(r.PathValue("id"))
	if !ok || cred.Display == nil {
		http.NotFound(w, r)
		return
	}
	var uri string
	switch r.PathValue("kind") {
	case "logo":
		uri = cred.Display.LogoURI
	case "background":
		uri = cred.Display.BackgroundURI
	default:
		http.NotFound(w, r)
		return
	}
	// A new store references the image as an asset file; a wallet written before
	// this change still embeds it as a data URI. Both are served here.
	contentType, data, ok := s.resolveDisplayImage(uri)
	if !ok {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

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

	data, err := s.wallet.CredentialsListingJSONWindow(offset, limit)
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

	var imported *StoredCredential
	var importErr error
	s.saveMutation(func() bool {
		imported, importErr = s.wallet.ImportCredential(raw)
		if importErr != nil {
			return false
		}
		s.wallet.AddLog("management", fmt.Sprintf("Imported %s credential %s", imported.Format, credentialLabel(*imported)), true)
		return true
	})
	if importErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": importErr.Error()})
		return
	}
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
	var removed bool
	s.saveMutation(func() bool {
		removed = s.wallet.RemoveCredential(id)
		if !removed {
			return false
		}
		s.wallet.AddLog("management", fmt.Sprintf("Deleted credential %s", label), true)
		return true
	})
	if !removed {
		http.Error(w, "credential not found", http.StatusNotFound)
		return
	}
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
	var entry StatusEntry
	var ok bool
	s.saveMutation(func() bool {
		entry, ok = s.wallet.SetCredentialStatus(id, body.Status)
		if !ok {
			return false
		}
		verb := fmt.Sprintf("Set status %d on", body.Status)
		switch body.Status {
		case 0:
			verb = "Activated"
		case 1:
			verb = "Revoked"
		}
		s.wallet.AddLog("management", fmt.Sprintf("%s credential %s", verb, id), true)
		return true
	})
	if !ok {
		http.Error(w, "credential has no status entry", http.StatusNotFound)
		return
	}
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
