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

// Management API handlers mirroring the wallet CLI commands (show, remove,
// issue, generate-pid, ca-cert, tls-cert) so a hosted wallet instance can be
// driven entirely over HTTP. Like the rest of the wallet server, these
// endpoints have no authentication: the wallet is a testing tool, so keep it
// on localhost or an isolated network. Internet-facing deployments run the
// demo profile (see demo.go), which disables the destructive endpoints and
// treats all wallet state as public and disposable.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/keys"
	"github.com/dominikschlosser/eudi-dev/internal/statuslist"
)

// handleGetCredential returns a single stored credential by ID.
func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cred, ok := s.wallet.GetCredential(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "credential not found"})
		return
	}
	writeJSON(w, http.StatusOK, s.wallet.CredentialSummaryWithStatus(cred))
}

// handleGetCredentialStatus resolves the live status of a credential: from
// the wallet's own status list when the entry is managed here, otherwise by
// fetching the external status list referenced by the credential.
func (s *Server) handleGetCredentialStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cred, ok := s.wallet.GetCredential(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "credential not found"})
		return
	}

	ref := CredentialStatusRef(cred)
	if entry, managed := s.wallet.StatusEntryFor(cred.ID); managed {
		info := map[string]any{"managed": true, "status": entry.Status, "source": "wallet"}
		if ref != nil {
			info["uri"] = ref.URI
			info["idx"] = ref.Idx
		}
		writeJSON(w, http.StatusOK, info)
		return
	}
	if ref == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "credential has no status list reference"})
		return
	}

	result, err := statuslist.Check(ref)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "checking external status list: " + err.Error(),
			"uri":   ref.URI,
			"idx":   ref.Idx,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"managed": false,
		"status":  result.Status,
		"source":  "remote",
		"uri":     ref.URI,
		"idx":     ref.Idx,
	})
}

// handleDeleteAllCredentials removes all stored credentials.
func (s *Server) handleDeleteAllCredentials(w http.ResponseWriter, r *http.Request) {
	count := s.wallet.ClearCredentials()
	s.wallet.AddLog("management", fmt.Sprintf("Deleted all credentials (%d)", count), true)
	s.triggerSave()
	writeJSON(w, http.StatusOK, map[string]int{"deleted": count})
}

// IssueAPIRequest is the POST /api/issue request body. The server handler
// and the CLI's local wallet backend both interpret issuance requests
// through it, so `issue --wallet` behaves identically against the local
// store and a running instance.
type IssueAPIRequest struct {
	Format          string                `json:"format"`
	Template        string                `json:"template"`
	Claims          map[string]any        `json:"claims"`
	PID             bool                  `json:"pid"`
	Omit            []string              `json:"omit"`
	AlwaysDisclosed []string              `json:"always_disclosed"`
	SaveAsTemplate  string                `json:"save_as_template"`
	VCT             string                `json:"vct"`
	DocType         string                `json:"doctype"`
	Namespace       string                `json:"namespace"`
	Exp             string                `json:"exp"`
	NBF             string                `json:"nbf"`
	StatusListURI   *string               `json:"status_list_uri"`
	StatusListIdx   *int                  `json:"status_list_idx"`
	TrustProfile    string                `json:"trust_profile"`
	Trust           IssuedAttestationSpec `json:"trust"`
}

// Options converts the API request into IssueOptions.
func (req IssueAPIRequest) Options() (IssueOptions, error) {
	opts := IssueOptions{
		Format:          req.Format,
		Template:        req.Template,
		Claims:          req.Claims,
		PID:             req.PID,
		Omit:            req.Omit,
		AlwaysDisclosed: req.AlwaysDisclosed,
		SaveTemplate:    req.SaveAsTemplate,
		VCT:             req.VCT,
		DocType:         req.DocType,
		Namespace:       req.Namespace,
		StatusListURI:   req.StatusListURI,
		StatusListIdx:   req.StatusListIdx,
		TrustProfile:    req.TrustProfile,
		Trust:           req.Trust,
	}
	if req.Exp != "" {
		expDuration, err := time.ParseDuration(req.Exp)
		if err != nil {
			return IssueOptions{}, fmt.Errorf("invalid exp duration: %w", err)
		}
		opts.ExpiresIn = expDuration
	}
	if req.NBF != "" {
		nbf, err := parseTimeOrDuration(req.NBF)
		if err != nil {
			return IssueOptions{}, err
		}
		opts.NotBefore = nbf
	}
	return opts, nil
}

// IssueSummary runs IssueCredential and returns the credential summary
// document served by POST /api/issue. The caller persists the wallet.
func (w *Wallet) IssueSummary(opts IssueOptions) (map[string]any, error) {
	result, err := w.IssueCredential(opts)
	if err != nil {
		return nil, err
	}
	summary := w.CredentialSummaryWithStatus(*result.Credential)
	if result.StatusRegistered {
		summary["status_list_idx"] = result.StatusIdx
	}
	if result.TemplatePath != "" {
		summary["template_path"] = result.TemplatePath
	}
	return summary, nil
}

// handleIssueCredential issues a credential with the wallet's issuer key and
// imports it, mirroring `issue <format> --wallet`.
func (s *Server) handleIssueCredential(w http.ResponseWriter, r *http.Request) {
	var req IssueAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parsing request body: " + err.Error()})
		return
	}

	if s.demo != nil && strings.TrimSpace(req.SaveAsTemplate) != "" {
		// Template writes are disabled in demo mode; without this check the
		// issue endpoint would bypass the blocked PUT /api/templates route.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "saving templates is disabled in public demo mode"})
		return
	}

	opts, err := req.Options()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	summary, err := s.wallet.IssueSummary(opts)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.wallet.AddLog("management", fmt.Sprintf("Issued %s credential %s", summary["format"], credentialTypeLabel(summary)), true)
	s.triggerSave()

	writeJSON(w, http.StatusCreated, summary)
}

// credentialTypeLabel names a credential summary for log entries: the vct for
// SD-JWT credentials, the doc type for mDocs, the id otherwise.
func credentialTypeLabel(summary map[string]any) string {
	for _, key := range []string{"vct", "doctype", "id"} {
		if v, ok := summary[key].(string); ok && v != "" {
			return v
		}
	}
	return "credential"
}

type generatePIDRequest struct {
	Claims map[string]any `json:"claims"`
	VCT    string         `json:"vct"`
}

// handleGeneratePID regenerates the default EUDI PID credentials (SD-JWT +
// mDoc), mirroring `wallet generate-pid`.
//
// Deprecated: use POST /api/issue with the pre-defined german-pid-sdjwt and
// german-pid-mdoc templates instead. The endpoint will be removed together
// with `wallet generate-pid` in a future release.
func (s *Server) handleGeneratePID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Deprecation", "true")
	var req generatePIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parsing request body: " + err.Error()})
		return
	}

	if err := s.wallet.GenerateDefaultCredentials(req.Claims, req.VCT); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.wallet.AddLog("management", "Regenerated default PID credentials", true)
	s.triggerSave()

	data, err := s.wallet.CredentialsJSON()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(data)
}

// handleCACertificate exports the shared wallet CA certificate, mirroring
// `wallet ca-cert`.
func (s *Server) handleCACertificate(w http.ResponseWriter, r *http.Request) {
	store := s.currentStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "wallet store is not configured"})
		return
	}
	certPEM, err := store.LoadOrCreateSharedCACertificatePEM()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "loading wallet CA certificate: " + err.Error()})
		return
	}
	writeCertificateExport(w, r, certPEM)
}

// handleTLSCertificate exports the wallet's HTTPS leaf certificate, mirroring
// `wallet tls-cert`.
func (s *Server) handleTLSCertificate(w http.ResponseWriter, r *http.Request) {
	store := s.currentStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "wallet store is not configured"})
		return
	}
	issuerURL := strings.TrimSpace(s.wallet.IssuerURL)
	if issuerURL == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "wallet issuer URL is not configured"})
		return
	}
	certPEM, err := store.LoadOrCreateIssuerTLSLeafCertificatePEMForURL(issuerURL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "loading wallet TLS certificate: " + err.Error()})
		return
	}
	writeCertificateExport(w, r, certPEM)
}

// writeCertificateExport writes certificate PEM bytes in the requested format:
// PEM by default, or a JWKS document via ?format=jwks.
func writeCertificateExport(w http.ResponseWriter, r *http.Request, certPEM []byte) {
	switch r.URL.Query().Get("format") {
	case "", "pem":
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(certPEM)
	case "jwks":
		jwks, err := keys.CertificatePEMToJWKS(certPEM)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "building JWKS: " + err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported format: expected pem or jwks"})
	}
}

func (s *Server) currentStore() *WalletStore {
	s.storeSyncMu.Lock()
	defer s.storeSyncMu.Unlock()
	return s.store
}

// parseTimeOrDuration parses a value as an RFC3339 timestamp or a relative
// duration (e.g. "-1h").
func parseTimeOrDuration(val string) (*time.Time, error) {
	if d, err := time.ParseDuration(val); err == nil {
		t := time.Now().Add(d)
		return &t, nil
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return nil, fmt.Errorf("invalid nbf value %q: expected RFC3339 (e.g. 2025-01-15T00:00:00Z) or duration (e.g. -1h)", val)
	}
	return &t, nil
}
