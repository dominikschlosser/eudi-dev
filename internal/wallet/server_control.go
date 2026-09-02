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

// Diagnostics and control: version, configuration, activity log, the last
// error, scripted failures and shutdown.

package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// processBuildID identifies the code this process is running: the SHA-256 of
// the executable, hashed once at startup. Comparing it against the binary on
// disk detects a server that outlived a rebuild.
var processBuildID = sync.OnceValue(func() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
})

// SetImprint serves the given pre-rendered imprint page at /imprint and
// makes /api/config advertise it so the UI shows the footer link.
func (s *Server) SetImprint(page []byte) {
	s.imprintHTML = page
}

func (s *Server) handleImprint(w http.ResponseWriter, r *http.Request) {
	if len(s.imprintHTML) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(s.imprintHTML)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"build_id": processBuildID(),
		"version":  s.version,
	}
	if s.demo == nil {
		doc["pid"] = os.Getpid()
	}
	writeJSON(w, http.StatusOK, doc)
}

// SetVersion sets the human-readable release version reported by
// /api/version and /api/config. The version lives in the cmd package, so the
// serve command injects it.
func (s *Server) SetVersion(version string) {
	s.version = version
}

// demoLogLimit caps what demo mode serves, since a shared wallet accumulates
// entries from every visitor and the UI only needs the recent tail. It bounds
// the response, not the log: maxLogEntries bounds what is kept.
const demoLogLimit = 50

// handleLog returns the activity log.
func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	log := s.wallet.GetLog()
	if s.demo != nil && len(log) > demoLogLimit {
		log = log[len(log)-demoLogLimit:]
	}
	writeJSON(w, http.StatusOK, log)
}

// handleClearLog removes all activity log entries.
func (s *Server) handleClearLog(w http.ResponseWriter, r *http.Request) {
	s.wallet.ClearLog()
	s.triggerSave()
	w.WriteHeader(http.StatusNoContent)
}

// handleLastError returns the last error, if any.
func (s *Server) handleLastError(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Vary", "Cookie, "+OwnerHeader)
	err := s.wallet.PeekLastError(callerOwners(r))
	if err == nil {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	writeJSON(w, http.StatusOK, err)
}

// handleClearLastError clears the last UI error.
func (s *Server) handleClearLastError(w http.ResponseWriter, r *http.Request) {
	s.wallet.ClearLastError(callerOwners(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

// handleGetConfig returns the wallet instance's full introspection document.
// Remote controllers use it to learn everything about an instance: identity
// (pid, port, build), storage locations, URLs, and runtime behavior.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	walletDir := ""
	if store := s.currentStore(); store != nil {
		walletDir = store.Dir
	}
	templatesDir := s.wallet.TemplatesDir
	if templatesDir == "" && walletDir != "" {
		templatesDir = filepath.Join(walletDir, "templates")
	}
	// Snapshot the runtime-mutable conformance fields together under the lock.
	// A local PUT /api/config/conformance can be changing them concurrently.
	mode, requireHAIP, requireEncrypted := s.wallet.ConformanceSettings()
	config := map[string]any{
		"port":               s.port,
		"build_id":           processBuildID(),
		"version":            s.version,
		"imprint":            len(s.imprintHTML) > 0,
		"base_url":           s.wallet.BaseURL,
		"issuer_url":         s.wallet.IssuerURL,
		"status_list_url":    s.wallet.StatusListURL(),
		"preferred_format":   s.wallet.PreferredFormat,
		"validation_mode":    string(mode),
		"vci_version":        string(s.wallet.VCIFeatureVersion()),
		"auto_accept":        s.wallet.AutoAccept,
		"session_transcript": string(s.wallet.SessionTranscript),
		"require_haip":       requireHAIP,
		// Presentations and issuance are gated by the same flag, but they are
		// reported separately: a client should be able to tell which half it
		// is being held to without inferring it.
		"require_haip_issuance":     requireHAIP,
		"require_encrypted_request": requireEncrypted,
		"force_client_attestation":  s.wallet.ForceClientAttestation,
		"adhoc_display_images":      s.wallet.AdhocDisplayImages,
		"credential_count":          len(s.wallet.GetCredentials()),
		// False when an external TLS terminator serves the issuer origin: the
		// built-in HTTPS listener is disabled then, and the wallet's
		// self-signed leaf certificate is never presented on the wire.
		"tls_listener": s.issuerPort > 0,
	}
	if demo := s.demoConfig(); demo != nil {
		config["demo"] = demo
	} else {
		// Host paths and the pid identify the process on its machine. They
		// are for local remote-control tooling, not anonymous demo visitors.
		config["pid"] = os.Getpid()
		config["wallet_dir"] = walletDir
		config["templates_dir"] = templatesDir
	}
	writeJSON(w, http.StatusOK, config)
}

// handleShutdown asks the wallet server process to exit. Like the rest of
// the management API it is unauthenticated (testing tool only). The response
// is sent before the process exits.
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	s.log("  Shutdown requested via API")
	writeJSON(w, http.StatusOK, map[string]any{"shutting_down": true, "pid": os.Getpid()})
	go func() {
		time.Sleep(200 * time.Millisecond)
		if s.ShutdownFunc != nil {
			s.ShutdownFunc()
			return
		}
		os.Exit(0)
	}()
}

// handleSetNextError sets a one-shot error override.
func (s *Server) handleSetNextError(w http.ResponseWriter, r *http.Request) {
	var body NextErrorOverride
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	s.wallet.SetNextError(&body)
	writeJSON(w, http.StatusOK, body)
}

// handleClearNextError clears the error override without consuming.
func (s *Server) handleClearNextError(w http.ResponseWriter, r *http.Request) {
	s.wallet.SetNextError(nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleSetPreferredFormat sets the global credential format preference.
func (s *Server) handleSetPreferredFormat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Format string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	s.wallet.mu.Lock()
	s.wallet.PreferredFormat = body.Format
	s.wallet.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"format": body.Format})
}

// handleSetAutoAccept flips auto-accept at runtime. The change is
// process-level like the conformance settings: it holds until the process
// restarts and applies to every flow reaching this wallet. Refused in demo
// mode, where a shared instance keeps its consent rules.
func (s *Server) handleSetAutoAccept(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	s.wallet.mu.Lock()
	s.wallet.AutoAccept = body.Enabled
	s.wallet.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"auto_accept": body.Enabled})
}

// handleSetConformance changes the wallet's runtime conformance settings
// (validation mode, HAIP, encrypted requests). On a local wallet every flow
// (the UI, the macOS URL-scheme handler and the CLI) hits this same wallet, so
// the change reaches all of them. Refused in demo mode, where the settings are
// shared and fixed (HAIP in debug mode).
func (s *Server) handleSetConformance(w http.ResponseWriter, r *http.Request) {
	if s.demo != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "conformance settings are fixed in public demo mode (run the wallet locally to change them)"})
		return
	}
	var body struct {
		Mode       *string `json:"mode,omitempty"`
		HAIP       *bool   `json:"haip,omitempty"`
		Encrypted  *bool   `json:"encrypted,omitempty"`
		VCIVersion *string `json:"vci_version,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	var mode ValidationMode
	if body.Mode != nil {
		parsed, err := ParseValidationMode(*body.Mode)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		mode = parsed
	}
	var vciVersion VCIVersion
	if body.VCIVersion != nil {
		parsed, err := ParseVCIVersion(*body.VCIVersion)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		vciVersion = parsed
	}
	s.wallet.mu.Lock()
	if body.Mode != nil {
		s.wallet.ValidationMode = mode
	}
	if body.VCIVersion != nil {
		s.wallet.VCIVersion = vciVersion
	}
	if body.HAIP != nil {
		s.wallet.RequireHAIP = *body.HAIP
	}
	if body.Encrypted != nil {
		s.wallet.RequireEncryptedRequest = *body.Encrypted
	}
	s.wallet.mu.Unlock()
	s.writeConformanceConfig(w)
}

// handleResetConformance restores the conformance settings the wallet started
// with. Refused in demo mode, like handleSetConformance.
func (s *Server) handleResetConformance(w http.ResponseWriter, r *http.Request) {
	if s.demo != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "conformance settings are fixed in public demo mode"})
		return
	}
	s.wallet.mu.Lock()
	s.wallet.ValidationMode = s.defaultValidationMode
	s.wallet.RequireHAIP = s.defaultRequireHAIP
	s.wallet.RequireEncryptedRequest = s.defaultRequireEncryptedRequest
	s.wallet.VCIVersion = s.defaultVCIVersion
	s.wallet.mu.Unlock()
	s.writeConformanceConfig(w)
}

func (s *Server) writeConformanceConfig(w http.ResponseWriter) {
	// Direct field reads: already inside the lock, so calling the locking
	// accessor here would self-deadlock (RWMutex is not reentrant).
	s.wallet.mu.RLock()
	vciVersion := s.wallet.VCIVersion
	if vciVersion == "" {
		vciVersion = VCIVersion10
	}
	resp := map[string]any{
		"validation_mode":           string(s.wallet.ValidationMode),
		"require_haip":              s.wallet.RequireHAIP,
		"require_encrypted_request": s.wallet.RequireEncryptedRequest,
		"vci_version":               string(vciVersion),
	}
	s.wallet.mu.RUnlock()
	writeJSON(w, http.StatusOK, resp)
}
