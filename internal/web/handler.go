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

package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"time"
)

const maxRequestBody = 1 << 20 // 1MB

// MuxOptions configures the decoder handler.
type MuxOptions struct {
	Credential  string // pre-filled credential served via GET /api/prefill
	Version     string // release version reported by GET /api/meta
	ImprintHTML []byte // pre-rendered legal notice served at GET /imprint
	Demo        bool   // public demo deployment, the UI shows a data disclaimer
}

// ListenAndServe starts the HTTP server on the given port.
func ListenAndServe(port int, opts MuxOptions) error {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      NewMuxWithOptions(opts),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServe()
}

// NewMux creates the HTTP handler with API and static file routes.
// If credential is non-empty, it is served via GET /api/prefill.
func NewMux(credential string) http.Handler {
	return NewMuxWithOptions(MuxOptions{Credential: credential})
}

// NewMuxWithOptions creates the HTTP handler with API and static file routes.
func NewMuxWithOptions(opts MuxOptions) http.Handler {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("POST /api/decode", handleDecode)
	mux.HandleFunc("POST /api/validate", handleValidate)
	mux.HandleFunc("GET /api/prefill", handlePrefill(opts.Credential))
	mux.HandleFunc("GET /api/meta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"version": opts.Version,
			"imprint": len(opts.ImprintHTML) > 0,
			"demo":    opts.Demo,
		})
	})
	mux.HandleFunc("GET /imprint", func(w http.ResponseWriter, r *http.Request) {
		if len(opts.ImprintHTML) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(opts.ImprintHTML)
	})

	// Static files
	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	return mux
}

func handlePrefill(credential string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential": credential})
	}
}

type decodeRequest struct {
	Input string `json:"input"`
}

func handleDecode(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	var req decodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input is required")
		return
	}

	result, err := Decode(req.Input)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(result)
}

type validateRequest struct {
	Input        string `json:"input"`
	Key          string `json:"key"`
	TrustListURL string `json:"trustListURL"`
	TrustListRaw string `json:"trustListRaw"`
	CheckStatus  bool   `json:"checkStatus"`
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	var req validateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input is required")
		return
	}

	result, err := Validate(req.Input, ValidateOpts{
		Key:          req.Key,
		TrustListURL: req.TrustListURL,
		TrustListRaw: req.TrustListRaw,
		CheckStatus:  req.CheckStatus,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(result)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
