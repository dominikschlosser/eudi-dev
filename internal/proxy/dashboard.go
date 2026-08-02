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

package proxy

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/web"
)

// Dashboard serves the web dashboard for live traffic inspection.
type Dashboard struct {
	store *Store
	port  int
}

// NewDashboard creates a new dashboard server.
func NewDashboard(store *Store, port int) *Dashboard {
	return &Dashboard{store: store, port: port}
}

// Handler returns the dashboard HTTP handler.
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/entries", d.handleEntries)
	mux.HandleFunc("GET /api/har", d.handleHAR)
	mux.HandleFunc("GET /api/stream", d.handleStream)

	// Mount the credential decoder web UI under /decode/
	decodeMux := web.NewMux("")
	mux.Handle("/decode/", http.StripPrefix("/decode", decodeMux))

	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	return mux
}

// ListenAndServe starts the dashboard HTTP server.
func (d *Dashboard) ListenAndServe() error {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", d.port),
		Handler:      d.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServe()
}

func (d *Dashboard) handleEntries(w http.ResponseWriter, r *http.Request) {
	entries := d.store.Entries()
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(entries)
}

func (d *Dashboard) handleHAR(w http.ResponseWriter, r *http.Request) {
	entries := d.store.Entries()
	har := GenerateHAR(entries)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"eudi-dev.har\"")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(har)
}

func (d *Dashboard) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	ch, unsub := d.store.Subscribe()
	defer unsub()

	for {
		select {
		case entry := <-ch:
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
