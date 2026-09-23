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
	"log"
	"net/http"
	"time"

	"github.com/dominikschlosser/eudi-dev/v2/internal/httpsec"
	"github.com/dominikschlosser/eudi-dev/v2/internal/web"
)

// streamKeepaliveInterval is how often an idle event stream sends a comment
// line. A variable so tests do not have to wait for it.
var streamKeepaliveInterval = 20 * time.Second

// A client that stops reading must eventually release its goroutine and subscription.
// Allow enough time for keepalives to reach active readers.
var streamWriteTimeout = 2 * time.Minute

type Dashboard struct {
	store *Store
	port  int
}

func NewDashboard(store *Store, port int) *Dashboard {
	return &Dashboard{store: store, port: port}
}

func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/entries", d.handleEntries)
	mux.HandleFunc("GET /api/har", d.handleHAR)
	mux.HandleFunc("GET /api/stream", d.handleStream)

	decodeMux := web.NewMux("")
	mux.Handle("/decode/", http.StripPrefix("/decode", decodeMux))

	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// Apply security headers because captured traffic contains untrusted input.
	return httpsec.Headers(mux)
}

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

	// Extend the deadline before each write. A fixed response deadline would end a
	// healthy stream, while no deadline would leave stalled clients holding a
	// subscription forever.
	rc := http.NewResponseController(w)
	extendDeadline := func() {
		if err := rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout)); err != nil {
			log.Printf("[Dashboard] stream write deadline not extended, the stream will end with the server's write timeout: %v", err)
		}
	}
	extendDeadline()

	// Subscribed before the response head goes out, so a client that starts
	// following and then reads the entry list cannot miss an entry that
	// arrives between the two requests.
	ch, unsub := d.store.Subscribe()
	defer unsub()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	keepalive := time.NewTicker(streamKeepaliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case entry := <-ch:
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			extendDeadline()
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-keepalive.C:
			extendDeadline()
			// Send SSE comments as keepalives so intermediaries do not close idle
			// streams.
			fmt.Fprint(w, ": keepalive\n\n") //nolint:errcheck // a dead connection ends the stream on the next write anyway
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
