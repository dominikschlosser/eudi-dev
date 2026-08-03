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
	"net/http"
	"strings"
	"sync"
	"time"
)

// DemoOptions configures the public-demo profile: a shared, anonymous
// sandbox exposed on the internet. Visitors keep the full credential flows
// (issue, present, decode, delete), while endpoints that control the process
// or write to the host are disabled.
type DemoOptions struct {
	// ResetInterval restores the wallet to a clean baseline (default PID
	// credentials, empty log) on this interval. 0 disables periodic resets.
	ResetInterval time.Duration
}

// demoState is the runtime state of an enabled demo profile.
type demoState struct {
	opts      DemoOptions
	mu        sync.Mutex
	nextReset time.Time
	stop      chan struct{}
	stopOnce  sync.Once
}

// SetDemo enables the public-demo profile. Call before ListenAndServe.
func (s *Server) SetDemo(opts DemoOptions) {
	s.demo = &demoState{opts: opts}
}

// DemoEnabled reports whether the public-demo profile is active.
func (s *Server) DemoEnabled() bool {
	return s.demo != nil
}

// demoMaxBodyBytes caps request bodies in demo mode; every legitimate
// payload (credentials, offers, presentations) is far smaller.
const demoMaxBodyBytes = 1 << 20

// Handler returns the server's root handler: the mux, wrapped with the demo
// guard when the demo profile is enabled.
func (s *Server) Handler() http.Handler {
	if s.demo == nil {
		return s.mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if demoBlockedRoute(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "endpoint disabled in public demo mode",
			})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, demoMaxBodyBytes)
		s.mux.ServeHTTP(w, r)
	})
}

// demoBlockedRoute reports whether the request targets an endpoint that must
// not be reachable by anonymous demo visitors: process control, writes to
// the server's filesystem, and behavior changes affecting all visitors.
func demoBlockedRoute(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && p == "/api/shutdown":
		return true
	case (r.Method == http.MethodPut || r.Method == http.MethodDelete) && strings.HasPrefix(p, "/api/templates/"):
		return true
	case (r.Method == http.MethodPost || r.Method == http.MethodDelete) && p == "/api/next-error":
		return true
	case r.Method == http.MethodPut && p == "/api/config/preferred-format":
		return true
	}
	return false
}

// ResetToBaseline drops all visitor-created state: credentials, activity
// log, status entries and the attestation registry. Keys, certificates and
// serving URLs are untouched, so trust list and status list URLs stay
// stable across resets.
func (w *Wallet) ResetToBaseline() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Credentials = nil
	w.Log = nil
	w.StatusEntries = nil
	w.StatusListCounter = 0
	w.IssuedAttestations = nil
}

// startDemoReset launches the periodic baseline reset when configured.
// Called from ListenAndServe/ListenAndServeBackground.
func (s *Server) startDemoReset() {
	if s.demo == nil || s.demo.opts.ResetInterval <= 0 {
		return
	}
	s.demo.mu.Lock()
	s.demo.stop = make(chan struct{})
	s.demo.nextReset = time.Now().Add(s.demo.opts.ResetInterval)
	s.demo.mu.Unlock()
	go func() {
		ticker := time.NewTicker(s.demo.opts.ResetInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := s.demoReset(); err != nil {
					s.log("  ERROR: demo reset: %v", err)
				}
			case <-s.demo.stop:
				return
			}
		}
	}()
}

// stopDemoReset stops the reset ticker. Safe to call multiple times.
func (s *Server) stopDemoReset() {
	if s.demo == nil || s.demo.stop == nil {
		return
	}
	s.demo.stopOnce.Do(func() { close(s.demo.stop) })
}

// demoReset restores the clean baseline and persists it. It holds
// storeSyncMu for the whole sequence so concurrent requests (which reload
// the store at their boundary) observe either the pre-reset or the fully
// regenerated state, never a half-reset one.
func (s *Server) demoReset() error {
	s.storeSyncMu.Lock()
	defer s.storeSyncMu.Unlock()

	s.wallet.ResetToBaseline()
	if err := s.wallet.GenerateDefaultCredentials(nil, ""); err != nil {
		return err
	}
	if s.store != nil {
		if err := s.store.Save(s.wallet); err != nil {
			return err
		}
	}
	s.demo.mu.Lock()
	s.demo.nextReset = time.Now().Add(s.demo.opts.ResetInterval)
	s.demo.mu.Unlock()
	s.log("  Demo reset: baseline restored")
	return nil
}

// demoConfig returns the demo section of GET /api/config, or nil when the
// demo profile is off.
func (s *Server) demoConfig() map[string]any {
	if s.demo == nil {
		return nil
	}
	cfg := map[string]any{
		"enabled":                true,
		"reset_interval_seconds": int(s.demo.opts.ResetInterval / time.Second),
	}
	s.demo.mu.Lock()
	if !s.demo.nextReset.IsZero() {
		cfg["next_reset"] = s.demo.nextReset.UTC().Format(time.RFC3339)
	}
	s.demo.mu.Unlock()
	return cfg
}
