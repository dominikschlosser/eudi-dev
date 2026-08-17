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
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/httpsec"
)

// DemoOptions configures the public-demo profile: a shared, anonymous
// demo environment exposed on the internet. ("Sandbox" is deliberately
// avoided here, it names the official German EUDI test ecosystem.)
// Visitors keep the full credential flows
// (issue, present, decode, delete), while endpoints that control the process
// or write to the host are disabled.
type DemoOptions struct {
	// ResetInterval restores the wallet to a clean baseline (default PID
	// credentials, empty log) on this interval. 0 disables periodic resets.
	ResetInterval time.Duration
	// ResetDaily restores the baseline at a fixed wall-clock time instead of
	// on an interval, so the reset lands at the same local time every day
	// rather than drifting with process restarts. Takes precedence over
	// ResetInterval.
	ResetDaily *DailySchedule
}

// DailySchedule is a wall-clock time of day in a specific location.
type DailySchedule struct {
	Hour     int
	Minute   int
	Location *time.Location
}

// Next returns the next occurrence strictly after now. Using the location's
// own calendar keeps it correct across DST changes: the reset stays at the
// configured local time rather than shifting by an hour.
func (d DailySchedule) Next(now time.Time) time.Time {
	local := now.In(d.Location)
	next := time.Date(local.Year(), local.Month(), local.Day(), d.Hour, d.Minute, 0, 0, d.Location)
	if !next.After(local) {
		next = time.Date(local.Year(), local.Month(), local.Day()+1, d.Hour, d.Minute, 0, 0, d.Location)
	}
	return next
}

// String renders the schedule for logs and the UI, e.g. "00:00 CET".
func (d DailySchedule) String() string {
	zone, _ := time.Now().In(d.Location).Zone()
	return fmt.Sprintf("%02d:%02d %s", d.Hour, d.Minute, zone)
}

// ParseDailySchedule reads "HH:MM" (server local time) or "HH:MM <IANA zone>",
// for example "00:00 Europe/Berlin".
func ParseDailySchedule(value string) (*DailySchedule, error) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 || len(fields) > 2 {
		return nil, fmt.Errorf("expected \"HH:MM\" or \"HH:MM <timezone>\"")
	}
	var hour, minute int
	if _, err := fmt.Sscanf(fields[0], "%d:%d", &hour, &minute); err != nil {
		return nil, fmt.Errorf("invalid time of day %q", fields[0])
	}
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return nil, fmt.Errorf("time of day %q is out of range", fields[0])
	}
	loc := time.Local
	if len(fields) == 2 {
		parsed, err := time.LoadLocation(fields[1])
		if err != nil {
			return nil, fmt.Errorf("unknown timezone %q: %w", fields[1], err)
		}
		loc = parsed
	}
	return &DailySchedule{Hour: hour, Minute: minute, Location: loc}, nil
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

// maxRequestBodyBytes caps request bodies. Every legitimate payload
// (credentials, offers, presentations, templates) is far smaller. The cap
// used to apply in demo mode alone, which left the size of a request the
// server will read up to whoever sent it everywhere else, on a server that
// reads several of them fully into memory.
const maxRequestBodyBytes = 1 << 20

// Handler returns the server's root handler: the mux, wrapped with the
// browser security headers, the cross-origin guard, the request body cap
// and, when the demo profile is enabled, the demo guard.
func (s *Server) Handler() http.Handler {
	return httpsec.Headers(s.guardAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.demo != nil && demoBlockedRoute(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "endpoint disabled in public demo mode",
			})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		s.mux.ServeHTTP(w, r)
	})))
}

// guardAPI wraps a handler with the cross-origin guard, naming the URLs this
// wallet is served under so a deployment behind a reverse proxy keeps
// working when the proxy does not pass the public Host through.
func (s *Server) guardAPI(next http.Handler) http.Handler {
	// /api/dc-api is the Digital Credentials API endpoint. A verifier's page
	// invokes it from its own origin by design, so it is exempt and relies on
	// the origin the platform reports and the consent dialog instead.
	return httpsec.GuardAPIExcept(next, []string{"/api/dc-api"}, s.wallet.BaseURL, s.wallet.IssuerURL)
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
	case r.Method == http.MethodPut && p == "/api/config/auto-accept":
		return true
	case (r.Method == http.MethodPut || r.Method == http.MethodDelete) && p == "/api/config/conformance":
		return true
	// Clearing the shared history is a change to what every other visitor
	// sees, and nothing on a demo instance needs it. The log is bounded on
	// its own, so keeping it is not a growth problem.
	case r.Method == http.MethodDelete && (p == "/api/log" || p == "/api/error"):
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
	if s.demo == nil {
		return
	}
	daily := s.demo.opts.ResetDaily
	if daily == nil && s.demo.opts.ResetInterval <= 0 {
		return
	}

	// nextResetAfter is evaluated per cycle so a daily schedule stays pinned
	// to the wall clock (and survives DST) instead of drifting.
	nextResetAfter := func(now time.Time) time.Time {
		if daily != nil {
			return daily.Next(now)
		}
		return now.Add(s.demo.opts.ResetInterval)
	}

	s.demo.mu.Lock()
	s.demo.stop = make(chan struct{})
	s.demo.nextReset = nextResetAfter(time.Now())
	stop := s.demo.stop
	s.demo.mu.Unlock()

	go func() {
		for {
			s.demo.mu.Lock()
			wait := time.Until(s.demo.nextReset)
			s.demo.mu.Unlock()
			if wait < 0 {
				wait = 0
			}
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
				if err := s.demoReset(); err != nil {
					s.log("  ERROR: demo reset: %v", err)
				}
				s.demo.mu.Lock()
				s.demo.nextReset = nextResetAfter(time.Now())
				s.demo.mu.Unlock()
			case <-stop:
				timer.Stop()
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
	// Re-issue the signing leaf from the same CA. Leaves are valid for a year
	// and a long-lived demo would eventually serve an expired one, which is
	// only ever noticed by whatever stops verifying. A daily reset keeps it
	// fresh. The CA itself is untouched, so anyone who pinned it stays good.
	if err := s.wallet.RefreshSigningCertificate(); err != nil {
		return err
	}
	if err := s.wallet.GenerateProtectedDefaults(); err != nil {
		return err
	}
	if s.store != nil {
		if err := s.store.Save(s.wallet); err != nil {
			return err
		}
	}
	// Scheduling belongs to startDemoReset: computing it here would break a
	// daily schedule, whose ResetInterval is zero.
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
	if s.demo.opts.ResetDaily != nil {
		cfg["reset_daily_at"] = s.demo.opts.ResetDaily.String()
		cfg["reset_interval_seconds"] = 0
	}
	s.demo.mu.Lock()
	if !s.demo.nextReset.IsZero() {
		cfg["next_reset"] = s.demo.nextReset.UTC().Format(time.RFC3339)
	}
	s.demo.mu.Unlock()
	return cfg
}
