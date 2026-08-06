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

package httpsec

import (
	"net/http"
	"net/url"
	"strings"
)

// GuardAPI refuses a request under /api/ that a page on another site sent.
//
// These APIs have no authentication on purpose, and the usual answer (keep
// them on localhost) does not cover the browser: every page a developer
// visits can reach localhost too. Nothing here is preflighted either, because
// a POST carrying text/plain is a CORS simple request, so a page could hand
// the wallet a presentation request and have credentials posted to a
// response_uri of its choosing. Reading the reply is what CORS stops, and
// this attack never needs to read it.
//
// The Origin header is what separates the two callers. A browser attaches it
// to exactly the requests in question and a page cannot forge it, while a
// CLI, a curl invocation or a test harness sends none at all and is let
// through untouched. Only /api/ is guarded: the protocol endpoints are meant
// to be reached from elsewhere, and a browser navigation to them carries no
// Origin to judge anyway.
//
// ownOrigins names additional origins to treat as this server's own, for a
// deployment whose public URL is not the Host it receives (a reverse proxy
// that rewrites it).
func GuardAPI(next http.Handler, ownOrigins ...string) http.Handler {
	return GuardAPIExcept(next, nil, ownOrigins...)
}

// GuardAPIExcept is GuardAPI with a list of paths that are cross-origin by
// contract rather than by accident.
//
// One endpoint genuinely is: the Digital Credentials API. A verifier's web
// page calls it from its own origin, which is the whole mechanism, and the
// wallet identifies that caller by the origin the request arrived with, which
// is what OpenID4VP over the Digital Credentials API authenticates an
// unsigned request by. Guarding it by origin refuses the only kind of caller
// it has. The protection there is that check plus the consent dialog, not
// this one.
func GuardAPIExcept(next http.Handler, crossOriginByContract []string, ownOrigins ...string) http.Handler {
	allowed := hostSet(ownOrigins)
	exempt := make(map[string]bool, len(crossOriginByContract))
	for _, p := range crossOriginByContract {
		exempt[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && !exempt[r.URL.Path] && isCrossOrigin(r, allowed) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"cross-origin API requests are not allowed"}` + "\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isCrossOrigin reports whether the request carries an Origin naming a site
// other than the one serving it.
func isCrossOrigin(r *http.Request, allowed map[string]bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		// Includes the literal "null" a sandboxed frame or a file:// page
		// sends, which is nobody's own origin.
		return true
	}
	host := strings.ToLower(u.Host)
	// Host only, not scheme: a TLS terminator in front of the server leaves
	// it serving http while the browser reports https for the same site.
	// Nothing an attacker controls can match the host either way.
	if host == strings.ToLower(r.Host) {
		return false
	}
	return !allowed[host]
}

// hostSet reduces origin URLs to the set of their hosts.
func hostSet(origins []string) map[string]bool {
	set := make(map[string]bool, len(origins))
	for _, raw := range origins {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			continue
		}
		set[strings.ToLower(u.Host)] = true
	}
	return set
}
