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

// Package httpsec holds the browser security headers every UI in this toolkit
// serves. All of them render content someone else supplied: credentials,
// issuer metadata, verifier requests, proxied traffic. These headers keep a
// hole in the escaping from becoming code execution.
package httpsec

import "net/http"

// ContentSecurityPolicy allows scripts and styles from the page's own origin
// and nothing else. Without 'unsafe-inline' in script-src, an injected
// handler or script tag does not run even when escaping fails. The remaining
// directives close the paths an injection would otherwise use to exfiltrate:
// no plugins, no base tag rewriting, no framing, forms and fetches to this
// origin only, images from this origin or data URIs.
const ContentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// Headers wraps a handler with the browser security headers: the policy
// above, no MIME sniffing (a stored credential served as JSON must never be
// interpreted as HTML), no framing, and no referrer leaking URLs to a
// verifier or issuer.
func Headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
