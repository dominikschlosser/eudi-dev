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
	"encoding/json"
	"net/http"
	"net/url"
)

// conformanceCookieName is the cookie the demo UI writes to carry a visitor's
// per-browser conformance overrides. It is read on every presentation and
// offer flow so the override reaches the server-side steps (the direct_post
// response to the verifier, the issuer backend calls) and the top-level
// /authorize navigation that a request header or JSON body cannot.
const conformanceCookieName = "eudi_conformance"

// conformanceOverride is the per-visitor conformance override the demo UI
// stores. Absent fields inherit the server's configured settings, so the
// wallet's own defaults (strict + HAIP under --demo) still apply when a
// visitor has changed nothing.
type conformanceOverride struct {
	Mode      string `json:"mode,omitempty"` // "strict" or "debug"
	HAIP      *bool  `json:"haip,omitempty"`
	Encrypted *bool  `json:"encrypted,omitempty"`
}

// conformanceOverrideFromRequest reads the override cookie. A missing or
// malformed cookie yields an empty override, i.e. inherit the server.
func conformanceOverrideFromRequest(r *http.Request) conformanceOverride {
	var o conformanceOverride
	ck, err := r.Cookie(conformanceCookieName)
	if err != nil {
		return o
	}
	raw, err := url.QueryUnescape(ck.Value)
	if err != nil {
		return o
	}
	// Best-effort: a cookie we cannot parse is treated as no override rather
	// than an error, so a stale or hand-edited value never breaks a flow.
	_ = json.Unmarshal([]byte(raw), &o)
	return o
}

// applyTo fills the conformance fields of opts that are not already set from an
// explicit per-request value (a header or JSON body), which take precedence
// over the cookie so CLI and programmatic callers keep full control.
func (o conformanceOverride) applyTo(opts presentationRequestOptions) presentationRequestOptions {
	if opts.RequireHAIP == nil {
		opts.RequireHAIP = o.HAIP
	}
	if opts.ValidationMode == "" {
		opts.ValidationMode = o.Mode
	}
	if opts.RequireEncryptedRequest == nil {
		opts.RequireEncryptedRequest = o.Encrypted
	}
	return opts
}

// hasConformanceOverride reports whether any conformance field is set, i.e.
// whether a per-request wallet clone is needed at all.
func (opts presentationRequestOptions) hasConformanceOverride() bool {
	return opts.RequireHAIP != nil || opts.ValidationMode != "" || opts.RequireEncryptedRequest != nil
}

// mergedConformanceOptions folds the per-request conformance override from
// three sources into base, in decreasing precedence: explicit body values
// already on base (highest), then the X-Eudi-Dev-* headers (the CLI and the
// conformance suite), then the eudi_conformance cookie (the browser UI). base
// carries the endpoint's own body values and any non-conformance options
// (AutoAccept, SessionTranscript), which pass through untouched.
func mergedConformanceOptions(r *http.Request, base presentationRequestOptions) presentationRequestOptions {
	// Headers fill what the body left unset.
	if base.RequireHAIP == nil {
		base.RequireHAIP = parseBoolHeader(r.Header.Get("X-Eudi-Dev-HAIP"))
	}
	if base.ValidationMode == "" {
		base.ValidationMode = r.Header.Get("X-Eudi-Dev-Mode")
	}
	if base.RequireEncryptedRequest == nil {
		base.RequireEncryptedRequest = parseBoolHeader(r.Header.Get("X-Eudi-Dev-Encrypted"))
	}
	// The cookie fills whatever body and headers left unset.
	return conformanceOverrideFromRequest(r).applyTo(base)
}
