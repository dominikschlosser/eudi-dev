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
	"net/http/httptest"
	"net/url"
	"testing"
)

func requestWithConformanceCookie(t *testing.T, rawJSON string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	r.AddCookie(&http.Cookie{Name: conformanceCookieName, Value: url.QueryEscape(rawJSON)})
	return r
}

func TestConformanceOverrideFromRequest(t *testing.T) {
	t.Run("no cookie inherits the server", func(t *testing.T) {
		o := conformanceOverrideFromRequest(httptest.NewRequest(http.MethodGet, "/authorize", nil))
		if o.Mode != "" || o.HAIP != nil || o.Encrypted != nil {
			t.Fatalf("expected empty override, got %+v", o)
		}
	})

	t.Run("valid cookie is parsed", func(t *testing.T) {
		o := conformanceOverrideFromRequest(requestWithConformanceCookie(t, `{"mode":"debug","haip":false,"encrypted":true}`))
		if o.Mode != "debug" {
			t.Errorf("mode = %q, want debug", o.Mode)
		}
		if o.HAIP == nil || *o.HAIP != false {
			t.Errorf("haip = %v, want false", o.HAIP)
		}
		if o.Encrypted == nil || *o.Encrypted != true {
			t.Errorf("encrypted = %v, want true", o.Encrypted)
		}
	})

	t.Run("malformed cookie is ignored, not an error", func(t *testing.T) {
		o := conformanceOverrideFromRequest(requestWithConformanceCookie(t, `not json`))
		if o.Mode != "" || o.HAIP != nil || o.Encrypted != nil {
			t.Fatalf("expected empty override for malformed cookie, got %+v", o)
		}
	})
}

func TestConformanceOverrideApplyToPrecedence(t *testing.T) {
	off := false
	cookie := conformanceOverride{Mode: "debug", HAIP: &off}

	// An explicit body/header value wins over the cookie.
	explicit := true
	got := cookie.applyTo(presentationRequestOptions{RequireHAIP: &explicit, ValidationMode: "strict"})
	if got.ValidationMode != "strict" {
		t.Errorf("mode = %q, want strict (explicit wins)", got.ValidationMode)
	}
	if got.RequireHAIP == nil || *got.RequireHAIP != true {
		t.Errorf("haip = %v, want true (explicit wins)", got.RequireHAIP)
	}

	// Empty explicit fields fall back to the cookie.
	got = cookie.applyTo(presentationRequestOptions{})
	if got.ValidationMode != "debug" {
		t.Errorf("mode = %q, want debug (from cookie)", got.ValidationMode)
	}
	if got.RequireHAIP == nil || *got.RequireHAIP != false {
		t.Errorf("haip = %v, want false (from cookie)", got.RequireHAIP)
	}
	if !got.hasConformanceOverride() {
		t.Error("expected hasConformanceOverride to be true")
	}

	if (presentationRequestOptions{}).hasConformanceOverride() {
		t.Error("expected empty options to report no conformance override")
	}
}
