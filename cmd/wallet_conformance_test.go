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

package cmd

import "testing"

func TestConformancePrefRoundTrip(t *testing.T) {
	off := false
	if err := saveConformancePref(conformancePref{Mode: "debug", HAIP: &off}); err != nil {
		t.Fatalf("saveConformancePref: %v", err)
	}
	t.Cleanup(func() { _ = saveConformancePref(conformancePref{}) })

	got := loadConformancePref()
	if got.Mode != "debug" {
		t.Errorf("mode = %q, want debug", got.Mode)
	}
	if got.HAIP == nil || *got.HAIP != false {
		t.Errorf("haip = %v, want false", got.HAIP)
	}

	h := got.headers()
	if h["X-Eudi-Dev-Mode"] != "debug" {
		t.Errorf("header mode = %q, want debug", h["X-Eudi-Dev-Mode"])
	}
	if h["X-Eudi-Dev-HAIP"] != "false" {
		t.Errorf("header haip = %q, want false", h["X-Eudi-Dev-HAIP"])
	}

	// Clearing removes the file and yields no headers.
	if err := saveConformancePref(conformancePref{}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if cleared := loadConformancePref(); cleared.Mode != "" || cleared.HAIP != nil || cleared.Encrypted != nil {
		t.Errorf("expected cleared preference, got %+v", cleared)
	}
	if loadConformancePref().headers() != nil {
		t.Error("expected no headers for a cleared preference")
	}
}
