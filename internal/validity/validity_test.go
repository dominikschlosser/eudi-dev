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

package validity

import (
	"strings"
	"testing"
	"time"
)

func TestRelative(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		t        time.Time
		wantPart string
		future   bool
	}{
		{"1 minute ago", now.Add(-30 * time.Second), "1 minute", false},
		{"5 minutes ago", now.Add(-5*time.Minute - time.Second), "5 minutes", false},
		{"1 hour ago", now.Add(-90*time.Minute - time.Second), "1 hour", false},
		{"3 hours ago", now.Add(-3*time.Hour - time.Second), "3 hours", false},
		{"1 day ago", now.Add(-36*time.Hour - time.Second), "1 day", false},
		{"5 days ago", now.Add(-5*24*time.Hour - time.Second), "5 days", false},
		{"1 month ago", now.Add(-35*24*time.Hour - time.Second), "1 month", false},
		{"3 months ago", now.Add(-95*24*time.Hour - time.Second), "3 months", false},
		{"in 5 minutes", now.Add(5*time.Minute + time.Second), "5 minutes", true},
		{"in 2 days", now.Add(2*24*time.Hour + time.Second), "2 days", true},
		{"in 3 months", now.Add(95*24*time.Hour + time.Second), "3 months", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Relative(tt.t, now)
			if !strings.Contains(got, tt.wantPart) {
				t.Errorf("Relative() = %q, want to contain %q", got, tt.wantPart)
			}
			if tt.future && !strings.HasPrefix(got, "in ") {
				t.Errorf("expected future prefix 'in ', got %q", got)
			}
			if !tt.future && !strings.HasSuffix(got, " ago") {
				t.Errorf("expected past suffix ' ago', got %q", got)
			}
		})
	}
}
