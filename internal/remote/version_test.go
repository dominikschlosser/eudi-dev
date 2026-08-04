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

package remote

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		raw   string
		want  Version
		valid bool
	}{
		{"1.19.0", Version{1, 19, 0}, true},
		{"v1.19.0", Version{1, 19, 0}, true},
		{" 1.19.0 ", Version{1, 19, 0}, true},
		{"1.19", Version{1, 19, 0}, true},
		{"1.19.0-rc.1", Version{1, 19, 0}, true},
		{"1.19.0+build.7", Version{1, 19, 0}, true},
		{"dev", Version{}, false},
		{"", Version{}, false},
		{"1", Version{}, false},
		{"1.x.0", Version{}, false},
	}
	for _, tc := range cases {
		got, ok := ParseVersion(tc.raw)
		if ok != tc.valid {
			t.Errorf("ParseVersion(%q) valid = %v, want %v", tc.raw, ok, tc.valid)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("ParseVersion(%q) = %+v, want %+v", tc.raw, got, tc.want)
		}
	}
}

func TestCheckCompatibility(t *testing.T) {
	cases := []struct {
		cli      string
		instance string
		want     Compatibility
	}{
		{"1.19.0", "1.19.0", Compatible},
		// Minor and patch releases keep the management API, in either
		// direction and regardless of the tag's v prefix.
		{"1.19.3", "1.19.0", Compatible},
		{"1.19.0", "1.18.11", Compatible},
		{"1.18.11", "1.19.0", Compatible},
		{"v1.19.0", "1.20.0", Compatible},
		// A major release is where breaking changes live.
		{"1.19.0", "2.0.0", Incompatible},
		{"2.0.0", "1.19.0", Incompatible},
		// A development build on either side claims nothing.
		{"dev", "1.19.0", CompatibilityUnknown},
		{"1.19.0", "dev", CompatibilityUnknown},
		// An instance too old to report a version at all.
		{"1.19.0", "", CompatibilityUnknown},
	}
	for _, tc := range cases {
		if got := CheckCompatibility(tc.cli, tc.instance); got != tc.want {
			t.Errorf("CheckCompatibility(%q, %q) = %v, want %v", tc.cli, tc.instance, got, tc.want)
		}
	}
}
