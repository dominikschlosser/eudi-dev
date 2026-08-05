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

// A URL handed to the browser can come from a remote wallet, and the opener
// launches more than web pages, so anything but http(s) has to be refused.
func TestIsWebURL(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://issuer.example/authorize?x=1", true},
		{"http://localhost:8085/callback", true},
		{"HTTPS://issuer.example/", true},
		{"javascript:alert(1)", false},
		{"data:text/html,<script>alert(1)</script>", false},
		{"file:///etc/passwd", false},
		{"vnc://192.168.1.1", false},
		{"/relative/path", false},
		{"", false},
	} {
		if got := isWebURL(tc.url); got != tc.want {
			t.Errorf("isWebURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}
