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

import (
	"runtime"
	"strings"
	"testing"
)

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

// A wallet server on a headless host has no desktop to open a browser on, and
// trying reaches nobody.
func TestHasDesktopSession(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("no session heuristic on %s", runtime.GOOS)
	}
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	if runtime.GOOS == "linux" {
		if hasDesktopSession() {
			t.Error("a linux host with no display should not count as a desktop")
		}
		t.Setenv("DISPLAY", ":0")
		if !hasDesktopSession() {
			t.Error("a linux host with DISPLAY set should count as a desktop")
		}
		return
	}

	if !hasDesktopSession() {
		t.Error("a local macOS session should count as a desktop")
	}
	t.Setenv("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")
	if hasDesktopSession() {
		t.Error("a macOS session arriving over SSH should not count as a desktop")
	}
}

// OID4VP has the wallet return the user agent to the verifier, but a script
// running presentations does not want browser windows appearing.
func TestFollowVerifierRedirectPrintsTheURL(t *testing.T) {
	t.Cleanup(func() { noOpen = false })
	noOpen = true

	out := captureStdout(t, func() { followVerifierRedirect("https://verifier.example/done?session=1") })
	if !strings.Contains(out, "https://verifier.example/done?session=1") {
		t.Errorf("the verifier redirect was not shown:\n%s", out)
	}

	if out := captureStdout(t, func() { followVerifierRedirect("") }); out != "" {
		t.Errorf("a verifier that returned no redirect should print nothing, got %q", out)
	}
}
