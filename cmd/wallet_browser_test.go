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

// OpenID4VP has the wallet return the user agent to the verifier. A script
// that runs presentations must not open browser windows.
func TestFollowVerifierRedirectPrintsTheURL(t *testing.T) {
	t.Cleanup(func() { noOpen = false })
	noOpen = true

	out := captureStdout(t, func() { followVerifierRedirect("https://verifier.example/done?session=1", false) })
	if !strings.Contains(out, "https://verifier.example/done?session=1") {
		t.Errorf("the verifier redirect was not shown:\n%s", out)
	}

	if out := captureStdout(t, func() { followVerifierRedirect("", false) }); out != "" {
		t.Errorf("a verifier that returned no redirect should print nothing, got %q", out)
	}
}
