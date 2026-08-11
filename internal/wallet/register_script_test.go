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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The generated script is what actually runs on a scheme dispatch, and it is
// only exercised by hand otherwise. These pin the parts that have broken the
// consent flow before. Rendering it touches nothing: RegisterURLSchemes
// writes files and talks to Launch Services, handlerScriptSource does not.
func TestHandlerScriptSource(t *testing.T) {
	script := handlerScriptSource("/usr/local/bin/eudi", RegisterOptions{ListenerPort: 8085})

	// The tab the handler opens is the one that started the flow. Without
	// the marker a demo instance only shows the "waiting for consent" bar,
	// because it cannot tell this tab from an uninvolved visitor's.
	if !strings.Contains(script, "consent=await") {
		t.Error("the script must mark the UI it opens as the consent owner")
	}
	if !strings.Contains(script, `open "$LISTENER/?focus=overview&consent=await"`) {
		t.Error("the marker must be on the URL the handler opens")
	}

	// Order matters: the submit blocks until consent is resolved, so the UI
	// has to be open before it.
	openIdx := strings.Index(script, "open_remote_ui")
	submitIdx := strings.Index(script, "submit_presentation()")
	if openIdx < 0 || submitIdx < 0 || openIdx > submitIdx {
		t.Errorf("the UI must be opened before the blocking submit (open at %d, submit at %d)", openIdx, submitIdx)
	}

	// Without --auto-accept a dispatch stays interactive, which is what
	// keeps the consent dialog for a user-initiated flow.
	if !strings.Contains(script, "INTERACTIVE=true") {
		t.Error("interactive dispatches must be submitted as interactive")
	}
	if !strings.Contains(script, `LISTENER="http://localhost:8085"`) {
		t.Error("the listener port must be rendered into the script")
	}
	if !strings.Contains(script, `BINARY="/usr/local/bin/eudi"`) {
		t.Error("the binary path must be rendered into the script")
	}
}

func TestHandlerScriptSourceAutoAccept(t *testing.T) {
	script := handlerScriptSource("/usr/local/bin/eudi", RegisterOptions{
		ListenerPort: 8085,
		AutoAccept:   true,
	})
	if !strings.Contains(script, "INTERACTIVE=false") {
		t.Error("--auto-accept must submit non-interactively")
	}
	if !strings.Contains(script, `AUTO_ACCEPT="true"`) {
		t.Error("the auto-accept mode must be rendered into the script")
	}
}

// A Homebrew upgrade replaces the versioned Cellar file the stable symlink
// points at. The handler must be registered with the symlink so it survives.
func TestStableBinaryPathKeepsHomebrewSymlink(t *testing.T) {
	root := t.TempDir()
	cellarBin := filepath.Join(root, "Cellar", "eudi-dev", "1.2.3", "bin")
	if err := os.MkdirAll(cellarBin, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(cellarBin, "eudi")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(binDir, "eudi")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}

	if got := stableBinaryPath(symlink); got != symlink {
		t.Errorf("Homebrew symlink: got %q, want the symlink %q", got, symlink)
	}
}

// A symlink outside a Cellar (a build or temp location) is not a stable launch
// point, so the resolved target is used.
func TestStableBinaryPathResolvesNonHomebrewSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "build", "eudi")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "eudi-link")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}

	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := stableBinaryPath(symlink); got != want {
		t.Errorf("non-Homebrew symlink: got %q, want the resolved target %q", got, want)
	}
}

// A real binary (no symlink) is returned unchanged.
func TestStableBinaryPathPlainFile(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "eudi")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(bin)
	if got := stableBinaryPath(bin); got != want {
		t.Errorf("plain file: got %q, want %q", got, want)
	}
}
