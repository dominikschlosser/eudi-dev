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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestHandlerScriptForwardsConformanceOverride(t *testing.T) {
	script := handlerScriptSource("/usr/local/bin/eudi", RegisterOptions{ListenerPort: 8085})

	for _, want := range []string{
		`CONF_FILE="$(dirname "$0")/conformance.json"`,
		"X-Eudi-Dev-Mode",
		"X-Eudi-Dev-HAIP",
		"X-Eudi-Dev-Encrypted",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("generated handler missing %q", want)
		}
	}
	// The headers ride on both submit paths.
	if got := strings.Count(script, `"${CONF_HEADERS[@]}"`); got != 2 {
		t.Errorf("expected the override headers on both submit_offer and submit_presentation, found %d", got)
	}
	// They are built only when a remote is configured; a local wallet uses its
	// own setting.
	idx := strings.Index(script, "CONF_HEADERS=()")
	if idx < 0 || !strings.Contains(script[idx:idx+80], `if [[ -n "$REMOTE_URL" ]]`) {
		t.Error("conformance headers must be gated on a remote being configured")
	}
	// The generated script must be valid bash.
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated handler is not valid bash: %v\n%s", err, out)
	}
}

// TestHandlerScriptSendsConformanceHeadersToRemote runs the generated handler
// end-to-end against a capture server, with remote.json and conformance.json in
// place, and proves the CLI conformance override reaches the remote as headers.
func TestHandlerScriptSendsConformanceHeadersToRemote(t *testing.T) {
	var gotMode, gotHAIP string
	captured := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/presentations") {
			gotMode = r.Header.Get("X-Eudi-Dev-Mode")
			gotHAIP = r.Header.Get("X-Eudi-Dev-HAIP")
			select {
			case captured <- struct{}{}:
			default:
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	// Auto-accept so the handler submits directly, without opening a browser or
	// starting a local listener.
	script := handlerScriptSource("/usr/local/bin/eudi", RegisterOptions{ListenerPort: 8085, AutoAccept: true})
	scriptPath := filepath.Join(dir, "url-handler.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "remote.json"), []byte(`{"url":"`+srv.URL+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "conformance.json"), []byte("{\n  \"mode\": \"debug\",\n  \"haip\": false\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", scriptPath, "openid4vp://authorize?client_id=x&request_uri=http://localhost:9/x")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("handler exited non-zero (%v): %s", err, out)
	}

	select {
	case <-captured:
	case <-time.After(5 * time.Second):
		t.Fatal("the remote never received the presentation submit")
	}
	if gotMode != "debug" {
		t.Errorf("X-Eudi-Dev-Mode = %q, want debug", gotMode)
	}
	if gotHAIP != "false" {
		t.Errorf("X-Eudi-Dev-HAIP = %q, want false", gotHAIP)
	}
}
