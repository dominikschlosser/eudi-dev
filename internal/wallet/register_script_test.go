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
