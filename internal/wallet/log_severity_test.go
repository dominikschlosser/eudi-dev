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
	"encoding/json"
	"testing"
)

// A warning is a third log state a bool cannot hold: not a failure (Success
// stays true) but marked so the UI can render it distinctly.
func TestAddWarningSeverity(t *testing.T) {
	w := generateTestWallet(t)
	before := len(w.GetLog())

	w.AddWarning("issuance", "issuer offers only unauthenticated access", map[string]any{"issuer": "https://issuer.example"})

	logs := w.GetLog()
	if len(logs) != before+1 {
		t.Fatalf("expected one new entry, log went %d -> %d", before, len(logs))
	}
	entry := logs[len(logs)-1]
	if entry.Severity != severityWarning {
		t.Errorf("Severity = %q, want %q", entry.Severity, severityWarning)
	}
	if !entry.Success {
		t.Error("a warning is not a failure, so Success must stay true")
	}

	// The severity crosses the JSON boundary to the frontend under "severity".
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["severity"] != severityWarning {
		t.Errorf("json severity = %v, want %q", decoded["severity"], severityWarning)
	}

	// A plain success carries no severity, so the field is omitted.
	w.AddLog("issuance", "imported", true)
	plain, _ := json.Marshal(w.GetLog()[len(w.GetLog())-1])
	var plainMap map[string]any
	_ = json.Unmarshal(plain, &plainMap)
	if _, ok := plainMap["severity"]; ok {
		t.Error("a plain entry must omit severity")
	}
}
