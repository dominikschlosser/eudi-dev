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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// registration-cert needs no intended use ID when the relying party has only
// one intended use.
func TestWalletRegistrarRegistersAndCertifies(t *testing.T) {
	resetRemoteTestState(t)
	t.Cleanup(func() { resetFlags(rootCmd); rootCmd.SetOut(nil) })
	dcql := filepath.Join(t.TempDir(), "query.json")
	if err := os.WriteFile(dcql, []byte(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := walletDir
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"wallet", "registrar", "register", "--name", "Example Shop", "--purpose", "Age check", "--dcql", dcql})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet registrar register: %v", err)
		}
	})
	identifier := regexp.MustCompile(`as (NTR[A-Z]{2}-[0-9A-F]+)`).FindStringSubmatch(out)
	if identifier == nil || !strings.Contains(out, "Intended use: ") {
		t.Fatalf("output %q, want the assigned identifier and intended use", out)
	}
	resetFlags(rootCmd)
	walletDir = dir

	registrationCert := func(args ...string) string {
		t.Helper()
		resetFlags(rootCmd)
		walletDir = dir
		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)
		rootCmd.SetArgs(append([]string{"wallet", "registrar", "registration-cert", "--identifier", identifier[1]}, args...))
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet registrar registration-cert %v: %v", args, err)
		}
		return strings.TrimSpace(buf.String())
	}
	var verifierInfo []map[string]string
	if out := registrationCert(); json.Unmarshal([]byte(out), &verifierInfo) != nil || verifierInfo[0]["format"] != "registration_cert" {
		t.Fatalf("output %q, want the verifier_info value alone", out)
	}
	if out := registrationCert("--print", "certificate"); strings.Count(out, ".") != 2 || strings.ContainsAny(out, "\n[") {
		t.Fatalf("output %q, want the bare certificate", out)
	}
}
