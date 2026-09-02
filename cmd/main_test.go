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
	"fmt"
	"os"
	"testing"
)

// TestMain isolates these tests from the developer's own configuration.
// Commands resolve the active wallet through remote.json in the config
// directory, so without a throwaway directory a test run would drive
// whatever wallet `wallet use <url>` points at.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "eudi-cmd-tests-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating temporary config directory: %v\n", err)
		os.Exit(1)
	}
	// HOME rather than EUDI_DEV_HOME, so the tests that set HOME themselves
	// resolve the config directory the same way. The explicit overrides are
	// cleared so a developer's environment cannot put the real directory back.
	os.Setenv("HOME", dir)
	os.Setenv("USERPROFILE", dir)
	os.Unsetenv("EUDI_DEV_HOME")
	os.Unsetenv("OID4VC_DEV_HOME")

	code := m.Run()

	os.RemoveAll(dir)
	os.Exit(code)
}
