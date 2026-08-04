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
//
// Commands resolve the active wallet through remote.json in the config
// directory, so on a machine where "wallet instances use <url>" points at a
// hosted wallet, running this package issued and deleted credentials on that
// live instance. It has happened, twice, including against the public demo.
// A throwaway config directory makes it impossible rather than a thing to
// remember.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "eudi-cmd-tests-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating temporary config directory: %v\n", err)
		os.Exit(1)
	}
	// HOME rather than EUDI_DEV_HOME, so the tests that point HOME somewhere
	// themselves keep resolving the config directory the same way. The
	// explicit overrides are cleared so a developer's environment cannot put
	// the real directory back.
	os.Setenv("HOME", dir)
	os.Setenv("USERPROFILE", dir)
	os.Unsetenv("EUDI_DEV_HOME")
	os.Unsetenv("OID4VC_DEV_HOME")

	code := m.Run()

	os.RemoveAll(dir)
	os.Exit(code)
}
