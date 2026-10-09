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

package web

import (
	"fmt"
	"os"
	"testing"
)

// The decoder reads the default wallet when it has no store. Tests get a
// temporary config directory instead of the real one.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "eudi-web-tests-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating temporary config directory: %v\n", err)
		os.Exit(1)
	}
	os.Setenv("EUDI_DEV_HOME", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
