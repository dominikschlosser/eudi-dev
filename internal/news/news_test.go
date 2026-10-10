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

package news

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadGivesChangedNewsANewID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "news.html")
	write := func(content string) *News {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		n, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	first := write("<h2>Try 3.0.0</h2>\n")
	if first.HTML != "<h2>Try 3.0.0</h2>" {
		t.Errorf("HTML = %q", first.HTML)
	}
	if second := write("<h2>Try 3.1.0</h2>"); second.ID == first.ID {
		t.Errorf("changed news kept the ID %s", first.ID)
	}
}

func TestLoadWantsAnHTMLSnippet(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "news.txt")
	empty := filepath.Join(dir, "empty.html")
	for _, p := range []string{text, empty} {
		if err := os.WriteFile(p, []byte(" "), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{text, empty} {
		if _, err := Load(p); err == nil {
			t.Errorf("Load(%s) accepted the file", filepath.Base(p))
		}
	}
}

func TestLoadInlinesAnImageNextToTheSnippet(t *testing.T) {
	dir := t.TempDir()
	png := []byte("\x89PNG fake")
	if err := os.WriteFile(filepath.Join(dir, "overview.png"), png, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "news.html")
	if err := os.WriteFile(path, []byte(`<img src="overview.png" alt="Overview">`), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `src="data:image/png;base64,` + base64.StdEncoding.EncodeToString(png) + `"`
	if !strings.Contains(n.HTML, want) {
		t.Errorf("HTML = %s, want the image inlined", n.HTML)
	}
}
