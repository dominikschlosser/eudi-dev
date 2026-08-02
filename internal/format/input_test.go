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

package format

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadInputRaw_RawString(t *testing.T) {
	raw, err := ReadInputRaw("eyJhbGciOiJFUzI1NiJ9.test.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "eyJhbGciOiJFUzI1NiJ9.test.sig" {
		t.Errorf("expected raw string back, got %q", raw)
	}
}

func TestReadInputRaw_URIPassthrough(t *testing.T) {
	uri := "openid4vp://authorize?client_id=test"
	raw, err := ReadInputRaw(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != uri {
		t.Errorf("expected URI passthrough, got %q", raw)
	}
}

func TestReadInputRaw_HTTPURLPassthrough(t *testing.T) {
	url := "https://example.com/credential"
	raw, err := ReadInputRaw(url)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != url {
		t.Errorf("expected URL passthrough, got %q", raw)
	}
}

func TestReadInputRaw_FileRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.txt")
	if err := os.WriteFile(path, []byte("  test-credential-data  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	raw, err := ReadInputRaw(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "test-credential-data" {
		t.Errorf("expected trimmed file content, got %q", raw)
	}
}

func TestReadInputRaw_JSONNotTreatedAsFile(t *testing.T) {
	// JSON strings starting with { should not be treated as file paths
	raw, err := ReadInputRaw(`{"credential_issuer":"https://example.com"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != `{"credential_issuer":"https://example.com"}` {
		t.Errorf("expected JSON passthrough, got %q", raw)
	}
}

func TestReadInputRaw_Whitespace(t *testing.T) {
	raw, err := ReadInputRaw("  some-token  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "some-token" {
		t.Errorf("expected trimmed input, got %q", raw)
	}
}

func TestReadInput_RawString(t *testing.T) {
	raw, err := ReadInput("eyJhbGciOiJFUzI1NiJ9.test.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "eyJhbGciOiJFUzI1NiJ9.test.sig" {
		t.Errorf("expected raw string back, got %q", raw)
	}
}

func TestReadInput_FileRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.txt")
	if err := os.WriteFile(path, []byte("  file-content  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	raw, err := ReadInput(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "file-content" {
		t.Errorf("expected trimmed file content, got %q", raw)
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("  content  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	content, err := readFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "content" {
		t.Errorf("expected trimmed content, got %q", content)
	}
}

func TestReadFile_NotFound(t *testing.T) {
	_, err := readFile("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestHTTPClientForURLHostDockerInternalFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]

	// host.docker.internal does not resolve on most hosts. The client must
	// fall back to localhost, which serves the same endpoint.
	url := "http://host.docker.internal:" + port + "/"
	client := HTTPClientForURL(url)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("expected localhost fallback to succeed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
