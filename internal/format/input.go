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
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

// HTTPClientForURL returns a fetch client configured for the target URL.
// Local developer endpoints bypass proxies and accept self-signed HTTPS certs.
func HTTPClientForURL(rawURL string) *http.Client {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return httpClient
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if isLocalFetchHost(u.Hostname()) {
		transport.Proxy = nil
		if strings.EqualFold(u.Scheme, "https") {
			//nolint:gosec // Local dev endpoints use self-signed certificates on localhost/host.docker.internal.
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
	}

	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}
}

func isLocalFetchHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1", "host.docker.internal":
		return true
	default:
		return false
	}
}

// readStdin reads all input from stdin, returning an error if stdin is a terminal.
func readStdin() (string, error) {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot read stdin: %w", err)
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return "", fmt.Errorf("no input provided (use a file path, URL, raw string, or pipe to stdin)")
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading stdin: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// readFile reads a file and returns its trimmed contents.
func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading file %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// ReadInput reads credential input from: URL, file path, "-" for stdin, or raw string.
func ReadInput(input string) (string, error) {
	input = strings.TrimSpace(input)

	if input == "-" || input == "" {
		return readStdin()
	}

	// Try as URL
	if strings.HasPrefix(input, "https://") || strings.HasPrefix(input, "http://") {
		return FetchURL(input)
	}

	// Try as file path
	if _, err := os.Stat(input); err == nil {
		return readFile(input)
	}

	// Treat as raw credential string
	return input, nil
}

// ReadInputRaw reads input from stdin, a file, or returns the raw string.
// Unlike ReadInput, it does NOT HTTP-fetch URLs — useful when the caller
// needs to detect the format before deciding whether to fetch.
func ReadInputRaw(input string) (string, error) {
	input = strings.TrimSpace(input)

	if input == "-" || input == "" {
		return readStdin()
	}

	// Skip URLs and URI schemes — return as-is for format detection
	if strings.Contains(input, "://") {
		return input, nil
	}

	// Try as file path (but not if it looks like a JWT or JSON)
	if !strings.HasPrefix(input, "{") {
		if _, err := os.Stat(input); err == nil {
			return readFile(input)
		}
	}

	return input, nil
}

// FetchURL fetches content from a URL and returns it as a trimmed string.
func FetchURL(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	// Go sends no Accept header by default; some servers reject that.
	req.Header.Set("Accept", "*/*")
	resp, err := HTTPClientForURL(url).Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching %s: HTTP %d", url, resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response from %s: %w", url, err)
	}

	return strings.TrimSpace(string(b)), nil
}
