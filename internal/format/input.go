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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: newPolicyTransport(),
}

// newPolicyTransport clones the default transport with a dialer that routes
// every connection through the fetch policy (see policy.go).
func newPolicyTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   dialControl,
	}).DialContext
	return transport
}

// HTTPClientForURL returns a fetch client configured for the target URL.
// Local developer endpoints bypass proxies and accept self-signed HTTPS certs.
func HTTPClientForURL(rawURL string) *http.Client {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return httpClient
	}

	transport := newPolicyTransport()
	if isLocalFetchHost(u.Hostname()) {
		transport.Proxy = nil
		if strings.EqualFold(u.Scheme, "https") {
			//nolint:gosec // Local dev endpoints use self-signed certificates on localhost/host.docker.internal.
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		// host.docker.internal is the container-side name for this machine.
		// On the host itself it usually does not resolve, so URLs baked into
		// credentials by Docker setups (status lists, issuer metadata) would
		// fail locally. Fall back to localhost, which is the same endpoint.
		dialer := &net.Dialer{Timeout: 10 * time.Second, Control: dialControl}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				if port, ok := strings.CutPrefix(addr, "host.docker.internal:"); ok {
					if conn2, err2 := dialer.DialContext(ctx, network, "localhost:"+port); err2 == nil {
						return conn2, nil
					}
				}
			}
			return conn, err
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

	// Try as file path. Inputs with a URI scheme (openid-credential-offer://,
	// file://, ...) are never file paths. Without this guard they could name
	// files on unusual filesystems.
	if !strings.Contains(input, "://") {
		if _, err := os.Stat(input); err == nil {
			return readFile(input)
		}
	}

	// Treat as raw credential string
	return input, nil
}

// ReadRemoteInput reads credential input in server context: http(s) URLs are
// fetched, everything else is returned verbatim. Unlike ReadInput it never
// touches stdin or the local filesystem, so visitor-supplied values cannot
// name files on the server.
func ReadRemoteInput(input string) (string, error) {
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "https://") || strings.HasPrefix(input, "http://") {
		return FetchURL(input)
	}
	return input, nil
}

// ReadInputRaw reads input from stdin, a file, or returns the raw string.
// Unlike ReadInput, it does NOT HTTP-fetch URLs. Useful when the caller
// needs to detect the format before deciding whether to fetch.
func ReadInputRaw(input string) (string, error) {
	input = strings.TrimSpace(input)

	if input == "-" || input == "" {
		return readStdin()
	}

	// Skip URLs and URI schemes. Return as-is for format detection
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

// maxFetchBytes caps remote responses. Credentials, trust lists and status
// lists are all far smaller, so anything larger is a misdirected fetch.
const maxFetchBytes = 10 << 20

// FetchURL fetches content from a URL and returns it as a trimmed string.
func FetchURL(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	// Go sends no Accept header by default. Some servers reject that.
	req.Header.Set("Accept", "*/*")
	resp, err := HTTPClientForURL(url).Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if msg := strings.TrimSpace(string(body)); msg != "" {
			return "", fmt.Errorf("fetching %s: HTTP %d: %s", url, resp.StatusCode, msg)
		}
		return "", fmt.Errorf("fetching %s: HTTP %d", url, resp.StatusCode)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading response from %s: %w", url, err)
	}
	if len(b) > maxFetchBytes {
		return "", fmt.Errorf("fetching %s: response exceeds %d bytes", url, maxFetchBytes)
	}

	return strings.TrimSpace(string(b)), nil
}
