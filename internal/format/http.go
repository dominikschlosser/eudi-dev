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
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type policyTransport struct {
	remote    *http.Transport
	remoteDev *http.Transport
	local     *http.Transport
	localDev  *http.Transport
	verify    func() bool
}

// NewHTTPClient sends remote requests through proxy, or through the proxy
// environment variables when proxy is nil. Local requests never use a proxy.
func NewHTTPClient(verify func() bool, roots *x509.CertPool, proxy ProxyFunc) *http.Client {
	remote := newPolicyTransport()
	remote.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	remoteDev := newPolicyTransport()
	if proxy != nil {
		remote.Proxy, remoteDev.Proxy = proxy, proxy
	}
	//nolint:gosec // The caller can explicitly disable TLS verification for development.
	remoteDev.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	local := newLocalPolicyTransport()
	local.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	localDev := newLocalPolicyTransport()
	//nolint:gosec // The caller can explicitly disable TLS verification for development.
	localDev.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout: remoteTimeout,
		Transport: &policyTransport{
			remote: remote, remoteDev: remoteDev, local: local, localDev: localDev, verify: verify,
		},
	}
}

func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	local := isLocalFetchHost(req.URL.Hostname())
	verify := !local
	if t.verify != nil {
		verify = t.verify()
	}
	if local {
		if verify {
			return t.local.RoundTrip(req)
		}
		return t.localDev.RoundTrip(req)
	}
	if verify {
		return t.remote.RoundTrip(req)
	}
	return t.remoteDev.RoundTrip(req)
}

func (t *policyTransport) CloseIdleConnections() {
	t.remote.CloseIdleConnections()
	t.remoteDev.CloseIdleConnections()
	t.local.CloseIdleConnections()
	t.localDev.CloseIdleConnections()
}

func TLSRoots(pem []byte) (*x509.CertPool, error) {
	if len(pem) == 0 {
		return nil, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("loading system TLS roots: %w", err)
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("TLS CA bundle contains no PEM certificates")
	}
	return roots, nil
}

// IsWebURL reports whether rawURL is an absolute http or https URL with a host.
// url.Parse also accepts javascript: and data: URLs, which must never reach a
// link or a browser.
func IsWebURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme == "http" || scheme == "https"
}
