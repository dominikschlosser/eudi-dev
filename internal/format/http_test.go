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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestTLSVerificationEveryDestinationAndRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	roots, err := TLSRoots(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		verify    *bool
		trusted   bool
		remote    bool
		validHost bool
		redirect  bool
		wantError bool
	}{
		{name: "verified local untrusted", verify: boolPointer(true), wantError: true},
		{name: "verified local trusted", verify: boolPointer(true), trusted: true},
		{name: "verified remote trusted", verify: boolPointer(true), trusted: true, remote: true, validHost: true},
		{name: "verified remote untrusted", verify: boolPointer(true), remote: true, wantError: true},
		{name: "verified remote wrong SAN", verify: boolPointer(true), trusted: true, remote: true, wantError: true},
		{name: "disabled local", verify: boolPointer(false)},
		{name: "disabled remote", verify: boolPointer(false), remote: true},
		{name: "disabled redirect to remote", verify: boolPointer(false), remote: true, redirect: true},
		{name: "verified redirect", verify: boolPointer(true), remote: true, redirect: true, wantError: true},
		{name: "generic local development"},
		{name: "generic redirect to remote", remote: true, redirect: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var verify func() bool
			if tc.verify != nil {
				verify = func() bool { return *tc.verify }
			}
			client := NewHTTPClient(verify, nil, nil)
			defer client.CloseIdleConnections()
			transport := client.Transport.(*policyTransport)
			if tc.trusted {
				transport.local.TLSClientConfig.RootCAs = roots
				transport.remote.TLSClientConfig.RootCAs = roots
			}
			target := server.URL
			if tc.remote {
				u, err := url.Parse(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				transport.remote.Proxy, transport.remoteDev.Proxy = nil, nil
				dial := func(ctx context.Context, network, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, u.Host)
				}
				transport.remote.DialContext, transport.remoteDev.DialContext = dial, dial
				host := "remote.example"
				if tc.validHost {
					host = server.Certificate().DNSNames[0]
				}
				target = "https://" + host + ":" + u.Port()
			}
			if tc.redirect {
				redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target, http.StatusFound) }))
				defer redirect.Close()
				response, err := client.Get(redirect.URL)
				assertTLSResult(t, response, err, tc.wantError)
			} else {
				response, err := client.Get(target)
				assertTLSResult(t, response, err, tc.wantError)
			}
		})
	}
}

func boolPointer(value bool) *bool { return &value }

func assertTLSResult(t *testing.T, response *http.Response, err error, wantError bool) {
	t.Helper()
	if response != nil {
		defer response.Body.Close()
	}
	if wantError {
		var certErr *tls.CertificateVerificationError
		if !errors.As(err, &certErr) {
			t.Fatalf("expected TLS certificate rejection, got %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("response = %q, error = %v", body, err)
	}
}

func TestTLSRootsRejectInvalidBundle(t *testing.T) {
	for _, bundle := range []string{"not PEM", "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"} {
		if _, err := TLSRoots([]byte(bundle)); err == nil {
			t.Fatal("invalid certificate bundle accepted")
		}
	}
}

func TestTLSVerificationRejectsExpiredTrustedCertificate(t *testing.T) {
	original := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer original.Close()
	cert := *original.Certificate()
	cert.NotBefore, cert.NotAfter = time.Now().Add(-24*time.Hour), time.Now().Add(-time.Hour)
	key := original.TLS.Certificates[0].PrivateKey
	der, err := x509.CreateCertificate(rand.Reader, &cert, &cert, cert.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	roots, err := TLSRoots(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	client := NewHTTPClient(func() bool { return true }, roots, nil)
	defer client.CloseIdleConnections()
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	var invalid x509.CertificateInvalidError
	if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
		t.Fatalf("expected certificate expiration, got %v", err)
	}
}

// Links, redirects and the system opener accept only http and https.
func TestIsWebURL(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://issuer.example/authorize?x=1", true},
		{"https:///no-host", false},
		{"http://localhost:8085/callback", true},
		{"HTTPS://issuer.example/", true},
		{"javascript:alert(1)", false},
		{"data:text/html,<script>alert(1)</script>", false},
		{"file:///etc/passwd", false},
		{"vnc://192.168.1.1", false},
		{"/relative/path", false},
		{"", false},
	} {
		if got := IsWebURL(tc.url); got != tc.want {
			t.Errorf("IsWebURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}
