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

// The HTTPS listener that serves issuer metadata, its certificate, and
// the renewal that keeps a long running wallet from serving an expired one.

package wallet

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/config"
)

// SetIssuerTLSCertificate sets the certificate used by the wallet's HTTPS endpoints.
func (s *Server) SetIssuerTLSCertificate(cert tls.Certificate) {
	s.issuerTLSCert = &cert
}

// SetIssuerListenPort overrides the local port of the built-in HTTPS issuer
// listener, which NewServer derives from the wallet's IssuerURL. Pass a
// negative port to disable the listener entirely. Used when an external TLS
// terminator serves the issuer origin (IssuerURL equals the base URL), where
// the derived port would otherwise be 443.
func (s *Server) SetIssuerListenPort(port int) {
	s.issuerPort = port
}

// setIssuerTLSCertificate replaces the certificate served on the HTTPS
// listener.
func (s *Server) setIssuerTLSCertificate(cert tls.Certificate) {
	s.tlsMu.Lock()
	defer s.tlsMu.Unlock()
	s.issuerTLSCert = &cert
}

// currentIssuerTLSCertificate is the certificate to answer a handshake with.
func (s *Server) currentIssuerTLSCertificate() *tls.Certificate {
	s.tlsMu.RLock()
	defer s.tlsMu.RUnlock()
	return s.issuerTLSCert
}

// renewIssuerTLSCertificateIfNeeded re-issues the HTTPS leaf as it approaches
// expiry, on the same reasoning as the signing leaf.
func (s *Server) renewIssuerTLSCertificateIfNeeded(now time.Time) {
	current := s.currentIssuerTLSCertificate()
	if current == nil || len(current.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(current.Certificate[0])
	if err != nil || now.Add(signingCertificateRenewBefore).Before(leaf.NotAfter) {
		return
	}
	var caCert *x509.Certificate
	if len(s.wallet.CertChain) > 1 {
		caCert = s.wallet.CertChain[len(s.wallet.CertChain)-1]
	}
	renewed, err := generateIssuerTLSCertificate(parseIssuerHost(s.wallet.IssuerURL), s.wallet.CAKey, caCert)
	if err != nil {
		s.log("  ERROR: re-issuing the HTTPS certificate: %v", err)
		return
	}
	s.setIssuerTLSCertificate(renewed)
	s.log("  Renewed:       HTTPS certificate")
}

// signingKeyExpiry is what the wallet publishes as the expiry of its signing
// key. It follows the signing certificate rather than a value computed once at
// startup: a wallet that runs for months would otherwise advertise a key that
// expired on its first day.
func (s *Server) signingKeyExpiry() time.Time {
	if expiry := s.wallet.SigningCertificateExpiry(); !expiry.IsZero() {
		return expiry
	}
	return time.Now().Add(24 * time.Hour)
}

func (s *Server) startIssuerTLSServer() error {
	if s.issuerPort <= 0 || s.issuerSrv != nil {
		return nil
	}

	if s.currentIssuerTLSCertificate() == nil {
		var caCert *x509.Certificate
		if len(s.wallet.CertChain) > 1 {
			caCert = s.wallet.CertChain[len(s.wallet.CertChain)-1]
		}
		cert, err := generateIssuerTLSCertificate(parseIssuerHost(s.wallet.IssuerURL), s.wallet.CAKey, caCert)
		if err != nil {
			return fmt.Errorf("generating issuer TLS certificate: %w", err)
		}
		s.setIssuerTLSCertificate(cert)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.issuerPort))
	if err != nil {
		return fmt.Errorf("listening for issuer HTTPS server: %w", err)
	}

	s.issuerSrv = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: config.SlowRequestTimeout,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		tlsListener := tls.NewListener(ln, &tls.Config{
			// Resolved per handshake so a renewal reaches clients without a
			// restart. A wallet outlives a certificate, and a listener holding
			// the one it started with would serve an expired leaf forever.
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return s.currentIssuerTLSCertificate(), nil
			},
			MinVersion: tls.VersionTLS12,
		})
		_ = s.issuerSrv.Serve(tlsListener)
	}()

	return nil
}
