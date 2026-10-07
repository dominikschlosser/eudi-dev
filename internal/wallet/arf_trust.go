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

package wallet

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
)

// RegistrationStatusClient fetches the status lists of registration
// certificates. The wallet's own list is answered in process, so strict TLS
// doesn't have to trust the wallet's self-signed HTTPS port. Other lists go
// through the outbound client.
func (w *Wallet) RegistrationStatusClient() *http.Client {
	outbound := w.HTTPClient()
	return &http.Client{Timeout: outbound.Timeout, Transport: ownStatusListTransport{wallet: w, next: outbound}}
}

type ownStatusListTransport struct {
	wallet *Wallet
	next   *http.Client
}

func (t ownStatusListTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || !sameURL(req.URL, t.wallet.Registrar().RegistrationStatusListURL()) {
		if t.next.Transport == nil {
			return nil, errors.New("the wallet has no outbound transport")
		}
		return t.next.Transport.RoundTrip(req)
	}
	token, err := t.wallet.Registrar().RegistrationStatusListToken()
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": []string{statuslist.MediaTypeJWT}},
		Body:          io.NopCloser(strings.NewReader(token)),
		ContentLength: int64(len(token)),
		Request:       req,
	}, nil
}

// PrepareARFChecks adds what --arf needs to a request: a client for the status
// lists of registration certificates, and the trusted CAs for access and
// registration certificates.
func (w *Wallet) PrepareARFChecks(params *AuthorizationRequestParams) {
	if !w.ARFChecks() {
		return
	}
	params.StatusClient = w.RegistrationStatusClient()
	params.RelyingPartyCAs = w.RelyingPartyCAs()
	params.RegistrarCAs = w.RegistrarCAs()
}

// RelyingPartyCAs are the CAs --arf trusts for access certificates (ARF
// RPA_04). The wallet CA signs the demo verifier's access certificate, and the
// relying party access CA signs the ones from the registrar.
// --relying-party-ca adds others.
func (w *Wallet) RelyingPartyCAs() []*x509.Certificate {
	cas := w.RegistrarCAs()
	if _, accessCA, err := w.RelyingPartyAccessCA(); err == nil {
		cas = append(cas, accessCA)
	}
	return cas
}

// RegistrarCAs are the CAs --arf trusts for registration certificates (ARF
// RPRC_02a). The wallet CA signs the registrar's certificate. The relying
// party access CA is not one of them, because it signs any visitor's CSR.
// --relying-party-ca adds others.
func (w *Wallet) RegistrarCAs() []*x509.Certificate {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var cas []*x509.Certificate
	if len(w.CertChain) > 0 {
		cas = append(cas, w.CertChain[len(w.CertChain)-1])
	}
	if configured, err := keys.ParseCertificatesPEM(w.RelyingPartyCAPEM); err == nil {
		cas = append(cas, configured...)
	}
	return cas
}

// TrustListCAs are the CAs --arf trusts for the signer of a trusted list. The
// wallet CA signs the wallet's own lists. --trust-list-ca adds others.
func (w *Wallet) TrustListCAs() []*x509.Certificate {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var cas []*x509.Certificate
	if len(w.CertChain) > 0 {
		cas = append(cas, w.CertChain[len(w.CertChain)-1])
	}
	if configured, err := keys.ParseCertificatesPEM(w.TrustListCAPEM); err == nil {
		cas = append(cas, configured...)
	}
	return cas
}

// sameURL compares scheme, host with its default port, and path. Host and
// scheme are case insensitive (RFC 3986 §6.2.2.1).
func sameURL(u *url.URL, raw string) bool {
	other, err := url.Parse(raw)
	if err != nil {
		return false
	}
	hostPort := func(v *url.URL) string {
		port := v.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[strings.ToLower(v.Scheme)]
		}
		return strings.ToLower(v.Hostname()) + ":" + port
	}
	return strings.EqualFold(u.Scheme, other.Scheme) && hostPort(u) == hostPort(other) && strings.TrimSuffix(u.Path, "/") == strings.TrimSuffix(other.Path, "/")
}

// RegistrarBase is the base URL of the registrar's default contact URLs and
// registry URIs.
func (w *Wallet) RegistrarBase() string {
	return firstNonEmpty(strings.TrimRight(w.IssuerURL, "/"), strings.TrimRight(w.BaseURL, "/"), "https://issuer.example")
}

// Registrar is the wallet's registrar. It works on the registrar state stored
// in the wallet.
func (w *Wallet) Registrar() *registrar.Registrar {
	return registrar.New(&w.mu, &w.State, registrarEnv{w})
}

// registrarEnv gives the registrar what it uses from the wallet.
type registrarEnv struct{ w *Wallet }

func (e registrarEnv) RegistrarBase() string { return e.w.RegistrarBase() }
func (e registrarEnv) RegistrarSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return e.w.RegistrarSigningMaterial()
}
func (e registrarEnv) RelyingPartyAccessCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	return e.w.RelyingPartyAccessCA()
}
func (e registrarEnv) AccessSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return e.w.AccessSigningMaterial()
}
func (e registrarEnv) TemplateLocation() credtemplate.Location { return e.w.Templates }

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
