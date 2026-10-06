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
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
)

const (
	registrationStatusListPath = "/api/registrar/status-list"
	// With 2^17 one-bit entries, random indices rarely collide, even after a
	// restart with memory storage has lost track of the used ones. The list
	// compresses to a few hundred bytes.
	registrationStatusListSize = 1 << 17
	// Index 0 belongs to the wallet's own registration certificates, which the
	// registrar never revokes.
	ownRegistrationStatusIndex = 0
)

var (
	errRegistrationStatusFull = errors.New("the registrar's status list has no free entry")
	errRegistrationChanged    = errors.New("the registration changed while the certificate was being issued. Try again")
)

// RegistrationStatus is the status list entry of one registration certificate
// (ETSI TS 119 475 V1.2.1 Table 7). A verifier's certificate covers an intended
// use. An attestation provider's certificate covers a service and has no
// intended use (ARF RPRC_13).
type RegistrationStatus struct {
	Index       int    `json:"index"`
	Identifier  string `json:"identifier"`
	IntendedUse string `json:"intendedUse"`
	Service     string `json:"service,omitempty"`
	Revoked     bool   `json:"revoked,omitempty"`
	// Superseded marks a certificate whose relying party was deleted or whose
	// registered content was changed or removed. Its content is out of date, so
	// it stays revoked.
	Superseded bool `json:"superseded,omitempty"`
	// Expires is when the certificate expires (Unix time). An expired
	// certificate needs no status, so its entry is freed.
	Expires int64 `json:"expires,omitempty"`
}

// RegistrationScope selects registration certificates: those of an intended
// use, those of a service, or with both empty, all of a relying party.
type RegistrationScope struct {
	ServiceIdentifier     string `json:"serviceIdentifier,omitempty"`
	IntendedUseIdentifier string `json:"intendedUseIdentifier,omitempty"`
}

// certificateKey names what one certificate certifies: an intended use, or for
// an attestation provider, a service.
type certificateKey struct {
	service, intendedUse string
}

func (k certificateKey) matches(s RegistrationStatus) bool {
	if k.intendedUse != "" {
		return s.IntendedUse == k.intendedUse
	}
	return s.IntendedUse == "" && s.Service == k.service
}

func statusKey(s RegistrationStatus) certificateKey {
	if s.IntendedUse != "" {
		return certificateKey{intendedUse: s.IntendedUse}
	}
	return certificateKey{service: s.Service}
}

// allocateRegistrationStatus reserves a status list entry for a new
// certificate. rp is the registration as it was read before signing. If it
// changed or was deleted since, the certificate would be out of date, so this
// fails.
func (w *Wallet) allocateRegistrationStatus(rp WalletRelyingParty, key certificateKey, expires time.Time) (int, error) {
	identifier := rp.Identifier[0].Identifier
	w.mu.Lock()
	defer w.mu.Unlock()
	i := relyingPartyIndex(w.RelyingParties, identifier)
	if i < 0 {
		return 0, fmt.Errorf("%w: %s", errRelyingPartyNotFound, identifier)
	}
	if !sameCertificateContent(rp, w.RelyingParties[i], key) {
		return 0, errRegistrationChanged
	}
	now := time.Now().Unix()
	w.RegistrationStatuses = slices.DeleteFunc(w.RegistrationStatuses, func(s RegistrationStatus) bool { return s.Expires > 0 && s.Expires < now })
	if len(w.RegistrationStatuses) >= registrationStatusListSize/2 {
		return 0, errRegistrationStatusFull
	}
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(registrationStatusListSize-1))
		if err != nil {
			return 0, err
		}
		index := int(n.Int64()) + 1
		if !slices.ContainsFunc(w.RegistrationStatuses, func(s RegistrationStatus) bool { return s.Index == index }) {
			w.RegistrationStatuses = append(w.RegistrationStatuses, RegistrationStatus{Index: index, Identifier: identifier, IntendedUse: key.intendedUse, Service: key.service, Expires: expires.Unix()})
			return index, nil
		}
	}
}

// replaceRegistrationStatus permanently revokes the older certificates with
// the same key once the certificate at index is signed. An intended use or a
// provider service has one valid certificate at a time. Entries are appended in
// issue order, so when two certificates are issued at once, the later one stays
// valid.
func (w *Wallet) replaceRegistrationStatus(identifier string, key certificateKey, index int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	newest := slices.IndexFunc(w.RegistrationStatuses, func(s RegistrationStatus) bool { return s.Index == index })
	for i := range newest {
		s := &w.RegistrationStatuses[i]
		if s.Identifier == identifier && key.matches(*s) {
			s.Revoked, s.Superseded = true, true
		}
	}
}

func (w *Wallet) releaseRegistrationStatus(index int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.RegistrationStatuses = slices.DeleteFunc(w.RegistrationStatuses, func(s RegistrationStatus) bool { return s.Index == index })
}

// supersedeRegistrationsLocked permanently revokes every certificate that
// match accepts. The caller holds w.mu.
func (w *Wallet) supersedeRegistrationsLocked(match func(RegistrationStatus) bool) {
	for i := range w.RegistrationStatuses {
		if match(w.RegistrationStatuses[i]) {
			w.RegistrationStatuses[i].Revoked = true
			w.RegistrationStatuses[i].Superseded = true
		}
	}
}

// SetRegistrationCertificatesRevoked revokes or activates the registration
// certificates in scope. It returns how many changed. The registration stays.
func (w *Wallet) SetRegistrationCertificatesRevoked(identifier string, scope RegistrationScope, revoked bool) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	i := relyingPartyIndex(w.RelyingParties, identifier)
	if i < 0 {
		return 0, fmt.Errorf("%w: %s", errRelyingPartyNotFound, identifier)
	}
	rp := w.RelyingParties[i]
	inScope, err := scopeFilter(rp, scope)
	if err != nil {
		return 0, err
	}
	changed := 0
	for j := range w.RegistrationStatuses {
		s := &w.RegistrationStatuses[j]
		if s.Revoked != revoked && !s.Superseded && s.Identifier == rp.Identifier[0].Identifier && inScope(*s) {
			s.Revoked = revoked
			changed++
		}
	}
	return changed, nil
}

// RegistrationCertificateStatuses lists the status list entries of the
// registration certificates issued for a relying party, or for all of them
// when identifier is empty.
func (w *Wallet) RegistrationCertificateStatuses(identifier string) []RegistrationStatus {
	if rp, ok := w.RelyingParty(identifier); ok {
		identifier = rp.Identifier[0].Identifier
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	statuses := []RegistrationStatus{}
	for _, s := range w.RegistrationStatuses {
		if identifier == "" || s.Identifier == identifier {
			statuses = append(statuses, s)
		}
	}
	return statuses
}

// RegistrationStatusList is the one-bit status list of the issued registration
// certificates. A set bit marks a revoked certificate.
func (w *Wallet) RegistrationStatusList() []byte {
	w.mu.RLock()
	defer w.mu.RUnlock()
	bitstring := make([]byte, registrationStatusListSize/8)
	for _, s := range w.RegistrationStatuses {
		if s.Revoked && s.Index > 0 && s.Index < registrationStatusListSize {
			bitstring[s.Index/8] |= 1 << (s.Index % 8)
		}
	}
	return bitstring
}

// RegistrationStatusListToken is the registrar's status list as a Token Status
// List JWT signed by the registrar key (ETSI TS 119 475 V1.2.1 §6.2.6.1).
func (w *Wallet) RegistrationStatusListToken() (string, error) {
	key, chain, err := w.RegistrarSigningMaterial()
	if err != nil {
		return "", fmt.Errorf("loading registrar signer: %w", err)
	}
	return statuslist.GenerateStatusListJWT(w.RegistrationStatusList(), key, statuslist.StatusListConfig{
		URI:       w.RegistrationStatusListURL(),
		Issuer:    w.RegistrarBase(),
		Bits:      1,
		TTL:       300,
		CertChain: chain,
	})
}

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
	if req.Method != http.MethodGet || !sameURL(req.URL, t.wallet.RegistrationStatusListURL()) {
		if t.next.Transport == nil {
			return nil, errors.New("the wallet has no outbound transport")
		}
		return t.next.Transport.RoundTrip(req)
	}
	token, err := t.wallet.RegistrationStatusListToken()
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
func (w *Wallet) RelyingPartyCAs() *x509.CertPool {
	pool := w.RegistrarCAs()
	if _, accessCA, err := w.RelyingPartyAccessCA(); err == nil {
		pool.AddCert(accessCA)
	}
	return pool
}

// RegistrarCAs are the CAs --arf trusts for registration certificates (ARF
// RPRC_02a). The wallet CA signs the registrar's certificate. The relying
// party access CA is not one of them, because it signs any visitor's CSR.
// --relying-party-ca adds others.
func (w *Wallet) RegistrarCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.CertChain) > 0 {
		pool.AddCert(w.CertChain[len(w.CertChain)-1])
	}
	pool.AppendCertsFromPEM(w.RelyingPartyCAPEM)
	return pool
}

func registrationStatusClaim(uri string, index int) map[string]any {
	return map[string]any{"status_list": map[string]any{"idx": index, "uri": uri}}
}

// RegistrationStatusListURL is where the registrar publishes its status list.
func (w *Wallet) RegistrationStatusListURL() string {
	return w.RegistrarBase() + registrationStatusListPath
}

// scopeFilter selects the status entries in scope. A service scope covers the
// service's provider certificate and the certificates of its intended uses.
func scopeFilter(rp WalletRelyingParty, scope RegistrationScope) (func(RegistrationStatus) bool, error) {
	if scope.IntendedUseIdentifier != "" {
		if _, _, ok := findIntendedUse(rp, scope.ServiceIdentifier, scope.IntendedUseIdentifier); !ok {
			return nil, fmt.Errorf("%w: no intended use %q", errRelyingPartyNotFound, scope.IntendedUseIdentifier)
		}
		return func(s RegistrationStatus) bool { return s.IntendedUse == scope.IntendedUseIdentifier }, nil
	}
	if scope.ServiceIdentifier == "" {
		return func(RegistrationStatus) bool { return true }, nil
	}
	service, ok := findService(rp, scope.ServiceIdentifier)
	if !ok {
		return nil, fmt.Errorf("%w: no service %q", errRelyingPartyNotFound, scope.ServiceIdentifier)
	}
	return func(s RegistrationStatus) bool {
		if s.IntendedUse == "" {
			return s.Service == service.ServiceIdentifier
		}
		return slices.ContainsFunc(service.IntendedUses, func(u IntendedUse) bool { return u.IntendedUseIdentifier == s.IntendedUse })
	}, nil
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
