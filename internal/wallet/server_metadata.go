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

// The documents the wallet publishes about itself: trust lists, issuer
// metadata, registrar records and the status list.

package wallet

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/statuslist"
)

// handleTrustList generates and serves an ETSI trust list JWT from the wallet's issuer key.
func (s *Server) handleTrustList(w http.ResponseWriter, r *http.Request) {
	if len(s.wallet.CertChain) < 2 {
		http.Error(w, "wallet has no CA certificate chain", http.StatusInternalServerError)
		return
	}
	group, ok := FindTrustListGroupForWallet(s.wallet, "", r.URL.Query().Get("vct"), r.URL.Query().Get("doctype"))
	if !ok {
		http.Error(w, "wallet has no matching trust list", http.StatusNotFound)
		return
	}
	jwt, err := GenerateTrustListJWTForWalletGroup(s.wallet, s.wallet.IssuerURL, group, "/api/trustlist")
	if err != nil {
		http.Error(w, fmt.Sprintf("generating trust list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

func (s *Server) handleTrustListIndex(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(strings.TrimSpace(s.wallet.IssuerURL), "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"trust_lists": BuildTrustListIndexEntries(s.wallet, issuer),
	})
}

func (s *Server) handleTrustListByID(w http.ResponseWriter, r *http.Request) {
	if len(s.wallet.CertChain) < 2 {
		http.Error(w, "wallet has no CA certificate chain", http.StatusInternalServerError)
		return
	}
	group, ok := FindTrustListGroupForWallet(s.wallet, r.PathValue("id"), "", "")
	if !ok {
		http.Error(w, "trust list not found", http.StatusNotFound)
		return
	}
	jwt, err := GenerateTrustListJWTForWalletGroup(s.wallet, s.wallet.IssuerURL, group, "/api/trustlists/"+group.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("generating trust list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

func (s *Server) handleJWTVCIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	jwk := buildIssuerSigningJWK(s.wallet, s.signingKeyExpiry())
	if jwk == nil {
		http.Error(w, "wallet has no issuer signing key", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": issuer,
		"jwks": map[string]any{
			"keys": []any{jwk},
		},
	})
}

func (s *Server) handleOpenIDCredentialIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	if len(s.wallet.CertChain) == 0 {
		http.Error(w, "wallet has no issuer certificate chain", http.StatusInternalServerError)
		return
	}
	jwt, err := signCredentialIssuerMetadataJWT(s.wallet, issuer, s.signingKeyExpiry())
	if err != nil {
		http.Error(w, fmt.Sprintf("signing issuer metadata: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/openidvci-issuer-metadata+jwt")
	w.Write([]byte(jwt))
}

func (s *Server) handleRegistrarWRPList(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	if s.wallet.CAKey == nil || len(s.wallet.CertChain) == 0 {
		http.Error(w, "wallet has no registrar signing material", http.StatusInternalServerError)
		return
	}
	record := buildRegistrarDataset(s.wallet, issuer)
	if !matchesRegistrarQuery(record, r) {
		recordJWT, err := signRegistrarResponseJWT(s.wallet.CAKey, []*x509.Certificate{s.wallet.CertChain[len(s.wallet.CertChain)-1]}, []RegistrarDataset{})
		if err != nil {
			http.Error(w, fmt.Sprintf("signing registrar response: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(recordJWT))
		return
	}
	recordJWT, err := signRegistrarResponseJWT(s.wallet.CAKey, []*x509.Certificate{s.wallet.CertChain[len(s.wallet.CertChain)-1]}, []RegistrarDataset{record})
	if err != nil {
		http.Error(w, fmt.Sprintf("signing registrar response: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(recordJWT))
}

func (s *Server) handleRegistrarWRPByIdentifier(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.wallet.IssuerURL, "/")
	if issuer == "" {
		http.Error(w, "wallet issuer URL is not configured", http.StatusNotFound)
		return
	}
	if s.wallet.CAKey == nil || len(s.wallet.CertChain) == 0 {
		http.Error(w, "wallet has no registrar signing material", http.StatusInternalServerError)
		return
	}
	record := buildRegistrarDataset(s.wallet, issuer)
	identifier := strings.TrimSpace(r.PathValue("identifier"))
	if identifier == "" || !recordHasIdentifier(record, identifier) {
		http.Error(w, "wallet relying party not found", http.StatusNotFound)
		return
	}
	recordJWT, err := signRegistrarResponseJWT(s.wallet.CAKey, []*x509.Certificate{s.wallet.CertChain[len(s.wallet.CertChain)-1]}, record)
	if err != nil {
		http.Error(w, fmt.Sprintf("signing registrar response: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(recordJWT))
}

// handleStatusList generates and serves a status list JWT.
func (s *Server) handleStatusList(w http.ResponseWriter, r *http.Request) {
	bitstring := s.wallet.BuildStatusBitstring()
	statusListURI := s.wallet.StatusListURL()
	certChain := s.wallet.CertChain
	if derived, err := s.wallet.DefaultSigningCertChain(); err == nil && len(derived) > 0 {
		certChain = derived
	}
	jwt, err := statuslist.GenerateStatusListJWT(bitstring, s.wallet.IssuerKey, statuslist.StatusListConfig{
		URI:       statusListURI,
		Issuer:    s.wallet.StatusListIssuer(),
		CertChain: certChain,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("generating status list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/statuslist+jwt")
	w.Write([]byte(jwt))
}

func matchesRegistrarQuery(record RegistrarDataset, r *http.Request) bool {
	q := r.URL.Query()
	if identifier := strings.TrimSpace(q.Get("identifier")); identifier != "" && !recordHasIdentifier(record, identifier) {
		return false
	}
	if entitlement := strings.TrimSpace(q.Get("entitlement")); entitlement != "" {
		match := false
		for _, candidate := range record.Entitlements {
			if candidate == entitlement {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if provides := strings.TrimSpace(q.Get("providesattestation")); provides != "" && !recordProvidesAttestation(record, provides) {
		return false
	}
	return true
}

func recordHasIdentifier(record RegistrarDataset, value string) bool {
	for _, identifier := range record.Identifier {
		if strings.TrimSpace(identifier.Identifier) == value {
			return true
		}
	}
	return false
}

func recordProvidesAttestation(record RegistrarDataset, value string) bool {
	for _, att := range record.ProvidesAttestations {
		switch att.Format {
		case "dc+sd-jwt":
			raw, ok := att.Meta["vct_values"].([]string)
			if ok {
				for _, candidate := range raw {
					if candidate == value {
						return true
					}
				}
			}
			if rawAny, ok := att.Meta["vct_values"].([]any); ok {
				for _, candidate := range rawAny {
					if s, ok := candidate.(string); ok && s == value {
						return true
					}
				}
			}
		case "mso_mdoc":
			if candidate, _ := att.Meta["doctype_value"].(string); candidate == value {
				return true
			}
		}
	}
	return false
}
