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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
)

// handleRegisterRelyingParty stores a relying party (TS05 v1.5 §3.1, POST /wrp).
func (s *Server) handleRegisterRelyingParty(w http.ResponseWriter, r *http.Request) {
	rp, ok := decodeRelyingParty(w, r)
	if !ok {
		return
	}
	var stored WalletRelyingParty
	var err error
	s.saveMutation(func() bool {
		stored, err = s.wallet.RegisterRelyingParty(rp, s.wallet.RegistrarBase())
		return err == nil
	})
	if err != nil {
		writeRegistrarError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}

// handleUpdateRelyingParty replaces a registration (TS05 v1.5 §3.1, PUT /wrp).
func (s *Server) handleUpdateRelyingParty(w http.ResponseWriter, r *http.Request) {
	rp, ok := decodeRelyingParty(w, r)
	if !ok {
		return
	}
	var stored WalletRelyingParty
	var err error
	s.saveMutation(func() bool {
		stored, err = s.wallet.UpdateRelyingParty(rp, s.wallet.RegistrarBase())
		return err == nil
	})
	if err != nil {
		writeRegistrarError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

func (s *Server) handleDeleteRelyingParty(w http.ResponseWriter, r *http.Request) {
	var err error
	s.saveMutation(func() bool {
		err = s.wallet.DeleteRelyingParty(r.PathValue("identifier"))
		return err == nil
	})
	if err != nil {
		writeRegistrarError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeRelyingParty(w http.ResponseWriter, r *http.Request) (WalletRelyingParty, bool) {
	var rp WalletRelyingParty
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&rp); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid relying party: " + err.Error()})
		return rp, false
	}
	return rp, true
}

// handleRegistrarWRPList answers the TS05 v1.5 §3.2 search (GET /wrp) with the
// matching records, paged by limit and cursor.
func (s *Server) handleRegistrarWRPList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	matching := slices.DeleteFunc(s.wallet.RegistrarRecords(), func(rp WalletRelyingParty) bool { return !matchesWRPQuery(rp, q) })
	limit := 20
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		limit = n
	}
	offset, _ := strconv.Atoi(q.Get("cursor"))
	offset = max(0, min(offset, len(matching)))
	end := offset + min(limit, len(matching)-offset)
	pagination := map[string]any{"has_next_page": end < len(matching)}
	if end < len(matching) {
		pagination["next_cursor"] = strconv.Itoa(end)
	}
	s.writeRegistrarResponse(w, r, map[string]any{"data": matching[offset:end], "pagination": pagination})
}

func (s *Server) handleRegistrarWRPByIdentifier(w http.ResponseWriter, r *http.Request) {
	rp, ok := s.registrarRecord(r.PathValue("identifier"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallet relying party not found"})
		return
	}
	s.writeRegistrarResponse(w, r, map[string]any{"data": rp})
}

// handleRegistrarWRPService narrows a record to one service (TS05 v1.5 §3.2.3).
func (s *Server) handleRegistrarWRPService(w http.ResponseWriter, r *http.Request) {
	rp, ok := s.registrarRecord(r.PathValue("identifier"))
	if ok {
		rp.Services = slices.DeleteFunc(slices.Clone(rp.Services), func(service WalletRelyingPartyService) bool {
			return service.ServiceIdentifier != r.PathValue("serviceidentifier")
		})
	}
	if !ok || len(rp.Services) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallet relying party service not found"})
		return
	}
	s.writeRegistrarResponse(w, r, map[string]any{"data": rp})
}

// handleCheckIntendedUse answers whether a relying party registered an intended
// use for a credential and claim (TS05 v1.5 §3.2.4).
func (s *Server) handleCheckIntendedUse(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rp, ok := s.registrarRecord(q.Get("identifier"))
	registered := false
	details := "the relying party is not registered"
	if ok {
		registered, details = checkIntendedUse(rp, q)
	}
	s.writeRegistrarResponse(w, r, map[string]any{"data": map[string]any{"isRegistered": registered, "details": details}})
}

func (s *Server) registrarRecord(identifier string) (WalletRelyingParty, bool) {
	records := s.wallet.RegistrarRecords()
	if i := relyingPartyIndex(records, identifier); i >= 0 {
		return records[i], true
	}
	return WalletRelyingParty{}, false
}

// writeRegistrarResponse adds iss and iat and signs the payload, as TS05 v1.5
// §3.2 requires. If the Accept header asks for application/json but not
// application/jwt, the payload is sent unsigned.
func (s *Server) writeRegistrarResponse(w http.ResponseWriter, r *http.Request, payload map[string]any) {
	payload["iss"] = s.wallet.RegistrarBase()
	payload["iat"] = time.Now().Unix()
	if accept := r.Header.Get("Accept"); strings.Contains(accept, "application/json") && !strings.Contains(accept, "application/jwt") {
		writeJSON(w, http.StatusOK, payload)
		return
	}
	key, chain, err := s.wallet.RegistrarSigningMaterial()
	if err != nil {
		http.Error(w, "loading registrar signer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signed, err := signRegistrarResponseJWT(key, chain, payload)
	if err != nil {
		http.Error(w, "signing registrar response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	_, _ = w.Write([]byte(signed))
}

// handleSetRegistrationCertificateStatus revokes or activates the
// registration certificates of an intended use, of a service, or of the whole
// relying party.
func (s *Server) handleSetRegistrationCertificateStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"`
		RegistrationScope
		Revoked bool `json:"revoked"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	var changed int
	var err error
	s.saveMutation(func() bool {
		changed, err = s.wallet.SetRegistrationCertificatesRevoked(req.Identifier, req.RegistrationScope, req.Revoked)
		return err == nil
	})
	if err != nil {
		writeRegistrarError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"changed": changed})
}

func (s *Server) handleRegistrationCertificateStatuses(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.wallet.RegistrationCertificateStatuses(r.URL.Query().Get("identifier")))
}

// handleRegistrationStatusList serves the status list of the registration
// certificates as a Token Status List (ETSI TS 119 475 V1.2.1 §6.2.6.1),
// signed by the registrar key.
func (s *Server) handleRegistrationStatusList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	token, err := s.wallet.RegistrationStatusListToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", statuslist.MediaTypeJWT)
	_, _ = w.Write([]byte(token))
}

// registrarPlaceholderPages serve the default URLs the registrar assigns when
// a registration or a catalogue entry names none. That way the links in
// registration certificates, in the consent dialog and in the catalogue work.
var registrarPlaceholderPages = map[string]string{
	"/privacy-policy":        "This page stands in for the privacy policy of a relying party registered with the eudi-dev test registrar. A relying party that registers its own URL links that one instead.",
	"/support":               "This page stands in for the support page of a relying party registered with the eudi-dev test registrar. A relying party that registers its own URL links that one instead.",
	"/supervisory-authority": "This page stands in for the supervisory authority contact of a relying party registered with the eudi-dev test registrar. A relying party that registers its own URL links that one instead.",
	"/rulebook":              "This page stands in for the rulebook of an attestation in the eudi-dev test catalogue. An attestation added with its own rulebook URL links that one instead.",
}

func placeholderPage(text string) http.HandlerFunc {
	body := "<!doctype html><meta charset=\"utf-8\"><title>Test registrar placeholder</title><p>" + text + "</p>"
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	}
}

func writeRegistrarError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, errRelyingPartyNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errRelyingPartyExists), errors.Is(err, errRegistrarFull), errors.Is(err, errRegistrationStatusFull), errors.Is(err, errRegistrationChanged):
		status = http.StatusConflict
	case errors.Is(err, errRegistrarSigning):
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
