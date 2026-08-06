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
	"fmt"
	"net/url"
	"time"
)

// RefreshCredential asks a credential's issuer for a fresh copy, using the
// refresh token it handed over at issuance.
//
// The credential keeps its id. A verifier query, a UI selection and the
// activity log all refer to credentials by id, so replacing one with a new
// entry would read as the old one being deleted and an unrelated one
// appearing, when what happened is that the same credential was renewed.
func (w *Wallet) RefreshCredential(id string) (*StoredCredential, error) {
	cred, ok := w.GetCredential(id)
	if !ok {
		return nil, fmt.Errorf("credential %s not found", id)
	}
	if !cred.CanRenew() {
		return nil, fmt.Errorf("credential %s cannot be renewed: its issuer handed over no refresh token", id)
	}
	renewal := *cred.Renewal

	var dpopKey *ecdsa.PrivateKey
	if renewal.UseDPoP {
		dpopKey = w.HolderKey
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", renewal.RefreshToken)
	if renewal.ClientID != "" {
		form.Set("client_id", renewal.ClientID)
	}
	// A refresh is a token request like the one that obtained the credential,
	// so an issuer that required client authentication then requires it now.
	if err := applyClientAuthentication(form, renewal.ClientAuth, w.HolderKey); err != nil {
		return nil, err
	}
	nonce := ""
	tokenResp, err := postFormWithDPoP(renewal.TokenEndpoint, form, dpopKey, "", &nonce, w.clientAttestationHeaders(renewal.ClientAuth))
	if err != nil {
		return nil, fmt.Errorf("renewing the access token: %w", err)
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("the token response carried no access_token")
	}
	cNonce, _ := tokenResp["c_nonce"].(string)
	authScheme := accessTokenScheme(tokenResp, renewal.UseDPoP)

	// The holder key alone: a renewal replaces one credential, so there is no
	// batch to match back to several ephemeral keys.
	proofKeys := []*ecdsa.PrivateKey{w.HolderKey}
	proofJWTs, err := createProofJWTs(proofKeys, renewal.Issuer, cNonce, nil)
	if err != nil {
		return nil, fmt.Errorf("building the proof: %w", err)
	}

	credResp, err := requestCredentialWithDPoP(w.ValidationMode, nil, renewal.CredentialEndpoint, accessToken, authScheme,
		proofJWTs, "", renewal.ConfigurationID, nil, dpopKey, w.HolderKey, &nonce)
	if err != nil {
		return nil, fmt.Errorf("requesting the credential: %w", err)
	}
	raw, err := selectHolderBoundCredential(credResp, proofKeys)
	if err != nil {
		return nil, fmt.Errorf("reading the renewed credential: %w", err)
	}

	// A rotated refresh token replaces the stored one, or the next renewal
	// would present one the issuer has already retired.
	if rotated, _ := tokenResp["refresh_token"].(string); rotated != "" {
		renewal.RefreshToken = rotated
	}

	renewed, err := w.ReplaceCredential(id, raw, &renewal)
	if err != nil {
		return nil, err
	}
	w.AddLogDetails("issuance", fmt.Sprintf("Renewed credential %s from %s", renewed.ID, renewal.Issuer), true, map[string]any{
		"credential_id": renewed.ID,
		"issuer":        renewal.Issuer,
		"format":        renewed.Format,
	})
	return renewed, nil
}

// RefreshCredential renews a credential and persists the result. The wallet
// does the exchange; the server owns the store and the log the operator sees.
func (s *Server) RefreshCredential(id string) (*StoredCredential, error) {
	renewed, err := s.wallet.RefreshCredential(id)
	if err != nil {
		return nil, err
	}
	s.log("  Renewed:       %s credential %s", renewed.Format, renewed.ID)
	s.persistWallet()
	return renewed, nil
}

// ReplaceCredential swaps a credential's contents for a freshly issued copy,
// keeping its id, its protection and its place in the list.
func (w *Wallet) ReplaceCredential(id, raw string, renewal *CredentialRenewal) (*StoredCredential, error) {
	// Imported first so the new copy is parsed exactly the way any other
	// credential is, then moved onto the existing entry and the appended one
	// dropped.
	imported, err := w.ImportCredential(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing the renewed credential: %w", err)
	}
	appendedID := imported.ID

	w.mu.Lock()
	defer w.mu.Unlock()

	var fresh StoredCredential
	kept := w.Credentials[:0]
	for _, c := range w.Credentials {
		if c.ID == appendedID {
			fresh = c
			continue
		}
		kept = append(kept, c)
	}
	w.Credentials = kept

	// The renewed copy was imported under a throwaway id, so a status entry
	// adopted during that import has to follow it onto the entry that keeps
	// the original id.
	if entry, ok := w.StatusEntries[appendedID]; ok {
		delete(w.StatusEntries, appendedID)
		w.StatusEntries[id] = entry
	}

	for i := range w.Credentials {
		if w.Credentials[i].ID != id {
			continue
		}
		fresh.ID = id
		fresh.Protected = w.Credentials[i].Protected
		fresh.Renewal = renewal
		w.Credentials[i] = fresh
		return &w.Credentials[i], nil
	}
	return nil, fmt.Errorf("credential %s not found", id)
}

// renewalCheckInterval is how often credentials are checked against their
// expiry. It only has to be shorter than the margin, so a credential is
// noticed while there is still time to renew it.
const renewalCheckInterval = 30 * time.Second

// renewalRetryAfter keeps a credential whose renewal failed from being retried
// on every sweep. An issuer that refused once will usually refuse again, and a
// wallet asking every half minute until the credential expires is noise that
// buries the reason.
const renewalRetryAfter = 10 * time.Minute

// renewExpiringCredentials renews what is close enough to expiry to be worth
// renewing. One credential failing is not a failure of the sweep: the others
// still need doing, and the task would otherwise be abandoned over a single
// issuer being unreachable.
func (s *Server) renewExpiringCredentials(now time.Time) error {
	for _, cred := range s.wallet.GetCredentials() {
		if !cred.CanRenew() || !CredentialNeedsRenewal(cred, now) {
			continue
		}
		if !s.renewalDue(cred.ID, now) {
			continue
		}
		if _, err := s.RefreshCredential(cred.ID); err != nil {
			s.noteRenewalFailure(cred.ID, now)
			s.log("  ERROR: renewing credential %s: %v", cred.ID, err)
		}
	}
	return nil
}

// renewalDue reports whether a credential may be tried again yet.
func (s *Server) renewalDue(credentialID string, now time.Time) bool {
	s.renewalMu.Lock()
	defer s.renewalMu.Unlock()
	next, seen := s.renewalBackoff[credentialID]
	return !seen || now.After(next)
}

func (s *Server) noteRenewalFailure(credentialID string, now time.Time) {
	s.renewalMu.Lock()
	defer s.renewalMu.Unlock()
	if s.renewalBackoff == nil {
		s.renewalBackoff = make(map[string]time.Time)
	}
	s.renewalBackoff[credentialID] = now.Add(renewalRetryAfter)
}
