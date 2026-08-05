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
)

// RefreshCredential asks a credential's issuer for a fresh copy, using the
// refresh token it handed over at issuance.
//
// The credential keeps its id. A verifier query, a UI selection and the
// activity log all refer to credentials by id, so replacing one with a new
// entry would read as the old one being deleted and an unrelated one
// appearing, when what happened is that the same credential was renewed.
func (s *Server) RefreshCredential(id string) (*StoredCredential, error) {
	cred, ok := s.wallet.GetCredential(id)
	if !ok {
		return nil, fmt.Errorf("credential %s not found", id)
	}
	if !cred.CanRenew() {
		return nil, fmt.Errorf("credential %s cannot be renewed: its issuer handed over no refresh token", id)
	}
	renewal := *cred.Renewal

	var dpopKey *ecdsa.PrivateKey
	if renewal.UseDPoP {
		dpopKey = s.wallet.HolderKey
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", renewal.RefreshToken)
	if renewal.ClientID != "" {
		form.Set("client_id", renewal.ClientID)
	}
	nonce := ""
	tokenResp, err := postFormWithDPoP(renewal.TokenEndpoint, form, dpopKey, "", &nonce, nil)
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
	proofKeys := []*ecdsa.PrivateKey{s.wallet.HolderKey}
	proofJWTs, err := createProofJWTs(proofKeys, renewal.Issuer, cNonce, nil)
	if err != nil {
		return nil, fmt.Errorf("building the proof: %w", err)
	}

	credResp, err := requestCredentialWithDPoP(nil, renewal.CredentialEndpoint, accessToken, authScheme,
		proofJWTs, "", renewal.ConfigurationID, nil, dpopKey, s.wallet.HolderKey, &nonce)
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

	renewed, err := s.wallet.ReplaceCredential(id, raw, &renewal)
	if err != nil {
		return nil, err
	}
	s.log("  Renewed:       %s credential %s from %s", renewed.Format, renewed.ID, renewal.Issuer)
	s.wallet.AddLogDetails("issuance", fmt.Sprintf("Renewed credential %s from %s", renewed.ID, renewal.Issuer), true, map[string]any{
		"credential_id": renewed.ID,
		"issuer":        renewal.Issuer,
		"format":        renewed.Format,
	})
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
