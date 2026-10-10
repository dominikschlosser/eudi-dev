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
	"slices"
	"strings"
	"time"
)

// RefreshCredential renews a credential with its refresh token. The renewed
// credential keeps the ID, so queries, UI selections and logs still match.
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

	// The credential request needs the Nonce Endpoint (§8.2) and the
	// issuer's encryption requirements. Both come from the Credential Issuer
	// Metadata (§12.2.2).
	metadata, signerChain, metadataErr := fetchIssuerMetadataDocument(w.HTTPClient(), renewal.Issuer, w.ARFChecks(), w.metadataPolicy(w.Mode(), nil))
	if metadataErr != nil {
		return nil, fmt.Errorf("fetching the issuer metadata of %s: %w", renewal.Issuer, metadataErr)
	}
	// A renewal requests a credential too, so the ARF checks apply. They run
	// before the token request, so a refusal keeps the refresh token.
	if findings := w.issuerARFCheck(metadata, signerChain, []string{renewal.ConfigurationID}); len(findings) > 0 {
		if err := w.reportARFIssuanceFindings(renewal.Issuer, findings); err != nil {
			return nil, err
		}
	}
	w.reportCatalogueFindings(renewal.Issuer, w.catalogueFindings(metadata, []string{renewal.ConfigurationID}))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", renewal.RefreshToken)
	if renewal.ClientID != "" {
		form.Set("client_id", renewal.ClientID)
	}
	// An issuer that required client authentication for the first token
	// request requires it for the refresh too.
	if err := applyClientAuthentication(form, renewal.ClientAuth, w.HolderKey); err != nil {
		return nil, err
	}
	nonce := ""
	tokenResp, err := postFormWithDPoP(w.HTTPClient(), renewal.TokenEndpoint, form, dpopKey, "", &nonce, w.attestorFor(renewal.ClientAuth))
	if err != nil {
		return nil, fmt.Errorf("renewing the access token: %w", err)
	}
	// The issuer may rotate the refresh token and retire the old one, so the
	// wallet keeps the new one even when a later step fails.
	if rotated, _ := tokenResp["refresh_token"].(string); rotated != "" {
		renewal.RefreshToken = rotated
		w.rememberRenewal(cred.ID, rotated, renewal)
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("the token response carried no access_token")
	}
	authScheme := accessTokenScheme(tokenResp, renewal.UseDPoP)

	cNonce, err := w.issuanceChallenge(metadata, tokenResp, renewal.Issuer, &nonce)
	if err != nil {
		return nil, err
	}
	responseEncryption, err := buildCredentialResponseEncryptionRequest(w.Mode(), metadata, w.HolderKey)
	if err != nil {
		return nil, err
	}

	// A renewal replaces one credential, so it needs one proof key.
	proofKeys := []*ecdsa.PrivateKey{w.HolderKey}

	// OpenID4VCI §8.2 requires credential_identifier "when an Authorization
	// Details of type openid_credential was returned from the Token Response",
	// and credential_configuration_id otherwise.
	credentialIdentifier, authorizedOther := resolveCredentialIdentifier(tokenResp, renewal.ConfigurationID)
	w.reportAuthorizedConfiguration(renewal.Issuer, renewal.ConfigurationID, authorizedOther)
	credentialConfigurationID := ""
	if credentialIdentifier == "" {
		credentialConfigurationID = renewal.ConfigurationID
	}

	attempt := credentialRequestAttempt{
		metadata:                  metadata,
		endpoint:                  renewal.CredentialEndpoint,
		issuer:                    renewal.Issuer,
		configID:                  renewal.ConfigurationID,
		accessToken:               accessToken,
		authScheme:                authScheme,
		credentialIdentifier:      credentialIdentifier,
		credentialConfigurationID: credentialConfigurationID,
		responseEncryption:        responseEncryption,
		dpopKey:                   dpopKey,
		proofKeys:                 proofKeys,
		// The key proof carries the original client ID as iss. It is empty for
		// an anonymous flow.
		clientID: renewal.ClientID,
		nonce:    &nonce,
	}
	proofs, err := w.buildCredentialProofs(attempt, cNonce)
	if err != nil {
		return nil, fmt.Errorf("building the proof: %w", err)
	}

	credResp, err := w.requestCredentialWithNonceRetry(attempt, proofs)
	if err != nil {
		return nil, fmt.Errorf("requesting the credential: %w", err)
	}
	raw, err := selectPrimaryCredential(credResp, proofKeys)
	if err != nil {
		return nil, fmt.Errorf("reading the renewed credential: %w", err)
	}
	if _, err := w.checkReceivedCredentials(credResp, renewal.Issuer); err != nil {
		return nil, err
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

func (s *Server) RefreshCredential(id string) (*StoredCredential, error) {
	renewed, err := s.wallet.RefreshCredential(id)
	if err != nil {
		// A failed renewal can still have rotated the refresh token.
		if cred, ok := s.wallet.GetCredential(id); ok {
			s.saveCredential(&cred, false)
		}
		return nil, err
	}
	s.log("  Renewed:       %s credential %s", renewed.Format, renewed.ID)
	s.saveCredential(renewed, true)
	return renewed, nil
}

// ReplaceCredential puts a renewed credential in place of the one with id.
// The renewal replaces the credential's content. The wallet's bookkeeping of
// it (protection, display, batch, use count) stays, and so does its place.
func (w *Wallet) ReplaceCredential(id, raw string, renewal *CredentialRenewal) (*StoredCredential, error) {
	fresh, err := w.parseDetectedFormat(strings.TrimSpace(raw), "", "")
	if err != nil {
		return nil, fmt.Errorf("parsing the renewed credential: %w", err)
	}

	w.mu.Lock()
	i := slices.IndexFunc(w.Credentials, func(c StoredCredential) bool { return c.ID == id })
	if i < 0 {
		w.mu.Unlock()
		return nil, fmt.Errorf("credential %s not found", id)
	}
	old := w.Credentials[i]
	fresh.ID = id
	fresh.Protected = old.Protected
	fresh.Renewal = renewal
	fresh.Display = old.Display
	// Batch membership stays, so listing, presentation, deletion and
	// revocation still see one credential. The renewal is bound to the
	// wallet holder key, so no per-copy key carries over.
	fresh.BatchGroup = old.BatchGroup
	fresh.Uses = old.Uses
	fresh.LastPresentedAt = old.LastPresentedAt
	w.Credentials[i] = fresh
	renewed := w.Credentials[i]
	w.mu.Unlock()

	// The renewed credential's entry on the wallet's own list replaces the
	// old one.
	if ref := w.ownStatusRef(renewed); ref != nil {
		w.registerStatusEntry(id, ref.Idx)
	}
	return &renewed, nil
}

// renewalCheckInterval has to be shorter than renewalMargin, so a credential
// is noticed while there is still time to renew it.
const renewalCheckInterval = 30 * time.Second

// renewalRetryAfter keeps a failed renewal from being retried on every sweep.
const renewalRetryAfter = 10 * time.Minute

// renewExpiringCredentials renews credentials inside renewalMargin. One
// failure does not stop the sweep.
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
