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
	"encoding/pem"
	"fmt"
	"slices"
	"time"
)

// DeferredIssuance is stored on its own because issuance may take hours. It
// holds everything the poller needs after the original flow ends.
type DeferredIssuance struct {
	ID               string `json:"id"`
	TransactionID    string `json:"transaction_id"`
	Issuer           string `json:"issuer"`
	DeferredEndpoint string `json:"deferred_endpoint"`
	ConfigurationID  string `json:"credential_configuration_id,omitempty"`
	Format           string `json:"format,omitempty"`
	// VCT and DocType identify what is being issued. They come from the
	// issuer metadata, since an offer carries only configuration ids.
	VCT     string `json:"vct,omitempty"`
	DocType string `json:"doctype,omitempty"`
	// Display keeps the display metadata from the original flow until
	// collection completes.
	Display     *CredentialDisplay `json:"display,omitempty"`
	AccessToken string             `json:"access_token"`
	AuthScheme  string             `json:"auth_scheme,omitempty"`
	// RefreshToken and AccessTokenExpiresAt let a long deferral get a new
	// access token. The original token is short lived, and an issuer may ask
	// the wallet to come back in an hour.
	RefreshToken         string    `json:"refresh_token,omitempty"`
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at,omitempty"`
	// The refresh request goes to the original token endpoint with the same
	// client ID.
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	// ClientAuth records how the issuance authenticated this client. A token
	// refresh is a request to the same endpoint and needs the same
	// authentication.
	ClientAuth      *ClientAuthentication `json:"client_auth,omitempty"`
	UseDPoP         bool                  `json:"use_dpop,omitempty"`
	IntervalSeconds int                   `json:"interval_seconds,omitempty"`
	CreatedAt       time.Time             `json:"created_at"`
	NextAttemptAt   time.Time             `json:"next_attempt_at"`
	Attempts        int                   `json:"attempts,omitempty"`
	LastError       string                `json:"last_error,omitempty"`
	// ProofKeyPEMs holds the binding keys from the credential request, holder
	// key first. A batch request adds ephemeral keys that exist only here, and
	// each credential is matched back to one of them.
	ProofKeyPEMs []string `json:"proof_keys,omitempty"`
}

// Interval is how long to wait between attempts, as the issuer asked.
func (p *DeferredIssuance) Interval() time.Duration {
	if p == nil || p.IntervalSeconds < 1 {
		return deferredPollInterval
	}
	return time.Duration(p.IntervalSeconds) * time.Second
}

func (p *DeferredIssuance) Expired(now time.Time) bool {
	return p != nil && now.Sub(p.CreatedAt) > deferredIssuanceMaxAge
}

const deferredIssuanceMaxAge = 24 * time.Hour

func newDeferredIssuance(ctx deferredContext, transactionID string, interval time.Duration) (*DeferredIssuance, error) {
	pems := make([]string, 0, len(ctx.proofKeys))
	for _, key := range ctx.proofKeys {
		encoded, err := encodeECPrivateKeyPEM(key)
		if err != nil {
			return nil, fmt.Errorf("encoding proof key for the deferred credential: %w", err)
		}
		pems = append(pems, encoded)
	}
	seconds := int(interval / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	vct, docType := credentialTypeForConfiguration(ctx.metadata, ctx.configID)
	now := time.Now()
	var accessTokenExpiry time.Time
	if ctx.expiresIn > 0 {
		accessTokenExpiry = now.Add(time.Duration(ctx.expiresIn) * time.Second)
	}
	return &DeferredIssuance{
		ID:                   newCredentialID(),
		TransactionID:        transactionID,
		Issuer:               ctx.issuer,
		DeferredEndpoint:     ctx.deferredEndpoint,
		ConfigurationID:      ctx.configID,
		Format:               ctx.format,
		VCT:                  vct,
		DocType:              docType,
		AccessToken:          ctx.accessToken,
		RefreshToken:         ctx.refreshToken,
		TokenEndpoint:        ctx.tokenEndpoint,
		ClientID:             ctx.clientID,
		ClientAuth:           ctx.clientAuth,
		AuthScheme:           ctx.authScheme,
		UseDPoP:              ctx.dpopKey != nil,
		IntervalSeconds:      seconds,
		CreatedAt:            now,
		NextAttemptAt:        now.Add(interval),
		AccessTokenExpiresAt: accessTokenExpiry,
		ProofKeyPEMs:         pems,
	}, nil
}

func (p *DeferredIssuance) ProofKeys() ([]*ecdsa.PrivateKey, error) {
	keys := make([]*ecdsa.PrivateKey, 0, len(p.ProofKeyPEMs))
	for _, encoded := range p.ProofKeyPEMs {
		key, err := decodeECPrivateKeyPEM(encoded)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func encodeECPrivateKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

func decodeECPrivateKeyPEM(encoded string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, fmt.Errorf("proof key is not valid PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func (w *Wallet) AddDeferredIssuance(pending *DeferredIssuance) {
	if w == nil || pending == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.capacity.deferred > 0 && len(w.DeferredIssuances) >= w.capacity.deferred {
		w.DeferredIssuances = slices.Delete(w.DeferredIssuances, 0, len(w.DeferredIssuances)-w.capacity.deferred+1)
	}
	w.DeferredIssuances = append(w.DeferredIssuances, *pending)
}

func (w *Wallet) DeferredIssuanceList() []DeferredIssuance {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]DeferredIssuance(nil), w.DeferredIssuances...)
}

func (w *Wallet) RemoveDeferredIssuance(id string) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, pending := range w.DeferredIssuances {
		if pending.ID == id {
			w.DeferredIssuances = append(w.DeferredIssuances[:i], w.DeferredIssuances[i+1:]...)
			return true
		}
	}
	return false
}

func (w *Wallet) UpdateDeferredIssuance(id string, apply func(*DeferredIssuance)) {
	if w == nil || apply == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.DeferredIssuances {
		if w.DeferredIssuances[i].ID == id {
			apply(&w.DeferredIssuances[i])
			return
		}
	}
}

// recordDeferredIssuance hands a deferred response to background collection
// and reports the issuance as successful.
func (w *Wallet) recordDeferredIssuance(pending *DeferredIssuance) *IssuanceResult {
	w.AddDeferredIssuance(pending)
	w.addProtocolLog("issuance", "issuance_deferred",
		fmt.Sprintf("Issuer deferred the credential, collecting it every %s", pending.Interval()), true, map[string]any{
			"issuer":         pending.Issuer,
			"transaction_id": pending.TransactionID,
			"interval":       pending.Interval().String(),
			"next_attempt":   pending.NextAttemptAt,
		})
	return &IssuanceResult{
		Pending:       true,
		TransactionID: pending.TransactionID,
		RetryInterval: pending.Interval().String(),
		Issuer:        pending.Issuer,
		Format:        pending.Format,
	}
}

// credentialTypeForConfiguration reads the credential type from metadata to
// label deferred records. Offers carry only configuration IDs.
func credentialTypeForConfiguration(metadata map[string]any, configID string) (vct, docType string) {
	configs, ok := metadata["credential_configurations_supported"].(map[string]any)
	if !ok {
		return "", ""
	}
	config, ok := configs[configID].(map[string]any)
	if !ok {
		return "", ""
	}
	vct, _ = config["vct"].(string)
	docType, _ = config["doctype"].(string)
	return vct, docType
}

// AccessTokenExpired includes a small margin so the token does not expire
// during the request.
func (p *DeferredIssuance) AccessTokenExpired(now time.Time) bool {
	if p == nil || p.AccessTokenExpiresAt.IsZero() {
		return false
	}
	return now.Add(15 * time.Second).After(p.AccessTokenExpiresAt)
}

func (p *DeferredIssuance) CanRefresh() bool {
	return p != nil && p.RefreshToken != "" && p.TokenEndpoint != ""
}

func DeferredIssuanceSummary(p DeferredIssuance) map[string]any {
	return map[string]any{
		"id":                          p.ID,
		"transaction_id":              p.TransactionID,
		"issuer":                      p.Issuer,
		"credential_configuration_id": p.ConfigurationID,
		"format":                      p.Format,
		"vct":                         p.VCT,
		"doctype":                     p.DocType,
		"display":                     p.Display,
		"can_refresh":                 p.CanRefresh(),
		"interval":                    p.Interval().String(),
		"created_at":                  p.CreatedAt,
		"next_attempt_at":             p.NextAttemptAt,
		"attempts":                    p.Attempts,
		"last_error":                  p.LastError,
	}
}
