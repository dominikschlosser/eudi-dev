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
	"time"

	"github.com/google/uuid"
)

// DeferredIssuance is a credential the issuer deferred, kept until the wallet
// manages to collect it. The issuer's interval can be hours, too long to hold
// the request that started the issuance, so the ticket is persisted and a
// poller works through it. It carries everything the deferred request needs:
// the flow that created it is gone by the time it runs.
type DeferredIssuance struct {
	ID               string `json:"id"`
	TransactionID    string `json:"transaction_id"`
	Issuer           string `json:"issuer"`
	DeferredEndpoint string `json:"deferred_endpoint"`
	ConfigurationID  string `json:"credential_configuration_id,omitempty"`
	Format           string `json:"format,omitempty"`
	// VCT and DocType name what is being issued, read from the issuer's
	// metadata for this configuration. A credential offer carries only
	// configuration ids, so without these a waiting credential is listed by an
	// issuer's internal name while a delivered one is listed by its type.
	VCT         string `json:"vct,omitempty"`
	DocType     string `json:"doctype,omitempty"`
	AccessToken string `json:"access_token"`
	AuthScheme  string `json:"auth_scheme,omitempty"`
	// RefreshToken and AccessTokenExpiresAt let a long deferral obtain a new
	// access token. The one the credential request used is short lived, and an
	// issuer may ask the wallet back in an hour, so without these the
	// collection fails on an authorization the issuer already expired.
	RefreshToken         string    `json:"refresh_token,omitempty"`
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at,omitempty"`
	// TokenEndpoint and ClientID are what a refresh needs, and the flow that
	// knew them is gone by the time the poller runs.
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	// ClientAuth is how the issuance authenticated this client, when it had
	// to. Renewing the access token is another token request at the same
	// endpoint, held to the same rule.
	ClientAuth      *ClientAuthentication `json:"client_auth,omitempty"`
	UseDPoP         bool                  `json:"use_dpop,omitempty"`
	IntervalSeconds int                   `json:"interval_seconds,omitempty"`
	CreatedAt       time.Time             `json:"created_at"`
	NextAttemptAt   time.Time             `json:"next_attempt_at"`
	Attempts        int                   `json:"attempts,omitempty"`
	LastError       string                `json:"last_error,omitempty"`
	// ProofKeyPEMs holds the keys the credential request proved possession of,
	// holder key first. A batch request adds ephemeral keys that exist nowhere
	// else, and the credential still has to be matched back to one of them.
	ProofKeyPEMs []string `json:"proof_keys,omitempty"`
}

// Interval is how long to wait between attempts, as the issuer asked.
func (p *DeferredIssuance) Interval() time.Duration {
	if p == nil || p.IntervalSeconds < 1 {
		return deferredPollInterval
	}
	return time.Duration(p.IntervalSeconds) * time.Second
}

// Expired reports whether a pending issuance is past being worth keeping. An
// issuer that has not produced the credential within a day is unlikely to, and
// the access token to collect it has probably expired.
func (p *DeferredIssuance) Expired(now time.Time) bool {
	return p != nil && now.Sub(p.CreatedAt) > deferredIssuanceMaxAge
}

// deferredIssuanceMaxAge is how long a deferred issuance is carried before the
// wallet gives up on it.
const deferredIssuanceMaxAge = 24 * time.Hour

// newDeferredIssuance builds a record from a deferred issuance in flight.
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
		ID:                   uuid.NewString(),
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

// ProofKeys decodes the keys the credential request was bound to.
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

// AddDeferredIssuance records a deferred credential to collect later.
func (w *Wallet) AddDeferredIssuance(pending *DeferredIssuance) {
	if w == nil || pending == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.DeferredIssuances = append(w.DeferredIssuances, *pending)
}

// DeferredIssuanceList returns a copy of the deferred credentials waiting to be
// collected.
func (w *Wallet) DeferredIssuanceList() []DeferredIssuance {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]DeferredIssuance(nil), w.DeferredIssuances...)
}

// RemoveDeferredIssuance drops a deferred credential by ID and reports whether
// it was there.
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

// UpdateDeferredIssuance applies a change to one record by ID.
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

// recordDeferredIssuance stores a deferred credential and reports it as the
// outcome. Nothing failed: the issuer took the request and named a time to
// come back.
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

// AdoptDeferredIssuances takes over deferred credentials recorded on another
// wallet, skipping any this one already tracks. A request that overrides the
// profile runs on a clone that is thrown away afterwards: a credential is safe
// there because it goes straight to the shared store, but a deferred issuance
// is a promise to come back, and only the server's own wallet is polled.
func (w *Wallet) AdoptDeferredIssuances(from *Wallet) int {
	if w == nil || from == nil || w == from {
		return 0
	}
	incoming := from.DeferredIssuanceList()
	if len(incoming) == 0 {
		return 0
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	known := make(map[string]bool, len(w.DeferredIssuances))
	for _, existing := range w.DeferredIssuances {
		known[existing.Issuer+"|"+existing.TransactionID] = true
	}
	adopted := 0
	for _, pending := range incoming {
		if known[pending.Issuer+"|"+pending.TransactionID] {
			continue
		}
		w.DeferredIssuances = append(w.DeferredIssuances, pending)
		adopted++
	}
	return adopted
}

// credentialTypeForConfiguration reads the credential type an issuer declares
// for one configuration id, so a deferred credential can be named the way a
// delivered one is.
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

// AccessTokenExpired reports whether the stored access token is past use. A
// small margin covers the round trip: a token expiring while the request is in
// flight is refused just the same.
func (p *DeferredIssuance) AccessTokenExpired(now time.Time) bool {
	if p == nil || p.AccessTokenExpiresAt.IsZero() {
		return false
	}
	return now.Add(15 * time.Second).After(p.AccessTokenExpiresAt)
}

// CanRefresh reports whether the record carries what obtaining a new access
// token needs.
func (p *DeferredIssuance) CanRefresh() bool {
	return p != nil && p.RefreshToken != "" && p.TokenEndpoint != ""
}

// DeferredIssuanceSummary is the document a caller reads a deferred credential
// from, wherever it asked. Built once here rather than in each backend: two
// hand-written maps that have to agree is how the credential type reached the
// API and not the local store.
func DeferredIssuanceSummary(p DeferredIssuance) map[string]any {
	return map[string]any{
		"id":                          p.ID,
		"transaction_id":              p.TransactionID,
		"issuer":                      p.Issuer,
		"credential_configuration_id": p.ConfigurationID,
		"format":                      p.Format,
		"vct":                         p.VCT,
		"doctype":                     p.DocType,
		"can_refresh":                 p.CanRefresh(),
		"interval":                    p.Interval().String(),
		"created_at":                  p.CreatedAt,
		"next_attempt_at":             p.NextAttemptAt,
		"attempts":                    p.Attempts,
		"last_error":                  p.LastError,
	}
}
