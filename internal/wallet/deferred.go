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

// PendingIssuance is a credential the issuer deferred, kept so the wallet can
// collect it when the issuer says it is ready.
//
// The issuer hands out a transaction_id and an interval to come back after,
// which can be hours. Waiting that out inside the request that started the
// issuance is not an option, so the ticket is persisted instead and a poller
// works through it in the background. Everything the deferred request needs
// travels with it, because the flow that created it is long gone by then.
type PendingIssuance struct {
	ID               string    `json:"id"`
	TransactionID    string    `json:"transaction_id"`
	Issuer           string    `json:"issuer"`
	DeferredEndpoint string    `json:"deferred_endpoint"`
	ConfigurationID  string    `json:"credential_configuration_id,omitempty"`
	Format           string    `json:"format,omitempty"`
	AccessToken      string    `json:"access_token"`
	AuthScheme       string    `json:"auth_scheme,omitempty"`
	UseDPoP          bool      `json:"use_dpop,omitempty"`
	IntervalSeconds  int       `json:"interval_seconds,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	NextAttemptAt    time.Time `json:"next_attempt_at"`
	Attempts         int       `json:"attempts,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
	// ProofKeyPEMs holds the keys the credential request proved possession of.
	// The holder key is always the first, and a batch request adds ephemeral
	// ones; a deferred credential still has to be matched back to the key it
	// was bound to, and those ephemeral keys exist nowhere else.
	ProofKeyPEMs []string `json:"proof_keys,omitempty"`
}

// Interval is how long to wait between attempts, as the issuer asked.
func (p *PendingIssuance) Interval() time.Duration {
	if p == nil || p.IntervalSeconds < 1 {
		return deferredPollInterval
	}
	return time.Duration(p.IntervalSeconds) * time.Second
}

// Expired reports whether a pending issuance has been carried around for
// longer than it is worth. An issuer that has not produced the credential
// within a day is not going to, and the access token that would collect it has
// almost certainly expired.
func (p *PendingIssuance) Expired(now time.Time) bool {
	return p != nil && now.Sub(p.CreatedAt) > pendingIssuanceMaxAge
}

// pendingIssuanceMaxAge is how long a deferred issuance is carried before the
// wallet gives up on it.
const pendingIssuanceMaxAge = 24 * time.Hour

// newPendingIssuance builds a record from a deferred issuance in flight.
func newPendingIssuance(ctx deferredContext, transactionID string, interval time.Duration) (*PendingIssuance, error) {
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
	now := time.Now()
	return &PendingIssuance{
		ID:               uuid.NewString(),
		TransactionID:    transactionID,
		Issuer:           ctx.issuer,
		DeferredEndpoint: ctx.deferredEndpoint,
		ConfigurationID:  ctx.configID,
		Format:           ctx.format,
		AccessToken:      ctx.accessToken,
		AuthScheme:       ctx.authScheme,
		UseDPoP:          ctx.dpopKey != nil,
		IntervalSeconds:  seconds,
		CreatedAt:        now,
		NextAttemptAt:    now.Add(interval),
		ProofKeyPEMs:     pems,
	}, nil
}

// ProofKeys decodes the keys the credential request was bound to.
func (p *PendingIssuance) ProofKeys() ([]*ecdsa.PrivateKey, error) {
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

// AddPendingIssuance records a deferred credential to collect later.
func (w *Wallet) AddPendingIssuance(pending *PendingIssuance) {
	if w == nil || pending == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.PendingIssuances = append(w.PendingIssuances, *pending)
}

// PendingIssuanceList returns a copy of the deferred credentials waiting to be
// collected.
func (w *Wallet) PendingIssuanceList() []PendingIssuance {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]PendingIssuance(nil), w.PendingIssuances...)
}

// RemovePendingIssuance drops a deferred credential by ID and reports whether
// it was there.
func (w *Wallet) RemovePendingIssuance(id string) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, pending := range w.PendingIssuances {
		if pending.ID == id {
			w.PendingIssuances = append(w.PendingIssuances[:i], w.PendingIssuances[i+1:]...)
			return true
		}
	}
	return false
}

// UpdatePendingIssuance applies a change to one record by ID.
func (w *Wallet) UpdatePendingIssuance(id string, apply func(*PendingIssuance)) {
	if w == nil || apply == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.PendingIssuances {
		if w.PendingIssuances[i].ID == id {
			apply(&w.PendingIssuances[i])
			return
		}
	}
}

// recordPendingIssuance stores a deferred credential and reports it as the
// outcome of the issuance. Nothing failed: the issuer took the request and
// named a time to come back, and the poller does that.
func (w *Wallet) recordPendingIssuance(pending *PendingIssuance) *IssuanceResult {
	w.AddPendingIssuance(pending)
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
