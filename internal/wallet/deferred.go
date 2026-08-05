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

// PendingIssuance is a credential the issuer deferred, kept until the wallet
// manages to collect it. The issuer's interval can be hours, too long to hold
// the request that started the issuance, so the ticket is persisted and a
// poller works through it. It carries everything the deferred request needs:
// the flow that created it is gone by the time it runs.
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
	// ProofKeyPEMs holds the keys the credential request proved possession of,
	// holder key first. A batch request adds ephemeral keys that exist nowhere
	// else, and the credential still has to be matched back to one of them.
	ProofKeyPEMs []string `json:"proof_keys,omitempty"`
}

// Interval is how long to wait between attempts, as the issuer asked.
func (p *PendingIssuance) Interval() time.Duration {
	if p == nil || p.IntervalSeconds < 1 {
		return deferredPollInterval
	}
	return time.Duration(p.IntervalSeconds) * time.Second
}

// Expired reports whether a pending issuance is past being worth keeping. An
// issuer that has not produced the credential within a day is unlikely to, and
// the access token to collect it has probably expired.
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
// outcome. Nothing failed: the issuer took the request and named a time to
// come back.
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

// AdoptPendingIssuances takes over deferred credentials recorded on another
// wallet, skipping any this one already tracks.
//
// A request that overrides the profile (haip, mode) runs on a clone of the
// wallet, which is thrown away when the request ends. A credential is safe
// there because it is written straight to the shared store, but a deferred
// issuance is a promise to come back later, and only the server's own wallet
// is polled. Left on the clone it was recorded, reported to the caller, and
// then never collected.
func (w *Wallet) AdoptPendingIssuances(from *Wallet) int {
	if w == nil || from == nil || w == from {
		return 0
	}
	incoming := from.PendingIssuanceList()
	if len(incoming) == 0 {
		return 0
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	known := make(map[string]bool, len(w.PendingIssuances))
	for _, existing := range w.PendingIssuances {
		known[existing.Issuer+"|"+existing.TransactionID] = true
	}
	adopted := 0
	for _, pending := range incoming {
		if known[pending.Issuer+"|"+pending.TransactionID] {
			continue
		}
		w.PendingIssuances = append(w.PendingIssuances, pending)
		adopted++
	}
	return adopted
}
