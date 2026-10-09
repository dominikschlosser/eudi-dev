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
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"time"
)

// maxBatchProofKeys caps the proof keys so an advertised batch_size cannot make
// requests arbitrarily large. Separate keys support EUDI ARF method C.
const maxBatchProofKeys = 8

func advertisedBatchSize(metadata map[string]any) int {
	batch, ok := metadata["batch_credential_issuance"].(map[string]any)
	if !ok {
		return 0
	}
	size, ok := batch["batch_size"].(float64)
	if !ok || size < 1 {
		return 0
	}
	return int(size)
}

// issuanceProofKeys returns the proof keys of a credential request, holder
// key first. buildCredentialProofs turns them into proofs. When the issuer
// advertises batch_size >= 2, each copy of the batch is bound to its own fresh
// key. RFC 9901 §10.1 requires this for SD-JWT batches. It is recommended for
// mdoc.
func issuanceProofKeys(holderKey *ecdsa.PrivateKey, metadata map[string]any) ([]*ecdsa.PrivateKey, error) {
	keys := []*ecdsa.PrivateKey{holderKey}
	batchSize := advertisedBatchSize(metadata)
	if batchSize < 2 {
		return keys, nil
	}
	count := batchSize
	if count > maxBatchProofKeys {
		count = maxBatchProofKeys
	}
	for len(keys) < count {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating batch proof key: %w", err)
		}
		keys = append(keys, key)
	}
	log.Printf("[VCI] Issuer advertises batch_credential_issuance (batch_size=%d), requesting %d copies", batchSize, len(keys))
	return keys, nil
}

func createProofJWTs(keys []*ecdsa.PrivateKey, audience, clientID, cNonce string, extraHeader map[string]any) ([]string, error) {
	proofs := make([]string, 0, len(keys))
	for _, key := range keys {
		proof, err := createProofJWT(key, audience, clientID, cNonce, extraHeader)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, proof)
	}
	return proofs, nil
}

// selectPrimaryCredential picks the credential to import as the primary copy
// from a credential response. OID4VCI 1.0 does not tie the order of the
// credentials array to the proofs in the request, so the binding key is read
// from each credential.
//
// An issuer may "issue fewer Credentials" than the keys sent and binds each
// key to at most one Credential. A single credential is taken with whatever
// proof key it is bound to. Among several, each is matched to a distinct proof
// key. The holder-key copy is the primary, or else the first one.
func selectPrimaryCredential(credResp map[string]any, keys []*ecdsa.PrivateKey) (string, error) {
	creds := credentialStringsFromResponse(credResp)
	if len(creds) == 0 {
		return "", fmt.Errorf("no credential in response")
	}
	if len(creds) == 1 {
		if len(keys) > 1 {
			log.Printf("[VCI] Issuer returned one credential for %d keys, storing a single copy", len(keys))
		}
		return creds[0], nil
	}

	holderCredential := ""
	matched := make([]int, len(keys))
	for _, raw := range creds {
		keyIndex := proofKeyIndex(raw, keys)
		if keyIndex < 0 {
			return "", fmt.Errorf("credential response contains a credential that is not bound to any proof key")
		}
		matched[keyIndex]++
		if keyIndex == 0 {
			holderCredential = raw
		}
	}
	for i, count := range matched {
		if count > 1 {
			return "", fmt.Errorf("credential response contains %d credentials bound to the same proof key (index %d)", count, i)
		}
	}
	log.Printf("[VCI] Matched %d batch credential(s) to distinct proof keys, importing one as the primary copy", len(creds))
	if holderCredential != "" {
		return holderCredential, nil
	}
	return creds[0], nil
}

func proofKeyIndex(raw string, keys []*ecdsa.PrivateKey) int {
	for i := range keys {
		if credentialBindsToKey(raw, &keys[i].PublicKey) {
			return i
		}
	}
	return -1
}

// primaryBindingKeyPEM returns the PEM of the credential's binding key when it
// is not the holder key (index 0), and "" otherwise. The holder key needs no
// per-copy record because batchSigningKey falls back to it.
func primaryBindingKeyPEM(raw string, keys []*ecdsa.PrivateKey) string {
	if idx := proofKeyIndex(raw, keys); idx > 0 {
		if pem, err := encodeECPrivateKeyPEM(keys[idx]); err == nil {
			return pem
		}
	}
	return ""
}

// storeBatchSiblings stores batch copies under one group, each with its own
// binding key, for EUDI ARF method C (Annex 2 Topic 10, ISSU_51-54).
//
// A presentation clone keeps only the primary copy. The credential sink has
// already forwarded it to the real wallet without the batch group, so siblings
// stored there would be disconnected from it.
func (w *Wallet) storeBatchSiblings(primary *StoredCredential, credResp map[string]any, keys []*ecdsa.PrivateKey, display *CredentialDisplay) []*StoredCredential {
	if primary == nil {
		return nil
	}
	stored := []*StoredCredential{primary}
	creds := credentialStringsFromResponse(credResp)
	if len(creds) <= 1 || len(keys) <= 1 {
		return stored
	}
	if w.credentialSink != nil {
		log.Printf("[VCI] Batch issued during a presentation is kept as its primary copy only")
		return stored
	}
	primaryIdx := proofKeyIndex(primary.Raw, keys)
	group := newCredentialID()
	w.setBatchFields(primary.ID, group, primary.BindingKeyPEM)
	primary.BatchGroup = group

	for _, raw := range creds {
		idx := proofKeyIndex(raw, keys)
		if idx < 0 || idx == primaryIdx {
			continue
		}
		pem, err := encodeECPrivateKeyPEM(keys[idx])
		if err != nil {
			log.Printf("[VCI] skipping a batch copy: encoding its binding key failed: %v", err)
			continue
		}
		copyCred, err := w.importBatchCopy(raw, group, pem)
		if err != nil {
			log.Printf("[VCI] skipping a batch copy: %v", err)
			continue
		}
		if display != nil {
			w.rememberDisplay(copyCred, display)
		}
		stored = append(stored, copyCred)
	}
	log.Printf("[VCI] Stored a batch of %d copies (group %s) for one-time-use presentation", len(stored), group)
	return stored
}

// collapseBatchMatches keeps one copy per batch so consent does not show
// identical copies as alternatives.
func (w *Wallet) collapseBatchMatches(matches []CredentialMatch, credentials []StoredCredential) []CredentialMatch {
	byID := make(map[string]StoredCredential, len(credentials))
	for _, c := range credentials {
		byID[c.ID] = c
	}
	groups := make(map[string][]int)
	for i, m := range matches {
		group := byID[m.CredentialID].BatchGroup
		if group == "" {
			continue
		}
		key := m.QueryID + "\x00" + group
		groups[key] = append(groups[key], i)
	}
	if len(groups) == 0 {
		return matches
	}
	keep := make(map[int]bool, len(groups))
	for _, idxs := range groups {
		keep[chooseBatchCopy(idxs, matches, byID)] = true
	}
	out := matches[:0]
	for i, m := range matches {
		if byID[m.CredentialID].BatchGroup != "" && !keep[i] {
			log.Printf("[DCQL]   query=%s: batch copy %s held back, another copy of the batch is presented", m.QueryID, m.CredentialID)
			continue
		}
		out = append(out, m)
	}
	return out
}

// chooseBatchCopy returns the index into matches of the batch copy to present.
// It picks a random copy among those presented the fewest times. Each copy is
// used once in random order before any copy is reused (EUDI ARF method C,
// ISSU_52).
func chooseBatchCopy(idxs []int, matches []CredentialMatch, byID map[string]StoredCredential) int {
	fewest := -1
	for _, i := range idxs {
		uses := byID[matches[i].CredentialID].Uses
		if fewest < 0 || uses < fewest {
			fewest = uses
		}
	}
	var least []int
	for _, i := range idxs {
		if byID[matches[i].CredentialID].Uses == fewest {
			least = append(least, i)
		}
	}
	return least[secureIntn(len(least))]
}

func secureIntn(n int) int {
	if n <= 1 {
		return 0
	}
	r, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(r.Int64())
}

// recordBatchPresentation marks a batch copy as presented, so the next
// presentation of the batch prefers a copy used fewer times. It does nothing
// for a credential outside a batch.
func (w *Wallet) recordBatchPresentation(id string) {
	w.mu.Lock()
	sink := w.batchPresentedSink
	bumped := false
	for i := range w.Credentials {
		if w.Credentials[i].ID == id {
			if w.Credentials[i].BatchGroup != "" {
				w.Credentials[i].Uses++
				w.Credentials[i].LastPresentedAt = time.Now()
				w.batchDirty = true
				bumped = true
			}
			break
		}
	}
	w.mu.Unlock()
	// Auto-accept and ISO-transcript presentations run on a clone. The use is
	// recorded on the source wallet so the rotation still advances.
	if bumped && sink != nil {
		sink(id)
	}
}

func (w *Wallet) setBatchFields(id, group, bindingKeyPEM string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == id {
			w.Credentials[i].BatchGroup = group
			w.Credentials[i].BindingKeyPEM = bindingKeyPEM
			return
		}
	}
}

// credentialStringsFromResponse extracts the credentials from a credential
// response. §8.3 defines a credentials array whose "elements of the array MUST
// be objects", each with a credential member.
func credentialStringsFromResponse(resp map[string]any) []string {
	rawCreds, ok := resp["credentials"].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, entry := range rawCreds {
		object, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if c, ok := object["credential"].(string); ok && c != "" {
			out = append(out, c)
		}
	}
	return out
}
