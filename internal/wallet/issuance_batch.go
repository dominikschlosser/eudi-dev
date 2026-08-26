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

// maxBatchProofKeys caps how many proofs the wallet sends for a batch. The
// wallet requests the batch the issuer advertises, one credential per proof
// (§8.3), so it holds several copies and can present an unused one each time
// (EUDI ARF method C). The cap keeps a large advertised batch_size from making
// a single request enormous.
const maxBatchProofKeys = 8

// advertisedBatchSize returns the issuer's batch_credential_issuance.batch_size,
// or 0 when the issuer does not advertise batch issuance support.
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

// issuanceProofKeys returns the private keys to prove possession of in the
// credential request. The wallet's holder key is always first. When the issuer
// advertises batch issuance with batch_size >= 2, fresh ephemeral keys are
// added so each credential in the batch is bound to a distinct key (required
// for SD-JWT batches per RFC 9901 §10.1, recommended for mdoc).
func issuanceProofKeys(holderKey *ecdsa.PrivateKey, metadata map[string]any, configID string) ([]*ecdsa.PrivateKey, error) {
	keys := []*ecdsa.PrivateKey{holderKey}
	// With a key attestation the batch is counted from the attestation rather
	// than the proofs: Appendix F.1 and F.3 have the issuer "issue a Credential
	// for each cryptographic public key specified in the attested_keys claim".
	// Several proofs over the same keys is not a shape the spec defines, so the
	// request stays at one proof.
	if _, required := credentialKeyAttestationRequirement(metadata, configID); required {
		return keys, nil
	}
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
	log.Printf("[VCI] Issuer advertises batch_credential_issuance (batch_size=%d), sending %d proofs", batchSize, len(keys))
	return keys, nil
}

// createProofJWTs creates one proof JWT per key. All proofs share the same
// audience, client id, nonce, and extra header members (e.g. a key_attestation
// covering every proof key).
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
// from a credential response. OID4VCI 1.0 defines no correspondence between the
// order of the credentials array and the proofs in the request, so the binding
// key is identified from each credential itself.
//
// An issuer may "issue fewer Credentials" than the proofs sent and binds each
// key to at most one Credential, so it may return one credential, or several
// fewer than advertised, and need not bind any of them to the wallet's holder
// key. A single credential is taken whichever proof key it names (its card then
// reads as bound to another key). Several credentials are each matched to a
// distinct proof key, and the holder-key copy is preferred as the primary,
// falling back to the first credential when the issuer bound none to it.
func selectPrimaryCredential(credResp map[string]any, keys []*ecdsa.PrivateKey) (string, error) {
	creds := credentialStringsFromResponse(credResp)
	if len(creds) == 0 {
		return "", fmt.Errorf("no credential in response")
	}
	if len(creds) == 1 {
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
	log.Printf("[VCI] Matched %d batch credential(s) to distinct proof keys; importing one as the primary copy", len(creds))
	if holderCredential != "" {
		return holderCredential, nil
	}
	return creds[0], nil
}

// proofKeyIndex returns the index of the proof key a credential is bound to, or
// -1 when it is bound to none of them.
func proofKeyIndex(raw string, keys []*ecdsa.PrivateKey) int {
	for i := range keys {
		if credentialBindsToKey(raw, &keys[i].PublicKey) {
			return i
		}
	}
	return -1
}

// primaryBindingKeyPEM returns the PEM of the proof key a credential is bound to
// when it is not the holder key (index 0), and "" otherwise. The holder key
// needs no per-copy record, since batchSigningKey falls back to it.
func primaryBindingKeyPEM(raw string, keys []*ecdsa.PrivateKey) string {
	if idx := proofKeyIndex(raw, keys); idx > 0 {
		if pem, err := encodeECPrivateKeyPEM(keys[idx]); err == nil {
			return pem
		}
	}
	return ""
}

// storeBatchSiblings stores the other copies of a batch alongside the copy
// importPrimaryCredential already imported as primary. A batch credential
// response holds one credential per proof key (§8.3); this stores the rest, each
// bound to the key it was issued against, under a batch group shared with the
// primary. The wallet then presents an unused copy each time so a Relying Party
// cannot link two presentations of the same credential (EUDI ARF Annex 2 Topic
// 10 method C, ISSU_51-54).
//
// The primary is already bound to its own key, so a single-credential response
// leaves it as it is. A batch collected on a presentation clone keeps its
// primary copy alone: its credentialSink forwarded that copy (with its key) to
// the real wallet at import time, but the siblings would land there under a
// group the primary copy does not carry back, so they are left off.
func (w *Wallet) storeBatchSiblings(primary *StoredCredential, credResp map[string]any, keys []*ecdsa.PrivateKey, display *CredentialDisplay) {
	creds := credentialStringsFromResponse(credResp)
	if primary == nil || len(creds) <= 1 || len(keys) <= 1 {
		return
	}
	if w.credentialSink != nil {
		log.Printf("[VCI] Batch issued during a presentation is kept as its primary copy only")
		return
	}
	primaryIdx := proofKeyIndex(primary.Raw, keys)
	group := newCredentialID()
	w.setBatchFields(primary.ID, group, primary.BindingKeyPEM)
	primary.BatchGroup = group

	stored := 1
	for _, raw := range creds {
		idx := proofKeyIndex(raw, keys)
		// Skip the copy already imported as primary; a negative index was
		// reported by selectPrimaryCredential.
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
		stored++
	}
	log.Printf("[VCI] Stored a batch of %d copies (group %s) for one-time-use presentation", stored, group)
}

// collapseBatchMatches reduces the copies of one batch that match a query to
// the single copy that will be presented, so the wallet presents one unused
// copy per batch and the consent dialog does not list identical copies as
// alternatives. The copy is chosen by chooseBatchCopy; matches outside a batch
// pass through untouched, in order.
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

// chooseBatchCopy returns the index into matches of the batch copy to present:
// a random one among those presented the fewest times. That shows each copy
// once in a random order and then resets and cycles again, reusing the copies,
// once all have been used (EUDI ARF method C, ISSU_52).
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

// secureIntn returns a uniform random int in [0, n) using crypto/rand, so which
// batch copy is presented cannot be predicted or biased. It returns 0 on the
// degenerate n <= 1 and on the practically impossible read error.
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
// presentation of the batch prefers a copy used fewer times. It is a no-op for
// a credential that is not part of a batch.
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
	// A presentation run on a clone carries the use back to the wallet the clone
	// was made from, so the rotation still advances (auto-accept and
	// ISO-transcript presentations run on a clone).
	if bumped && sink != nil {
		sink(id)
	}
}

// setBatchFields records a copy's batch group and per-copy binding key on the
// store entry with the given id, the way rememberDisplay records a display.
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
// response, reading only the shape §8.3 defines: a credentials array whose
// "elements of the array MUST be objects", each with a credential member. A
// top-level credential string and an array of bare strings are draft shapes.
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
