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
)

// batchProofKeyCount is the number of proofs the wallet sends when the issuer
// advertises batch_credential_issuance. Two proofs are enough to exercise
// batch issuance (per-key credential copies with distinct binding keys)
// without inflating requests. The advertised batch_size still caps the count.
const batchProofKeyCount = 2

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
	count := batchProofKeyCount
	if count > batchSize {
		count = batchSize
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
// audience, nonce, and extra header members (e.g. a key_attestation covering
// every proof key).
func createProofJWTs(keys []*ecdsa.PrivateKey, audience, cNonce string, extraHeader map[string]any) ([]string, error) {
	proofs := make([]string, 0, len(keys))
	for _, key := range keys {
		proof, err := createProofJWT(key, audience, cNonce, extraHeader)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, proof)
	}
	return proofs, nil
}

// selectHolderBoundCredential picks the credential from a credential response
// that is bound to the wallet's holder key (keys[0]). OID4VCI 1.0 defines no
// correspondence between the order of the credentials array and the proofs in
// the request, so the binding key is identified from each credential itself.
// Every returned credential must be bound to one of the proof keys.
func selectHolderBoundCredential(credResp map[string]any, keys []*ecdsa.PrivateKey) (string, error) {
	creds := credentialStringsFromResponse(credResp)
	if len(creds) == 0 {
		return "", fmt.Errorf("no credential in response")
	}
	if len(keys) <= 1 && len(creds) == 1 {
		return creds[0], nil
	}

	holderCredential := ""
	matched := make([]int, len(keys))
	for _, raw := range creds {
		keyIndex := -1
		for i, key := range keys {
			if credentialBindsToKey(raw, &key.PublicKey) {
				keyIndex = i
				break
			}
		}
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
	if holderCredential == "" {
		return "", fmt.Errorf("credential response contains no credential bound to the wallet's holder key")
	}
	log.Printf("[VCI] Matched %d batch credential(s) to their proof keys; importing the holder-key-bound credential", len(creds))
	return holderCredential, nil
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
