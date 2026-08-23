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
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

const testBatchVCT = "urn:example:batch-pid"

// storeTestBatch generates a batch of SD-JWT copies of one credential, each
// bound to one of keys (keys[0] must be the wallet holder key), and stores them
// the way an issuance does: the holder copy imported, the rest tied to it.
func storeTestBatch(t *testing.T, w *Wallet, keys []*ecdsa.PrivateKey) {
	t.Helper()
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	credEntries := make([]any, 0, len(keys))
	var holderRaw string
	for i, k := range keys {
		raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
			Issuer:    "https://issuer.example",
			VCT:       testBatchVCT,
			Claims:    map[string]any{"family_name": "Doe", "given_name": "Jane"},
			Key:       issuerKey,
			HolderKey: &k.PublicKey,
		})
		if err != nil {
			t.Fatalf("generating batch copy %d: %v", i, err)
		}
		credEntries = append(credEntries, map[string]any{"credential": raw})
		if i == 0 {
			holderRaw = raw
		}
	}
	primary, err := w.ImportCredential(holderRaw)
	if err != nil {
		t.Fatalf("importing the holder copy: %v", err)
	}
	w.storeBatchSiblings(primary, map[string]any{"credentials": credEntries}, keys, nil)
}

func batchTestQuery() map[string]any {
	return map[string]any{"credentials": []any{map[string]any{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{testBatchVCT}},
		"claims": []any{map[string]any{"path": []any{"family_name"}}},
	}}}
}

func TestBatchSigningKeyPrefersCopyKey(t *testing.T) {
	w := generateTestWallet(t)

	holderSigned, err := w.batchSigningKey(StoredCredential{})
	if err != nil {
		t.Fatalf("batchSigningKey for a plain credential: %v", err)
	}
	if holderSigned != w.HolderKey {
		t.Fatal("a credential with no binding key must present with the wallet holder key")
	}

	copyKey := testKey(t)
	pem, err := encodeECPrivateKeyPEM(copyKey)
	if err != nil {
		t.Fatalf("encoding the copy key: %v", err)
	}
	got, err := w.batchSigningKey(StoredCredential{BindingKeyPEM: pem})
	if err != nil {
		t.Fatalf("batchSigningKey for a batch copy: %v", err)
	}
	if !got.PublicKey.Equal(&copyKey.PublicKey) {
		t.Fatal("a batch copy must present with its own binding key")
	}
}

func TestStoreBatchSiblingsStoresEveryCopy(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)

	creds := w.GetCredentials()
	if len(creds) != len(keys) {
		t.Fatalf("expected %d stored copies, got %d", len(keys), len(creds))
	}
	group := creds[0].BatchGroup
	if group == "" {
		t.Fatal("the batch copies must carry a batch group")
	}
	holderCopies, keyedCopies := 0, 0
	for i := range creds {
		c := creds[i]
		if c.BatchGroup != group {
			t.Fatalf("copy %s carries a different batch group", c.ID)
		}
		if c.BindingKeyPEM == "" {
			holderCopies++
		} else {
			keyedCopies++
		}
		if w.keyBindingNotHeld(&c) {
			t.Fatalf("batch copy %s reads as not presentable, but its key is held", c.ID)
		}
	}
	if holderCopies != 1 {
		t.Fatalf("expected exactly one holder-key copy, got %d", holderCopies)
	}
	if keyedCopies != len(keys)-1 {
		t.Fatalf("expected %d copies bound to their own key, got %d", len(keys)-1, keyedCopies)
	}
}

func TestBatchPresentsEachCopyOnceThenReuses(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)

	// The key each stored copy signs with, to check the KB-JWT signer.
	pubByID := make(map[string]*ecdsa.PublicKey)
	for _, c := range w.GetCredentials() {
		sk, err := w.batchSigningKey(c)
		if err != nil {
			t.Fatalf("resolving the signing key of %s: %v", c.ID, err)
		}
		pubByID[c.ID] = &sk.PublicKey
	}

	query := batchTestQuery()
	params := PresentationParams{Nonce: "n", ClientID: "https://verifier.example"}

	presentedOnce := make(map[string]int)
	for round := 0; round < len(keys); round++ {
		matches := w.EvaluateDCQL(query)
		if len(matches) != 1 {
			t.Fatalf("round %d: a batch must read as one match, got %d", round, len(matches))
		}
		id := matches[0].CredentialID
		presentedOnce[id]++

		result, err := w.CreateVPTokenMap(matches, params)
		if err != nil {
			t.Fatalf("round %d: creating the presentation: %v", round, err)
		}
		token := result.TokenMap["pid"]
		kbJWT := token[strings.LastIndex(token, "~")+1:]
		if _, err := jws.Verify(kbJWT, pubByID[id]); err != nil {
			t.Fatalf("round %d: the KB-JWT is not signed by the presented copy's key: %v", round, err)
		}
	}

	if len(presentedOnce) != len(keys) {
		t.Fatalf("a full cycle must present each of %d copies once, saw %d distinct", len(keys), len(presentedOnce))
	}
	for id, n := range presentedOnce {
		if n != 1 {
			t.Fatalf("copy %s was presented %d times before the batch cycled", id, n)
		}
	}

	// Every copy has now been used, so the batch reuses one instead of failing.
	matches := w.EvaluateDCQL(query)
	if len(matches) != 1 {
		t.Fatalf("after exhaustion a batch still presents one copy, got %d", len(matches))
	}
	if _, err := w.CreateVPTokenMap(matches, params); err != nil {
		t.Fatalf("presenting an exhausted batch must reuse a copy, not fail: %v", err)
	}
	highest := 0
	for _, c := range w.GetCredentials() {
		if c.Uses > highest {
			highest = c.Uses
		}
	}
	if highest != 2 {
		t.Fatalf("the reused copy should be on its second use, got a highest use count of %d", highest)
	}
}
