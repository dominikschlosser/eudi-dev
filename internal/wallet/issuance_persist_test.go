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

import "testing"

// A conformance override (which the public demo always carries) runs the offer
// flow on a per-request wallet clone. The imported credential must still be
// persisted to the wallet the server serves and reloads, not left on the clone.
// Otherwise issuance reports success and the credential disappears, which is
// what happened on the demo: a poll reloading the store from disk dropped the
// not-yet-saved credential before the flow saved it.
func TestSaveIssuedCredentialPersistsFromRequestClone(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	srv := NewServer(w, 0, func() {
		if err := store.Save(w); err != nil {
			t.Fatalf("save: %v", err)
		}
	})
	srv.SetStore(store)

	reqWallet, err := cloneWalletForPresentation(w, presentationRequestOptions{ValidationMode: "debug"})
	if err != nil {
		t.Fatalf("cloneWalletForPresentation: %v", err)
	}
	clone := srv.cloneWithWallet(reqWallet)

	cred := StoredCredential{
		ID:      "cred-1",
		Format:  "mso_mdoc",
		DocType: "eu.europa.ec.eudi.taxid.1",
		Raw:     "deadbeef",
		Claims:  map[string]any{"tax_number": "06958170437"},
	}
	// The offer flow imported it into the clone. A concurrent request has since
	// reloaded w from disk (still empty), so w no longer holds it.
	reqWallet.RestoreCredential(cred)

	clone.saveIssuedCredential(&IssuanceResult{Imported: &cred})

	reloaded, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, c := range reloaded.Credentials {
		if c.ID == cred.ID {
			return // persisted, as it must be
		}
	}
	t.Fatal("issued credential was lost: saving from a request clone did not persist it to the served wallet")
}
