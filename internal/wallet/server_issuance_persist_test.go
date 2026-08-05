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

// An issuance flow can stay open for a long time: an authorization code flow
// waits for the user to sign in at the issuer, and meanwhile every request
// reloads the wallet from the store, replacing the credential list. A reload
// landing between the import and the save used to drop the freshly issued
// credential, so issuance reported success and stored nothing.
func TestSaveIssuedCredential_SurvivesConcurrentStoreReload(t *testing.T) {
	srv := newTestServer(t, true)

	saved := 0
	srv.onSave = func() { saved++ }

	issued := StoredCredential{
		ID:     "issued-during-a-long-flow",
		Format: "dc+sd-jwt",
		VCT:    "urn:test:ticket:1",
		Raw:    "header.payload.signature",
		Claims: map[string]any{"given_name": "Alice"},
	}
	srv.wallet.RestoreCredential(issued)

	// What a reload does: the persisted state replaces the in-memory list,
	// and the credential the flow just imported is not in it yet.
	persisted := &Wallet{Credentials: []StoredCredential{}}
	srv.applyPersistedWalletState(persisted)
	if _, ok := srv.wallet.GetCredential(issued.ID); ok {
		t.Fatal("precondition failed: the reload should have dropped the credential")
	}

	srv.saveIssuedCredential(&IssuanceResult{CredentialID: issued.ID, Imported: &issued})

	if _, ok := srv.wallet.GetCredential(issued.ID); !ok {
		t.Fatal("the issued credential was lost: issuance reported success and stored nothing")
	}
	if saved != 1 {
		t.Fatalf("expected exactly one save, got %d", saved)
	}
}

// Restoring is idempotent: a credential still present must not be duplicated.
func TestSaveIssuedCredential_DoesNotDuplicate(t *testing.T) {
	srv := newTestServer(t, true)
	srv.onSave = func() {}

	issued := StoredCredential{ID: "kept", Format: "dc+sd-jwt", VCT: "urn:test:ticket:1"}
	srv.wallet.RestoreCredential(issued)
	before := len(srv.wallet.GetCredentials())

	srv.saveIssuedCredential(&IssuanceResult{CredentialID: issued.ID, Imported: &issued})

	if got := len(srv.wallet.GetCredentials()); got != before {
		t.Fatalf("credential count changed from %d to %d", before, got)
	}
}
