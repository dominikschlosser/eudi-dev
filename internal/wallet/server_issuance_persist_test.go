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

// The reload race also wiped the status entry adopted at import for a
// credential on this wallet's own status list (the demo issuer's ticket is the
// common case). The credential was put back, its entry was not, so the UI
// showed "External status" on a list this wallet serves and nothing could
// revoke the credential.
func TestSaveIssuedCredential_KeepsTheAdoptedStatusEntry(t *testing.T) {
	srv := newTestServer(t, true)
	srv.onSave = func() {}
	srv.wallet.BaseURL = "https://wallet.example"

	issued := StoredCredential{
		ID:     "ticket-with-own-status",
		Format: "dc+sd-jwt",
		VCT:    "urn:test:ticket:1",
		Raw:    "header.payload.signature",
		Claims: map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{
					"uri": srv.wallet.StatusListURL(),
					"idx": 22,
				},
			},
		},
	}
	// What the import did: stored the credential and adopted its entry.
	srv.wallet.RestoreCredential(issued)
	srv.wallet.adoptOwnStatusEntry(&issued)
	if _, ok := srv.wallet.StatusEntryFor(issued.ID); !ok {
		t.Fatal("precondition failed: the import should have adopted the status entry")
	}

	// A concurrent reload lands between the import and the save.
	srv.applyPersistedWalletState(&Wallet{Credentials: []StoredCredential{}})
	if _, ok := srv.wallet.StatusEntryFor(issued.ID); ok {
		t.Fatal("precondition failed: the reload should have wiped the status entry")
	}

	srv.saveIssuedCredential(&IssuanceResult{CredentialID: issued.ID, Imported: &issued})

	entry, ok := srv.wallet.StatusEntryFor(issued.ID)
	if !ok {
		t.Fatal("the adopted status entry was lost: the credential shows as externally governed")
	}
	if entry.Index != 22 {
		t.Fatalf("status entry index = %d, want the credential's own idx 22", entry.Index)
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
