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

package registrar

import (
	"errors"
	"testing"
	"time"
)

func TestExpiredStatusEntriesAreFreed(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	id := rp.Identifier[0].Identifier
	use := rp.Services[0].IntendedUses[0].IntendedUseIdentifier
	w.RegistrationStatuses = []RegistrationStatus{{Index: 5, Identifier: "NTRNL-1", Expires: time.Now().Add(-time.Hour).Unix()}}
	if _, err := w.allocateRegistrationStatus(rp, certificateKey{intendedUse: use}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(w.RegistrationStatuses) != 1 || w.RegistrationStatuses[0].Identifier != id {
		t.Errorf("statuses %+v, want only the new entry", w.RegistrationStatuses)
	}
}

// Only the current certificate of an intended use is kept in the state.
func TestASupersededCertificateIsNotStored(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	issueTestRegistrationCertificate(t, w, rp)
	issueTestRegistrationCertificate(t, w, rp)
	if len(w.RegistrationStatuses) != 2 || w.RegistrationStatuses[0].Certificate != "" || w.RegistrationStatuses[1].Certificate == "" {
		t.Errorf("statuses %+v, want the certificate of the newer entry only", w.RegistrationStatuses)
	}
}

func TestAnUpdateRevokesCertificatesWhoseContentChanged(t *testing.T) {
	for name, change := range map[string]func(rp *WalletRelyingParty){
		"fewer claims": func(rp *WalletRelyingParty) {
			rp.Services[0].IntendedUses[0].Credentials[0].Claims = []RegisteredClaim{{Path: []any{"family_name"}}}
		},
		"another purpose": func(rp *WalletRelyingParty) {
			rp.Services[0].IntendedUses[0].Purpose = []MultiLangString{{Lang: "en", Content: "Marketing"}}
		},
		"another name": func(rp *WalletRelyingParty) { rp.Services[0].ServiceTradeName = "Other Shop" },
	} {
		t.Run(name, func(t *testing.T) {
			w := generateTestWallet(t)
			rp := registerTestRelyingParty(t, w)
			issueTestRegistrationCertificate(t, w, rp)
			change(&rp)
			if _, err := w.UpdateRelyingParty(rp); err != nil {
				t.Fatal(err)
			}
			if statuses := w.RegistrationCertificateStatuses(rp.Identifier[0].Identifier); len(statuses) != 1 || !statuses[0].Revoked {
				t.Errorf("statuses %+v, want the certificate revoked", statuses)
			}
		})
	}
}

func TestAnUnchangedUpdateKeepsCertificatesValid(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	issueTestRegistrationCertificate(t, w, rp)
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	if statuses := w.RegistrationCertificateStatuses(rp.Identifier[0].Identifier); len(statuses) != 1 || statuses[0].Revoked {
		t.Errorf("statuses %+v, want the certificate valid", statuses)
	}
}

func TestActivatingLeavesRemovedIntendedUsesRevoked(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	issueTestRegistrationCertificate(t, w, rp)
	rp.Services[0].IntendedUses[0].IntendedUseIdentifier = ""
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	if n, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{}, false); err != nil || n != 0 {
		t.Fatalf("activated %d (%v), want 0", n, err)
	}
}

func TestStatusesAreListedUnderEveryIdentifier(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	rp.Identifier = append(rp.Identifier, Identifier{Type: "http://data.europa.eu/eudi/id/EUID", Identifier: "DEHRB.12345"})
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	issueTestRegistrationCertificate(t, w, rp)
	if got := w.RegistrationCertificateStatuses("DEHRB.12345"); len(got) != 1 {
		t.Errorf("statuses %+v, want the certificate", got)
	}
}

// When an intended use changes, its old certificate describes outdated
// content, so Activate leaves it revoked.
func TestActivatingLeavesChangedIntendedUsesRevoked(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	issueTestRegistrationCertificate(t, w, rp)
	rp.Services[0].IntendedUses[0].Purpose = []MultiLangString{{Lang: "en", Content: "Marketing"}}
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	if n, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{}, false); err != nil || n != 0 {
		t.Fatalf("activated %d (%v), want 0", n, err)
	}
}

func TestACertificateForChangedContentIsNotIssued(t *testing.T) {
	w := generateTestWallet(t)
	snapshot := registerTestRelyingParty(t, w)
	use := snapshot.Services[0].IntendedUses[0].IntendedUseIdentifier
	changed, _ := cloneRelyingParty(snapshot)
	changed.Services[0].IntendedUses[0].Purpose = []MultiLangString{{Lang: "en", Content: "Marketing"}}
	if _, err := w.UpdateRelyingParty(changed); err != nil {
		t.Fatal(err)
	}
	if _, err := w.allocateRegistrationStatus(snapshot, certificateKey{intendedUse: use}, time.Now().Add(time.Hour)); !errors.Is(err, errRegistrationChanged) {
		t.Errorf("error %v, want the changed registration refused", err)
	}
}
