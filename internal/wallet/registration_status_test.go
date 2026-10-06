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
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// registrarServer serves the registrar, so registration certificates point at a
// status list the test can fetch.
func registrarServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	srv := newTestServer(t, true)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	srv.wallet.IssuerURL = ts.URL
	return srv, ts
}

func issuedCertificate(t *testing.T, w *Wallet, rp WalletRelyingParty) map[string]any {
	t.Helper()
	certs, _ := verifiedRegistrationCertificates(map[string]any{"verifier_info": issueTestRegistrationCertificate(t, w, rp).VerifierInfo})
	return certs[0]
}

func TestARegistrationCertificateCarriesItsStatus(t *testing.T) {
	srv, ts := registrarServer(t)
	cert := issuedCertificate(t, srv.wallet, registerTestRelyingParty(t, srv.wallet))
	if got := registrationCertificateContentFindings(cert); len(got) != 0 {
		t.Errorf("content findings %v, want none", got)
	}
	if got := registrationStatusFindings(cert, ts.Client()); len(got) != 0 {
		t.Fatalf("status findings %v, want a valid status", got)
	}
}

func TestRevokingARegistrationCertificate(t *testing.T) {
	for name, revoke := range map[string]func(t *testing.T, w *Wallet, rp WalletRelyingParty){
		"revoke the intended use": func(t *testing.T, w *Wallet, rp WalletRelyingParty) {
			if n, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier}, true); err != nil || n != 1 {
				t.Fatalf("revoked %d (%v), want 1", n, err)
			}
		},
		"delete the relying party": func(t *testing.T, w *Wallet, rp WalletRelyingParty) {
			if err := w.DeleteRelyingParty(rp.Identifier[0].Identifier); err != nil {
				t.Fatal(err)
			}
		},
		"update without the intended use": func(t *testing.T, w *Wallet, rp WalletRelyingParty) {
			rp.Services[0].IntendedUses[0].IntendedUseIdentifier = ""
			if _, err := w.UpdateRelyingParty(rp, w.RegistrarBase()); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv, ts := registrarServer(t)
			rp := registerTestRelyingParty(t, srv.wallet)
			cert := issuedCertificate(t, srv.wallet, rp)
			revoke(t, srv.wallet, rp)
			if got := registrationStatusFindings(cert, ts.Client()); len(got) != 1 || !strings.Contains(got[0], "revoked") {
				t.Fatalf("status findings %v, want the revocation", got)
			}
		})
	}
}

// A status the wallet cannot read is a finding, since the wallet cannot verify
// that the certificate is not revoked.
func TestAnUnreachableStatusListIsAFinding(t *testing.T) {
	srv, ts := registrarServer(t)
	cert := issuedCertificate(t, srv.wallet, registerTestRelyingParty(t, srv.wallet))
	ts.Close()
	if got := registrationStatusFindings(cert, ts.Client()); len(got) != 1 || !strings.Contains(got[0], "cannot be checked") {
		t.Errorf("status findings %v, want one unknown status", got)
	}
}

func TestRegistrationStatusesAreStored(t *testing.T) {
	for name, open := range map[string]func(t *testing.T) *WalletStore{
		"file":   func(t *testing.T) *WalletStore { return NewWalletStore(t.TempDir()) },
		"entity": func(t *testing.T) *WalletStore { store, _ := entityStore(t); return store },
	} {
		t.Run(name, func(t *testing.T) {
			store := open(t)
			w, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			rp := registerTestRelyingParty(t, w)
			issueTestRegistrationCertificate(t, w, rp)
			if err := w.DeleteRelyingParty(rp.Identifier[0].Identifier); err != nil {
				t.Fatal(err)
			}
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if len(reloaded.RegistrationStatuses) != 1 || !reloaded.RegistrationStatuses[0].Revoked {
				t.Fatalf("statuses %+v, want the revoked certificate", reloaded.RegistrationStatuses)
			}
		})
	}
}

func TestAReactivatedRegistrationCertificateIsValid(t *testing.T) {
	srv, ts := registrarServer(t)
	rp := registerTestRelyingParty(t, srv.wallet)
	cert := issuedCertificate(t, srv.wallet, rp)
	use := rp.Services[0].IntendedUses[0].IntendedUseIdentifier
	if _, err := srv.wallet.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{IntendedUseIdentifier: use}, true); err != nil {
		t.Fatal(err)
	}
	if n, err := srv.wallet.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{IntendedUseIdentifier: use}, false); err != nil || n != 1 {
		t.Fatalf("reactivated %d (%v), want 1", n, err)
	}
	if got := registrationStatusFindings(cert, ts.Client()); len(got) != 0 {
		t.Errorf("status findings %v, want a valid status", got)
	}
	if statuses := srv.wallet.RegistrationCertificateStatuses(rp.Identifier[0].Identifier); len(statuses) != 1 || statuses[0].Revoked {
		t.Errorf("statuses %+v, want one active certificate", statuses)
	}
}

// Reloading wallet state that another process saved replaces the server's
// registrar state.
func TestAReloadTakesTheStoredRegistrar(t *testing.T) {
	srv := newTestServer(t, true)
	stored := generateTestWallet(t)
	rp := registerTestRelyingParty(t, stored)
	issueTestRegistrationCertificate(t, stored, rp)
	srv.applyPersistedWalletState(stored)
	if _, ok := srv.wallet.RelyingParty(rp.Identifier[0].Identifier); !ok || len(srv.wallet.RegistrationCertificateStatuses("")) != 1 {
		t.Errorf("after the reload the server holds %d parties and %d statuses, want the stored ones",
			len(srv.wallet.RegisteredRelyingParties()), len(srv.wallet.RegistrationCertificateStatuses("")))
	}
}

func TestADemoResetClearsTheRegistrar(t *testing.T) {
	w := generateTestWallet(t)
	issueTestRegistrationCertificate(t, w, registerTestRelyingParty(t, w))
	w.ResetToBaseline()
	if len(w.RegisteredRelyingParties()) != 0 || len(w.RegistrationCertificateStatuses("")) != 0 {
		t.Errorf("after the reset %d parties and %d statuses remain", len(w.RegisteredRelyingParties()), len(w.RegistrationCertificateStatuses("")))
	}
}

// The wallet reads its own registrar's status list without a network round
// trip, whatever form the URL takes.
func TestTheWalletReadsItsOwnStatusListInProcess(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://Wallet.Example:443"
	rp := registerTestRelyingParty(t, w)
	cert := issuedCertificate(t, w, rp)
	if got := registrationStatusFindings(cert, w.RegistrationStatusClient()); len(got) != 0 {
		t.Fatalf("status findings %v, want the in-process list to answer", got)
	}
	for _, raw := range []string{"https://wallet.example/api/registrar/status-list", "HTTPS://WALLET.EXAMPLE:443/api/registrar/status-list/"} {
		u, _ := url.Parse(raw)
		if !sameURL(u, w.RegistrationStatusListURL()) {
			t.Errorf("%s does not match %s", raw, w.RegistrationStatusListURL())
		}
	}
}

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

// A presentation runs on a copy of the wallet. The copy keeps the relying
// party CAs, so --relying-party-ca applies to every request.
func TestThePresentationCopyKeepsTheRelyingPartyCAs(t *testing.T) {
	w := generateTestWallet(t)
	w.RequireARF = true
	w.RelyingPartyCAPEM = []byte("-----BEGIN CERTIFICATE-----\n")
	clone, err := cloneWalletForPresentation(w, presentationRequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(clone.RelyingPartyCAPEM) != string(w.RelyingPartyCAPEM) || !clone.ARFChecks() {
		t.Error("the presentation copy dropped the ARF settings")
	}
}

// An auto-accepted presentation runs on a copy of the wallet. The copy answers
// the registrar's status list in process, so it sees revocations.
func TestThePresentationCopySeesRevokedRegistrationCertificates(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	cert := issuedCertificate(t, w, rp)
	if _, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{}, true); err != nil {
		t.Fatal(err)
	}
	clone, err := cloneWalletForPresentation(w, presentationRequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := registrationStatusFindings(cert, clone.RegistrationStatusClient()); len(got) != 1 || !strings.Contains(got[0], "revoked") {
		t.Errorf("status findings %v, want the revocation", got)
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
			if _, err := w.UpdateRelyingParty(rp, w.RegistrarBase()); err != nil {
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
	if _, err := w.UpdateRelyingParty(rp, w.RegistrarBase()); err != nil {
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
	if _, err := w.UpdateRelyingParty(rp, w.RegistrarBase()); err != nil {
		t.Fatal(err)
	}
	if n, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{}, false); err != nil || n != 0 {
		t.Fatalf("activated %d (%v), want 0", n, err)
	}
}

// A new certificate replaces the old one, so an intended use has one valid
// certificate at a time. Activate doesn't bring a replaced one back.
func TestANewCertificateReplacesTheOldOne(t *testing.T) {
	srv, ts := registrarServer(t)
	w := srv.wallet
	rp := registerTestRelyingParty(t, w)
	id := rp.Identifier[0].Identifier
	old := issuedCertificate(t, w, rp)
	current := issuedCertificate(t, w, rp)
	if got := registrationStatusFindings(old, ts.Client()); len(got) != 1 || !strings.Contains(got[0], "revoked") {
		t.Fatalf("status findings %v, want the replaced certificate revoked", got)
	}
	if got := registrationStatusFindings(current, ts.Client()); len(got) != 0 {
		t.Fatalf("status findings %v, want the new certificate valid", got)
	}
	if _, err := w.SetRegistrationCertificatesRevoked(id, RegistrationScope{}, true); err != nil {
		t.Fatal(err)
	}
	if n, err := w.SetRegistrationCertificatesRevoked(id, RegistrationScope{}, false); err != nil || n != 1 {
		t.Fatalf("activated %d (%v), want only the current certificate", n, err)
	}
	if got := registrationStatusFindings(old, ts.Client()); len(got) != 1 {
		t.Errorf("status findings %v, want the replaced certificate still revoked", got)
	}
}

func TestStatusesAreListedUnderEveryIdentifier(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	rp.Identifier = append(rp.Identifier, Identifier{Type: "http://data.europa.eu/eudi/id/EUID", Identifier: "DEHRB.12345"})
	if _, err := w.UpdateRelyingParty(rp, w.RegistrarBase()); err != nil {
		t.Fatal(err)
	}
	issueTestRegistrationCertificate(t, w, rp)
	if got := w.RegistrationCertificateStatuses("DEHRB.12345"); len(got) != 1 {
		t.Errorf("statuses %+v, want the certificate", got)
	}
}

// When an intended use changes, its old certificate describes content that is
// not registered any more, so Activate leaves it revoked.
func TestActivatingLeavesChangedIntendedUsesRevoked(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	issueTestRegistrationCertificate(t, w, rp)
	rp.Services[0].IntendedUses[0].Purpose = []MultiLangString{{Lang: "en", Content: "Marketing"}}
	if _, err := w.UpdateRelyingParty(rp, w.RegistrarBase()); err != nil {
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
	if _, err := w.UpdateRelyingParty(changed, w.RegistrarBase()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.allocateRegistrationStatus(snapshot, certificateKey{intendedUse: use}, time.Now().Add(time.Hour)); !errors.Is(err, errRegistrationChanged) {
		t.Errorf("error %v, want the changed registration refused", err)
	}
}
