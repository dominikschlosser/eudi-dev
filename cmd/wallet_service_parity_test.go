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

package cmd

// Every management command runs against either the local store or a remote
// instance, and prints from the same document. The two backends build those
// documents in different places: the local one from the wallet in memory, the
// remote one from whatever the HTTP handler chose to put in its response. A
// field that only one of them fills is invisible until a column shows an id
// where a type belongs, which is how the deferred credential type shipped
// broken in 1.19.8: the record carried it, GET /api/deferred did not return it.
//
// These tests pin the shape rather than the values. Ids and timestamps differ
// between two wallets; the set of keys a command can read must not.

import (
	"sort"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/remote"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

// parityWallets returns the same wallet state behind both backends: one served
// over HTTP, one read from a store.
func parityWallets(t *testing.T, seed func(*wallet.Wallet)) (local walletService, remoteSvc walletService) {
	t.Helper()

	newWallet := func() *wallet.Wallet {
		holder, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		issuer, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		w := wallet.New(holder, issuer, false)
		w.AutoAccept = true
		w.TemplatesDir = t.TempDir()
		seed(w)
		return w
	}

	served := newWallet()
	srv := wallet.NewServer(served, 0, nil)
	srv.ShutdownFunc = func() {}
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatalf("starting the wallet server: %v", err)
	}

	stored := newWallet()
	store := wallet.NewWalletStore(t.TempDir())
	if err := store.Save(stored); err != nil {
		t.Fatal(err)
	}

	localSvc := &localWallet{load: func() (*wallet.Wallet, *wallet.WalletStore, error) {
		return stored, store, nil
	}}
	return localSvc, &remoteWallet{c: remote.NewClient(addr)}
}

func keysOf(doc map[string]any) []string {
	out := make([]string, 0, len(doc))
	for k, v := range doc {
		// A backend that returns the key with an empty value still lets the
		// CLI read it, so only a missing key counts as a difference.
		if v == nil {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func assertSameKeys(t *testing.T, what string, localDoc, remoteDoc map[string]any) {
	t.Helper()
	inRemote := make(map[string]bool, len(remoteDoc))
	for _, k := range keysOf(remoteDoc) {
		inRemote[k] = true
	}
	for _, k := range keysOf(localDoc) {
		if !inRemote[k] {
			t.Errorf("%s: the local backend returns %q and the remote one does not, so the same command prints differently against a remote wallet", what, k)
		}
	}
	inLocal := make(map[string]bool, len(localDoc))
	for _, k := range keysOf(localDoc) {
		inLocal[k] = true
	}
	for _, k := range keysOf(remoteDoc) {
		if !inLocal[k] {
			t.Errorf("%s: the remote backend returns %q and the local one does not", what, k)
		}
	}
}

func TestCredentialDocumentsMatchAcrossBackends(t *testing.T) {
	resetRemoteTestState(t)
	localSvc, remoteSvc := parityWallets(t, func(w *wallet.Wallet) {
		if err := w.GenerateProtectedDefaults(); err != nil {
			t.Fatal(err)
		}
	})

	localCreds, err := localSvc.Credentials()
	if err != nil {
		t.Fatalf("local credentials: %v", err)
	}
	remoteCreds, err := remoteSvc.Credentials()
	if err != nil {
		t.Fatalf("remote credentials: %v", err)
	}
	if len(localCreds) == 0 || len(localCreds) != len(remoteCreds) {
		t.Fatalf("credential counts differ: local %d, remote %d", len(localCreds), len(remoteCreds))
	}
	assertSameKeys(t, "credential list entry", localCreds[0], remoteCreds[0])

	localOne, err := localSvc.Credential(localCreds[0]["id"].(string))
	if err != nil {
		t.Fatalf("local credential: %v", err)
	}
	remoteOne, err := remoteSvc.Credential(remoteCreds[0]["id"].(string))
	if err != nil {
		t.Fatalf("remote credential: %v", err)
	}
	assertSameKeys(t, "credential detail", localOne, remoteOne)
}

// The case that shipped broken: a deferred credential names what is being
// issued, and only one backend used to say so.
func TestDeferredDocumentsMatchAcrossBackends(t *testing.T) {
	resetRemoteTestState(t)
	localSvc, remoteSvc := parityWallets(t, func(w *wallet.Wallet) {
		w.AddPendingIssuance(&wallet.PendingIssuance{
			ID:              "pending-1",
			TransactionID:   "tx-1",
			Issuer:          "https://issuer.example",
			ConfigurationID: "msisdn-sd-jwt-key-attestations",
			Format:          "dc+sd-jwt",
			VCT:             "eu.europa.ec.eudi.msisdn.1",
			IntervalSeconds: 60,
		})
	})

	localPending, err := localSvc.DeferredIssuances()
	if err != nil {
		t.Fatalf("local deferred: %v", err)
	}
	remotePending, err := remoteSvc.DeferredIssuances()
	if err != nil {
		t.Fatalf("remote deferred: %v", err)
	}
	if len(localPending) != 1 || len(remotePending) != 1 {
		t.Fatalf("deferred counts differ: local %d, remote %d", len(localPending), len(remotePending))
	}
	assertSameKeys(t, "deferred entry", localPending[0], remotePending[0])

	// The type has to reach the caller, whichever backend answered.
	for name, doc := range map[string]map[string]any{"local": localPending[0], "remote": remotePending[0]} {
		if got := doc["vct"]; got != "eu.europa.ec.eudi.msisdn.1" {
			t.Errorf("%s backend reports vct %v, so the row is labelled by the issuer's configuration id", name, got)
		}
	}
}

// The config document is the one place the two legitimately differ: a running
// server knows its port, build and listeners, a store on disk does not. What
// must hold is that nothing the local backend reports goes missing remotely.
func TestConfigDocumentsMatchAcrossBackends(t *testing.T) {
	resetRemoteTestState(t)
	localSvc, remoteSvc := parityWallets(t, func(*wallet.Wallet) {})

	localCfg, err := localSvc.Config()
	if err != nil {
		t.Fatalf("local config: %v", err)
	}
	remoteCfg, err := remoteSvc.Config()
	if err != nil {
		t.Fatalf("remote config: %v", err)
	}
	inRemote := make(map[string]bool, len(remoteCfg))
	for _, k := range keysOf(remoteCfg) {
		inRemote[k] = true
	}
	for _, k := range keysOf(localCfg) {
		if !inRemote[k] {
			t.Errorf("config document: the local backend reports %q and a remote wallet does not", k)
		}
	}
}
