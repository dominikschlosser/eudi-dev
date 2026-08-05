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
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
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
	servedStore := wallet.NewWalletStore(t.TempDir())
	if err := servedStore.Save(served); err != nil {
		t.Fatal(err)
	}
	// A store without a save hook is a trap: withFreshStore reloads from the
	// store on every request while triggerSave only calls onSave, so writes
	// would be dropped by the next reload.
	srv := wallet.NewServer(served, 0, func() {
		if err := servedStore.Save(served); err != nil {
			t.Errorf("saving the served wallet: %v", err)
		}
	})
	srv.SetStore(servedStore)
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

// The table compares document shapes. This pins the one value that shipped
// wrong: a deferred credential has to name what is being issued, not the
// issuer's internal configuration id.
func TestDeferredDocumentsCarryTheCredentialType(t *testing.T) {
	resetRemoteTestState(t)
	localSvc, remoteSvc := parityWallets(t, func(w *wallet.Wallet) {
		w.AddPendingIssuance(&wallet.PendingIssuance{
			ID: "pending-1", TransactionID: "tx-1", Issuer: "https://issuer.example",
			ConfigurationID: "msisdn-sd-jwt-key-attestations", Format: "dc+sd-jwt",
			VCT: "eu.europa.ec.eudi.msisdn.1", IntervalSeconds: 60,
		})
	})

	for name, svc := range map[string]walletService{"local": localSvc, "remote": remoteSvc} {
		docs, err := svc.DeferredIssuances()
		if err != nil {
			t.Fatalf("%s deferred: %v", name, err)
		}
		if len(docs) != 1 {
			t.Fatalf("%s backend returned %d deferred records, want 1", name, len(docs))
		}
		if got := docs[0]["vct"]; got != "eu.europa.ec.eudi.msisdn.1" {
			t.Errorf("%s backend reports vct %v, so the row is labelled by the issuer's configuration id", name, got)
		}
	}
}

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

// --- every method, checked ---

// parityCase observes one walletService method through a backend and reduces
// the result to something comparable: document keys, a count, a normalized
// value. Two backends return different ids, paths and timestamps; what a
// caller can read from them must not differ.
//
// Cases seed through the service rather than the filesystem. The two backends
// resolve their state differently (the local template store comes from a
// global, the remote one from the server), and a test that reaches around
// that would be testing its own plumbing.
type parityCase struct {
	method  string
	observe func(t *testing.T, svc walletService) any
	skip    string
}

// importedCredential puts one deletable credential in the wallet and returns
// its id. The PID baseline is protected and refuses deletion on both backends.
func importedCredential(t *testing.T, s walletService) string {
	t.Helper()
	docs, err := s.Credentials()
	if err != nil || len(docs) == 0 {
		t.Fatalf("listing credentials: %v", err)
	}
	full, err := s.Credential(docs[0]["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := full["raw"].(string)
	if raw == "" {
		t.Fatal("no raw credential to import")
	}
	imported, err := s.ImportCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := imported["id"].(string)
	if id == "" {
		t.Fatalf("import returned no id: %v", imported)
	}
	return id
}

func saveParityTemplate(t *testing.T, s walletService) {
	t.Helper()
	if _, err := s.SaveTemplate(credtemplate.Template{
		Name: "parity", Format: "sdjwt", VCT: "urn:test:parity:1",
		Claims: map[string]any{"given_name": "Alice"},
	}); err != nil {
		t.Fatal(err)
	}
}

func parityCases() []parityCase {
	return []parityCase{
		{method: "URL", skip: "the local store has no URL by definition, which is what distinguishes the backends"},
		{method: "Config", skip: "a running server knows its port, build and listeners and a store on disk does not; TestConfigDocumentsMatchAcrossBackends pins the direction that must hold"},

		{method: "Credentials", observe: func(t *testing.T, s walletService) any {
			docs, err := s.Credentials()
			if err != nil {
				t.Fatal(err)
			}
			return docKeys(t, docs)
		}},
		{method: "Credential", observe: func(t *testing.T, s walletService) any {
			docs, err := s.Credentials()
			if err != nil || len(docs) == 0 {
				t.Fatalf("listing credentials: %v", err)
			}
			doc, err := s.Credential(docs[0]["id"].(string))
			if err != nil {
				t.Fatal(err)
			}
			return keysOf(doc)
		}},
		{method: "DeferredIssuances", observe: func(t *testing.T, s walletService) any {
			docs, err := s.DeferredIssuances()
			if err != nil {
				t.Fatal(err)
			}
			return docKeys(t, docs)
		}},
		{method: "ImportCredential", observe: func(t *testing.T, s walletService) any {
			docs, err := s.Credentials()
			if err != nil || len(docs) == 0 {
				t.Fatalf("listing credentials: %v", err)
			}
			full, err := s.Credential(docs[0]["id"].(string))
			if err != nil {
				t.Fatal(err)
			}
			imported, err := s.ImportCredential(full["raw"].(string))
			if err != nil {
				t.Fatal(err)
			}
			return keysOf(imported)
		}},
		{method: "RefreshCredential", skip: "renewing needs a live issuer to exchange a refresh token with; internal/wallet covers the operation against a stub"},
		{method: "RemoveCredential", observe: func(t *testing.T, s walletService) any {
			id := importedCredential(t, s)
			before, err := s.Credentials()
			if err != nil {
				t.Fatal(err)
			}
			if err := s.RemoveCredential(id); err != nil {
				t.Fatal(err)
			}
			after, err := s.Credentials()
			if err != nil {
				t.Fatal(err)
			}
			return len(before) - len(after)
		}},
		{method: "RemoveAllCredentials", observe: func(t *testing.T, s walletService) any {
			importedCredential(t, s)
			deleted, err := s.RemoveAllCredentials()
			if err != nil {
				t.Fatal(err)
			}
			left, err := s.Credentials()
			if err != nil {
				t.Fatal(err)
			}
			return []int{deleted, len(left)}
		}},
		{method: "Issue", observe: func(t *testing.T, s walletService) any {
			doc, err := s.Issue(map[string]any{
				"format": "sdjwt", "vct": "urn:test:parity:1",
				"claims": map[string]any{"given_name": "Alice"}, "wallet": true,
			})
			if err != nil {
				t.Fatal(err)
			}
			return keysOf(doc)
		}},
		{method: "Logs", observe: func(t *testing.T, s walletService) any {
			entries, err := s.Logs()
			if err != nil {
				t.Fatal(err)
			}
			// Typed on both sides, so the compiler fixes the shape. What can
			// differ is whether a backend reports anything at all.
			return len(entries) > 0
		}},
		{method: "SaveTemplate", observe: func(t *testing.T, s walletService) any {
			saveParityTemplate(t, s)
			tpl, err := s.Template("parity")
			if err != nil {
				t.Fatal(err)
			}
			// The returned path is documented to differ: only a store has one.
			return []string{tpl.Name, tpl.Format, tpl.VCT}
		}},
		{method: "Templates", observe: func(t *testing.T, s walletService) any {
			saveParityTemplate(t, s)
			templates, err := s.Templates()
			if err != nil {
				t.Fatal(err)
			}
			for _, tpl := range templates {
				if tpl.Name == "parity" {
					return tpl.VCT
				}
			}
			t.Fatalf("the saved template is missing from %d templates", len(templates))
			return nil
		}},
		{method: "Template", observe: func(t *testing.T, s walletService) any {
			saveParityTemplate(t, s)
			tpl, err := s.Template("parity")
			if err != nil {
				t.Fatal(err)
			}
			return []string{tpl.Name, tpl.Format, tpl.VCT}
		}},
		{method: "DeleteTemplate", observe: func(t *testing.T, s walletService) any {
			saveParityTemplate(t, s)
			if err := s.DeleteTemplate("parity"); err != nil {
				t.Fatal(err)
			}
			_, err := s.Template("parity")
			return err != nil
		}},
		{method: "Certificate", observe: func(t *testing.T, s walletService) any {
			pem, err := s.Certificate("ca", "pem", walletCertOptions{port: 8085})
			if err != nil {
				t.Fatal(err)
			}
			return strings.HasPrefix(string(pem), "-----BEGIN CERTIFICATE-----")
		}},
	}
}

// Adding a walletService method without a parity case fails here, so the
// duality cannot quietly grow another un-mirrored path.
func TestEveryWalletServiceMethodHasAParityCase(t *testing.T) {
	covered := make(map[string]bool)
	for _, c := range parityCases() {
		covered[c.method] = true
	}
	iface := reflect.TypeOf((*walletService)(nil)).Elem()
	for i := range iface.NumMethod() {
		if name := iface.Method(i).Name; !covered[name] {
			t.Errorf("walletService.%s has no parity case: a command using it can behave differently against a local store and a remote instance", name)
		}
	}
}

func TestWalletServiceBackendsAgree(t *testing.T) {
	for _, c := range parityCases() {
		if c.skip != "" {
			t.Run(c.method, func(t *testing.T) { t.Skip(c.skip) })
			continue
		}
		t.Run(c.method, func(t *testing.T) {
			resetRemoteTestState(t)
			localSvc, remoteSvc := parityWallets(t, seedPID)

			localObs := c.observe(t, localSvc)
			remoteObs := c.observe(t, remoteSvc)
			if !reflect.DeepEqual(localObs, remoteObs) {
				t.Errorf("%s differs between backends:\n  local:  %v\n  remote: %v", c.method, localObs, remoteObs)
			}
		})
	}
}

func docKeys(t *testing.T, docs []map[string]any) any {
	t.Helper()
	if len(docs) == 0 {
		return []string{}
	}
	return keysOf(docs[0])
}

func seedPID(w *wallet.Wallet) {
	if err := w.GenerateProtectedDefaults(); err != nil {
		panic(err)
	}
}
