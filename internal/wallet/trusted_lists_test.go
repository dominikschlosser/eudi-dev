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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustlist"
)

// The anchors of the --arf checks come from the wallet's lists of access
// certificate providers and registration certificate providers (ETSI TS 119
// 602 V1.1.1 Annexes F and G). The wallet CA anchors neither.
func TestTheARFAnchorsComeFromTheWalletsLists(t *testing.T) {
	w := generateTestWallet(t)
	_, accessCA, err := w.RelyingPartyAccessCA()
	if err != nil {
		t.Fatal(err)
	}
	_, registrarCA, err := w.RegistrarCA()
	if err != nil {
		t.Fatal(err)
	}
	walletCA := w.TrustAnchorCertificate()
	contains := func(certs []*x509.Certificate, cert *x509.Certificate) bool {
		return slices.ContainsFunc(certs, cert.Equal)
	}
	if got := w.RelyingPartyCAs(); !contains(got, accessCA) || contains(got, walletCA) {
		t.Errorf("access anchors %d, want the relying party access CA and not the wallet CA", len(got))
	}
	if got := w.RegistrarCAs(); !contains(got, registrarCA) || contains(got, walletCA) || contains(got, accessCA) {
		t.Errorf("registrar anchors %d, want the registrar CA only", len(got))
	}
	if got := w.RegistrationStatusCAs(); !contains(got, registrarCA) {
		t.Errorf("status anchors %d, want the registrar CA", len(got))
	}
}

// A CA put on the PID list anchors the PIDs of that issuer (ARF ISSU_07).
func TestAnAddedIssuerCAAnchorsItsPIDs(t *testing.T) {
	foreign := generateTestWalletWithPID(t)
	pid := foreign.GetCredentials()[0]
	w := generateTestWallet(t)
	w.RequireARF = true
	if findings := w.trustAnchorFindings(receivedCredential(pid.Raw)); !containsSubstring(findings, "ISSU_07") {
		t.Fatalf("findings %v, want ISSU_07 for a foreign PID", findings)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.TrustAnchorCertificate().Raw}))
	if _, err := w.AddTrustedEntity(credtemplate.CategoryPID, "Foreign PID Provider", caPEM); err != nil {
		t.Fatal(err)
	}
	if findings := w.trustAnchorFindings(receivedCredential(pid.Raw)); len(findings) != 0 {
		t.Errorf("findings %v, want none with the issuer CA on the PID list", findings)
	}
}

// An external PID list on the list of trusted lists anchors its providers,
// once its signer chains to a trusted list operator (ARF ISSU_07, TLPub_07).
func TestAnExternalPIDListAnchorsItsProviders(t *testing.T) {
	foreign := generateTestWalletWithPID(t)
	foreign.IssuerURL = "https://foreign.example"
	pid := foreign.GetCredentials()[0]
	list, err := GenerateTrustListJWTForWalletGroup(foreign, foreign.IssuerURL, DefaultTrustListGroupForWallet(foreign), "/api/trustlists/pid")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(list)) }))
	t.Cleanup(srv.Close)

	w := generateTestWallet(t)
	w.RequireARF = true
	if _, err := w.AddTrustedList(srv.URL); err != nil {
		t.Fatal(err)
	}
	if findings := w.trustAnchorFindings(receivedCredential(pid.Raw)); !containsSubstring(findings, "ISSU_07") {
		t.Errorf("findings %v, want ISSU_07 while the list operator is unknown", findings)
	}
	w.TrustListCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.TrustAnchorCertificate().Raw})
	if findings := w.trustAnchorFindings(receivedCredential(pid.Raw)); len(findings) != 0 {
		t.Errorf("findings %v, want none with a trusted list operator", findings)
	}
}

// Only issuance services that are not withdrawn anchor a credential (ETSI TS
// 119 602 V1.1.1 Table H.3).
func TestOnlyCurrentIssuanceServicesAreAnchors(t *testing.T) {
	cert := func(name string) trustlist.CertInfo { return trustlist.CertInfo{Subject: name} }
	list := &trustlist.TrustList{Entities: []trustlist.TrustedEntity{{Services: []trustlist.TrustedService{
		{ServiceType: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance", ServiceStatus: pubEAANotifiedStatus, Certificates: []trustlist.CertInfo{cert("notified")}},
		{ServiceType: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance", ServiceStatus: "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn", Certificates: []trustlist.CertInfo{cert("withdrawn")}},
		{ServiceType: "http://uri.etsi.org/19602/SvcType/PubEAA/Revocation", Certificates: []trustlist.CertInfo{cert("revocation")}},
	}}}}
	if got := trustlist.ServiceCertificates(list, trustlist.IssuanceServices); len(got) != 1 || got[0].Subject != "notified" {
		t.Errorf("anchors %+v, want the notified issuance service", got)
	}
}

// The list of trusted lists points to all of the wallet's lists, with each
// list's type and signer certificate (ETSI TS 119 602 V1.1.1 §6.3.13).
func TestTheListOfTrustedListsPointsToEveryList(t *testing.T) {
	foreign := generateTestWallet(t)
	external, err := GenerateTrustListJWTForWalletGroup(foreign, "https://foreign.example", DefaultTrustListGroupForWallet(foreign), "/api/trustlists/pid")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(external)) }))
	t.Cleanup(srv.Close)
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	w.ConfiguredTrustedListURLs = []string{srv.URL}
	w.TrustListCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.TrustAnchorCertificate().Raw})

	raw, err := GenerateListOfTrustedLists(w, w.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyTrustListSigner(raw, w.TrustListCAs()); err != nil {
		t.Fatal(err)
	}
	list, err := trustlist.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if list.SchemeInfo.LoTEType != listOfTrustedListsType {
		t.Errorf("type %q, want %q", list.SchemeInfo.LoTEType, listOfTrustedListsType)
	}
	types := map[string]string{}
	for _, p := range list.SchemeInfo.Pointers {
		types[p.Location] = p.LoTEType
		if len(p.Certificates) != 1 || p.SchemeOperatorName == "" || p.SchemeTerritory == "" {
			t.Errorf("pointer %+v, want one signer certificate, the operator name and the territory", p)
		}
	}
	for location, want := range map[string]string{
		"https://wallet.example/api/trustlists/pid":       pidTrustListType,
		"https://wallet.example/api/trustlists/access-ca": accessCAListType,
		"https://wallet.example/api/trustlists/registrar": registrarListType,
		srv.URL: pidTrustListType,
	} {
		if types[location] != want {
			t.Errorf("pointer %s has type %q, want %q", location, types[location], want)
		}
	}
}

// Users add providers and external lists through the API, and the wallet
// stores them.
func TestTheTrustAPIAddsAndRemovesEntitiesAndLists(t *testing.T) {
	srv := newTestServer(t, true)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: generateTestWallet(t).TrustAnchorCertificate().Raw}))
	body, _ := json.Marshal(map[string]string{"list": "eaa", "name": "Example University", "certificates": caPEM})
	rec := serverRequest(t, srv, http.MethodPost, "/api/trust/entities", string(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("adding an entity: %d %s", rec.Code, rec.Body)
	}
	var entity TrustedEntity
	if err := json.Unmarshal(rec.Body.Bytes(), &entity); err != nil {
		t.Fatal(err)
	}
	if rec := serverRequest(t, srv, http.MethodPost, "/api/trust/lists", `{"url":"https://lists.example/pid"}`); rec.Code != http.StatusCreated {
		t.Fatalf("adding a list: %d %s", rec.Code, rec.Body)
	}
	if rec := serverRequest(t, srv, http.MethodPost, "/api/trust/entities", `{"list":"nowhere","certificates":""}`); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown list: %d, want 400", rec.Code)
	}

	var state TrustedListState
	if err := json.Unmarshal(serverRequest(t, srv, http.MethodGet, "/api/trust", "").Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Entities) != 1 || state.Entities[0].Name != "Example University" || len(state.Lists) != 1 || !strings.HasSuffix(state.ListsURL, "/api/trustlists/lists") {
		t.Fatalf("state %+v", state)
	}
	// The wallet signs the entity onto its list.
	group, _ := FindTrustListGroupForWallet(srv.wallet, "eaa", "", "")
	raw, err := GenerateTrustListJWTForWalletGroup(srv.wallet, srv.wallet.IssuerURL, group, "/api/trustlists/eaa")
	if err != nil {
		t.Fatal(err)
	}
	if list, err := trustlist.Parse(raw); err != nil || !slices.ContainsFunc(list.Entities, func(e trustlist.TrustedEntity) bool { return e.Name == "Example University" }) {
		t.Errorf("the eaa list does not name the entity (%v)", err)
	}

	if rec := serverRequest(t, srv, http.MethodDelete, "/api/trust/entities/"+entity.ID, ""); rec.Code != http.StatusNoContent {
		t.Errorf("removing the entity: %d", rec.Code)
	}
	if rec := serverRequest(t, srv, http.MethodDelete, "/api/trust/lists?url=https://lists.example/pid", ""); rec.Code != http.StatusNoContent {
		t.Errorf("removing the list: %d", rec.Code)
	}
	if rec := serverRequest(t, srv, http.MethodDelete, "/api/trust/entities/"+entity.ID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("removing it again: %d, want 404", rec.Code)
	}
}

// Added providers and lists survive a reload on every storage mode.
func TestTrustedEntitiesAndListsSurviveAReload(t *testing.T) {
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
			caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.TrustAnchorCertificate().Raw}))
			entity, err := w.AddTrustedEntity("qeaa", "Example Bank", caPEM)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.AddTrustedList("https://lists.example/pid"); err != nil {
				t.Fatal(err)
			}
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if got := reloaded.ListTrustedEntities(); len(got) != 1 || got[0].ID != entity.ID {
				t.Errorf("entities %+v, want the added one", got)
			}
			if got := reloaded.ExternalTrustedLists(); !slices.Equal(got, []string{"https://lists.example/pid"}) {
				t.Errorf("lists %v, want the added one", got)
			}
		})
	}
}

// A list of trusted lists leads the wallet to the lists in its pointers. A
// pointed-to list must be signed with a certificate from its pointer (ETSI TS
// 119 602 V1.1.1 §6.3.13).
func TestAListOfTrustedListsLeadsToItsLists(t *testing.T) {
	foreign := generateTestWalletWithPID(t)
	pid := foreign.GetCredentials()[0]
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var raw string
		var err error
		if r.URL.Path == "/api/trustlists/lists" {
			raw, err = GenerateListOfTrustedLists(foreign, foreign.IssuerURL)
		} else {
			raw, err = GenerateTrustListJWTForWalletGroup(foreign, foreign.IssuerURL, DefaultTrustListGroupForWallet(foreign), "/api/trustlists/pid")
		}
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = rw.Write([]byte(raw))
	}))
	t.Cleanup(srv.Close)
	foreign.IssuerURL = srv.URL

	w := generateTestWallet(t)
	w.RequireARF = true
	w.TrustListCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.TrustAnchorCertificate().Raw})
	if _, err := w.AddTrustedList(srv.URL + "/api/trustlists/lists"); err != nil {
		t.Fatal(err)
	}
	if findings := w.trustAnchorFindings(receivedCredential(pid.Raw)); len(findings) != 0 {
		t.Errorf("findings %v, want none through the pointed-to PID list", findings)
	}
	state := w.TrustState()
	if !slices.ContainsFunc(state.Lists, func(l TrustedListLink) bool {
		return l.URL == srv.URL+"/api/trustlists/pid" && l.Via == srv.URL+"/api/trustlists/lists" && l.Error == ""
	}) {
		t.Errorf("lists %+v, want the PID list reached through the list of trusted lists", state.Lists)
	}
}

// Strict mode refuses an unreadable list. Debug mode adds it and says why it
// can't be used.
func TestAnUnreadableListIsRefusedInStrictModeAndReportedInDebugMode(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	if _, err := w.AddTrustedList(srv.URL); err == nil {
		t.Error("strict mode added an unreadable list")
	}
	w.ValidationMode = ValidationModeDebug
	link, err := w.AddTrustedList(srv.URL)
	if err != nil || link.Error == "" {
		t.Errorf("link %+v, err %v, want the list with the reason", link, err)
	}
	if state := w.TrustState(); len(state.Lists) != 1 || state.Lists[0].Error == "" {
		t.Errorf("lists %+v, want the list with the reason", state.Lists)
	}
}

// A CA added to the registrar list anchors the registration certificates and
// their status lists (ETSI TS 119 602 V1.1.1 Table G.3).
func TestAnAddedRegistrarCAAnchorsCertificatesAndStatusLists(t *testing.T) {
	w := generateTestWallet(t)
	ca := generateTestWallet(t).TrustAnchorCertificate()
	if _, err := w.AddTrustedEntity(registrarListID, "Other Registrar", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(w.RegistrarCAs(), ca.Equal) || !slices.ContainsFunc(w.RegistrationStatusCAs(), ca.Equal) {
		t.Error("the added registrar CA anchors neither the certificates nor their status lists")
	}
}

// An unreachable list is fetched once a minute, not on every check.
func TestAFailedListIsReusedForAMinute(t *testing.T) {
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		http.NotFound(rw, nil)
	}))
	t.Cleanup(srv.Close)
	w := generateTestWallet(t)
	for range 3 {
		if _, err := w.readTrustedList(srv.URL); err == nil {
			t.Fatal("read an unreachable list")
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("fetched %d times, want once", got)
	}
}

// Any visitor can name a list URL, so the list cache stays bounded.
func TestTheTrustedListCacheIsBounded(t *testing.T) {
	w := generateTestWallet(t)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte("list"))
	}))
	defer srv.Close()
	for i := range maxCachedLists + 5 {
		if _, err := w.rawTrustedList(fmt.Sprintf("%s/list-%d", srv.URL, i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(w.listCache); n > maxCachedLists {
		t.Errorf("cached lists = %d, want at most %d", n, maxCachedLists)
	}
}
