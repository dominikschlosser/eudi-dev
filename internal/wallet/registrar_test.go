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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

func TestTheRegistrarAssignsWhatARegistrationLeavesOut(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	rp := registerTestRelyingParty(t, w)

	id := rp.Identifier[0]
	if !organizationIdentifierPattern.MatchString(id.Identifier) || id.Type != euidIdentifierType {
		t.Errorf("identifier %+v, want an assigned EUID in organizationIdentifier form", id)
	}
	if rp.RegistryURI != "https://wallet.example/api/registrar/wrp/"+id.Identifier || rp.LegalPerson.LegalName[0] != "Example Shop" {
		t.Errorf("registry URI %q, legal name %v", rp.RegistryURI, rp.LegalPerson.LegalName)
	}
	use := rp.Services[0].IntendedUses[0]
	if use.IntendedUseIdentifier == "" || use.CreatedAt == "" || len(use.PrivacyPolicy) == 0 {
		t.Errorf("intended use %+v, want an identifier, a date and a privacy policy", use)
	}
	if _, err := w.RegisterRelyingParty(rp, w.RegistrarBase()); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("registering the same identifier again: %v", err)
	}
}

func TestAnUpdateKeepsRegisteredIntendedUses(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	kept := rp.Services[0].IntendedUses[0].IntendedUseIdentifier
	created := rp.Services[0].IntendedUses[0].CreatedAt
	rp.Services[0].IntendedUses[0].CreatedAt = "1999-01-01"
	added := IntendedUse{
		Purpose:     []MultiLangString{{Lang: "en", Content: "Ticket check"}},
		Credentials: []RegisteredCredential{{Format: "mso_mdoc", Meta: map[string]any{"doctype_value": mock.PIDNamespace}, Claims: []RegisteredClaim{{Path: []any{mock.PIDNamespace, "given_name"}}}}},
	}
	rp.Services[0].IntendedUses = append(rp.Services[0].IntendedUses, added)

	updated, err := w.UpdateRelyingParty(rp, w.RegistrarBase())
	if err != nil {
		t.Fatalf("UpdateRelyingParty: %v", err)
	}
	uses := updated.Services[0].IntendedUses
	if len(uses) != 2 || uses[0].IntendedUseIdentifier != kept || uses[0].CreatedAt != created || uses[1].IntendedUseIdentifier == "" {
		t.Fatalf("intended uses %+v, want the first kept with its date and the second assigned", uses)
	}
	if err := w.DeleteRelyingParty(rp.Identifier[0].Identifier); err != nil {
		t.Fatalf("DeleteRelyingParty: %v", err)
	}
	if _, err := w.UpdateRelyingParty(rp, w.RegistrarBase()); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Errorf("updating a deleted registration: %v", err)
	}
}

func TestRegistrationsAreChecked(t *testing.T) {
	use := func(id string) IntendedUse {
		return IntendedUse{IntendedUseIdentifier: id, Credentials: []RegisteredCredential{{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []any{mock.DefaultPIDVCT}}, Claims: []RegisteredClaim{{Path: []any{"given_name"}}}}}}
	}
	for _, tc := range []struct {
		name string
		rp   WalletRelyingParty
		want string
	}{
		{"country name", WalletRelyingParty{TradeName: "Shop", Country: "Germany"}, "two-letter country code"},
		{"too many services", WalletRelyingParty{TradeName: "Shop", Services: make([]WalletRelyingPartyService, 21)}, "at most 20 services"},
		{"credential without claims", WalletRelyingParty{TradeName: "Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{{
			Credentials: []RegisteredCredential{{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []any{mock.DefaultPIDVCT}}}},
		}}}}}, "needs at least one claim"},
		{"identifier with a space", WalletRelyingParty{TradeName: "Shop", Identifier: []Identifier{{Identifier: "LEIXG-12 34"}}}, "not an organizationIdentifier"},
		{"service twice", WalletRelyingParty{TradeName: "Shop", Services: []WalletRelyingPartyService{{ServiceIdentifier: "web"}, {ServiceIdentifier: "web"}}}, "registered twice"},
		{"intended use twice", WalletRelyingParty{TradeName: "Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{use("a"), use("a")}}}}, "registered twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := generateTestWallet(t).RegisterRelyingParty(tc.rp, "https://wallet.example")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestRegistrationsAreStored(t *testing.T) {
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
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := reloaded.RelyingParty(rp.Identifier[0].Identifier); !ok || got.Services[0].IntendedUses[0].IntendedUseIdentifier != rp.Services[0].IntendedUses[0].IntendedUseIdentifier {
				t.Fatalf("reloaded registration %+v, found %v", got, ok)
			}
			if err := reloaded.DeleteRelyingParty(rp.Identifier[0].Identifier); err != nil {
				t.Fatal(err)
			}
			if err := store.Save(reloaded); err != nil {
				t.Fatal(err)
			}
			if again, err := store.LoadOrCreate(); err != nil || len(again.RegisteredRelyingParties()) != 0 {
				t.Fatalf("registrations after delete %+v (%v), want none", again.RegisteredRelyingParties(), err)
			}
		})
	}
}

// The wallet checks a registration certificate without the registry. So a
// relying party's certificates keep working after the wallet loses the
// registry, for example on memory storage after a restart.
func TestIssuedCertificatesWorkWithoutTheRegistry(t *testing.T) {
	registrar := generateTestWallet(t)
	rp := registerTestRelyingParty(t, registrar)
	result := issueTestRegistrationCertificate(t, registrar, rp)

	fresh := generateTestWallet(t)
	if len(fresh.RegisteredRelyingParties()) != 0 {
		t.Fatal("the fresh wallet has registrations")
	}
	request := func(claim string) *AuthorizationRequestParams {
		return &AuthorizationRequestParams{
			DCQLQuery: map[string]any{"credentials": []any{map[string]any{
				"id": "pid", "format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{map[string]any{"path": []any{claim}}},
			}}},
			FullParams: map[string]string{"verifier_info": result.VerifierInfo},
		}
	}
	certs, _ := verifiedRegistrationCertificates(map[string]any{"verifier_info": result.VerifierInfo})
	if findings := overAskingFindings(certs[0], request("given_name").DCQLQuery); len(findings) != 0 {
		t.Errorf("a registered claim: %v", findings)
	}
	if findings := overAskingFindings(certs[0], request("birthdate").DCQLQuery); len(findings) != 1 {
		t.Errorf("an unregistered claim: %v, want one finding", findings)
	}
	if purposes, _ := consentRegistration(request("given_name")); len(purposes) != 1 || purposes[0] != "Age check" {
		t.Errorf("purposes %v, want Age check", purposes)
	}
}

func registrarJSON(t *testing.T, srv *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	return rec
}

// The registrar API follows TS05 v1.5 for records and the German sandbox for
// certificates.
func TestTheRegistrarAPI(t *testing.T) {
	srv := newTestServer(t, true)
	created := registrarJSON(t, srv, "POST", "/api/registrar/wrp", `{"tradeName":"Example Shop","services":[{"serviceIdentifier":"web","intendedUses":[{"purpose":[{"lang":"en","content":"Age check"}],"credentials":[{"format":"dc+sd-jwt","meta":{"vct_values":["`+mock.DefaultPIDVCT+`"]},"claims":[{"path":["given_name"]}]}]}]}]}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /wrp: %d %s", created.Code, created.Body.String())
	}
	var rp WalletRelyingParty
	if err := json.Unmarshal(created.Body.Bytes(), &rp); err != nil {
		t.Fatal(err)
	}
	id, use := rp.Identifier[0].Identifier, rp.Services[0].IntendedUses[0].IntendedUseIdentifier

	t.Run("signed list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/registrar/wrp?intendeduseidentifier="+use, nil)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Header().Get("Content-Type") != "application/jwt" {
			t.Fatalf("content type %q, want application/jwt", rec.Header().Get("Content-Type"))
		}
		payload, err := base64.RawURLEncoding.DecodeString(strings.Split(rec.Body.String(), ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		var page struct {
			Iss  string               `json:"iss"`
			Data []WalletRelyingParty `json:"data"`
		}
		if err := json.Unmarshal(payload, &page); err != nil || page.Iss == "" || len(page.Data) != 1 || page.Data[0].TradeName != "Example Shop" {
			t.Fatalf("page %+v (%v), want the one matching registration", page, err)
		}
	})
	t.Run("the wallet's own record lists first", func(t *testing.T) {
		var page struct{ Data []WalletRelyingParty }
		if err := json.Unmarshal(registrarJSON(t, srv, "GET", "/api/registrar/wrp", "").Body.Bytes(), &page); err != nil || len(page.Data) != 2 || len(page.Data[0].Services[0].Entitlements) == 0 {
			t.Fatalf("records %+v (%v), want the provider record and the registration", page.Data, err)
		}
	})
	t.Run("one service", func(t *testing.T) {
		if rec := registrarJSON(t, srv, "GET", "/api/registrar/wrp/"+id+"/services/web", ""); rec.Code != http.StatusOK {
			t.Fatalf("service: %d", rec.Code)
		}
		if rec := registrarJSON(t, srv, "GET", "/api/registrar/wrp/"+id+"/services/other", ""); rec.Code != http.StatusNotFound {
			t.Fatalf("unknown service: %d, want 404", rec.Code)
		}
	})
	t.Run("check intended use", func(t *testing.T) {
		for claim, want := range map[string]bool{"given_name": true, "birthdate": false} {
			rec := registrarJSON(t, srv, "GET", "/api/registrar/wrp/check-intended-use?identifier="+id+"&intendeduseidentifier="+use+"&claimpath="+claim, "")
			var page struct {
				Data struct {
					IsRegistered bool `json:"isRegistered"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || page.Data.IsRegistered != want {
				t.Errorf("claim %s: %s, want isRegistered %v", claim, rec.Body.String(), want)
			}
		}
	})
	t.Run("certificates", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csr, _ := json.Marshal(testAccessCSR(t, key))
		if rec := registrarJSON(t, srv, "POST", "/api/registrar/access-certificates", `{"identifier":"`+id+`","csr":`+string(csr)+`}`); rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), "x509_hash:") {
			t.Fatalf("access certificate: %d %s", rec.Code, rec.Body.String())
		}
		if rec := registrarJSON(t, srv, "POST", "/api/registrar/registration-certificates", `{"identifier":"`+id+`","intendedUseIdentifier":"`+use+`"}`); rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), "verifierInfo") {
			t.Fatalf("registration certificate: %d %s", rec.Code, rec.Body.String())
		}
		if rec := registrarJSON(t, srv, "POST", "/api/registrar/registration-certificates", `{"identifier":"LEIXG-1","intendedUseIdentifier":"`+use+`"}`); rec.Code != http.StatusNotFound {
			t.Fatalf("an unregistered relying party: %d, want 404", rec.Code)
		}
	})
	t.Run("update", func(t *testing.T) {
		rp.TradeName = "Example Store"
		body, _ := json.Marshal(rp)
		rec := registrarJSON(t, srv, "PUT", "/api/registrar/wrp", string(body))
		var updated WalletRelyingParty
		if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil || rec.Code != http.StatusOK ||
			updated.TradeName != "Example Store" || updated.Services[0].IntendedUses[0].IntendedUseIdentifier != use {
			t.Fatalf("PUT: %d %s, want the new name and the kept intended use", rec.Code, rec.Body.String())
		}
	})
	t.Run("pages", func(t *testing.T) {
		var first, second struct {
			Data       []WalletRelyingParty `json:"data"`
			Pagination struct {
				HasNextPage bool   `json:"has_next_page"`
				NextCursor  string `json:"next_cursor"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(registrarJSON(t, srv, "GET", "/api/registrar/wrp?limit=1", "").Body.Bytes(), &first); err != nil ||
			len(first.Data) != 1 || !first.Pagination.HasNextPage || first.Pagination.NextCursor != "1" {
			t.Fatalf("first page %+v (%v), want one record and a cursor", first, err)
		}
		if err := json.Unmarshal(registrarJSON(t, srv, "GET", "/api/registrar/wrp?limit=1&cursor=1", "").Body.Bytes(), &second); err != nil ||
			len(second.Data) != 1 || second.Pagination.HasNextPage || second.Data[0].Identifier[0].Identifier != id {
			t.Fatalf("second page %+v (%v), want the registration and no next page", second, err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		if rec := registrarJSON(t, srv, "DELETE", "/api/registrar/wrp/"+id, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("DELETE: %d", rec.Code)
		}
		if rec := registrarJSON(t, srv, "GET", "/api/registrar/wrp/"+id, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("GET after DELETE: %d, want 404", rec.Code)
		}
	})
}

// A registration can't claim another party's identifier, not even as an
// additional identifier.
func TestARegistrationCannotTakeAnotherPartysIdentifier(t *testing.T) {
	w := generateTestWallet(t)
	taken := registerTestRelyingParty(t, w).Identifier[0].Identifier
	_, err := w.RegisterRelyingParty(WalletRelyingParty{
		TradeName:  "Other Shop",
		Identifier: []Identifier{{Identifier: "NTRNL-OTHER"}, {Identifier: taken}},
	}, w.RegistrarBase())
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("error %v, want the identifier taken", err)
	}
}

// The primary identifier is in every issued certificate, so an update sent
// through another identifier keeps it.
func TestAnUpdateThroughASecondaryIdentifierKeepsThePrimary(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	primary := rp.Identifier[0]
	rp.Identifier = append(rp.Identifier, Identifier{Type: "http://data.europa.eu/eudi/id/EUID", Identifier: "DEHRB.12345"})
	if _, err := w.UpdateRelyingParty(rp, w.RegistrarBase()); err != nil {
		t.Fatal(err)
	}
	rp.Identifier = []Identifier{rp.Identifier[1]}
	updated, err := w.UpdateRelyingParty(rp, w.RegistrarBase())
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Identifier) != 2 || updated.Identifier[0] != primary {
		t.Errorf("identifiers %+v, want %v first", updated.Identifier, primary)
	}
}

func TestTheRegistrarServesItsPlaceholderPages(t *testing.T) {
	srv := newTestServer(t, true)
	for path := range registrarPlaceholderPages {
		resp := serverRequest(t, srv, http.MethodGet, path, "")
		if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), "test registrar") {
			t.Errorf("GET %s = %d %q", path, resp.Code, resp.Body.String())
		}
	}
}
