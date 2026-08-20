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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// caller describes how one client reaches the wallet: a browser holding a
// session cookie, a client naming the browser it acts for, or neither.
type caller struct {
	cookie string
	owner  string
}

func (c caller) apply(r *http.Request) {
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.cookie})
	}
	if c.owner != "" {
		r.Header.Set(OwnerHeader, c.owner)
	}
}

func listRequestsAs(t *testing.T, srv *Server, who caller) []map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/requests", nil)
	who.apply(req)
	rec := httptest.NewRecorder()
	srv.handleListRequests(rec, req)
	var docs []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&docs); err != nil {
		t.Fatalf("decoding the request list: %v", err)
	}
	return docs
}

func pendingPresentation(owner string) *ConsentRequest {
	return &ConsentRequest{
		ID:       newConsentID(),
		Type:     "presentation",
		Owner:    owner,
		Status:   "pending",
		ClientID: "https://verifier.example",
	}
}

// TestPendingRequests_ReachTheBrowserThatStartedThem covers a wallet several
// people reach: a consent request is listed for the browser it came from, and
// for no other.
func TestPendingRequests_ReachTheBrowserThatStartedThem(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	w.CreateConsentRequest(pendingPresentation("browser-a"))

	forA := listRequestsAs(t, srv, caller{cookie: "browser-a"})
	if len(forA) != 1 || forA[0]["mine"] != true {
		t.Fatalf("the starting browser sees %v, want the request as its own", forA)
	}
	if forB := listRequestsAs(t, srv, caller{cookie: "browser-b"}); len(forB) != 0 {
		t.Errorf("another visitor sees %d requests, want none", len(forB))
	}
}

// TestPendingRequests_ClientNamingTheBrowserItActsFor covers the URL handler
// and the CLI: they submit over the API and open a page separately, naming the
// same browser on both, which is what ties the two acts together.
func TestPendingRequests_ClientNamingTheBrowserItActsFor(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	w.CreateConsentRequest(pendingPresentation("dispatch-nonce"))

	// The page the client opened carries the nonce it was opened with, next to
	// a session cookie of its own.
	page := listRequestsAs(t, srv, caller{cookie: "browser-a", owner: "dispatch-nonce"})
	if len(page) != 1 || page[0]["mine"] != true {
		t.Fatalf("the page the client opened sees %v, want the request as its own", page)
	}
	if other := listRequestsAs(t, srv, caller{cookie: "browser-b"}); len(other) != 0 {
		t.Errorf("another visitor sees %d requests, want none", len(other))
	}
}

// TestPendingRequests_UnownedStayVisible is the compatibility rule. A client
// that names no browser is every client written before the wallet asked for
// one, and the CLI and API clients that have no browser at all. What they
// create stays visible to every caller, so a single-user wallet and every
// existing integration keep working.
func TestPendingRequests_UnownedStayVisible(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	w.CreateConsentRequest(pendingPresentation(""))

	for _, who := range []struct {
		name string
		as   caller
	}{
		{"a caller with nothing at all, such as the CLI polling", caller{}},
		{"a browser that started nothing", caller{cookie: "browser-b"}},
		{"a page a client opened for something else", caller{cookie: "browser-b", owner: "other-nonce"}},
	} {
		docs := listRequestsAs(t, srv, who.as)
		if len(docs) != 1 {
			t.Errorf("%s sees %d requests, want the unowned one", who.name, len(docs))
		}
	}
}

// TestRequestOwner covers which owner a call stamps on the request it creates.
func TestRequestOwner(t *testing.T) {
	for _, tc := range []struct {
		name string
		as   caller
		want string
	}{
		{"a page submitting its own URI", caller{cookie: "browser-a"}, "browser-a"},
		{"a client naming the browser it acts for", caller{owner: "dispatch-nonce"}, "dispatch-nonce"},
		{"a client naming a browser beats the cookie it does not hold", caller{cookie: "browser-a", owner: "dispatch-nonce"}, "dispatch-nonce"},
		{"a client that names nothing", caller{}, ""},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
		tc.as.apply(req)
		if got := requestOwner(req); got != tc.want {
			t.Errorf("%s: owner = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestOwnerFromQuery covers the event stream, which EventSource opens without
// headers, so the page puts the owner in the URL instead.
func TestOwnerFromQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/requests/stream?owner=dispatch-nonce", nil)
	if got := presentedOwner(req); got != "dispatch-nonce" {
		t.Errorf("owner = %q, want the one in the query", got)
	}
}

// TestBrowserSession covers where a session comes from and what it carries.
func TestBrowserSession(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id := newBrowserSession(rec, req, true)
	if id == "" {
		t.Fatal("expected a session id")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].Value != id {
		t.Fatalf("cookies = %v, want the session that was minted", cookies)
	}
	got := cookies[0]
	if !got.HttpOnly {
		t.Error("the session is the wallet's own and no script needs to read it")
	}
	if got.SameSite != http.SameSiteLaxMode {
		t.Error("the session travels with a navigation to the wallet, which is how a verifier's link arrives")
	}
	if got.Path != "/" {
		t.Errorf("path = %q, want / so the API and the flow endpoints share it", got.Path)
	}
	if !got.Secure {
		t.Error("a wallet served over https marks its session Secure")
	}
	if got.MaxAge != 0 || !got.Expires.IsZero() {
		t.Error("a session cookie lives as long as the browser is open")
	}

	// A browser that already has one keeps it, so every tab answers for the
	// same requests.
	again := httptest.NewRecorder()
	kept := httptest.NewRequest(http.MethodGet, "/", nil)
	kept.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
	if got := newBrowserSession(again, kept, true); got != id {
		t.Errorf("session = %q, want the one the browser already had", got)
	}
	if len(again.Result().Cookies()) != 0 {
		t.Error("a browser that already has a session is not given another")
	}
}

// TestBrowserSecure covers which browsers get a Secure session. A reverse
// proxy terminates TLS and forwards plain http, so it says so in a header, and
// a browser on plain http must not be marked Secure or it keeps nothing.
func TestBrowserSecure(t *testing.T) {
	w := generateTestWallet(t)
	// The base URL says https even for the browser reaching localhost over
	// plain http, which is the documented reverse-proxy shape.
	w.BaseURL = "https://eudi-test.dev"
	srv := NewServer(w, 0, nil)

	forwarded := httptest.NewRequest(http.MethodGet, "/", nil)
	forwarded.Header.Set("X-Forwarded-Proto", "https")
	if !srv.browserSecure(forwarded) {
		t.Error("a browser the proxy reached over https marks its session Secure")
	}

	chained := httptest.NewRequest(http.MethodGet, "/", nil)
	chained.Header.Set("X-Forwarded-Proto", "https, http")
	if !srv.browserSecure(chained) {
		t.Error("the first hop is the browser's own, and it was https")
	}

	if srv.browserSecure(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Error("a browser on plain http would never send a Secure session back")
	}

	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.TLS = &tls.ConnectionState{}
	if !srv.browserSecure(direct) {
		t.Error("a browser that reached the wallet over TLS itself marks its session Secure")
	}
}

// TestPageRequestMintsTheSession covers the middleware on the UI: a browser
// that starts at the page rather than at a link needs a session by the time it
// submits a URI of its own, and the files the page pulls in need none.
func TestPageRequestMintsTheSession(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	handler := srv.withBrowserSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for _, tc := range []struct {
		method, path string
		wantCookie   bool
	}{
		{http.MethodGet, "/", true},
		{http.MethodGet, "/index.html", true},
		{http.MethodGet, "/app.js", false},
		{http.MethodGet, "/style.css", false},
		{http.MethodPost, "/", false},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		got := len(rec.Result().Cookies()) == 1
		if got != tc.wantCookie {
			t.Errorf("%s %s: session minted = %v, want %v", tc.method, tc.path, got, tc.wantCookie)
		}
	}
}

// TestClientName covers the marker every client this project ships sends.
func TestClientName(t *testing.T) {
	for _, tc := range []struct {
		header, name string
	}{
		{"eudi-cli/1.25.2", "eudi-cli"},
		{"eudi-url-handler/dev", "eudi-url-handler"},
		{"eudi-ui", "eudi-ui"},
		{"", ""},
	} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		if tc.header != "" {
			req.Header.Set(ClientHeader, tc.header)
		}
		if got := clientName(req); got != tc.name {
			t.Errorf("%q -> %q, want %q", tc.header, got, tc.name)
		}
	}
}

// TestNoteStaleClient covers what a client too old to name itself is told. Its
// own output cannot be changed any more, so the wallet says it in the activity
// log, which the page that client opens is served fresh to read.
func TestNoteStaleClient(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)

	named := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
	named.Header.Set(OwnerHeader, "a-page-it-opened")
	srv.noteStaleClient(named)
	if entry := findLogEntry(w.GetLog(), "client_names_no_page"); entry != nil {
		t.Fatalf("a client that names a page is not reported: %s", entry.Detail)
	}

	srv.noteStaleClient(httptest.NewRequest(http.MethodPost, "/api/presentations", nil))
	entry := findLogEntry(w.GetLog(), "client_names_no_page")
	if entry == nil {
		t.Fatal("expected the notice for a client that names nothing")
	}
	if entry.Severity != severityWarning {
		t.Errorf("severity = %q, want %q", entry.Severity, severityWarning)
	}

	// Once per server, so the flow the user is watching stays readable.
	srv.noteStaleClient(httptest.NewRequest(http.MethodPost, "/api/presentations", nil))
	var notices int
	for _, e := range w.GetLog() {
		if e.Details != nil && e.Details["event"] == "client_names_no_page" {
			notices++
		}
	}
	if notices != 1 {
		t.Errorf("%d notices, want one per server", notices)
	}

	// A second server reports for itself: one wallet's silence is not another's.
	other := NewServer(w, 0, nil)
	other.noteStaleClient(httptest.NewRequest(http.MethodPost, "/api/presentations", nil))
	notices = 0
	for _, e := range w.GetLog() {
		if e.Details != nil && e.Details["event"] == "client_names_no_page" {
			notices++
		}
	}
	if notices != 2 {
		t.Errorf("%d notices, want one from each server", notices)
	}
}

// TestApprovingOwner covers a presentation the issuer asks for mid-issuance.
// It belongs to the browser the offer belonged to, and an offer submitted by a
// client that named none takes the browser that approved it, so the issuer's
// question reaches whoever answered the offer.
func TestApprovingOwner(t *testing.T) {
	if got := approvingOwner("browser-a", "browser-b"); got != "browser-a" {
		t.Errorf("owner = %q, want the browser the offer belonged to", got)
	}
	if got := approvingOwner("", "browser-b"); got != "browser-b" {
		t.Errorf("owner = %q, want the browser that approved the offer", got)
	}
	if got := approvingOwner("", ""); got != "" {
		t.Errorf("owner = %q, want none when neither named a browser", got)
	}
}

// TestBackwardsCompatibility_ClientsThatNameNoBrowser pins what a wallet owes
// clients written before it asked to be told which browser a flow is for: an
// installed URL handler script, a CLI from an older release, and anything
// driving the HTTP API directly. They submit over the API and name nothing, so
// what they create is unowned, and unowned stays reachable from every caller.
func TestBackwardsCompatibility_ClientsThatNameNoBrowser(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)

	for _, client := range []struct {
		name    string
		prepare func(*http.Request)
	}{
		{"a URL handler installed before the wallet asked for a name", func(r *http.Request) {}},
		{"a CLI from an older release", func(r *http.Request) {}},
		{"a script driving the API directly", func(r *http.Request) {
			r.Header.Set("User-Agent", "curl/8.4.0")
		}},
	} {
		submission := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
		client.prepare(submission)
		if owner := requestOwner(submission); owner != "" {
			t.Errorf("%s: owner = %q, want none", client.name, owner)
		}
		w.CreateConsentRequest(pendingPresentation(requestOwner(submission)))
	}

	for _, who := range []struct {
		name string
		as   caller
	}{
		{"the client polling for what it submitted", caller{}},
		{"the page it opened before the wallet ever set a session", caller{}},
		{"the page it opened once the wallet set one", caller{cookie: "browser-a"}},
	} {
		if got := len(listRequestsAs(t, srv, who.as)); got != 3 {
			t.Errorf("%s sees %d requests, want all 3", who.name, got)
		}
	}
}

// TestBackwardsCompatibility_OlderClientIsToldToUpgrade pins the one channel
// left for a client whose own output cannot be changed any more. The wallet
// says it in the activity log, which the page that client opens is served
// fresh to read, and the flow itself is untouched.
func TestBackwardsCompatibility_OlderClientIsToldToUpgrade(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)

	srv.noteStaleClient(httptest.NewRequest(http.MethodPost, "/api/presentations", nil))
	entry := findLogEntry(w.GetLog(), "client_names_no_page")
	if entry == nil {
		t.Fatal("expected the notice")
	}
	if !strings.Contains(entry.Detail, "eudi wallet register") || !strings.Contains(entry.Detail, OwnerHeader) {
		t.Errorf("the notice does not say how to fix it: %s", entry.Detail)
	}

	w.CreateConsentRequest(pendingPresentation(""))
	if got := len(listRequestsAs(t, srv, caller{})); got != 1 {
		t.Errorf("the submitted request is listed %d times, want 1", got)
	}
}

// TestBackwardsCompatibility_CurrentClientNamesThePageItOpened pins the other
// side: a client shipped with this wallet names the page on both acts, so what
// it submits reaches that page and no other.
func TestBackwardsCompatibility_CurrentClientNamesThePageItOpened(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)

	submission := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
	submission.Header.Set(ClientHeader, "eudi-url-handler/1.25.2")
	submission.Header.Set(OwnerHeader, "dispatch-nonce")
	owner := requestOwner(submission)
	if owner != "dispatch-nonce" {
		t.Fatalf("owner = %q, want the page the client named", owner)
	}
	w.CreateConsentRequest(pendingPresentation(owner))

	if got := listRequestsAs(t, srv, caller{cookie: "browser-a", owner: "dispatch-nonce"}); len(got) != 1 {
		t.Errorf("the page the client opened sees %d requests, want 1", len(got))
	}
	if got := listRequestsAs(t, srv, caller{cookie: "browser-b"}); len(got) != 0 {
		t.Errorf("another visitor sees %d requests, want none", len(got))
	}
	srv.noteStaleClient(submission)
	if entry := findLogEntry(w.GetLog(), "client_names_no_page"); entry != nil {
		t.Errorf("a client that names a page is reported: %s", entry.Detail)
	}
}

// TestProtocolURLCannotNameTheBrowser covers /authorize and /credential-offer.
// Their full URL is written by the verifier or the issuer, so a query
// parameter on them is a counterparty's word about whose browser this is. Only
// a header names a browser, and a navigation cannot set one.
func TestProtocolURLCannotNameTheBrowser(t *testing.T) {
	navigation := httptest.NewRequest(http.MethodGet, "/authorize?client_id=x&owner=elsewhere", nil)
	navigation.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "browser-a"})
	if got := requestOwner(navigation); got != "browser-a" {
		t.Errorf("owner = %q, want the browser that navigated", got)
	}

	offer := httptest.NewRequest(http.MethodGet, "/credential-offer?credential_offer=x&owner=elsewhere", nil)
	if got := requestOwner(offer); got != "" {
		t.Errorf("owner = %q, want none: the link says nothing about whose browser this is", got)
	}

	// The event stream is the one place the query carries it, because
	// EventSource sets no headers, and it only says what the caller may see.
	stream := httptest.NewRequest(http.MethodGet, "/api/requests/stream?owner=dispatch-nonce", nil)
	if got := callerOwners(stream); len(got) != 1 || got[0] != "dispatch-nonce" {
		t.Errorf("stream owners = %v, want the name the page holds", got)
	}
}

// TestAnswerBelongsToTheBrowserThatWasAsked covers approve and deny. The id
// travels in an address bar, so knowing one is not the same as being the
// browser the question was put to.
func TestAnswerBelongsToTheBrowserThatWasAsked(t *testing.T) {
	for _, action := range []string{"approve", "deny"} {
		w := generateTestWallet(t)
		srv := NewServer(w, 0, nil)
		req := pendingPresentation("browser-a")
		req.ResultCh = make(chan ConsentResult, 1)
		req.SubmissionCh = make(chan SubmissionResult, 1)
		w.CreateConsentRequest(req)

		stranger := httptest.NewRequest(http.MethodPost, "/api/requests/"+req.ID+"/"+action, strings.NewReader("{}"))
		stranger.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "browser-b"})
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, stranger)

		if rec.Code != http.StatusNotFound {
			t.Errorf("%s by another browser: %d, want 404", action, rec.Code)
		}
		if got, _ := w.GetRequest(req.ID); got != nil && got.Status != "pending" {
			t.Errorf("%s by another browser resolved the request as %q", action, got.Status)
		}
	}
}

// TestUnownedRequestStaysAnswerable is the other half: a request no client
// named a browser for is every client written before this, and any caller may
// still answer it.
func TestUnownedRequestStaysAnswerable(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	req := pendingPresentation("")
	req.ResultCh = make(chan ConsentResult, 1)
	req.SubmissionCh = make(chan SubmissionResult, 1)
	w.CreateConsentRequest(req)

	deny := httptest.NewRequest(http.MethodPost, "/api/requests/"+req.ID+"/deny", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, deny)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny by a caller with no browser: %d, want 200", rec.Code)
	}
	if result := <-req.ResultCh; result.Approved {
		t.Error("expected the denial to reach the flow")
	}
}

// TestRedirectedBrowserReachesItsRequest covers a browser that keeps no
// session: an iframe where a Lax cookie is not sent, or one with cookies off.
// The wallet handed it the request id in the redirect, so naming that id is
// enough to reach the request it was redirected for.
func TestRedirectedBrowserReachesItsRequest(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	req := pendingPresentation("a-session-this-browser-never-kept")
	w.CreateConsentRequest(req)

	if got := listRequestsAs(t, srv, caller{}); len(got) != 0 {
		t.Fatalf("a caller naming nothing sees %d requests, want none", len(got))
	}

	named := httptest.NewRequest(http.MethodGet, "/api/requests?request="+req.ID, nil)
	rec := httptest.NewRecorder()
	srv.handleListRequests(rec, named)
	var docs []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&docs); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(docs) != 1 || docs[0]["id"] != req.ID {
		t.Fatalf("naming the redirected id sees %v, want that request", docs)
	}

	// Naming an id nobody was handed reaches nothing.
	other := pendingPresentation("another-browser")
	w.CreateConsentRequest(other)
	guess := httptest.NewRequest(http.MethodGet, "/api/requests?request=not-an-id", nil)
	rec = httptest.NewRecorder()
	srv.handleListRequests(rec, guess)
	docs = nil
	if err := json.NewDecoder(rec.Body).Decode(&docs); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(docs) != 0 {
		t.Errorf("naming an id nobody holds sees %v, want nothing", docs)
	}
}

// TestUIRequestNamesTheRequestItIsFor covers what the wallet hands whoever
// runs it: the id of the request waiting, so the page it leads to answers that
// one. Whether that means opening a window is the command's call, which is
// what lets a run that opens nothing still say where the request is.
func TestUIRequestNamesTheRequestItIsFor(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	var announced []string
	srv.SetOnUIRequest(func(requestID string) { announced = append(announced, requestID) })

	srv.triggerUIRequest("request-a")
	_, unsubscribe := w.Subscribe()
	defer unsubscribe()
	srv.triggerUIRequest("request-b")

	if len(announced) != 2 || announced[0] != "request-a" || announced[1] != "request-b" {
		t.Errorf("announced %v, want both requests named", announced)
	}
	if w.AttachedUIs() != 1 {
		t.Errorf("attached UIs = %d, want the watching tab counted", w.AttachedUIs())
	}
}

// TestOwnerNeverLeavesTheServer pins that the value naming a browser stays
// here. ConsentRequest is marshalled field by field, so a field added there
// could echo it and let any caller claim the request.
func TestOwnerNeverLeavesTheServer(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	w.CreateConsentRequest(pendingPresentation("browser-a"))

	docs := listRequestsAs(t, srv, caller{cookie: "browser-a"})
	if len(docs) != 1 {
		t.Fatalf("listed %d requests, want 1", len(docs))
	}
	encoded, err := json.Marshal(docs[0])
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(encoded), "browser-a") {
		t.Errorf("the request document carries the browser it belongs to: %s", encoded)
	}
}

// TestLastErrorReachesTheFlowItBelongsTo covers the report a failure raises.
// It goes to the browser whose flow raised it, and one raised by a client that
// named no browser stays readable by every caller.
func TestLastErrorReachesTheFlowItBelongsTo(t *testing.T) {
	w := generateTestWallet(t)
	w.NotifyError(WalletError{Message: "A's flow", Owner: "browser-a"})

	if got := w.PeekLastError([]string{"browser-a"}); got == nil || got.Message != "A's flow" {
		t.Errorf("the browser whose flow failed reads %v, want its own error", got)
	}
	if got := w.PeekLastError([]string{"browser-b"}); got != nil {
		t.Errorf("another browser reads %v, want nothing", got)
	}

	w.NotifyError(WalletError{Message: "a client with no browser"})
	for _, owners := range [][]string{nil, {"browser-b"}} {
		if got := w.PeekLastError(owners); got == nil || got.Message != "a client with no browser" {
			t.Errorf("caller %v reads %v, want the unowned error", owners, got)
		}
	}

	// A caller clears every slot it reads, so an error it was shown is one it
	// can dismiss. Otherwise the unowned one would come back on every reload.
	w.ClearLastError([]string{"browser-b"})
	for _, owners := range [][]string{nil, {"browser-b"}} {
		if got := w.PeekLastError(owners); got != nil {
			t.Errorf("caller %v still reads %v after dismissing it", owners, got)
		}
	}
	if got := w.PeekLastError([]string{"browser-a"}); got == nil {
		t.Error("dismissing one browser's error dropped another's")
	}
}

// TestStoredErrorsStayBounded covers a map keyed by a value callers choose.
func TestStoredErrorsStayBounded(t *testing.T) {
	w := generateTestWallet(t)
	// The unowned slot is a key like the rest, so it is in the map while the
	// rest arrive: it must not stop eviction or be evicted out of turn.
	w.NotifyError(WalletError{Message: "a client with no browser"})
	for i := 0; i < maxStoredErrors*3; i++ {
		w.NotifyError(WalletError{Message: "failed", Owner: fmt.Sprintf("browser-%d", i)})
	}
	rt := w.runtimeState()
	rt.mu.RLock()
	held := len(rt.lastErrors)
	rt.mu.RUnlock()
	if held > maxStoredErrors {
		t.Errorf("holding %d errors, want at most %d", held, maxStoredErrors)
	}
}

// TestOwnerNameIsBounded covers the same for the name itself, which arrives in
// a header and ends up as a key.
func TestOwnerNameIsBounded(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
	req.Header.Set(OwnerHeader, strings.Repeat("x", maxOwnerLength+1))
	if got := requestOwner(req); got != "" {
		t.Errorf("owner = %q, want none for a name longer than a name", got)
	}
	req.Header.Set(OwnerHeader, strings.Repeat("x", maxOwnerLength))
	if got := requestOwner(req); got == "" {
		t.Error("a name of the greatest allowed length is still a name")
	}
}

// TestALateAnswerIsToldWhichHappened covers the sentence a user gets when the
// dialog they left open is no longer answerable. A request that ran out of
// time was answered by nobody, and saying otherwise sends them looking for the
// tab that did it.
func TestALateAnswerIsToldWhichHappened(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)

	for _, tc := range []struct {
		name, resolveAs, want string
	}{
		{"expired", statusExpired, "This request timed out before it was answered"},
		{"answered", "denied", "This request was already answered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := pendingPresentation("browser-a")
			req.ID = "late-" + tc.name
			w.CreateConsentRequest(req)
			if _, ok := w.ResolveRequest(req.ID, tc.resolveAs); !ok {
				t.Fatalf("resolving as %s", tc.resolveAs)
			}

			call := httptest.NewRequest(http.MethodPost, "/api/requests/"+req.ID+"/approve", nil)
			call.Header.Set(OwnerHeader, "browser-a")
			call.SetPathValue("id", req.ID)
			rec := httptest.NewRecorder()
			srv.handleApproveRequest(rec, call)

			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
			}
			var body map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if body["error"] != tc.want {
				t.Errorf("error = %q, want %q", body["error"], tc.want)
			}
		})
	}
}
