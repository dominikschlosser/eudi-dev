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
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/config"
)

// sessionCookieName identifies a browser to a wallet several people reach. It
// authenticates nobody (ADR-0002), and docs/public-demo.md covers it under the
// demo's imprint.
const sessionCookieName = "eudi_session"

// OwnerHeader names the browser a client submits on behalf of. The URL handler
// and the CLI put the same value in the page URL they open and on the call
// they make, which is what ties the two acts together.
const OwnerHeader = config.OwnerHeader

// ownerParam carries it where a header cannot go: the URL a client opens, and
// the event stream.
const ownerParam = "owner"

// newBrowserSession creates a session and sets it on the response. Only the
// handlers that serve a browser call it: a caller that drops the cookie would
// own requests it can never ask for again.
func newBrowserSession(w http.ResponseWriter, r *http.Request, secure bool) string {
	if existing := browserSession(r); existing != "" {
		return existing
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	//nolint:gosec // G124: Secure is set for TLS connections; the wallet also serves plain http on localhost, so it cannot be unconditional.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
	return id
}

func browserSession(r *http.Request) string {
	if r == nil {
		return ""
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie == nil {
		return ""
	}
	return cookie.Value
}

// namedOwner reads the browser a client names on the call it makes.
func namedOwner(r *http.Request) string {
	if r == nil {
		return ""
	}
	return boundedOwner(r.Header.Get(OwnerHeader))
}

// maxOwnerLength is as long as a name from any client this project ships. A
// caller chooses the value, and it ends up as a map key, so it is bounded.
const maxOwnerLength = 128

func boundedOwner(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxOwnerLength {
		return ""
	}
	return value
}

// presentedOwner is what a caller offers as its own, including the query,
// which is how the event stream carries it: EventSource sets no headers.
func presentedOwner(r *http.Request) string {
	if token := namedOwner(r); token != "" {
		return token
	}
	if r == nil {
		return ""
	}
	return boundedOwner(r.URL.Query().Get(ownerParam))
}

// requestOwner is the owner to stamp on a request this call creates. A named
// browser wins, because a client submitting for one holds no cookie from it.
func requestOwner(r *http.Request) string {
	// The header only. /authorize and /credential-offer are addressed by the
	// verifier or the issuer, so a query parameter on them is the
	// counterparty's word about whose browser this is.
	if token := namedOwner(r); token != "" {
		return token
	}
	return browserSession(r)
}

// callerOwners is everything a caller may answer for. A page the URL handler
// opened holds both its own session and the owner that handler named.
func callerOwners(r *http.Request) []string {
	var owners []string
	if session := browserSession(r); session != "" {
		owners = append(owners, session)
	}
	if token := presentedOwner(r); token != "" && !ownedBy(owners, token) {
		owners = append(owners, token)
	}
	return owners
}

// ownsRequest reports whether a caller may see and answer a consent request.
// An unowned one stays visible to everybody, which is what keeps a single-user
// wallet and every client written before this working. Naming the id counts
// too: the wallet handed it to this browser in the redirect, and one that keeps
// no cookie has nothing else to show for it.
func ownsRequest(owners []string, req *ConsentRequest, named string) bool {
	if req == nil {
		return false
	}
	return req.Owner == "" || ownedBy(owners, req.Owner) || (named != "" && req.ID == named)
}

func ownedBy(owners []string, want string) bool {
	for _, v := range owners {
		if v == want {
			return true
		}
	}
	return false
}

// browserSecure reports whether this browser reached the wallet over https. A
// reverse proxy terminates TLS and forwards plain http, so it says so in
// X-Forwarded-Proto. Marking the cookie Secure for a browser that is not on
// https would lose it, and with it every request that browser started.
func (s *Server) browserSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if comma := strings.IndexByte(proto, ','); comma >= 0 {
		proto = proto[:comma]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// withBrowserSession gives the UI a session before it submits anything.
func (s *Server) withBrowserSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPageRequest(r) {
			newBrowserSession(w, r, s.browserSecure(r))
		}
		next.ServeHTTP(w, r)
	})
}

func isPageRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	return r.URL.Path == "/" || r.URL.Path == "/index.html"
}

// namedRequest is the request a caller names by id, which the wallet put in
// the URL it redirected that browser to.
func namedRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.URL.Query().Get("request")
}

// approvingOwner is the browser a presentation asked for mid-issuance belongs
// to. An offer that named none takes the browser that approved it.
func approvingOwner(offerOwner, approverOwner string) string {
	if offerOwner != "" {
		return offerOwner
	}
	return approverOwner
}
