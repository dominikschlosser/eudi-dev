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
	"net/http"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/config"
)

// ClientHeader names the client and its release. A submission that carries it
// comes from a client this project ships, which is what tells a current URL
// handler apart from one installed before the wallet asked to be named.
const ClientHeader = config.ClientHeader

// staleClientNotice names what a submission that identifies no page costs, and
// the two ways to fix it.
const staleClientNotice = "This client named neither itself nor a page, so what it submits is offered to every open tab " +
	"rather than the one that started it. Re-register the URL handler with 'eudi wallet register', or send " +
	OwnerHeader + " from your own client to say which page a flow belongs to."

// clientName returns the name a client gives itself, empty when it gives none.
func clientName(r *http.Request) string {
	if r == nil {
		return ""
	}
	raw := strings.TrimSpace(r.Header.Get(ClientHeader))
	name, _, _ := strings.Cut(raw, "/")
	return strings.TrimSpace(name)
}

// noteStaleClient reports a submission that names neither itself nor a page,
// which is what a URL handler installed before the wallet asked for either
// looks like. The activity log is where it goes: such a client dispatches
// headlessly, so its own output reaches nobody, and the log is read in the UI.
func (s *Server) noteStaleClient(r *http.Request) {
	if clientName(r) != "" || requestOwner(r) != "" {
		return
	}
	s.staleClientOnce.Do(func() {
		s.wallet.addProtocolWarning("wallet", "client_names_no_page", staleClientNotice, nil)
	})
}
