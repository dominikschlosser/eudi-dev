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
	"net/url"
)

// handleCredentialOfferEndpoint is the wallet's OID4VCI credential offer
// endpoint. It accepts the same `credential_offer` / `credential_offer_uri`
// query parameters that would follow an openid-credential-offer:// scheme, so
// issuers can deliver offers to the wallet's plain web URL. The counterpart
// of the /authorize endpoint for presentation requests. An optional `tx_code`
// parameter supplies the pre-authorized code flow transaction code.
func (s *Server) handleCredentialOfferEndpoint(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	offerParams := url.Values{}
	if v := query.Get("credential_offer"); v != "" {
		offerParams.Set("credential_offer", v)
	}
	if v := query.Get("credential_offer_uri"); v != "" {
		offerParams.Set("credential_offer_uri", v)
	}
	if len(offerParams) == 0 {
		http.Error(w, "missing credential_offer or credential_offer_uri parameter", http.StatusBadRequest)
		return
	}

	s.processOfferURI(w, "openid-credential-offer://?"+offerParams.Encode(), query.Get("tx_code"), isBrowserNavigation(r), false)
}
