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

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// TestRemoteAcceptLeavesTheOfferForTheWallet covers a credential_offer_uri an
// issuer serves once. Whoever reads it first spends it, so the CLI reads
// nothing when a wallet is going to: a read here would leave that wallet with
// a 404 for an offer the user is holding in front of them.
func TestRemoteAcceptLeavesTheOfferForTheWallet(t *testing.T) {
	var offerReads atomic.Int32
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One read only, as the issuer this was found against behaves.
		if offerReads.Add(1) > 1 {
			http.Error(w, `{"message":"Credential offer not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credential_issuer":            "https://issuer.example",
			"credential_configuration_ids": []string{"pid"},
			"grants": map[string]any{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
					"pre-authorized_code": "code",
					"tx_code":             map[string]any{"length": 4},
				},
			},
		})
	}))
	defer issuer.Close()

	var walletCalls atomic.Int32
	walletSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/offers" {
			walletCalls.Add(1)
			// The offer is the wallet's to read, and this stands in for it.
			_, _ = http.Get(issuer.URL + "/offer")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer walletSrv.Close()

	previous := remoteFlag
	remoteFlag = walletSrv.URL
	t.Cleanup(func() { remoteFlag = previous })
	noOpen = true
	t.Cleanup(func() { noOpen = false })

	offerURI := "openid-credential-offer://?credential_offer_uri=" +
		url.QueryEscape(issuer.URL+"/offer")
	// Interactive, which is the case a transaction-code prompt would run in.
	if err := acceptOID4URI(offerURI, dispatchOID4Opts{}); err != nil {
		t.Fatalf("accepting the offer: %v", err)
	}

	if got := walletCalls.Load(); got != 1 {
		t.Fatalf("the wallet was asked %d times, want once", got)
	}
	if got := offerReads.Load(); got != 1 {
		t.Errorf("the offer was read %d times, want once and by the wallet", got)
	}
}
