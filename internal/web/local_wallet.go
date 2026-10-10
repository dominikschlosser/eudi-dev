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

package web

import (
	"fmt"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

// A decoder that runs alone uses the default wallet.
func loadLocalWallet(store *wallet.WalletStore) (*wallet.Wallet, error) {
	if store == nil {
		store = wallet.NewWalletStore("")
	}
	return store.LoadOrCreate()
}

// The local CA verifies locally issued credentials without a trusted list.
func localWalletTrustAnchors(store *wallet.WalletStore) []trustlist.CertInfo {
	w, err := loadLocalWallet(store)
	if err != nil || w == nil || len(w.CertChain) == 0 {
		return nil
	}
	ca := w.CertChain[len(w.CertChain)-1]
	return []trustlist.CertInfo{{Raw: ca.Raw, PublicKey: ca.PublicKey}}
}

func verifyWithLocalWalletIssuerKey(token *sdjwt.Token, store *wallet.WalletStore) (*sdjwt.VerifyResult, string) {
	if token == nil {
		return nil, ""
	}
	kid, _ := token.Header["kid"].(string)
	if strings.TrimSpace(kid) == "" {
		return nil, ""
	}

	w, err := loadLocalWallet(store)
	if err != nil || w == nil || w.IssuerKey == nil {
		return nil, ""
	}
	if mock.KeyIDForPublicKey(&w.IssuerKey.PublicKey) != strings.TrimSpace(kid) {
		return nil, ""
	}

	return sdjwt.Verify(token, &w.IssuerKey.PublicKey), "local wallet issuer key"
}

// checkCatalogueTrust validates a credential with the trusted lists of its
// entry in the wallet's attestation catalogue, as the wallet does with a
// received credential.
func checkCatalogueTrust(raw string, opts ValidateOpts) CheckResult {
	result := CheckResult{Name: "trust", Status: "skipped"}
	if opts.Offline {
		result.Detail = "Needs the trusted lists of the attestation catalogue"
		result.NeedsNetwork = true
		return result
	}
	w := opts.Wallet
	if w == nil {
		var err error
		if w, err = loadLocalWallet(opts.WalletStore); err != nil || w == nil {
			result.Detail = "No wallet with an attestation catalogue"
			return result
		}
	}
	anchoring, found := w.CheckCatalogueAnchoring(raw)
	switch {
	case !found:
		result.Detail = "The attestation catalogue has no entry for this credential type"
	case anchoring.AnchoredBy != "":
		result.Status = "pass"
		result.Detail = fmt.Sprintf("Anchored by the trusted list %s of the catalogue entry %q", anchoring.AnchoredBy, anchoring.Entry)
	case len(anchoring.Findings) > 0:
		result.Status = "fail"
		result.Detail = strings.Join(anchoring.Findings, " ")
	default:
		result.Detail = fmt.Sprintf("The catalogue entry %q links no readable trusted list. An EAA needs anchors only when the wallet has them (ARF ISSU_10)", anchoring.Entry)
	}
	return result
}
