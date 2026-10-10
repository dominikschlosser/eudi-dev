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
	"crypto"
	"fmt"
	"strings"

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

// credentialTrust is what one validation trusts. Validate resolves it once,
// and every check reads it. A supplied key or trusted list is the only trust
// source. Without one, the trusted list of the credential's entry in the
// wallet's attestation catalogue is.
type credentialTrust struct {
	// keys, issuance and revocation come from the supplied key and trusted
	// list. Issuance services anchor credentials, revocation services their
	// status lists (ETSI TS 119 602 V1.1.1 Table D.3).
	keys                 []crypto.PublicKey
	issuance, revocation []trustlist.CertInfo
	err                  error
	catalogue            wallet.CatalogueAnchoring
	catalogueFound       bool
	noWallet             bool
}

func resolveTrust(raw string, opts ValidateOpts) credentialTrust {
	var t credentialTrust
	t.keys, t.issuance, t.revocation, t.err = suppliedTrust(opts)
	if opts.Offline {
		return t
	}
	w := opts.Wallet
	if w == nil {
		loaded, err := loadLocalWallet(opts.WalletStore)
		if err != nil || loaded == nil {
			t.noWallet = true
			return t
		}
		w = loaded
	}
	t.catalogue, t.catalogueFound = w.CheckCatalogueAnchoring(raw)
	return t
}

func (t credentialTrust) supplied() bool {
	return len(t.keys) > 0 || len(t.issuance) > 0 || len(t.revocation) > 0
}

// catalogueAnchors are the issuance and revocation certificates of the
// catalogue list that anchors the credential. They count only without a
// supplied key or list.
func (t credentialTrust) catalogueAnchors() (issuance, revocation []trustlist.CertInfo, ok bool) {
	if t.supplied() || t.catalogue.AnchoredBy == "" {
		return nil, nil, false
	}
	return trustlist.CertInfos(t.catalogue.IssuanceAnchors), trustlist.CertInfos(t.catalogue.StatusAnchors), true
}

// anchoredBy names the catalogue list that anchors the credential.
func (t credentialTrust) anchoredBy() string {
	return fmt.Sprintf("the trusted list %s of the catalogue entry %q", t.catalogue.AnchoredBy, t.catalogue.Entry)
}

// checkCatalogueTrust validates a credential with the trusted lists of its
// entry in the wallet's attestation catalogue, as the wallet does with a
// received credential.
func checkCatalogueTrust(trust credentialTrust, opts ValidateOpts) CheckResult {
	result := CheckResult{Name: "trust", Status: "skipped"}
	if opts.Offline {
		result.Detail = "Needs the trusted lists of the attestation catalogue"
		result.NeedsNetwork = true
		return result
	}
	if trust.noWallet {
		result.Detail = "No wallet with an attestation catalogue"
		return result
	}
	anchoring := trust.catalogue
	switch {
	case !trust.catalogueFound:
		result.Detail = "The attestation catalogue has no entry for this credential type"
	case anchoring.AnchoredBy != "":
		result.Status = "pass"
		result.Detail = "Anchored by " + trust.anchoredBy()
	case len(anchoring.Findings) > 0:
		result.Status = "fail"
		result.Detail = strings.Join(anchoring.Findings, " ")
	default:
		result.Detail = fmt.Sprintf("The catalogue entry %q links no readable trusted list. An EAA needs anchors only when the wallet has them (ARF ISSU_10)", anchoring.Entry)
	}
	return result
}
