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
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

// localWalletTrustAnchors returns the local wallet's CA certificates as
// trust list entries. Credentials issued by the local wallet then validate
// with a full chain, without a network lookup or an explicit trust list.
func localWalletTrustAnchors() []trustlist.CertInfo {
	store := wallet.NewWalletStore("")
	w, err := store.LoadOrCreate()
	if err != nil || w == nil || len(w.CertChain) == 0 {
		return nil
	}
	ca := w.CertChain[len(w.CertChain)-1]
	return []trustlist.CertInfo{{Raw: ca.Raw, PublicKey: ca.PublicKey}}
}

func verifyWithLocalWalletIssuerKey(token *sdjwt.Token) (*sdjwt.VerifyResult, string) {
	if token == nil {
		return nil, ""
	}
	kid, _ := token.Header["kid"].(string)
	if strings.TrimSpace(kid) == "" {
		return nil, ""
	}

	store := wallet.NewWalletStore("")
	w, err := store.LoadOrCreate()
	if err != nil || w == nil || w.IssuerKey == nil {
		return nil, ""
	}
	if mock.KeyIDForPublicKey(&w.IssuerKey.PublicKey) != strings.TrimSpace(kid) {
		return nil, ""
	}

	return sdjwt.Verify(token, &w.IssuerKey.PublicKey), "local wallet issuer key"
}
