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
	"fmt"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
)

// mdocMatches builds one match per stored mdoc credential, each under its own
// credential query id, disclosing everything it holds.
func mdocMatches(t *testing.T, w *Wallet) []CredentialMatch {
	t.Helper()
	var matches []CredentialMatch
	for _, c := range w.GetCredentials() {
		if c.Format != "mso_mdoc" {
			continue
		}
		keys := make([]string, 0, len(c.Claims))
		for k := range c.Claims {
			keys = append(keys, k)
		}
		matches = append(matches, CredentialMatch{
			QueryID:      fmt.Sprintf("q%d", len(matches)),
			CredentialID: c.ID,
			Format:       c.Format,
			DocType:      c.DocType,
			SelectedKeys: keys,
		})
	}
	return matches
}

// ISO 18013-7 Annex B carries one mdoc generated nonce per response, in the
// apu of the encrypted response, and the verifier rebuilds every document's
// session transcript from it. A response holding several mdocs therefore has
// to sign them all over the same nonce: a nonce generated per document leaves
// every document but the reported one unverifiable.
func TestISOResponseSignsEveryMDocOverTheReportedNonce(t *testing.T) {
	w := pidBaselineWallet(t)
	w.SessionTranscript = SessionTranscriptISO

	matches := mdocMatches(t, w)
	if len(matches) < 2 {
		t.Fatalf("the baseline holds %d mdoc credentials, want at least 2", len(matches))
	}

	params := PresentationParams{
		Nonce:       "verifier-nonce",
		ClientID:    "x509_hash:example",
		ResponseURI: "https://verifier.example/response",
	}
	result, err := w.CreateVPTokenMap(matches, params)
	if err != nil {
		t.Fatalf("creating the vp_token map: %v", err)
	}
	if result.MDocNonce == "" {
		t.Fatal("ISO mode reported no mdoc generated nonce")
	}

	// What the verifier reconstructs: one transcript, from the one nonce the
	// response carries.
	transcript, err := buildSessionTranscriptISO(params.ClientID, params.ResponseURI, params.Nonce, result.MDocNonce)
	if err != nil {
		t.Fatalf("rebuilding the session transcript: %v", err)
	}

	for _, m := range matches {
		token, ok := result.TokenMap[m.QueryID]
		if !ok {
			t.Fatalf("query %s has no presentation", m.QueryID)
		}
		doc, err := mdoc.Parse(token)
		if err != nil {
			t.Fatalf("query %s: parsing the DeviceResponse: %v", m.QueryID, err)
		}
		if err := mdoc.VerifyDeviceAuth(doc, transcript); err != nil {
			t.Errorf("query %s: device auth does not verify against the reported mdoc nonce: %v", m.QueryID, err)
		}
	}
}
