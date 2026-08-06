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
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// The two formats state their lifetime in different places. A caller deciding
// whether to renew must not have to know which one it is holding, so both are
// read here and a credential that states nothing is never treated as expiring.
func TestCredentialExpiryReadsBothFormats(t *testing.T) {
	w := generateTestWallet(t)

	sdjwtCred, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:test:expiry:1",
		Claims:    map[string]any{"given_name": "Alice"},
		ExpiresIn: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issuing the sd-jwt: %v", err)
	}
	mdocCred, err := w.IssueCredential(IssueOptions{
		Format: "mdoc", DocType: "eu.europa.ec.eudi.pid.1",
		Claims:    map[string]any{"eu.europa.ec.eudi.pid.1": map[string]any{"given_name": "Alice"}},
		ExpiresIn: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issuing the mdoc: %v", err)
	}

	for name, cred := range map[string]StoredCredential{"sd-jwt": *sdjwtCred.Credential, "mdoc": *mdocCred.Credential} {
		expiry := CredentialExpiry(cred)
		if expiry.IsZero() {
			t.Errorf("%s: no expiry read, so the wallet cannot know when to renew it", name)
			continue
		}
		if delta := time.Until(expiry); delta < 90*time.Minute || delta > 150*time.Minute {
			t.Errorf("%s: expiry is %v away, want about two hours", name, delta.Round(time.Minute))
		}
		if CredentialNeedsRenewal(cred, time.Now()) {
			t.Errorf("%s: a credential valid for two hours was marked as needing renewal", name)
		}
		// Inside the margin it is due, just outside it is not.
		if !CredentialNeedsRenewal(cred, expiry.Add(-renewalMargin/2)) {
			t.Errorf("%s: a credential expiring within the margin was not marked for renewal", name)
		}
		if CredentialNeedsRenewal(cred, expiry.Add(-2*renewalMargin)) {
			t.Errorf("%s: a credential outside the margin was marked for renewal too early", name)
		}
	}
}

func TestCredentialWithoutAStatedLifetimeNeverExpires(t *testing.T) {
	if got := CredentialExpiry(StoredCredential{Format: "dc+sd-jwt", Raw: "not-a-credential"}); !got.IsZero() {
		t.Errorf("an unparsable credential reported expiry %v", got)
	}
	if CredentialNeedsRenewal(StoredCredential{Format: "dc+sd-jwt", Raw: "not-a-credential"}, time.Now()) {
		t.Error("a credential with no stated lifetime was marked for renewal")
	}
}

// The stored order is arrival order, which put a freshly issued credential
// at the bottom of a list that pages ten at a time. Newest first, and stable
// so the same list does not reorder itself between two reads.
func TestSortCredentialsNewestFirst(t *testing.T) {
	// Signed directly rather than through mock.GenerateSDJWT, which always
	// stamps iat with the current time and offers no way to choose it.
	at := func(unix int64) StoredCredential {
		key, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jws.Sign(
			map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"},
			map[string]any{"vct": "urn:example:ordered", "iat": unix},
			key,
		)
		if err != nil {
			t.Fatal(err)
		}
		return StoredCredential{ID: fmt.Sprintf("c%d", unix), Format: "dc+sd-jwt", Raw: raw}
	}

	oldest, middle, newest := at(1000), at(2000), at(3000)
	creds := []StoredCredential{oldest, middle, newest}
	SortCredentialsNewestFirst(creds)

	var order []string
	for _, c := range creds {
		order = append(order, c.ID)
	}
	if order[0] != "c3000" || order[1] != "c2000" || order[2] != "c1000" {
		t.Fatalf("order = %v, want newest first", order)
	}

	// Sorting again must not move anything: an unstable order is what makes
	// a list look like it shuffles itself.
	SortCredentialsNewestFirst(creds)
	if creds[0].ID != "c3000" || creds[2].ID != "c1000" {
		t.Error("a second sort reordered an already sorted list")
	}
}

// A credential that states no issuance time still has to appear, after the
// ones that do, without disturbing its neighbours.
func TestSortCredentialsNewestFirst_UndatedGoLast(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dated, err := jws.Sign(
		map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"},
		map[string]any{"vct": "urn:example:dated", "iat": int64(5000)},
		key,
	)
	if err != nil {
		t.Fatal(err)
	}

	creds := []StoredCredential{
		{ID: "undated-a", Format: "dc+sd-jwt", Raw: "not-a-credential"},
		{ID: "dated", Format: "dc+sd-jwt", Raw: dated},
		{ID: "undated-b", Format: "dc+sd-jwt", Raw: "also-not-a-credential"},
	}
	SortCredentialsNewestFirst(creds)

	if creds[0].ID != "dated" {
		t.Errorf("first = %q, want the credential that states a time", creds[0].ID)
	}
	if creds[1].ID != "undated-a" || creds[2].ID != "undated-b" {
		t.Errorf("undated order = %q, %q, want their original relative order", creds[1].ID, creds[2].ID)
	}
}
