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
	"sort"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
)

// renewalMargin is how long before expiry a credential is worth renewing. It
// only has to cover the round trip to the issuer.
const renewalMargin = time.Minute

// CredentialExpiry reports when a credential stops being valid, or the zero
// time when it says nothing. The formats differ: an SD-JWT carries exp in its
// payload, an mdoc validUntil in its MSO.
func CredentialExpiry(cred StoredCredential) time.Time {
	switch cred.Format {
	case "mso_mdoc":
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
			return time.Time{}
		}
		validity := doc.IssuerAuth.MSO.ValidityInfo
		if validity == nil || validity.ValidUntil == nil {
			return time.Time{}
		}
		return *validity.ValidUntil
	default:
		token, err := sdjwt.ParseLenient(cred.Raw)
		if err != nil || token == nil {
			return time.Time{}
		}
		exp, ok := token.Payload["exp"].(float64)
		if !ok || exp <= 0 {
			return time.Time{}
		}
		return time.Unix(int64(exp), 0)
	}
}

// CredentialNeedsRenewal reports whether a credential is close enough to
// expiry to be worth renewing now. A credential without a stated lifetime
// never is.
func CredentialNeedsRenewal(cred StoredCredential, now time.Time) bool {
	expiry := CredentialExpiry(cred)
	if expiry.IsZero() {
		return false
	}
	return now.Add(renewalMargin).After(expiry)
}

// CredentialIssuedAt is when a credential says it was issued, or the zero time
// when it says nothing. Same split as CredentialExpiry: iat in a JWT payload,
// signed in an mdoc MSO.
func CredentialIssuedAt(cred StoredCredential) time.Time {
	switch cred.Format {
	case "mso_mdoc":
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
			return time.Time{}
		}
		validity := doc.IssuerAuth.MSO.ValidityInfo
		if validity == nil || validity.Signed == nil {
			return time.Time{}
		}
		return *validity.Signed
	default:
		token, err := sdjwt.ParseLenient(cred.Raw)
		if err != nil || token == nil {
			return time.Time{}
		}
		iat, ok := token.Payload["iat"].(float64)
		if !ok || iat <= 0 {
			return time.Time{}
		}
		return time.Unix(int64(iat), 0)
	}
}

// SortCredentialsNewestFirst orders credentials by issuance time, newest
// first. Credentials stating no issuance time sort last. Ties keep arrival
// order (ids are random, so they are no tiebreaker).
func SortCredentialsNewestFirst(creds []StoredCredential) {
	issued := make(map[string]time.Time, len(creds))
	for _, c := range creds {
		issued[c.ID] = CredentialIssuedAt(c)
	}
	sort.SliceStable(creds, func(i, j int) bool {
		a, b := issued[creds[i].ID], issued[creds[j].ID]
		if a.Equal(b) {
			return false
		}
		if a.IsZero() {
			return false
		}
		if b.IsZero() {
			return true
		}
		return a.After(b)
	})
}
