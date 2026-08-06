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

package mdoc

import (
	"crypto/sha256"
	"testing"
)

// docWithDigest builds the smallest document VerifyValueDigests will look at:
// one element in one namespace, against whatever digest the MSO claims for it.
func docWithDigest(raw []byte, signed []byte) *Document {
	return &Document{
		NameSpaces: map[string][]IssuerSignedItem{
			"ns": {{ElementIdentifier: "given_name", DigestID: 1, RawCBOR: raw}},
		},
		IssuerAuth: &IssuerAuth{
			MSO: &MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests:    map[string]map[uint64][]byte{"ns": {1: signed}},
			},
		},
	}
}

// The digest comparison is what stops a holder changing an element value the
// issuer never signed, so it has to reject every way the two can differ, not
// just an equal-length mismatch.
func TestVerifyValueDigests(t *testing.T) {
	raw := []byte("the encoded item")
	correct := sha256.Sum256(raw)

	differs := sha256.Sum256(raw)
	differs[0] ^= 0xff

	cases := []struct {
		name   string
		signed []byte
		wantOK bool
	}{
		{name: "the digest the issuer signed", signed: correct[:], wantOK: true},
		{name: "a different digest", signed: differs[:], wantOK: false},
		// A prefix of the right digest: shorter than the hash, and equal for
		// every byte it has. Comparing only those bytes would accept it.
		{name: "a truncated digest", signed: correct[:16], wantOK: false},
		{name: "an empty digest", signed: []byte{}, wantOK: false},
		{name: "a digest with trailing bytes", signed: append(correct[:], 0x00), wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyValueDigests(docWithDigest(raw, tc.signed))
			if tc.wantOK && err != nil {
				t.Errorf("VerifyValueDigests = %v, want nil", err)
			}
			if !tc.wantOK && err == nil {
				t.Error("VerifyValueDigests accepted an element the issuer did not sign")
			}
		})
	}
}
