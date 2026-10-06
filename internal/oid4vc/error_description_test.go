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

package oid4vc

import "testing"

func TestErrorDescriptionKeepsToTheRFC6749CharacterSet(t *testing.T) {
	for in, want := range map[string]string{
		`client attestation PoP aud "https://x" is not this server`: `client attestation PoP aud 'https://x' is not this server`,
		"OID4VP 1.0 §5.2: nonce is required":                        "OID4VP 1.0 section 5.2: nonce is required",
		"path a\\b\nnext line ✓":                                    "path a/b next line",
	} {
		got := ErrorDescription(in)
		if got != want {
			t.Errorf("ErrorDescription(%q) = %q, want %q", in, got, want)
		}
		for _, r := range got {
			if r < 0x20 || r > 0x7E || r == '"' || r == '\\' {
				t.Errorf("ErrorDescription(%q) keeps %q", in, r)
			}
		}
	}
}
