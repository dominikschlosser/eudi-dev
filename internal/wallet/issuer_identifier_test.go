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

import "testing"

// RFC 8414 §3.3 requires the metadata issuer to be identical to the
// identifier the metadata was fetched for.
func TestValidateAuthorizationServerIssuerComparesExactly(t *testing.T) {
	if err := validateAuthorizationServerIssuer("https://as.example", map[string]any{"issuer": "https://as.example"}); err != nil {
		t.Fatalf("identical issuer refused: %v", err)
	}
	if err := validateAuthorizationServerIssuer("https://as.example", map[string]any{"issuer": "https://as.example/"}); err == nil {
		t.Fatal("an issuer that differs by a trailing slash was accepted")
	}
}
