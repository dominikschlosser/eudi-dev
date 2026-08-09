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

package jwe

import (
	"encoding/base64"
	"testing"
)

// An epk whose coordinates are not a point on P-256 must be refused before
// any shared secret is agreed with it. crypto/ecdh enforced this before the
// decoding moved to go-jose and go-jose enforces it now, so this pins the
// behaviour across the change rather than claiming a new one.
func TestParsePublicKeyJWK_RejectsOffCurvePoint(t *testing.T) {
	b := func(n byte) string {
		out := make([]byte, 32)
		out[31] = n
		return base64.RawURLEncoding.EncodeToString(out)
	}
	_, err := ParsePublicKeyJWK(map[string]any{
		"kty": "EC", "crv": "P-256", "x": b(1), "y": b(2),
	})
	if err == nil {
		t.Fatal("accepted a point that is not on the curve")
	}
	t.Logf("refused: %v", err)
}
