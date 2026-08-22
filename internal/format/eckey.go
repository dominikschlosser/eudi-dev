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

package format

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
)

// ECPublicCoords returns the fixed-width big-endian X and Y coordinates of an
// EC public key, the encoding a JWK uses for "x" and "y". The width follows the
// curve, so the same call serves P-256, P-384 and P-521.
func ECPublicCoords(pub *ecdsa.PublicKey) (x, y []byte, err error) {
	raw, err := pub.Bytes()
	if err != nil {
		return nil, nil, err
	}
	// raw is the SEC1 uncompressed point 0x04 || X || Y, each coordinate the
	// curve width, so the two halves after the prefix are X and Y.
	body := raw[1:]
	half := len(body) / 2
	return body[:half], body[half:], nil
}

// ECPublicKeyFromCoords rebuilds an EC public key from its JWK coordinates and
// checks that the point lies on the curve. The coordinates may arrive shorter
// than the curve width when a leading zero was stripped, so each is left-padded
// into its slot.
func ECPublicKeyFromCoords(curve elliptic.Curve, x, y []byte) (*ecdsa.PublicKey, error) {
	size := (curve.Params().BitSize + 7) / 8
	if len(x) > size || len(y) > size {
		return nil, fmt.Errorf("coordinate longer than the %d-byte curve width", size)
	}
	data := make([]byte, 1+2*size)
	data[0] = 4
	copy(data[1+size-len(x):1+size], x)
	copy(data[1+2*size-len(y):], y)
	return ecdsa.ParseUncompressedPublicKey(curve, data)
}
