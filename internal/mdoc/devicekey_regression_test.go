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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

// These pin what DeviceKey reads out of an MSO and what it refuses, so the
// COSE_Key decoding underneath can change without anyone having to take on
// trust that a holder-bound credential still resolves to the same key.
// Written against the hand-rolled label decoding.

// msoWithDeviceKey builds the smallest document DeviceKey looks at: the
// display map records that a deviceKey is present, and the CBOR beside it is
// what actually gets decoded.
func msoWithDeviceKey(t *testing.T, coseKey map[any]any) *Document {
	t.Helper()
	raw, err := cbor.Marshal(coseKey)
	if err != nil {
		t.Fatal(err)
	}
	return &Document{
		IssuerAuth: &IssuerAuth{
			MSO: &MSO{
				DeviceKeyInfo: map[string]any{"deviceKey": "present"},
				DeviceKeyCBOR: raw,
			},
		},
	}
}

// coseEC2 is a COSE_Key with the integer labels a real one carries:
// 1=kty, -1=crv, -2=x, -3=y.
func coseEC2(x, y []byte) map[any]any {
	return map[any]any{
		int64(1):  int64(2),
		int64(-1): int64(1),
		int64(-2): x,
		int64(-3): y,
	}
}

// A holder-bound credential must resolve to exactly the key the issuer put
// in it. Anything else and key binding checks the wrong key.
func TestDeviceKey_ResolvesTheBoundKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y, err := format.ECPublicCoords(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	doc := msoWithDeviceKey(t, coseEC2(x, y))

	got, err := DeviceKey(doc)
	if err != nil {
		t.Fatalf("DeviceKey: %v", err)
	}
	if !got.Equal(&key.PublicKey) {
		t.Error("DeviceKey resolved a different key than the one bound")
	}
}

// A coordinate shorter than the curve size is where padding mistakes turn
// into a different point, and where a stricter decoder starts refusing keys
// its predecessor read. Real issuers emit these, because anything encoding a
// big.Int directly drops the leading zero byte. Searched rather than skipped:
// a skip here would hide exactly the regression it exists to catch.
func TestDeviceKey_ShortCoordinate(t *testing.T) {
	for attempt := 0; attempt < 20000; attempt++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		x, y, err := format.ECPublicCoords(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if x[0] != 0 {
			continue
		}
		// Unpadded, the way a lax encoder would write it.
		doc := msoWithDeviceKey(t, coseEC2(bytes.TrimLeft(x, "\x00"), y))
		got, err := DeviceKey(doc)
		if err != nil {
			t.Fatalf("DeviceKey with a short X: %v", err)
		}
		if !got.Equal(&key.PublicKey) {
			t.Fatal("a short X coordinate resolved to a different key")
		}
		return
	}
	t.Fatal("no key with a short X coordinate generated in 20000 attempts")
}

// What DeviceKey must refuse. Returning a key for any of these would report
// a credential as holder-bound when it is not, or bind it to the wrong key.
func TestDeviceKey_Rejects(t *testing.T) {
	valid := make([]byte, 32)
	valid[31] = 1

	for _, tc := range []struct {
		name string
		doc  *Document
	}{
		{"nil document", nil},
		{"no MSO", &Document{IssuerAuth: &IssuerAuth{}}},
		{"no deviceKeyInfo", &Document{IssuerAuth: &IssuerAuth{MSO: &MSO{}}}},
		{"deviceKeyInfo without a deviceKey", &Document{IssuerAuth: &IssuerAuth{MSO: &MSO{DeviceKeyInfo: map[string]any{}}}}},
		{"deviceKey is present but its CBOR is not a COSE_Key", &Document{IssuerAuth: &IssuerAuth{MSO: &MSO{DeviceKeyInfo: map[string]any{"deviceKey": "x"}, DeviceKeyCBOR: []byte{0x01, 0x02}}}}},
		{"key type is not EC2", msoWithDeviceKey(t, map[any]any{
			int64(1): int64(1), int64(-1): int64(1), int64(-2): valid, int64(-3): valid,
		})},
		{"curve is not P-256", msoWithDeviceKey(t, map[any]any{
			int64(1): int64(2), int64(-1): int64(2), int64(-2): valid, int64(-3): valid,
		})},
		{"missing x", msoWithDeviceKey(t, map[any]any{
			int64(1): int64(2), int64(-1): int64(1), int64(-3): valid,
		})},
		{"missing y", msoWithDeviceKey(t, map[any]any{
			int64(1): int64(2), int64(-1): int64(1), int64(-2): valid,
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DeviceKey(tc.doc); err == nil {
				t.Error("DeviceKey accepted an MSO it should refuse")
			}
		})
	}
}

// CBOR decoders differ on the Go type they give an integer, and the label
// values arrive through that. All of these mean EC2 over P-256.
func TestDeviceKey_IntegerLabelTypes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y, err := format.ECPublicCoords(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		kty, crv any
	}{
		{"int64", int64(2), int64(1)},
		{"uint64", uint64(2), uint64(1)},
		{"int", 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := msoWithDeviceKey(t, map[any]any{
				int64(1): tc.kty, int64(-1): tc.crv, int64(-2): x, int64(-3): y,
			})
			got, err := DeviceKey(doc)
			if err != nil {
				t.Fatalf("DeviceKey: %v", err)
			}
			if !got.Equal(&key.PublicKey) {
				t.Error("resolved a different key")
			}
		})
	}
}
