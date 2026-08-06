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

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

// These pin what JWK parsing accepts and rejects, so the implementation
// underneath can be replaced without anyone having to take on trust that it
// still reads the same documents. Written against the hand-rolled parsers
// and kept unchanged across the move to a library.

// jwkFor renders a public key as a JWK document the way a peer would send it.
func ecJWK(t *testing.T, key *ecdsa.PublicKey, crv string) []byte {
	t.Helper()
	size := (key.Curve.Params().BitSize + 7) / 8
	doc := map[string]string{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, size))),
		"y":   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, size))),
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Every curve the parser claims to support must survive a round trip with
// its coordinates intact.
func TestParseJWK_ECCurves(t *testing.T) {
	for _, tc := range []struct {
		crv   string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	} {
		t.Run(tc.crv, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseJWK(ecJWK(t, &key.PublicKey, tc.crv))
			if err != nil {
				t.Fatalf("ParseJWK: %v", err)
			}
			got, ok := parsed.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("parsed %T, want *ecdsa.PublicKey", parsed)
			}
			if !got.Equal(&key.PublicKey) {
				t.Error("round trip did not preserve the key")
			}
		})
	}
}

// A coordinate with a leading zero byte is where a parser that trims or
// mispads silently produces a different key.
func TestParseJWK_ECLeadingZeroCoordinate(t *testing.T) {
	for attempt := 0; attempt < 200; attempt++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if key.X.BitLen() > 248 { // not a leading zero byte
			continue
		}
		parsed, err := ParseJWK(ecJWK(t, &key.PublicKey, "P-256"))
		if err != nil {
			t.Fatalf("ParseJWK: %v", err)
		}
		if !parsed.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
			t.Fatal("a key with a short X coordinate did not round trip")
		}
		return
	}
	t.Skip("no short coordinate generated in 200 attempts")
}

func TestParseJWK_RSARoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseJWK(doc)
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	got, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("parsed %T, want *rsa.PublicKey", parsed)
	}
	if !got.Equal(&key.PublicKey) {
		t.Error("round trip did not preserve the RSA key")
	}
}

// What the parser must refuse. A parser that accepts these hands a caller a
// key that is not the one the peer meant.
func TestParseJWK_Rejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
	}{
		{"not JSON", `not json at all`},
		{"unknown key type", `{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`},
		{"missing key type", `{"crv":"P-256","x":"AAAA","y":"AAAA"}`},
		{"unsupported curve", `{"kty":"EC","crv":"P-192","x":"AAAA","y":"AAAA"}`},
		{"x is not base64url", `{"kty":"EC","crv":"P-256","x":"!!!!","y":"AAAA"}`},
		{"y is not base64url", `{"kty":"EC","crv":"P-256","x":"AAAA","y":"!!!!"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseJWK([]byte(tc.doc)); err == nil {
				t.Error("accepted a document it should refuse")
			}
		})
	}
}

// The private form has to come back with the same D, or a signature made
// with the parsed key verifies against nobody.
func TestParseJWKPrivate_ECRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
		"d":   base64.RawURLEncoding.EncodeToString(key.D.FillBytes(make([]byte, 32))),
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseJWKPrivate(doc)
	if err != nil {
		t.Fatalf("ParseJWKPrivate: %v", err)
	}
	got, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("parsed %T, want *ecdsa.PrivateKey", parsed)
	}
	if got.D.Cmp(key.D) != 0 {
		t.Error("private scalar did not survive the round trip")
	}
	if !got.PublicKey.Equal(&key.PublicKey) {
		t.Error("public part did not survive the round trip")
	}
}

// A coordinate shorter than the curve width violates RFC 7518 section
// 6.2.1.2. The strict reading refuses it and the lenient one repairs it and
// says so, which is what lets strict mode reject a sloppy document while the
// debug path still decodes it.
func TestParseJWK_ShortCoordinateStrictVersusLenient(t *testing.T) {
	for attempt := 0; attempt < 20000; attempt++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if key.X.BitLen() > 248 { // no leading zero byte, keep looking
			continue
		}
		doc, err := json.Marshal(map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(key.X.Bytes()), // short
			"y":   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
		})
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseJWK(doc); err == nil {
			t.Error("ParseJWK accepted a coordinate narrower than the curve")
		}

		got, repaired, err := ParseJWKLenient(doc)
		if err != nil {
			t.Fatalf("ParseJWKLenient: %v", err)
		}
		if !repaired {
			t.Error("ParseJWKLenient did not report repairing the padding")
		}
		if !got.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
			t.Error("the repaired key is not the one that was sent")
		}
		return
	}
	t.Fatal("no key with a short X coordinate generated in 20000 attempts")
}

// A conformant document must not be reported as repaired, or every debug-mode
// presentation grows a finding that says nothing.
func TestParseJWKLenient_ReportsNoRepairForAConformantKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, repaired, err := ParseJWKLenient(ecJWK(t, &key.PublicKey, "P-256"))
	if err != nil {
		t.Fatalf("ParseJWKLenient: %v", err)
	}
	if repaired {
		t.Error("reported a repair for a document that needed none")
	}
	if !got.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("round trip did not preserve the key")
	}
}

// Leniency is about padding only. A document that is wrong in some other way
// must still be refused by both readings.
func TestParseJWKLenient_StillRefusesRealErrors(t *testing.T) {
	for _, doc := range []string{
		`{"kty":"EC","crv":"P-192","x":"AAAA","y":"AAAA"}`,
		`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`,
		`not json`,
	} {
		if _, _, err := ParseJWKLenient([]byte(doc)); err == nil {
			t.Errorf("ParseJWKLenient accepted %q", doc)
		}
	}
}
