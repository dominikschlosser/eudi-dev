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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func TestNameCOSEHeader(t *testing.T) {
	named := NameCOSEHeader(map[string]any{"1": int64(-7), "4": []byte("key-1"), "99": "left alone"})

	if named["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", named["alg"])
	}
	if _, ok := named["kid"]; !ok {
		t.Errorf("kid was not named: %v", named)
	}
	if named["99"] != "left alone" {
		t.Errorf("an unknown label was not passed through: %v", named)
	}
}

func TestNameCOSEHeaderIsEmptyForAnEmptyHeader(t *testing.T) {
	if got := NameCOSEHeader(nil); got != nil {
		t.Errorf("NameCOSEHeader(nil) = %v, want nil", got)
	}
}

// An unregistered algorithm identifier survives as its number.
func TestNameCOSEHeaderKeepsAnUnknownAlgorithm(t *testing.T) {
	named := NameCOSEHeader(map[string]any{"1": int64(-999)})

	if named["alg"] != int64(-999) {
		t.Errorf("alg = %v, want the raw identifier", named["alg"])
	}
}

// testCertDER builds a document signer issued by an IACA, so that subject and
// issuer are genuinely different: x509.CreateCertificate takes the issuer from
// the parent it signs with, not from the template's Issuer field.
func testCertDER(t *testing.T) []byte {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test IACA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "Test Document Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// x5chain arrives as raw DER, which tells a reader nothing. It is replaced by
// something placeable, and a chain that does not parse still has to appear.
func TestNameCOSEHeaderDescribesCertificates(t *testing.T) {
	der := testCertDER(t)

	t.Run("a single certificate", func(t *testing.T) {
		named := NameCOSEHeader(map[string]any{"33": der})
		chain, ok := named["x5chain"].([]any)
		if !ok || len(chain) != 1 {
			t.Fatalf("x5chain = %#v, want one described certificate", named["x5chain"])
		}
		desc, ok := chain[0].(map[string]any)
		if !ok {
			t.Fatalf("entry = %#v, want a description map", chain[0])
		}
		if desc["subject"] != "CN=Test Document Signer" {
			t.Errorf("subject = %v", desc["subject"])
		}
		if desc["issuer"] != "CN=Test IACA" {
			t.Errorf("issuer = %v", desc["issuer"])
		}
		if desc["serial"] != "4242" {
			t.Errorf("serial = %v, want 4242", desc["serial"])
		}
	})

	t.Run("a chain of several", func(t *testing.T) {
		named := NameCOSEHeader(map[string]any{"33": []any{der, der}})
		chain, ok := named["x5chain"].([]any)
		if !ok || len(chain) != 2 {
			t.Fatalf("x5chain = %#v, want two entries", named["x5chain"])
		}
	})

	t.Run("bytes that are not a certificate", func(t *testing.T) {
		named := NameCOSEHeader(map[string]any{"33": []byte("nonsense")})
		chain, ok := named["x5chain"].([]any)
		if !ok || len(chain) != 1 {
			t.Fatalf("x5chain = %#v", named["x5chain"])
		}
		if _, isString := chain[0].(string); !isString {
			t.Errorf("entry = %#v, want it reported as unparseable", chain[0])
		}
	})

	t.Run("something that is neither", func(t *testing.T) {
		named := NameCOSEHeader(map[string]any{"33": 42})
		if named["x5chain"] != 42 {
			t.Errorf("x5chain = %#v, want the value passed through", named["x5chain"])
		}
	})
}

func TestNameCOSEKey(t *testing.T) {
	named := NameCOSEKey(map[string]any{
		"1":  int64(2),
		"-1": int64(1),
		"-2": []byte{1, 2, 3},
		"-3": []byte{4, 5, 6},
		"3":  int64(-7),
	})

	if named["kty"] != "EC2" {
		t.Errorf("kty = %v, want EC2", named["kty"])
	}
	if named["crv"] != "P-256" {
		t.Errorf("crv = %v, want P-256", named["crv"])
	}
	if named["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", named["alg"])
	}
	if named["x"] != base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}) {
		t.Errorf("x = %v, want it base64url encoded", named["x"])
	}
	if named["y"] != base64.RawURLEncoding.EncodeToString([]byte{4, 5, 6}) {
		t.Errorf("y = %v, want it base64url encoded", named["y"])
	}
}

func TestNameCOSEKeyIsEmptyForAnEmptyKey(t *testing.T) {
	if got := NameCOSEKey(map[string]any{}); got != nil {
		t.Errorf("NameCOSEKey({}) = %v, want nil", got)
	}
}

func TestNameCOSEKeyKeepsUnknownValues(t *testing.T) {
	named := NameCOSEKey(map[string]any{"1": int64(99), "-1": int64(99), "77": "other"})

	if named["kty"] != int64(99) {
		t.Errorf("kty = %v, want the raw value", named["kty"])
	}
	if named["crv"] != int64(99) {
		t.Errorf("crv = %v, want the raw value", named["crv"])
	}
	if named["77"] != "other" {
		t.Errorf("unknown label = %v, want it passed through", named["77"])
	}
}

// The thumbprint identifies a device key the way a kid does elsewhere, so it
// has to be stable for one key and different for another.
func TestDeviceKeyThumbprint(t *testing.T) {
	key := testKey(t)

	first := DeviceKeyThumbprint(&key.PublicKey)
	if first == "" {
		t.Fatal("thumbprint is empty")
	}
	if second := DeviceKeyThumbprint(&key.PublicKey); first != second {
		t.Error("the same key produced two different thumbprints")
	}
	if other := DeviceKeyThumbprint(&testKey(t).PublicKey); other == first {
		t.Error("two different keys share a thumbprint")
	}
	if got := DeviceKeyThumbprint(nil); got != "" {
		t.Errorf("DeviceKeyThumbprint(nil) = %q, want empty", got)
	}
}

func TestItemDigest(t *testing.T) {
	raw := []byte("the encoded item")
	signed := sha256.Sum256(raw)
	doc := docWithDigest(raw, signed[:])

	got, want, err := ItemDigest(doc, "ns", doc.NameSpaces["ns"][0])
	if err != nil {
		t.Fatalf("ItemDigest: %v", err)
	}
	if string(got) != string(want) {
		t.Error("the recomputed digest does not match the one the issuer signed")
	}
	if string(got) != string(signed[:]) {
		t.Error("the recomputed digest is not the SHA-256 of the encoded item")
	}
}

func TestItemDigestErrors(t *testing.T) {
	raw := []byte("item")
	signed := sha256.Sum256(raw)

	t.Run("no MSO", func(t *testing.T) {
		if _, _, err := ItemDigest(&Document{}, "ns", IssuerSignedItem{}); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("an element that kept no encoded form", func(t *testing.T) {
		doc := docWithDigest(raw, signed[:])
		if _, _, err := ItemDigest(doc, "ns", IssuerSignedItem{DigestID: 1}); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("an unsupported digest algorithm", func(t *testing.T) {
		doc := docWithDigest(raw, signed[:])
		doc.IssuerAuth.MSO.DigestAlgorithm = "MD5"
		if _, _, err := ItemDigest(doc, "ns", doc.NameSpaces["ns"][0]); err == nil {
			t.Error("expected an error")
		}
	})

	// A namespace the MSO says nothing about yields no signed digest rather
	// than an error, and the empty want is what marks it unverifiable.
	t.Run("a namespace the MSO does not cover", func(t *testing.T) {
		doc := docWithDigest(raw, signed[:])
		_, want, err := ItemDigest(doc, "other", doc.NameSpaces["ns"][0])
		if err != nil {
			t.Fatalf("ItemDigest: %v", err)
		}
		if want != nil {
			t.Errorf("want = %x, expected nothing signed for that namespace", want)
		}
	})
}

func TestDigestHasher(t *testing.T) {
	payload := []byte("payload")
	sum256 := sha256.Sum256(payload)
	sum384 := sha512.Sum384(payload)
	sum512 := sha512.Sum512(payload)

	tests := []struct {
		alg  string
		want []byte
	}{
		// An MSO that names no algorithm means SHA-256.
		{"", sum256[:]},
		{"SHA-256", sum256[:]},
		{"SHA-384", sum384[:]},
		{"SHA-512", sum512[:]},
	}
	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			hash, err := digestHasher(tt.alg)
			if err != nil {
				t.Fatalf("digestHasher(%q): %v", tt.alg, err)
			}
			if string(hash(payload)) != string(tt.want) {
				t.Errorf("digest for %q does not match", tt.alg)
			}
		})
	}

	if _, err := digestHasher("SHA-1"); err == nil {
		t.Error("an unsupported digest algorithm was accepted")
	}
}

// CBOR decoders hand back whichever integer type fits, so every one of them
// has to read back as the same number.
func TestCOSEInt(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want int64
	}{
		{"int64", int64(-7), -7},
		{"uint64", uint64(7), 7},
		{"int", -35, -35},
		{"not a number", "ES256", 0},
		{"nil", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := coseInt(tt.in); got != tt.want {
				t.Errorf("coseInt(%#v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}
