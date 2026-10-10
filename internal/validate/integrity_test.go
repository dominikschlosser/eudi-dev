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

package validate

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
)

func TestCheckSDJWTIntegrity_AllMatch(t *testing.T) {
	discRaw1 := base64.RawURLEncoding.EncodeToString([]byte(`["salt1","name","Alice"]`))
	discRaw2 := base64.RawURLEncoding.EncodeToString([]byte(`["salt2","age",30]`))

	digest1 := sha256Sum(discRaw1)
	digest2 := sha256Sum(discRaw2)

	token := &sdjwt.Token{
		Payload: map[string]any{
			"_sd_alg": "sha-256",
			"_sd":     []any{digest1, digest2},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: discRaw1, Name: "name", Value: "Alice", Digest: digest1},
			{Raw: discRaw2, Name: "age", Value: float64(30), Digest: digest2},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSDJWTIntegrity_Mismatch(t *testing.T) {
	discRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt","name","Alice"]`))
	digest := sha256Sum(discRaw)

	token := &sdjwt.Token{
		Payload: map[string]any{
			"_sd": []any{"wrong-digest"},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: discRaw, Name: "name", Value: "Alice", Digest: digest},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSDJWTIntegrity_NoDisclosures(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{"sub": "user"},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "skipped" {
		t.Errorf("expected skipped, got %s", result.Status)
	}
}

func TestCheckSDJWTIntegrity_NestedSD(t *testing.T) {
	discRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt","email","test@example.com"]`))
	digest := sha256Sum(discRaw)

	token := &sdjwt.Token{
		Payload: map[string]any{
			"address": map[string]any{
				"_sd": []any{digest},
			},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: discRaw, Name: "email", Value: "test@example.com", Digest: digest},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "pass" {
		t.Errorf("expected pass for nested _sd, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSDJWTIntegrity_NestedDisclosureValue(t *testing.T) {
	// The address disclosure contains the locality digest in its own _sd array.

	addressDiscRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt-addr","address",{"_sd":["LOCALITY_DIGEST_PLACEHOLDER"]}]`))
	addressDigest := sha256Sum(addressDiscRaw)

	localityDiscRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt-loc","locality","KOELN"]`))
	localityDigest := sha256Sum(localityDiscRaw)

	addressValue := map[string]any{
		"_sd": []any{localityDigest},
	}

	token := &sdjwt.Token{
		Payload: map[string]any{
			"_sd_alg": "sha-256",
			"_sd":     []any{addressDigest},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: addressDiscRaw, Name: "address", Value: addressValue, Digest: addressDigest},
			{Raw: localityDiscRaw, Name: "locality", Value: "KOELN", Digest: localityDigest},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "pass" {
		t.Errorf("expected pass for nested disclosure value with _sd, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSDJWTIntegrity_NestedArrayDisclosure(t *testing.T) {
	// The array disclosure contains element digest placeholders.

	subDiscRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt-de","DE"]`))
	subDigest := sha256Sum(subDiscRaw)

	natDiscRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt-nat","nationalities",[]]`))
	natDigest := sha256Sum(natDiscRaw)

	natValue := []any{
		map[string]any{"...": subDigest},
	}

	token := &sdjwt.Token{
		Payload: map[string]any{
			"_sd": []any{natDigest},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: natDiscRaw, Name: "nationalities", Value: natValue, Digest: natDigest},
			{Raw: subDiscRaw, Value: "DE", Digest: subDigest, IsArrayEntry: true},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "pass" {
		t.Errorf("expected pass for nested array disclosure, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_AllMatch(t *testing.T) {
	rawCBOR1 := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}
	rawCBOR2 := []byte{0xb5, 0x06, 0x07, 0x08, 0x09}

	hash1 := sha256.Sum256(rawCBOR1)
	hash2 := sha256.Sum256(rawCBOR2)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: rawCBOR1},
				{DigestID: 1, ElementIdentifier: "given_name", RawCBOR: rawCBOR2},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: hash1[:],
						1: hash2[:],
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_DigestMismatch(t *testing.T) {
	rawCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: rawCBOR},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: []byte("wrong-digest-value-that-wont-match"),
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

// The issuer signature covers only the MSO, so an element in a namespace the
// MSO does not list has no issuer behind it.
func TestCheckMDOCIntegrity_ElementOutsideTheMSO(t *testing.T) {
	rawCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}
	hash := sha256.Sum256(rawCBOR)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: rawCBOR}},
			"org.example.added": {{DigestID: 0, ElementIdentifier: "vip", RawCBOR: rawCBOR}},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests:    map[string]map[uint64][]byte{"org.iso.18013.5.1": {0: hash[:]}},
			},
		},
	}

	if result := CheckMDOCIntegrity(doc); result.Status != Fail {
		t.Errorf("expected fail for an element outside the MSO, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_NoMSO(t *testing.T) {
	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"ns": {{DigestID: 0, ElementIdentifier: "x"}},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "skipped" {
		t.Errorf("expected skipped, got %s", result.Status)
	}
}

func sha256Sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestCheckSDJWTIntegrity_ArrayElementDisclosure(t *testing.T) {
	discRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt","item1"]`))
	digest := sha256Sum(discRaw)

	token := &sdjwt.Token{
		Payload: map[string]any{
			"items": []any{
				map[string]any{"...": digest},
			},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: discRaw, Value: "item1", Digest: digest, IsArrayEntry: true},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "pass" {
		t.Errorf("expected pass for array element, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_Tag24EncodedRawCBOR(t *testing.T) {
	// MSO ValueDigests hash the full Tag-24 encoding (#6.24(bstr)).
	innerCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}

	// Tag 24 with 5-byte content: 0xd8 0x18 0x45 <5 bytes>
	tag24Bytes := append([]byte{0xd8, 0x18, 0x45}, innerCBOR...)

	hash := sha256.Sum256(tag24Bytes)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: tag24Bytes},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: hash[:],
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "pass" {
		t.Errorf("expected pass for Tag-24 encoded RawCBOR, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_Tag24FailsWithInnerBytesDigest(t *testing.T) {
	// A digest over only the inner bytes must fail.
	innerCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}
	tag24Bytes := append([]byte{0xd8, 0x18, 0x45}, innerCBOR...)

	hashInner := sha256.Sum256(innerCBOR)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: tag24Bytes},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: hashInner[:],
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "fail" {
		t.Errorf("expected fail when digest is over inner bytes but RawCBOR is Tag-24, got %s: %s", result.Status, result.Detail)
	}
}
