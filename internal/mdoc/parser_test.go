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
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// buildIssuerSignedCBOR builds a minimal CBOR-encoded IssuerSigned map
// with the given namespace items. Each item is Tag-24 wrapped.
func buildIssuerSignedCBOR(t *testing.T, namespace string, items []map[string]any) []byte {
	t.Helper()

	var taggedItems []cbor.Tag
	for _, item := range items {
		itemBytes, err := cbor.Marshal(item)
		if err != nil {
			t.Fatalf("marshaling item: %v", err)
		}
		taggedItems = append(taggedItems, cbor.Tag{Number: 24, Content: itemBytes})
	}

	issuerSigned := map[string]any{
		"nameSpaces": map[string]any{
			namespace: taggedItems,
		},
	}

	data, err := cbor.Marshal(issuerSigned)
	if err != nil {
		t.Fatalf("marshaling issuerSigned: %v", err)
	}
	return data
}

func TestParseIssuerSigned_DeduplicatesClaims(t *testing.T) {
	items := []map[string]any{
		{"digestID": uint64(1), "random": []byte("r1"), "elementIdentifier": "resident_country", "elementValue": "DE"},
		{"digestID": uint64(2), "random": []byte("r2"), "elementIdentifier": "resident_country", "elementValue": "DE"},
		{"digestID": uint64(3), "random": []byte("r3"), "elementIdentifier": "family_name", "elementValue": "Mustermann"},
	}

	data := buildIssuerSignedCBOR(t, "eu.europa.ec.eudi.pid.1", items)
	doc, err := parseIssuerSigned(data)
	if err != nil {
		t.Fatalf("parseIssuerSigned() error: %v", err)
	}

	ns := doc.NameSpaces["eu.europa.ec.eudi.pid.1"]
	if len(ns) != 2 {
		t.Fatalf("expected 2 unique claims, got %d", len(ns))
	}

	seen := make(map[string]bool)
	for _, item := range ns {
		if seen[item.ElementIdentifier] {
			t.Errorf("duplicate claim %q found", item.ElementIdentifier)
		}
		seen[item.ElementIdentifier] = true
	}
}

func TestParseIssuerSigned_FirstOccurrenceWins(t *testing.T) {
	items := []map[string]any{
		{"digestID": uint64(1), "random": []byte("r1"), "elementIdentifier": "country", "elementValue": "DE"},
		{"digestID": uint64(2), "random": []byte("r2"), "elementIdentifier": "country", "elementValue": "FR"},
	}

	data := buildIssuerSignedCBOR(t, "ns1", items)
	doc, err := parseIssuerSigned(data)
	if err != nil {
		t.Fatalf("parseIssuerSigned() error: %v", err)
	}

	ns := doc.NameSpaces["ns1"]
	if len(ns) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(ns))
	}
	if ns[0].ElementValue != "DE" {
		t.Errorf("expected first value 'DE', got %v", ns[0].ElementValue)
	}
}

func TestParseIssuerAuth_TaggedInput(t *testing.T) {
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26}, // protected: {1: -7} (ES256)
		map[any]any{},            // unprotected
		[]byte("payload"),        // payload
		make([]byte, 64),         // signature (64 bytes for ES256)
	}

	tagged := cbor.Tag{Number: 18, Content: coseArr}

	ia, err := parseIssuerAuth(tagged)
	if err != nil {
		t.Fatalf("parseIssuerAuth(tagged) error: %v", err)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(ia.RawCOSE); err != nil {
		t.Errorf("go-cose UnmarshalCBOR failed on RawCOSE: %v", err)
	}
}

func TestParseIssuerAuth_UntaggedArrayInput(t *testing.T) {
	// Simulate what happens after DeviceResponse roundtrip:
	// issuerAuth arrives as []any (tag stripped during decode→re-encode)
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26}, // protected: {1: -7} (ES256)
		map[any]any{},            // unprotected
		[]byte("payload"),        // payload
		make([]byte, 64),         // signature
	}

	ia, err := parseIssuerAuth(coseArr)
	if err != nil {
		t.Fatalf("parseIssuerAuth([]any) error: %v", err)
	}

	// RawCOSE must include Tag 18 for go-cose
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(ia.RawCOSE); err != nil {
		t.Errorf("go-cose UnmarshalCBOR failed on RawCOSE from []any input: %v", err)
	}
}

func TestParseIssuerAuth_BytesInput(t *testing.T) {
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26},
		map[any]any{},
		[]byte("payload"),
		make([]byte, 64),
	}
	tagged := cbor.Tag{Number: 18, Content: coseArr}
	data, err := cbor.Marshal(tagged)
	if err != nil {
		t.Fatal(err)
	}

	ia, err := parseIssuerAuth(data)
	if err != nil {
		t.Fatalf("parseIssuerAuth([]byte) error: %v", err)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(ia.RawCOSE); err != nil {
		t.Errorf("go-cose UnmarshalCBOR failed on RawCOSE from []byte input: %v", err)
	}
}

func TestParseIssuerAuth_UntaggedBytesInput(t *testing.T) {
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26},
		map[any]any{},
		[]byte("payload"),
		make([]byte, 64),
	}
	data, err := cbor.Marshal(coseArr)
	if err != nil {
		t.Fatal(err)
	}

	ia, err := parseIssuerAuth(data)
	if err != nil {
		t.Fatalf("parseIssuerAuth(untagged []byte) error: %v", err)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(ia.RawCOSE); err != nil {
		t.Errorf("go-cose UnmarshalCBOR failed on RawCOSE from untagged []byte input: %v", err)
	}
}

func TestParseIssuerSignedItem_RawCBORContainsTag24(t *testing.T) {
	// RawCBOR keeps the full Tag-24 encoding, since MSO ValueDigests hash the
	// complete #6.24(bstr .cbor IssuerSignedItem) encoding.
	item := map[string]any{
		"digestID":          uint64(0),
		"random":            []byte("random-salt"),
		"elementIdentifier": "family_name",
		"elementValue":      "Mustermann",
	}

	innerBytes, err := cbor.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}

	data := buildIssuerSignedCBOR(t, "ns1", []map[string]any{item})
	doc, err := parseIssuerSigned(data)
	if err != nil {
		t.Fatalf("parseIssuerSigned() error: %v", err)
	}

	ns := doc.NameSpaces["ns1"]
	if len(ns) != 1 {
		t.Fatalf("expected 1 item, got %d", len(ns))
	}

	if len(ns[0].RawCBOR) <= len(innerBytes) {
		t.Errorf("RawCBOR length %d should be larger than inner bytes length %d (should include Tag-24 wrapper)",
			len(ns[0].RawCBOR), len(innerBytes))
	}

	// 0xd8 0x18 is the Tag-24 prefix.
	if len(ns[0].RawCBOR) < 2 || ns[0].RawCBOR[0] != 0xd8 || ns[0].RawCBOR[1] != 0x18 {
		t.Errorf("RawCBOR should start with Tag-24 CBOR prefix (0xd8 0x18), got %x", ns[0].RawCBOR[:2])
	}

	var decoded cbor.Tag
	if err := cbor.Unmarshal(ns[0].RawCBOR, &decoded); err != nil {
		t.Fatalf("failed to unmarshal RawCBOR as Tag: %v", err)
	}
	if decoded.Number != 24 {
		t.Errorf("expected tag number 24, got %d", decoded.Number)
	}
}

func TestParseIssuerAuth_ExtractsUnprotectedHeader(t *testing.T) {
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26},                         // protected
		map[any]any{int64(33): []byte("cert-der-bytes")}, // unprotected with x5chain
		[]byte("payload"),
		make([]byte, 64),
	}

	ia, err := parseIssuerAuth(cbor.Tag{Number: 18, Content: coseArr})
	if err != nil {
		t.Fatalf("parseIssuerAuth() error: %v", err)
	}

	if ia.UnprotectedHeader == nil {
		t.Fatal("expected UnprotectedHeader to be set")
	}
	if _, ok := ia.UnprotectedHeader[int64(33)]; !ok {
		t.Error("expected x5chain (label 33) in UnprotectedHeader")
	}
}
