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
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// VerifyValueDigests checks the disclosed items against the digests the issuer
// signed in the MSO. The issuer signature only covers the MSO, so without this
// a holder could change any element value and still present a document whose
// signature verifies.
func VerifyValueDigests(doc *Document) error {
	if doc == nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return fmt.Errorf("document carries no MSO to check digests against")
	}
	mso := doc.IssuerAuth.MSO
	hash, err := digestHasher(mso.DigestAlgorithm)
	if err != nil {
		return err
	}
	if len(doc.NameSpaces) == 0 {
		return fmt.Errorf("document discloses no elements")
	}

	for namespace, items := range doc.NameSpaces {
		digests, ok := mso.ValueDigests[namespace]
		if !ok {
			return fmt.Errorf("the MSO carries no digests for namespace %q", namespace)
		}
		for _, item := range items {
			want, ok := digests[item.DigestID]
			if !ok {
				return fmt.Errorf("element %q has digest id %d, which the MSO does not list",
					item.ElementIdentifier, item.DigestID)
			}
			if len(item.RawCBOR) == 0 {
				return fmt.Errorf("element %q kept no encoded form to hash", item.ElementIdentifier)
			}
			got := hash(item.RawCBOR)
			if len(got) != len(want) || !equalBytes(got, want) {
				return fmt.Errorf("element %q does not match the digest the issuer signed", item.ElementIdentifier)
			}
		}
	}
	return nil
}

// VerifyDeviceAuth checks that the holder signed this presentation for this
// exact request. The signature covers the session transcript, so a response
// captured from one request cannot be replayed into another.
func VerifyDeviceAuth(doc *Document, sessionTranscript []byte) error {
	if doc == nil || doc.DeviceSigned == nil || doc.DeviceSigned.DeviceAuth == nil {
		return fmt.Errorf("presentation carries no device signature")
	}
	if len(doc.DeviceSigned.RawDeviceSignature) == 0 {
		return fmt.Errorf("device authentication is not a signature (deviceMac is not supported)")
	}

	deviceKey, err := DeviceKey(doc)
	if err != nil {
		return err
	}

	// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript,
	// DocType, DeviceNameSpacesBytes], and the payload is Tag24 of its CBOR.
	// The wallet sends empty DeviceNameSpaces, which is what this rebuilds.
	emptyNamespaces, err := tag24(map[string]any{})
	if err != nil {
		return err
	}
	var transcript any
	if err := cbor.Unmarshal(sessionTranscript, &transcript); err != nil {
		return fmt.Errorf("decoding the session transcript: %w", err)
	}
	authentication, err := cbor.Marshal([]any{
		"DeviceAuthentication", transcript, doc.DocType, cbor.RawMessage(emptyNamespaces),
	})
	if err != nil {
		return fmt.Errorf("encoding DeviceAuthentication: %w", err)
	}
	payload, err := tag24Raw(authentication)
	if err != nil {
		return err
	}

	// DeviceAuth carries the COSE_Sign1 untagged.
	var msg cose.UntaggedSign1Message
	if err := msg.UnmarshalCBOR(doc.DeviceSigned.RawDeviceSignature); err != nil {
		return fmt.Errorf("parsing the device signature: %w", err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, deviceKey)
	if err != nil {
		return fmt.Errorf("creating the device signature verifier: %w", err)
	}
	// The payload is detached: the holder signed the DeviceAuthentication the
	// verifier just rebuilt, and the response carries only the signature. It
	// has to be put back before verifying, which is also what makes this check
	// mean anything: a mismatch means the holder signed a different request.
	msg.Payload = payload
	if err := msg.Verify(nil, verifier); err != nil {
		return fmt.Errorf("the device signature does not verify against this request: %w", err)
	}
	return nil
}

// DeviceKey returns the holder key the issuer bound the credential to.
func DeviceKey(doc *Document) (*ecdsa.PublicKey, error) {
	if doc == nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return nil, fmt.Errorf("document carries no MSO")
	}
	info := doc.IssuerAuth.MSO.DeviceKeyInfo
	if info == nil {
		return nil, fmt.Errorf("the MSO names no device key, so the credential is not holder-bound")
	}
	raw, ok := info["deviceKey"]
	if !ok {
		return nil, fmt.Errorf("deviceKeyInfo carries no deviceKey")
	}
	key, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("deviceKey is not a COSE_Key map")
	}

	// COSE_Key for EC2: 1=kty, -1=crv, -2=x, -3=y. CBOR integer keys arrive
	// here as their decimal strings.
	if kty := coseInt(key["1"]); kty != 2 {
		return nil, fmt.Errorf("device key type %d is not EC2", kty)
	}
	if crv := coseInt(key["-1"]); crv != 1 {
		return nil, fmt.Errorf("device key curve %d is not P-256", crv)
	}
	x, xok := key["-2"].([]byte)
	y, yok := key["-3"].([]byte)
	if !xok || !yok {
		return nil, fmt.Errorf("device key is missing its coordinates")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func coseInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	case int:
		return int64(n)
	}
	return 0
}

func digestHasher(alg string) (func([]byte) []byte, error) {
	switch alg {
	case "", "SHA-256":
		return func(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }, nil
	case "SHA-384":
		return func(b []byte) []byte { sum := sha512.Sum384(b); return sum[:] }, nil
	case "SHA-512":
		return func(b []byte) []byte { sum := sha512.Sum512(b); return sum[:] }, nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", alg)
	}
}

func equalBytes(a, b []byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func tag24(value any) ([]byte, error) {
	encoded, err := cbor.Marshal(value)
	if err != nil {
		return nil, err
	}
	return tag24Raw(encoded)
}

func tag24Raw(encoded []byte) ([]byte, error) {
	wrapped, err := cbor.Marshal(cbor.Tag{Number: 24, Content: encoded})
	if err != nil {
		return nil, fmt.Errorf("wrapping in Tag 24: %w", err)
	}
	return wrapped, nil
}
