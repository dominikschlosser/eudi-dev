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

// Package jwe decrypts compact JSON Web Encryption using ECDH-ES.
//
// The wallet decrypts request objects a verifier encrypted to it, and the
// proxy decrypts traffic it is shown a key for. Both agree a shared secret,
// run it through the Concat KDF and open an AEAD, and both used to carry
// their own copy of all three. The key derivation in particular has no margin
// for a copy that drifts: a wrong length prefix or a missing round counter
// yields a key that decrypts nothing, and the failure looks like a bad
// ciphertext rather than a bug here.
package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

// Header is the parsed protected header of a compact JWE.
type Header struct {
	Enc string
	EPK map[string]any
	APU []byte
	APV []byte
	Raw map[string]any
}

// ParseHeader decodes the protected header of a compact JWE.
func ParseHeader(compact string) (Header, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return Header{}, fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return Header{}, fmt.Errorf("decoding JWE header: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(headerBytes, &raw); err != nil {
		return Header{}, fmt.Errorf("parsing JWE header: %w", err)
	}
	h := Header{Raw: raw}
	h.Enc, _ = raw["enc"].(string)
	if h.Enc == "" {
		return Header{}, fmt.Errorf("missing enc in JWE header")
	}
	h.EPK, _ = raw["epk"].(map[string]any)
	// A malformed apu or apv is left empty rather than refused: it changes the
	// derived key, so decryption fails on its own with a clearer error.
	if b64, ok := raw["apu"].(string); ok {
		h.APU, _ = format.DecodeBase64URL(b64)
	}
	if b64, ok := raw["apv"].(string); ok {
		h.APV, _ = format.DecodeBase64URL(b64)
	}
	return h, nil
}

// Decrypt decrypts a compact JWE addressed to key using ECDH-ES.
func Decrypt(compact string, key *ecdh.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("decryption requires a private key")
	}
	header, err := ParseHeader(compact)
	if err != nil {
		return nil, err
	}
	if header.EPK == nil {
		return nil, fmt.Errorf("missing epk in JWE header")
	}
	epk, err := ParsePublicKeyJWK(header.EPK)
	if err != nil {
		return nil, fmt.Errorf("parsing epk: %w", err)
	}
	z, err := key.ECDH(epk)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement: %w", err)
	}
	keyBitLen, err := EncKeyBitLen(header.Enc)
	if err != nil {
		return nil, err
	}
	return DecryptWithCEK(compact, ConcatKDF(z, header.Enc, header.APU, header.APV, keyBitLen))
}

// DecryptWithCEK decrypts a compact JWE whose content encryption key is
// already known, which is how the proxy reads traffic from a key log.
func DecryptWithCEK(compact string, cek []byte) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}
	header, err := ParseHeader(compact)
	if err != nil {
		return nil, err
	}
	switch header.Enc {
	case "A128GCM", "A256GCM":
	default:
		return nil, fmt.Errorf("unsupported content encryption algorithm: %s", header.Enc)
	}

	iv, err := format.DecodeBase64URL(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding IV: %w", err)
	}
	ciphertext, err := format.DecodeBase64URL(parts[3])
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}
	tag, err := format.DecodeBase64URL(parts[4])
	if err != nil {
		return nil, fmt.Errorf("decoding tag: %w", err)
	}
	// The AAD is the ASCII of the encoded protected header, not its bytes.
	return OpenAESGCM(cek, iv, ciphertext, tag, []byte(parts[0]))
}

// OpenAESGCM opens an AES-GCM ciphertext given the tag separately, the way
// JWE carries it.
func OpenAESGCM(key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	// Concatenated into a new slice: appending to ciphertext would write the
	// tag into its backing array when it has the capacity, corrupting the
	// caller's buffer.
	plaintext, err := aead.Open(nil, iv, slices.Concat(ciphertext, tag), aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}
	return plaintext, nil
}

// ConcatKDF derives a content encryption key the way JWA specifies for
// ECDH-ES (NIST SP 800-56A, one round of SHA-256).
func ConcatKDF(z []byte, enc string, apu, apv []byte, keyBitLen int) []byte {
	h := sha256.New()

	// round = 0x00000001
	var round [4]byte
	binary.BigEndian.PutUint32(round[:], 1)
	h.Write(round[:])

	h.Write(z)
	writeWithLength(h, []byte(enc)) // AlgorithmID
	writeWithLength(h, apu)         // PartyUInfo
	writeWithLength(h, apv)         // PartyVInfo

	// SuppPubInfo = keyBitLen (4-byte big-endian)
	var suppPub [4]byte
	binary.BigEndian.PutUint32(suppPub[:], uint32(keyBitLen))
	h.Write(suppPub[:])

	return h.Sum(nil)[:keyBitLen/8]
}

// writeWithLength writes a 4-byte big-endian length prefix followed by data,
// writing just the zero length when data is empty.
func writeWithLength(h io.Writer, data []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	h.Write(lenBuf[:])
	if len(data) > 0 {
		h.Write(data)
	}
}

// EncKeyBitLen returns the content encryption key length for enc.
func EncKeyBitLen(enc string) (int, error) {
	switch enc {
	case "A128GCM":
		return 128, nil
	case "A256GCM":
		return 256, nil
	case "A128CBC-HS256":
		return 256, nil // 128-bit MAC key plus 128-bit encryption key
	default:
		return 0, fmt.Errorf("unsupported content encryption algorithm: %s", enc)
	}
}

// ParsePublicKeyJWK reads a P-256 public key from a JWK map, as carried in an
// epk header.
func ParsePublicKeyJWK(m map[string]any) (*ecdh.PublicKey, error) {
	crv, _ := m["crv"].(string)
	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}
	xB64, _ := m["x"].(string)
	yB64, _ := m["y"].(string)
	if xB64 == "" || yB64 == "" {
		return nil, fmt.Errorf("missing x or y coordinate")
	}
	x, err := format.DecodeBase64URL(xB64)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	y, err := format.DecodeBase64URL(yB64)
	if err != nil {
		return nil, fmt.Errorf("decoding y: %w", err)
	}
	// Uncompressed point: 0x04 || x || y, each coordinate at the curve size.
	point := make([]byte, 0, 65)
	point = append(point, 0x04)
	point = append(point, padTo32(x)...)
	point = append(point, padTo32(y)...)
	return ecdh.P256().NewPublicKey(point)
}

// padTo32 left pads a coordinate to the P-256 size. A JWK may drop leading
// zero bytes, and a short coordinate is not a valid point encoding.
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
