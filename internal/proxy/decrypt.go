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

package proxy

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

// DecryptJWEWithCEK decrypts a JWE compact serialization using the provided
// content encryption key (CEK). The CEK is the raw AES key bytes that were
// derived during ECDH-ES key agreement.
// This is intended for debugging: the wallet includes the CEK in a debug
// header so the proxy can decrypt JARM responses.
func DecryptJWEWithCEK(jwe string, cek []byte) ([]byte, error) {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}

	headerB64 := parts[0]
	// parts[1] is the encrypted key (empty for ECDH-ES)
	ivBytes, err := format.DecodeBase64URL(parts[2])
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

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// AAD is the ASCII bytes of the base64url-encoded protected header
	aad := []byte(headerB64)

	// AES-GCM expects ciphertext || tag
	// Concatenated into a new slice: appending to ciphertext would write the
	// tag into its backing array when it has the capacity, corrupting the
	// caller's buffer.
	sealed := slices.Concat(ciphertext, tag)

	plaintext, err := aead.Open(nil, ivBytes, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// DecryptJWEWithJWK decrypts a JWE compact serialization using a JWK private key.
// It performs ECDH-ES key agreement between the JWK private key and the ephemeral
// public key from the JWE header, then derives the CEK via Concat KDF.
func DecryptJWEWithJWK(jwe string, jwkJSON string) ([]byte, error) {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}

	// Parse JWE protected header
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding JWE header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing JWE header: %w", err)
	}

	enc, _ := header["enc"].(string)
	if enc == "" {
		return nil, fmt.Errorf("missing enc in JWE header")
	}

	keyBitLen, err := encKeyBitLen(enc)
	if err != nil {
		return nil, err
	}

	// Parse the recipient's private key from JWK
	privKey, err := parseECPrivateKeyJWK(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing JWK private key: %w", err)
	}

	// Parse the sender's ephemeral public key from JWE header
	epkMap, ok := header["epk"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing epk in JWE header")
	}
	epkPub, err := parseECPublicKeyFromMap(epkMap)
	if err != nil {
		return nil, fmt.Errorf("parsing epk: %w", err)
	}

	// ECDH key agreement
	z, err := privKey.ECDH(epkPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement: %w", err)
	}

	// Decode apu/apv from header (base64url-encoded)
	var apu, apv []byte
	if apuB64, ok := header["apu"].(string); ok {
		apu, _ = format.DecodeBase64URL(apuB64)
	}
	if apvB64, ok := header["apv"].(string); ok {
		apv, _ = format.DecodeBase64URL(apvB64)
	}

	// Derive CEK via Concat KDF
	cek := concatKDF(z, enc, apu, apv, keyBitLen)

	return DecryptJWEWithCEK(jwe, cek)
}

// parseECPrivateKeyJWK parses an EC private key from a JWK JSON string.
func parseECPrivateKeyJWK(jwkJSON string) (*ecdh.PrivateKey, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		D   string `json:"d"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		return nil, err
	}
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	dBytes, err := format.DecodeBase64URL(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("decoding d: %w", err)
	}

	return ecdh.P256().NewPrivateKey(dBytes)
}

// parseECPublicKeyFromMap parses an EC public key from a JWK map (e.g. from a JWE epk header).
func parseECPublicKeyFromMap(m map[string]any) (*ecdh.PublicKey, error) {
	crv, _ := m["crv"].(string)
	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}
	xB64, _ := m["x"].(string)
	yB64, _ := m["y"].(string)
	if xB64 == "" || yB64 == "" {
		return nil, fmt.Errorf("missing x or y coordinate")
	}

	xBytes, err := format.DecodeBase64URL(xB64)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	yBytes, err := format.DecodeBase64URL(yB64)
	if err != nil {
		return nil, fmt.Errorf("decoding y: %w", err)
	}

	// Construct uncompressed point: 0x04 || x || y, then convert to ECDH
	pub := make([]byte, 1+32+32)
	pub[0] = 0x04
	copy(pub[1:33], padTo32(xBytes))
	copy(pub[33:65], padTo32(yBytes))

	ecdhPub, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("constructing ECDH public key: %w", err)
	}
	return ecdhPub, nil
}

// concatKDF derives a key using the Concat KDF from NIST SP 800-56A (RFC 7518 §4.6).
func concatKDF(z []byte, enc string, apu, apv []byte, keyBitLen int) []byte {
	h := sha256.New()

	var round [4]byte
	binary.BigEndian.PutUint32(round[:], 1)
	h.Write(round[:])

	h.Write(z)

	kdfWriteWithLength(h, []byte(enc))
	kdfWriteWithLength(h, apu)
	kdfWriteWithLength(h, apv)

	var suppPub [4]byte
	binary.BigEndian.PutUint32(suppPub[:], uint32(keyBitLen))
	h.Write(suppPub[:])

	derived := h.Sum(nil)
	return derived[:keyBitLen/8]
}

// kdfWriteWithLength writes a 4-byte big-endian length prefix followed by data.
func kdfWriteWithLength(h io.Writer, data []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	h.Write(lenBuf[:])
	if len(data) > 0 {
		h.Write(data)
	}
}

// encKeyBitLen returns the key bit length for the given content encryption algorithm.
func encKeyBitLen(enc string) (int, error) {
	switch enc {
	case "A128GCM":
		return 128, nil
	case "A256GCM":
		return 256, nil
	case "A128CBC-HS256":
		return 256, nil
	default:
		return 0, fmt.Errorf("unsupported content encryption algorithm: %s", enc)
	}
}

// padTo32 left-pads b with zeros to 32 bytes (P-256 coordinate size).
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
