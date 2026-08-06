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

package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jwe"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
)

func EncryptJWE(payload []byte, recipientKey *ecdsa.PublicKey, kid string, alg string, enc string, apu, apv []byte) (string, []byte, error) {
	return encryptJWE(payload, recipientKey, kid, alg, enc, "", apu, apv)
}

func EncryptJWEWithContentType(payload []byte, recipientKey *ecdsa.PublicKey, kid string, alg string, enc string, cty string, apu, apv []byte) (string, []byte, error) {
	return encryptJWE(payload, recipientKey, kid, alg, enc, cty, apu, apv)
}

// encryptJWE encrypts payload as a compact JWE using ECDH-ES with AES-GCM or AES-CBC-HS.
// recipientKey is the verifier's public EC key, kid identifies it,
// alg is the JWE key agreement algorithm from the JWK (e.g. "ECDH-ES"),
// enc is the content encryption algorithm (e.g. "A128GCM", "A256GCM", "A128CBC-HS256"),
// cty is the optional JWE content type, apu is the Agreement PartyUInfo, and apv is the
// Agreement PartyVInfo. Returns the JWE compact serialization and the derived content
// encryption key (CEK).
func encryptJWE(payload []byte, recipientKey *ecdsa.PublicKey, kid string, alg string, enc string, cty string, apu, apv []byte) (string, []byte, error) {
	keyBitLen, err := jwe.EncKeyBitLen(enc)
	if err != nil {
		return "", nil, err
	}

	// Generate ephemeral EC P-256 key pair
	ephemeralPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	ephemeralPub := ephemeralPriv.PublicKey()

	// Convert recipient ECDSA public key to ECDH
	recipientECDH, err := recipientKey.ECDH()
	if err != nil {
		return "", nil, fmt.Errorf("converting recipient key to ECDH: %w", err)
	}

	// ECDH key agreement
	z, err := ephemeralPriv.ECDH(recipientECDH)
	if err != nil {
		return "", nil, fmt.Errorf("ECDH key agreement: %w", err)
	}

	// Derive key via Concat KDF (NIST SP 800-56A, RFC 7518 §4.6)
	derivedKey := jwe.ConcatKDF(z, enc, apu, apv, keyBitLen)

	// Build protected header
	epkX, epkY := unmarshalECDHPublicKey(ephemeralPub)
	header := map[string]any{
		"alg": alg,
		"enc": enc,
		"kid": kid,
		"epk": map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   format.EncodeBase64URL(epkX),
			"y":   format.EncodeBase64URL(epkY),
		},
	}
	if apu != nil {
		header["apu"] = format.EncodeBase64URL(apu)
	}
	if apv != nil {
		header["apv"] = format.EncodeBase64URL(apv)
	}
	if cty != "" {
		header["cty"] = cty
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling header: %w", err)
	}
	headerB64 := format.EncodeBase64URL(headerJSON)

	var iv, ciphertext, tag []byte

	switch enc {
	case "A128GCM", "A256GCM":
		iv, ciphertext, tag, err = encryptAESGCM(derivedKey, payload, []byte(headerB64))
	case "A128CBC-HS256":
		iv, ciphertext, tag, err = encryptAESCBCHS256(derivedKey, payload, []byte(headerB64))
	default:
		return "", nil, fmt.Errorf("unsupported enc algorithm: %s", enc)
	}
	if err != nil {
		return "", nil, err
	}

	// Compact serialization: header.encryptedKey.iv.ciphertext.tag
	// ECDH-ES has no encrypted key (empty string)
	jweStr := headerB64 + ".." +
		format.EncodeBase64URL(iv) + "." +
		format.EncodeBase64URL(ciphertext) + "." +
		format.EncodeBase64URL(tag)
	return jweStr, derivedKey, nil
}

// encryptAESGCM encrypts with AES-GCM (for A128GCM / A256GCM).
func encryptAESGCM(key, plaintext, aad []byte) (iv, ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	iv = make([]byte, 12) // 96-bit IV
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("generating IV: %w", err)
	}

	sealed := aead.Seal(nil, iv, plaintext, aad)
	ciphertext = sealed[:len(sealed)-aead.Overhead()]
	tag = sealed[len(sealed)-aead.Overhead():]
	return iv, ciphertext, tag, nil
}

// encryptAESCBCHS256 encrypts with AES-128-CBC + HMAC-SHA-256 per RFC 7516 §5.2.6.
// Key layout: derivedKey = MAC_KEY (16 bytes) || ENC_KEY (16 bytes)
func encryptAESCBCHS256(derivedKey, plaintext, aad []byte) (iv, ciphertext, tag []byte, err error) {
	if len(derivedKey) != 32 {
		return nil, nil, nil, fmt.Errorf("A128CBC-HS256 requires 256-bit key, got %d bits", len(derivedKey)*8)
	}

	macKey := derivedKey[:16]
	encKey := derivedKey[16:]

	// Generate 128-bit IV
	iv = make([]byte, aes.BlockSize) // 16 bytes
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("generating IV: %w", err)
	}

	// PKCS#7 padding
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	// AES-CBC encrypt
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	// Compute authentication tag: HMAC-SHA-256(MAC_KEY, AAD || IV || ciphertext || AL)
	// AL = bit length of AAD as 64-bit big-endian
	var al [8]byte
	binary.BigEndian.PutUint64(al[:], uint64(len(aad)*8))

	mac := hmac.New(sha256.New, macKey)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ciphertext)
	mac.Write(al[:])
	fullMAC := mac.Sum(nil)

	// Tag = first 128 bits (16 bytes) of HMAC output
	tag = fullMAC[:16]

	return iv, ciphertext, tag, nil
}

// pkcs7Pad adds PKCS#7 padding to plaintext.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// unmarshalECDHPublicKey extracts the raw x, y coordinates from an ECDH public key.
func unmarshalECDHPublicKey(pub *ecdh.PublicKey) (x, y []byte) {
	raw := pub.Bytes() // uncompressed point: 0x04 || x || y
	coordLen := (len(raw) - 1) / 2
	return raw[1 : 1+coordLen], raw[1+coordLen:]
}

// ecdsaPublicKeyFromJWK reads a peer's P-256 encryption key from the x and y
// a JWK carried.
//
// mode decides what happens to a coordinate narrower than the curve, which
// RFC 7518 does not allow. Strict refuses it, because a wallet held to the
// specification should not quietly accept a document that breaks it. Debug
// repairs it and reports that it did, so the flow reaches the step worth
// watching and the violation is still visible in the finding.
func ecdsaPublicKeyFromJWK(mode ValidationMode, xB64, yB64 string) (*ecdsa.PublicKey, string, error) {
	doc, err := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256", "x": xB64, "y": yB64,
	})
	if err != nil {
		return nil, "", fmt.Errorf("encoding JWK: %w", err)
	}

	if mode == ValidationModeStrict {
		parsed, err := keys.ParseJWK(doc)
		if err != nil {
			return nil, "", err
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return nil, "", fmt.Errorf("JWK is not an EC key")
		}
		return key, "", nil
	}

	parsed, repaired, err := keys.ParseJWKLenient(doc)
	if err != nil {
		return nil, "", err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("JWK is not an EC key")
	}
	finding := ""
	if repaired {
		finding = "encryption JWK has an EC coordinate narrower than P-256 requires (RFC 7518 6.2.1.2); it was left padded to read the key"
	}
	return key, finding, nil
}
