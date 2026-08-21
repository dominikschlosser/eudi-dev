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

// Package keys loads cryptographic keys from PEM and JWK files.
package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

// DIDReference returns the first of the given key identifiers that is a DID,
// or the empty string when none of them is. Nothing in this toolkit resolves
// one: HAIP 1.0 §6.1.1 has an issuer's signing certificate and its trust chain
// travel in the x5c header, SD-JWT VC resolves iss over HTTPS, and the EUDI
// ecosystem builds on both. A key named only by a DID is therefore a key no
// signature check here can find, which is worth saying rather than reporting
// as a key that happens to be missing.
//
// Recognising such a mechanism without implementing it is the rule of
// [ADR-0013].
//
// [ADR-0013]: docs/adr/0013-only-the-eudi-stack-is-supported.md
func DIDReference(identifiers ...string) string {
	for _, identifier := range identifiers {
		trimmed := strings.TrimSpace(identifier)
		if strings.HasPrefix(trimmed, "did:") {
			return trimmed
		}
	}
	return ""
}

// LoadPublicKey loads a public key from a PEM file or JWK JSON file.
func LoadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	return ParsePublicKey(data)
}

// LoadPrivateKey loads a private key from a PEM file or JWK JSON file.
func LoadPrivateKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	return ParsePrivateKey(data)
}

// ParsePrivateKey parses a private key from PEM or JWK bytes.
func ParsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return parsePEMPrivateBlock(block)
	}
	return ParseJWKPrivate(data)
}

func parsePEMPrivateBlock(block *pem.Block) (crypto.PrivateKey, error) {
	// Try PKCS#8 first (works for EC + RSA)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	// Try EC
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	// Try RSA PKCS#1
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unable to parse PEM private key (tried PKCS#8, EC, PKCS#1)")
}

// ParseJWKPrivate reads a private key from a JWK document, repairing short
// coordinates rather than refusing them: a private JWK is the operator's own
// key file, not a document from a peer. Public keys are held to the spec in
// ParseJWK.
func ParseJWKPrivate(data []byte) (crypto.PrivateKey, error) {
	var jwk josev4.JSONWebKey
	if err := jwk.UnmarshalJSON(padECCoordinates(data)); err != nil {
		return nil, fmt.Errorf("not a valid PEM or JWK: %w", err)
	}
	switch key := jwk.Key.(type) {
	case *ecdsa.PrivateKey:
		return key, nil
	case *rsa.PrivateKey:
		return key, nil
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return nil, fmt.Errorf("JWK carries no private key parameters")
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %T", jwk.Key)
	}
}

// ParsePublicKey parses a public key from PEM or JWK bytes.
func ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return parsePEMBlock(block)
	}
	return ParseJWK(data)
}

func parsePEMBlock(block *pem.Block) (crypto.PublicKey, error) {
	switch block.Type {
	case "PUBLIC KEY", "EC PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
		}
		return key, nil
	}
}

// ParseJWKLenient reads a public key from a JWK whose EC coordinates may be
// shorter than RFC 7518 §6.2.1.2 requires, and reports whether it repaired
// one. Debug path only: the repair plus the finding is more useful than
// refusing to decode. Strict mode must call ParseJWK instead.
func ParseJWKLenient(data []byte) (crypto.PublicKey, bool, error) {
	key, err := ParseJWK(data)
	if err == nil {
		return key, false, nil
	}
	repaired := padECCoordinates(data)
	if bytes.Equal(repaired, data) {
		// Nothing to repair, so the refusal above stands.
		return nil, false, err
	}
	key, err = ParseJWK(repaired)
	if err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// ecCurveSizes is the byte width each curve's coordinates must have in a JWK.
var ecCurveSizes = map[string]int{"P-256": 32, "P-384": 48, "P-521": 66}

// padECCoordinates left pads short EC coordinates to the curve width. A
// coordinate whose leading byte is zero encodes one byte short from anything
// writing big.Int.Bytes() directly, which RFC 7518 §6.2.1.2 disallows and
// go-jose enforces. Whether to repair is the caller's decision.
func padECCoordinates(data []byte) []byte {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return data
	}
	if kty, _ := doc["kty"].(string); kty != "EC" {
		return data
	}
	crv, _ := doc["crv"].(string)
	size, ok := ecCurveSizes[crv]
	if !ok {
		return data
	}
	changed := false
	for _, field := range []string{"x", "y", "d"} {
		encoded, ok := doc[field].(string)
		if !ok {
			continue
		}
		raw, err := format.DecodeBase64URL(encoded)
		if err != nil || len(raw) >= size {
			continue
		}
		padded := make([]byte, size)
		copy(padded[size-len(raw):], raw)
		doc[field] = format.EncodeBase64URL(padded)
		changed = true
	}
	if !changed {
		return data
	}
	repaired, err := json.Marshal(doc)
	if err != nil {
		return data
	}
	return repaired
}

// ParseJWK reads a public key from a JWK document. go-jose does the decoding;
// the type switch keeps this function's contract of EC and RSA only, since
// go-jose also understands OKP and symmetric keys that no caller handles.
func ParseJWK(data []byte) (crypto.PublicKey, error) {
	var jwk josev4.JSONWebKey
	if err := jwk.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("not a valid PEM or JWK: %w", err)
	}
	switch key := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		return key, nil
	case *rsa.PublicKey:
		return key, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %T", jwk.Key)
	}
}
