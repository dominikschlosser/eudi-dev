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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

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

// ParseJWKPrivate parses a JWK JSON object containing a private key.
func ParseJWKPrivate(data []byte) (crypto.PrivateKey, error) {
	var jwk map[string]any
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("not a valid PEM or JWK: %w", err)
	}

	kty, _ := jwk["kty"].(string)
	switch kty {
	case "EC":
		return parseECJWKPrivate(jwk)
	case "RSA":
		return parseRSAJWKPrivate(jwk)
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", kty)
	}
}

func parseECJWKPrivate(jwk map[string]any) (*ecdsa.PrivateKey, error) {
	pub, err := parseECJWK(jwk)
	if err != nil {
		return nil, err
	}
	dB64, _ := jwk["d"].(string)
	if dB64 == "" {
		return nil, fmt.Errorf("EC JWK missing private key parameter 'd'")
	}
	dBytes, err := format.DecodeBase64URL(dB64)
	if err != nil {
		return nil, fmt.Errorf("decoding d: %w", err)
	}
	return &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(dBytes),
	}, nil
}

func parseRSAJWKPrivate(jwk map[string]any) (*rsa.PrivateKey, error) {
	pub, err := parseRSAJWK(jwk)
	if err != nil {
		return nil, err
	}
	dB64, _ := jwk["d"].(string)
	if dB64 == "" {
		return nil, fmt.Errorf("RSA JWK missing private key parameter 'd'")
	}
	dBytes, err := format.DecodeBase64URL(dB64)
	if err != nil {
		return nil, fmt.Errorf("decoding d: %w", err)
	}
	key := &rsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(dBytes),
	}
	// Parse optional CRT parameters
	if pB64, ok := jwk["p"].(string); ok {
		if pBytes, err := format.DecodeBase64URL(pB64); err == nil {
			key.Primes = append(key.Primes, new(big.Int).SetBytes(pBytes))
		}
	}
	if qB64, ok := jwk["q"].(string); ok {
		if qBytes, err := format.DecodeBase64URL(qB64); err == nil {
			key.Primes = append(key.Primes, new(big.Int).SetBytes(qBytes))
		}
	}
	key.Precompute()
	return key, nil
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

// ParseJWK parses a JWK JSON object into a public key.
func ParseJWK(data []byte) (crypto.PublicKey, error) {
	var jwk map[string]any
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("not a valid PEM or JWK: %w", err)
	}

	kty, _ := jwk["kty"].(string)
	switch kty {
	case "EC":
		return parseECJWK(jwk)
	case "RSA":
		return parseRSAJWK(jwk)
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", kty)
	}
}

func parseECJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	xB64, _ := jwk["x"].(string)
	yB64, _ := jwk["y"].(string)

	xBytes, err := format.DecodeBase64URL(xB64)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	yBytes, err := format.DecodeBase64URL(yB64)
	if err != nil {
		return nil, fmt.Errorf("decoding y: %w", err)
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func parseRSAJWK(jwk map[string]any) (*rsa.PublicKey, error) {
	nB64, _ := jwk["n"].(string)
	eB64, _ := jwk["e"].(string)

	nBytes, err := format.DecodeBase64URL(nB64)
	if err != nil {
		return nil, fmt.Errorf("decoding n: %w", err)
	}
	eBytes, err := format.DecodeBase64URL(eB64)
	if err != nil {
		return nil, fmt.Errorf("decoding e: %w", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}
