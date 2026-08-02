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

package sdjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jsonutil"
)

// VerifyResult contains the result of signature and validity verification.
type VerifyResult struct {
	SignatureValid bool
	Expired        bool
	NotYetValid    bool
	Algorithm      string
	KeyID          string
	Issuer         string
	ExpiresAt      *time.Time
	IssuedAt       *time.Time
	NotBefore      *time.Time
	Errors         []string
}

// Verify verifies the SD-JWT signature using the provided public key.
func Verify(token *Token, pubKey crypto.PublicKey) *VerifyResult {
	result := &VerifyResult{}

	result.KeyID = jsonutil.GetString(token.Header, "kid")
	result.Algorithm = jsonutil.GetString(token.Header, "alg")
	result.Issuer = jsonutil.GetString(token.Payload, "iss")

	// Parse time claims
	now := time.Now()
	if exp, ok := jsonutil.GetFloat64(token.Payload, "exp"); ok {
		t := time.Unix(int64(exp), 0)
		result.ExpiresAt = &t
		result.Expired = now.After(t)
	}
	if iat, ok := jsonutil.GetFloat64(token.Payload, "iat"); ok {
		t := time.Unix(int64(iat), 0)
		result.IssuedAt = &t
	}
	if nbf, ok := jsonutil.GetFloat64(token.Payload, "nbf"); ok {
		t := time.Unix(int64(nbf), 0)
		result.NotBefore = &t
		result.NotYetValid = now.Before(t)
	}

	// Verify signature
	jwtRaw := strings.SplitN(token.Raw, "~", 2)[0]
	parts := strings.SplitN(jwtRaw, ".", 3)
	if len(parts) != 3 {
		result.Errors = append(result.Errors, "invalid JWT structure")
		return result
	}

	sigInput := []byte(parts[0] + "." + parts[1])
	sig, err := format.DecodeBase64URL(parts[2])
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("decoding signature: %v", err))
		return result
	}

	alg := result.Algorithm
	switch alg {
	case "ES256":
		result.SignatureValid = verifyECDSA(pubKey, sigInput, sig, crypto.SHA256)
	case "ES384":
		result.SignatureValid = verifyECDSA(pubKey, sigInput, sig, crypto.SHA384)
	case "ES512":
		result.SignatureValid = verifyECDSA(pubKey, sigInput, sig, crypto.SHA512)
	case "RS256":
		result.SignatureValid = verifyRSA(pubKey, sigInput, sig, crypto.SHA256)
	case "RS384":
		result.SignatureValid = verifyRSA(pubKey, sigInput, sig, crypto.SHA384)
	case "RS512":
		result.SignatureValid = verifyRSA(pubKey, sigInput, sig, crypto.SHA512)
	case "PS256":
		result.SignatureValid = verifyRSAPSS(pubKey, sigInput, sig, crypto.SHA256)
	default:
		result.Errors = append(result.Errors, fmt.Sprintf("unsupported algorithm: %s", alg))
	}

	if !result.SignatureValid && len(result.Errors) == 0 {
		result.Errors = append(result.Errors, "signature verification failed")
	}

	return result
}

func verifyECDSA(pubKey crypto.PublicKey, sigInput, sig []byte, hash crypto.Hash) bool {
	ecKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	h := hash.New()
	h.Write(sigInput)
	digest := h.Sum(nil)

	// JWS ECDSA signature is r||s (raw, not DER)
	keySize := (ecKey.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keySize {
		return false
	}

	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])

	return ecdsa.Verify(ecKey, digest, r, s)
}

func verifyRSA(pubKey crypto.PublicKey, sigInput, sig []byte, hash crypto.Hash) bool {
	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	h := hash.New()
	h.Write(sigInput)
	return rsa.VerifyPKCS1v15(rsaKey, hash, h.Sum(nil), sig) == nil
}

func verifyRSAPSS(pubKey crypto.PublicKey, sigInput, sig []byte, hash crypto.Hash) bool {
	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	h := hash.New()
	h.Write(sigInput)
	return rsa.VerifyPSS(rsaKey, hash, h.Sum(nil), sig, nil) == nil
}
