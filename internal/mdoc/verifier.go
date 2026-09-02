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
	"crypto"
	"fmt"
	"time"

	"github.com/veraison/go-cose"
)

// VerifyResult contains the mDOC verification result.
type VerifyResult struct {
	SignatureValid bool
	Expired        bool
	NotYetValid    bool
	Algorithm      string
	DocType        string
	ValidFrom      *time.Time
	ValidUntil     *time.Time
	Signed         *time.Time
	Errors         []string
	// Warnings records a signature that verifies but rests on a spec deviation
	// worked around here.
	Warnings []string
}

// Verify verifies the mDOC issuerAuth COSE_Sign1 signature.
func Verify(doc *Document, pubKey crypto.PublicKey) *VerifyResult {
	if doc == nil {
		return &VerifyResult{Errors: []string{"no document to verify"}}
	}

	result := &VerifyResult{
		DocType: doc.DocType,
	}

	if doc.IssuerAuth == nil {
		result.Errors = append(result.Errors, "no issuerAuth found")
		return result
	}

	mso := doc.IssuerAuth.MSO
	if mso != nil {
		if mso.DigestAlgorithm == "" {
			// ISO 18013-5 requires digestAlgorithm. Digest verification falls
			// back to SHA-256.
			result.Warnings = append(result.Warnings, "the MSO carries no digestAlgorithm, which ISO 18013-5 requires (assuming SHA-256)")
		}
		if mso.ValidityInfo != nil {
			result.ValidFrom = mso.ValidityInfo.ValidFrom
			result.ValidUntil = mso.ValidityInfo.ValidUntil
			result.Signed = mso.ValidityInfo.Signed

			now := time.Now()
			if mso.ValidityInfo.ValidUntil != nil && now.After(*mso.ValidityInfo.ValidUntil) {
				result.Expired = true
			}
			if mso.ValidityInfo.ValidFrom != nil && now.Before(*mso.ValidityInfo.ValidFrom) {
				result.NotYetValid = true
			}
		}
	}

	if doc.IssuerAuth.ProtectedHeader != nil {
		// COSE algorithm label is 1
		if alg, ok := doc.IssuerAuth.ProtectedHeader[int64(1)]; ok {
			switch v := alg.(type) {
			case int64:
				result.Algorithm = coseAlgName(v)
			case uint64:
				result.Algorithm = coseAlgName(int64(v))
			}
		}
	}

	if result.Algorithm == "" {
		result.Errors = append(result.Errors, "cannot determine COSE algorithm from protected header")
		return result
	}

	coseAlg, ok := coseAlgorithm(result.Algorithm)
	if !ok {
		result.Errors = append(result.Errors, fmt.Sprintf("unsupported COSE algorithm: %s", result.Algorithm))
		return result
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(doc.IssuerAuth.RawCOSE); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("parsing COSE_Sign1: %v", err))
		return result
	}

	verifier, err := cose.NewVerifier(coseAlg, pubKey)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("creating verifier: %v", err))
		return result
	}

	if err := msg.Verify(nil, verifier); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("signature verification failed: %v", err))
		return result
	}

	result.SignatureValid = true
	return result
}

func coseAlgName(id int64) string {
	switch id {
	case -7:
		return "ES256"
	case -35:
		return "ES384"
	case -36:
		return "ES512"
	case -37:
		return "PS256"
	case -257:
		return "RS256"
	default:
		return fmt.Sprintf("unknown(%d)", id)
	}
}

func coseAlgorithm(name string) (cose.Algorithm, bool) {
	switch name {
	case "ES256":
		return cose.AlgorithmES256, true
	case "ES384":
		return cose.AlgorithmES384, true
	case "ES512":
		return cose.AlgorithmES512, true
	case "PS256":
		return cose.AlgorithmPS256, true
	default:
		return 0, false
	}
}
