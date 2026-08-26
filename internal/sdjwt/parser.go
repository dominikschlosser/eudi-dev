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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

// Parse splits and decodes an SD-JWT and processes its Disclosures per RFC
// 9901 §7.1, where every MUST-reject condition is an error: "If any step
// fails, the SD-JWT is not valid, and processing MUST be aborted."
//
// It covers steps 3 to 5, which turn Disclosures into claims. The
// Issuer-signed JWT signature is not checked here (see Verify).
func Parse(raw string) (*Token, error) {
	token, err := parseStructure(raw)
	if err != nil {
		return nil, err
	}

	// RFC 9901 §7.1 steps 3 to 5.
	resolved, err := processPayload(token.Payload, token.Disclosures)
	if err != nil {
		return nil, err
	}
	token.ResolvedClaims = resolved

	// Add warnings for disclosed claims whose children are all undisclosed, on
	// top of any structural warning parseStructure already recorded.
	token.Warnings = append(token.Warnings, checkFullyUndisclosedChildren(token.Disclosures)...)

	return token, nil
}

// splitComponents assigns the tilde-separated components after the
// Issuer-signed JWT to Disclosures and to the optional Key Binding JWT.
//
// RFC 9901 §4 gives SD-JWT = JWT "~" *(DISCLOSURE "~"), so no component a
// tilde follows may be empty, and the slot after the final tilde is the
// KB-JWT: "In the case that there is no Key Binding JWT, the last element MUST
// be an empty string and the last separating tilde character MUST NOT be
// omitted."
//
// A single non-empty trailing component that is not a KB-JWT is read as a
// Disclosure whose trailing tilde was dropped, for issuers that emit that. That
// workaround returns a warning naming the deviation so a caller can pass it on.
func splitComponents(components []string) ([]string, *JWT, string, error) {
	if len(components) == 0 {
		return nil, nil, "", nil
	}

	discParts := components
	var kbJWT *JWT
	var warning string
	last := strings.TrimSpace(components[len(components)-1])
	if last == "" {
		discParts = components[:len(components)-1]
	} else if jwt := parseKeyBindingJWT(last); jwt != nil {
		discParts = components[:len(components)-1]
		kbJWT = jwt
	} else {
		// The last component is a Disclosure, so the credential ended without the
		// final tilde. RFC 9901 §4 requires it (the slot after it, empty here when
		// there is no KB-JWT, MUST NOT be omitted).
		warning = "the SD-JWT omits the tilde that RFC 9901 requires after the last disclosure"
	}

	for i, d := range discParts {
		if strings.TrimSpace(d) == "" {
			return nil, nil, "", fmt.Errorf("invalid SD-JWT: component %d between two tildes is empty", i+1)
		}
	}
	return discParts, kbJWT, warning, nil
}

// parseKeyBindingJWT decodes a trailing component as a Key Binding JWT.
// RFC 9901 §4.3 requires the typ header parameter of a KB-JWT to be kb+jwt,
// which is what tells a KB-JWT apart from a Disclosure here.
func parseKeyBindingJWT(component string) *JWT {
	if strings.Count(component, ".") != 2 {
		return nil
	}
	jwt, err := parseJWT(component)
	if err != nil {
		return nil
	}
	if typ, ok := jwt.Header["typ"].(string); !ok || typ != "kb+jwt" {
		return nil
	}
	return jwt
}

// checkFullyUndisclosedChildren warns when a disclosure's value has children
// that are ALL undisclosed (e.g., an array with only {"...": hash} entries
// or an object with only _sd hashes and no resolved sub-claims).
func checkFullyUndisclosedChildren(disclosures []Disclosure) []string {
	digestMap := make(map[string]bool)
	for _, d := range disclosures {
		digestMap[d.Digest] = true
	}

	var warnings []string
	for _, d := range disclosures {
		if d.IsArrayEntry {
			continue
		}
		switch val := d.Value.(type) {
		case []any:
			if len(val) == 0 {
				continue
			}
			allUndisclosed := true
			for _, item := range val {
				ds, isPlaceholder, err := arrayElementDigest(item)
				if err != nil || !isPlaceholder || digestMap[ds] {
					allUndisclosed = false
					break
				}
			}
			if allUndisclosed {
				warnings = append(warnings, fmt.Sprintf("%s is disclosed but all %d array elements are undisclosed", d.Name, len(val)))
			}
		case map[string]any:
			sdArr, ok := val["_sd"].([]any)
			if !ok || len(sdArr) == 0 {
				continue
			}
			// Check if there are any non-_sd keys (i.e., visible sub-claims)
			hasVisibleClaims := false
			for k := range val {
				if k != "_sd" && k != "_sd_alg" {
					hasVisibleClaims = true
					break
				}
			}
			// Also check if any _sd digests are resolved
			if !hasVisibleClaims {
				hasResolved := false
				for _, item := range sdArr {
					if ds, ok := item.(string); ok && digestMap[ds] {
						hasResolved = true
						break
					}
				}
				if !hasResolved {
					warnings = append(warnings, fmt.Sprintf("%s is disclosed but all %d sub-claims are undisclosed", d.Name, len(sdArr)))
				}
			}
		}
	}
	return warnings
}

func parseJWT(raw string) (*JWT, error) {
	header, payload, sig, err := format.ParseJWTParts(raw)
	if err != nil {
		return nil, err
	}
	return &JWT{
		Raw:       raw,
		Header:    header,
		Payload:   payload,
		Signature: sig,
	}, nil
}

func parseDisclosure(raw string, sdAlg string) (*Disclosure, error) {
	decoded, err := format.DecodeBase64URL(raw)
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}

	var arr []any
	if err := json.Unmarshal(decoded, &arr); err != nil {
		return nil, fmt.Errorf("JSON decode: %w", err)
	}

	disc := &Disclosure{
		Raw:     raw,
		Decoded: string(decoded),
	}

	// Compute digest
	digest, err := computeDigest(raw, sdAlg)
	if err != nil {
		return nil, err
	}
	disc.Digest = digest

	// RFC 9901 §4.2.1 requires the salt to be a string and says of the claim
	// name: "It MUST be a string and MUST NOT be _sd, ..., or a claim name
	// existing in the object as a permanently disclosed claim." §4.2.2
	// requires the same salt type for an array element Disclosure.
	switch len(arr) {
	case 3:
		// [salt, name, value]
		salt, ok := arr[0].(string)
		if !ok {
			return nil, fmt.Errorf("salt is not a string")
		}
		name, ok := arr[1].(string)
		if !ok {
			return nil, fmt.Errorf("claim name is not a string")
		}
		disc.Salt = salt
		disc.Name = name
		disc.Value = arr[2]
	case 2:
		// [salt, value]. Array element disclosure
		salt, ok := arr[0].(string)
		if !ok {
			return nil, fmt.Errorf("salt is not a string")
		}
		disc.Salt = salt
		disc.Value = arr[1]
		disc.IsArrayEntry = true
	default:
		return nil, fmt.Errorf("unexpected disclosure array length: %d", len(arr))
	}

	return disc, nil
}

// defaultSDAlg is the hash algorithm RFC 9901 §4.1.1 prescribes when the
// payload carries no _sd_alg: "If the _sd_alg claim is not present at the top
// level, a default value of sha-256 MUST be used."
const defaultSDAlg = "sha-256"

// hashForSDAlg maps an _sd_alg value to its hash. The comparison is
// case-sensitive because RFC 9901 §4.1.1 states "This claim value is a
// case-sensitive string with the hash algorithm identifier", and the
// identifiers come from the "Hash Name String" column of the Named
// Information Hash Algorithm Registry, which spells them in lower case.
func hashForSDAlg(sdAlg string) (func() hash.Hash, error) {
	switch sdAlg {
	case "sha-256":
		return sha256.New, nil
	case "sha-384":
		return sha512.New384, nil
	case "sha-512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported _sd_alg: %q", sdAlg)
	}
}

func computeDigest(raw string, sdAlg string) (string, error) {
	newHash, err := hashForSDAlg(sdAlg)
	if err != nil {
		return "", err
	}
	h := newHash()
	h.Write([]byte(raw))
	return format.EncodeBase64URL(h.Sum(nil)), nil
}

// ReferencedDigests returns every digest the credential refers to: the entries
// of its "_sd" arrays and the array elements of the form {"...": digest}. A
// disclosure whose digest is missing from this set belongs to some other
// credential, so it discloses nothing here.
func ReferencedDigests(token *Token) map[string]bool {
	out := make(map[string]bool)
	if token == nil {
		return out
	}
	collectDigests(token.Payload, out)
	for _, d := range token.Disclosures {
		// A nested disclosure's digest lives inside its parent's value.
		collectDigests(d.Value, out)
	}
	return out
}

func collectDigests(value any, out map[string]bool) {
	switch v := value.(type) {
	case map[string]any:
		if digest, isPlaceholder, err := arrayElementDigest(v); err == nil && isPlaceholder {
			out[digest] = true
			return
		}
		for key, val := range v {
			if key == "_sd" {
				if arr, ok := val.([]any); ok {
					for _, entry := range arr {
						if digest, ok := entry.(string); ok {
							out[digest] = true
						}
					}
				}
				continue
			}
			collectDigests(val, out)
		}
	case []any:
		for _, item := range v {
			collectDigests(item, out)
		}
	}
}

// Inspect decodes an SD-JWT for display without applying the rejection rules
// of RFC 9901 §7.1. A decoder is asked the opposite question from a wallet:
// the credential is already suspected of being wrong, and the point is to see
// what it contains. It returns whatever it could decode, with Violation naming
// the rule that would have rejected it and ResolvedClaims left empty.
//
// Nothing that decides trust may use this.
func Inspect(raw string) (*Token, error) {
	token, err := Parse(raw)
	if err == nil {
		return token, nil
	}

	structural, structuralErr := parseStructure(raw)
	if structuralErr != nil {
		return nil, structuralErr
	}
	structural.Violation = err.Error()
	return structural, nil
}

// parseStructure decodes the parts of an SD-JWT without applying the
// rejection rules that turn a decoded credential into a valid one. It is what
// Parse and Inspect share: the split, the Issuer-signed JWT, the Disclosures
// and the Key Binding JWT.
func parseStructure(raw string) (*Token, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, "~")

	if len(parts) < 1 || parts[0] == "" {
		return nil, fmt.Errorf("invalid SD-JWT: no JWT part found")
	}

	jwt, err := parseJWT(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}

	token := &Token{
		Raw:       raw,
		Header:    jwt.Header,
		Payload:   jwt.Payload,
		Signature: jwt.Signature,
	}

	// RFC 9901 §4.1.1: "This claim value is a case-sensitive string with the
	// hash algorithm identifier." A value that is not a string, or names an
	// algorithm this build cannot compute, fails §7.1 step 2.d ("Check that
	// the _sd_alg claim value is understood").
	sdAlg := defaultSDAlg
	if rawAlg, present := token.Payload["_sd_alg"]; present {
		alg, ok := rawAlg.(string)
		if !ok {
			return nil, fmt.Errorf("_sd_alg is not a string")
		}
		sdAlg = alg
	}
	if _, err := hashForSDAlg(sdAlg); err != nil {
		return nil, err
	}

	discParts, kbJWT, warning, err := splitComponents(parts[1:])
	if err != nil {
		return nil, err
	}
	token.KeyBindingJWT = kbJWT
	if warning != "" {
		token.Warnings = append(token.Warnings, warning)
	}

	for i, d := range discParts {
		disc, err := parseDisclosure(d, sdAlg)
		if err != nil {
			return nil, fmt.Errorf("parsing disclosure %d: %w", i+1, err)
		}
		token.Disclosures = append(token.Disclosures, *disc)
	}

	return token, nil
}
