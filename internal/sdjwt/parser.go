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

// Parse splits and decodes an SD-JWT token.
func Parse(raw string) (*Token, error) {
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

	// Parse disclosures (everything between first and last ~)
	sdAlg := "sha-256"
	if alg, ok := token.Payload["_sd_alg"].(string); ok {
		sdAlg = strings.ToLower(alg)
	}

	for i := 1; i < len(parts); i++ {
		d := strings.TrimSpace(parts[i])
		if d == "" {
			continue
		}

		// Last non-empty part could be a key binding JWT
		if i == len(parts)-1 || (i == len(parts)-2 && parts[len(parts)-1] == "") {
			if strings.Count(d, ".") == 2 {
				// Check if it's a KB-JWT by trying to parse it
				kbJWT, kbErr := parseJWT(d)
				if kbErr == nil {
					if typ, ok := kbJWT.Header["typ"].(string); ok && typ == "kb+jwt" {
						token.KeyBindingJWT = kbJWT
						continue
					}
				}
			}
		}

		disc, err := parseDisclosure(d, sdAlg)
		if err != nil {
			return nil, fmt.Errorf("parsing disclosure %d: %w", i, err)
		}
		token.Disclosures = append(token.Disclosures, *disc)
	}

	// Resolve claims by matching _sd digests
	token.ResolvedClaims = resolveClaims(token.Payload, token.Disclosures)

	// Generate warnings for disclosed claims whose children are all undisclosed
	token.Warnings = checkFullyUndisclosedChildren(token.Disclosures)

	return token, nil
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
				obj, ok := item.(map[string]any)
				if !ok {
					allUndisclosed = false
					break
				}
				ds, ok := obj["..."].(string)
				if !ok || digestMap[ds] {
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

	switch len(arr) {
	case 3:
		// [salt, name, value]
		disc.Salt, _ = arr[0].(string)
		disc.Name, _ = arr[1].(string)
		disc.Value = arr[2]
	case 2:
		// [salt, value]. Array element disclosure
		disc.Salt, _ = arr[0].(string)
		disc.Value = arr[1]
		disc.IsArrayEntry = true
	default:
		return nil, fmt.Errorf("unexpected disclosure array length: %d", len(arr))
	}

	return disc, nil
}

func computeDigest(raw string, sdAlg string) (string, error) {
	var h hash.Hash
	switch sdAlg {
	case "sha-256":
		h = sha256.New()
	case "sha-384":
		h = sha512.New384()
	case "sha-512":
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported _sd_alg: %q", sdAlg)
	}
	h.Write([]byte(raw))
	return format.EncodeBase64URL(h.Sum(nil)), nil
}

// resolveClaims merges disclosures into the payload by matching _sd digests.
func resolveClaims(payload map[string]any, disclosures []Disclosure) map[string]any {
	digestMap := make(map[string]*Disclosure)
	for i := range disclosures {
		digestMap[disclosures[i].Digest] = &disclosures[i]
	}
	return resolveObject(payload, digestMap)
}

func resolveObject(obj map[string]any, digestMap map[string]*Disclosure) map[string]any {
	result := make(map[string]any)

	for k, v := range obj {
		if k == "_sd" || k == "_sd_alg" {
			continue
		}
		result[k] = resolveValue(v, digestMap)
	}

	if sdArr, ok := obj["_sd"].([]any); ok {
		for _, d := range sdArr {
			digest, ok := d.(string)
			if !ok {
				continue
			}
			if disc, found := digestMap[digest]; found && !disc.IsArrayEntry {
				result[disc.Name] = resolveValue(disc.Value, digestMap)
			}
		}
	}

	return result
}

func resolveArray(arr []any, digestMap map[string]*Disclosure) []any {
	var result []any
	for _, item := range arr {
		if obj, ok := item.(map[string]any); ok {
			if digest, ok := obj["..."].(string); ok {
				if disc, found := digestMap[digest]; found && disc.IsArrayEntry {
					result = append(result, resolveValue(disc.Value, digestMap))
					continue
				}
			}
		}
		result = append(result, resolveValue(item, digestMap))
	}
	return result
}

func resolveValue(v any, digestMap map[string]*Disclosure) any {
	switch val := v.(type) {
	case map[string]any:
		return resolveObject(val, digestMap)
	case []any:
		return resolveArray(val, digestMap)
	default:
		return v
	}
}
