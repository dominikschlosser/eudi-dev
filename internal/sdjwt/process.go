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

import "fmt"

// processor carries the state RFC 9901 §7.1 step 3 needs while it walks the
// Issuer-signed JWT payload and the Disclosure values reached from it.
type processor struct {
	// byDigest maps a Disclosure digest to the Disclosure that produced it.
	byDigest map[string]*Disclosure
	// seen records every embedded digest encountered anywhere in the
	// credential, for step 4.
	seen map[string]bool
	// used records the digests that resolved to a Disclosure, for step 5.
	used map[string]bool
}

// processPayload applies RFC 9901 §7.1 steps 3 to 5 and returns the Processed
// SD-JWT Payload. Any condition the specification marks MUST-reject is
// returned as an error instead of being silently repaired or skipped, because
// §7.1 closes with "If any step fails, the SD-JWT is not valid, and
// processing MUST be aborted."
func processPayload(payload map[string]any, disclosures []Disclosure) (map[string]any, error) {
	p := &processor{
		byDigest: make(map[string]*Disclosure, len(disclosures)),
		seen:     make(map[string]bool),
		used:     make(map[string]bool),
	}
	for i := range disclosures {
		d := &disclosures[i]
		// RFC 9901 §4: "A Holder MUST NOT send a Disclosure that was not
		// included in the issued SD-JWT or send a Disclosure more than once."
		if _, duplicate := p.byDigest[d.Digest]; duplicate {
			return nil, fmt.Errorf("disclosure %s is present more than once", shortDigest(d.Digest))
		}
		p.byDigest[d.Digest] = d
	}

	resolved, err := p.object(payload, true)
	if err != nil {
		return nil, err
	}

	// Step 5: "If any Disclosure was not referenced by digest value in the
	// Issuer-signed JWT (directly or recursively via other Disclosures), the
	// SD-JWT MUST be rejected."
	for i := range disclosures {
		d := &disclosures[i]
		if !p.used[d.Digest] {
			return nil, fmt.Errorf("disclosure %s (%s) is not referenced by any digest in the credential", shortDigest(d.Digest), disclosureLabel(d))
		}
	}

	return resolved, nil
}

// object processes one JSON object of the payload: it keeps the claims that
// are already there, inserts the claims disclosed by the digests in its "_sd"
// array, and drops the "_sd" key itself (§7.1 steps 3.b.i, 3.c.ii and 3.e).
// top marks the SD-JWT payload itself, the only object where _sd_alg belongs.
func (p *processor) object(obj map[string]any, top bool) (map[string]any, error) {
	result := make(map[string]any, len(obj))

	for k, v := range obj {
		switch k {
		case "_sd":
			// Step 3.e: "Remove all _sd keys and their contents from the
			// Issuer-signed JWT payload."
			continue
		case "_sd_alg":
			// Step 3.f removes _sd_alg from the payload. RFC 9901 §4.1.1
			// says of the claim: "When used, this claim MUST appear at the
			// top level of the SD-JWT payload. It MUST NOT be used in any
			// object nested within the payload."
			if top {
				continue
			}
			return nil, fmt.Errorf("_sd_alg appears in an object nested within the payload")
		}
		resolved, err := p.value(v)
		if err != nil {
			return nil, err
		}
		result[k] = resolved
	}

	rawSD, present := obj["_sd"]
	if !present {
		return result, nil
	}
	// RFC 9901 §4.2.4.1: "The _sd key MUST refer to an array of strings, each
	// string being a digest of a Disclosure or a decoy digest".
	entries, ok := rawSD.([]any)
	if !ok {
		return nil, fmt.Errorf(`"_sd" is not an array`)
	}

	for _, entry := range entries {
		digest, ok := entry.(string)
		if !ok {
			return nil, fmt.Errorf(`"_sd" contains an entry that is not a string`)
		}
		if err := p.markSeen(digest); err != nil {
			return nil, err
		}
		disc, found := p.byDigest[digest]
		if !found {
			// Step 3.c.i: "If no such Disclosure can be found, the digest
			// MUST be ignored." That covers decoy digests (§4.2.5) and
			// claims the Holder withheld.
			continue
		}
		if disc.IsArrayEntry {
			// Step 3.c.ii.1: "If the contents of the respective Disclosure is
			// not a JSON array of three elements (salt, claim name, claim
			// value), the SD-JWT MUST be rejected."
			return nil, fmt.Errorf("disclosure %s is referenced from an _sd array but holds two elements instead of a salt, claim name and claim value", shortDigest(digest))
		}
		if disc.Name == "_sd" || disc.Name == "..." {
			// Step 3.c.ii.2: "If the claim name is _sd or ..., the SD-JWT
			// MUST be rejected."
			return nil, fmt.Errorf("disclosure %s discloses a claim named %q", shortDigest(digest), disc.Name)
		}
		if _, exists := result[disc.Name]; exists {
			// Step 3.c.ii.3: "If the claim name already exists at the level
			// of the _sd key, the SD-JWT MUST be rejected." Without this a
			// Disclosure can shadow a signed claim such as vct, leaving the
			// resolved claims and the payload stating different things.
			return nil, fmt.Errorf("disclosure %s discloses claim %q, which already exists at the level of its _sd key", shortDigest(digest), disc.Name)
		}
		p.used[digest] = true

		// Step 3.c.ii.5 recurses into the disclosed value before it lands in
		// the payload, so nested digests are resolved and checked as well.
		resolved, err := p.value(disc.Value)
		if err != nil {
			return nil, err
		}
		// Step 3.c.ii.4: "Insert, at the level of the _sd key, a new claim
		// using the claim name and claim value from the Disclosure."
		result[disc.Name] = resolved
	}

	return result, nil
}

// array processes one JSON array: each {"...": digest} placeholder is
// replaced by its disclosed value, and a placeholder with no Disclosure is
// dropped (§7.1 steps 3.c.iii and 3.d).
func (p *processor) array(arr []any) ([]any, error) {
	result := make([]any, 0, len(arr))

	for _, item := range arr {
		digest, isPlaceholder, err := arrayElementDigest(item)
		if err != nil {
			return nil, err
		}
		if !isPlaceholder {
			resolved, err := p.value(item)
			if err != nil {
				return nil, err
			}
			result = append(result, resolved)
			continue
		}

		if err := p.markSeen(digest); err != nil {
			return nil, err
		}
		disc, found := p.byDigest[digest]
		if !found {
			// Step 3.d: "Remove all array elements for which the digest was
			// not found in the previous step." Leaving the placeholder in
			// place would present a digest to the application as if it were
			// the element's value.
			continue
		}
		if !disc.IsArrayEntry {
			// Step 3.c.iii.1: "If the contents of the respective Disclosure
			// is not a JSON array of two elements (salt, value), the SD-JWT
			// MUST be rejected."
			return nil, fmt.Errorf("disclosure %s is referenced from an array element but holds three elements instead of a salt and a value", shortDigest(digest))
		}
		p.used[digest] = true

		// Step 3.c.iii.3 recurses into the disclosed value.
		resolved, err := p.value(disc.Value)
		if err != nil {
			return nil, err
		}
		// Step 3.c.iii.2: "Replace the array element with the value from the
		// Disclosure."
		result = append(result, resolved)
	}

	return result, nil
}

func (p *processor) value(v any) (any, error) {
	switch val := v.(type) {
	case map[string]any:
		return p.object(val, false)
	case []any:
		return p.array(val)
	default:
		return v, nil
	}
}

// markSeen records an embedded digest and enforces RFC 9901 §7.1 step 4: "If
// any digest value is encountered more than once in the Issuer-signed JWT
// payload (directly or recursively via other Disclosures), the SD-JWT MUST be
// rejected." §4.1 states the same rule for the Issuer: "The same digest value
// MUST NOT appear more than once in the SD-JWT."
func (p *processor) markSeen(digest string) error {
	if p.seen[digest] {
		return fmt.Errorf("digest %s appears more than once in the credential", shortDigest(digest))
	}
	p.seen[digest] = true
	return nil
}

// arrayElementDigest reports the digest an array element hides, if it is a
// digest placeholder at all. RFC 9901 §4.2.4.2: "For each digest, an object
// of the form {"...": "<digest>"} is added to the array. The key MUST always
// be the string ... (three dots). The value MUST be the digest of the
// Disclosure created as described in Section 4.2.3. There MUST NOT be any
// other keys in the object."
func arrayElementDigest(item any) (digest string, isPlaceholder bool, err error) {
	obj, isObject := item.(map[string]any)
	if !isObject {
		return "", false, nil
	}
	raw, present := obj["..."]
	if !present {
		return "", false, nil
	}
	if len(obj) != 1 {
		return "", false, fmt.Errorf(`array element carries a "..." key alongside %d other keys`, len(obj)-1)
	}
	value, isString := raw.(string)
	if !isString {
		return "", false, fmt.Errorf(`array element "..." does not refer to a string`)
	}
	return value, true, nil
}

// shortDigest keeps an error message readable while still naming the digest
// the reader has to find in the payload.
func shortDigest(digest string) string {
	const shown = 12
	if len(digest) <= shown {
		return digest
	}
	return digest[:shown] + "..."
}

func disclosureLabel(d *Disclosure) string {
	if d.IsArrayEntry {
		return "array element"
	}
	return "claim " + d.Name
}
