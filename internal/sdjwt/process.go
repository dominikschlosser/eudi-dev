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
	// deviations collects rule breaks that a strict consumer rejects but that
	// still leave the payload resolvable, so lenient parsing can carry on.
	deviations []string
	// reportedDuplicateDigest keeps the mirrored-claims deviation to one entry
	// however many digests repeat.
	reportedDuplicateDigest bool
}

// processPayload applies RFC 9901 §7.1 steps 3 to 5 and returns the Processed
// SD-JWT Payload with the deviations it found. A condition the specification
// marks MUST-reject is recorded as a deviation and the payload resolved around
// it, so lenient parsing stays usable; Parse turns any deviation into the
// rejection §7.1 requires.
func processPayload(payload map[string]any, disclosures []Disclosure) (map[string]any, []string, error) {
	p := &processor{
		byDigest: make(map[string]*Disclosure, len(disclosures)),
		seen:     make(map[string]bool),
		used:     make(map[string]bool),
	}
	for i := range disclosures {
		d := &disclosures[i]
		// RFC 9901 §4: "A Holder MUST NOT send a Disclosure that was not
		// included in the issued SD-JWT or send a Disclosure more than once."
		// The duplicate resolves to the same claim, so the extra copy is ignored.
		if _, duplicate := p.byDigest[d.Digest]; duplicate {
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s is present more than once, so the extra copy is ignored", shortDigest(d.Digest)))
			continue
		}
		p.byDigest[d.Digest] = d
	}

	resolved := p.object(payload, true)

	// Step 5: "If any Disclosure was not referenced by digest value in the
	// Issuer-signed JWT (directly or recursively via other Disclosures), the
	// SD-JWT MUST be rejected." An unreferenced disclosure is simply never
	// inserted, so it is ignored.
	for i := range disclosures {
		d := &disclosures[i]
		if !p.used[d.Digest] {
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s (%s) is not referenced by any digest in the credential, so it is ignored", shortDigest(d.Digest), disclosureLabel(d)))
		}
	}

	return resolved, p.deviations, nil
}

// object processes one JSON object of the payload: it keeps the claims that
// are already there, inserts the claims disclosed by the digests in its "_sd"
// array, and drops the "_sd" key itself (§7.1 steps 3.b.i, 3.c.ii and 3.e).
// top marks the SD-JWT payload itself, the only object where _sd_alg belongs.
func (p *processor) object(obj map[string]any, top bool) map[string]any {
	result := make(map[string]any, len(obj))

	for k, v := range obj {
		switch k {
		case "_sd":
			// Step 3.e: "Remove all _sd keys and their contents from the
			// Issuer-signed JWT payload."
			continue
		case "_sd_alg":
			// Step 3.f removes _sd_alg from the payload. RFC 9901 §4.1.1 keeps
			// it at the top level only, and a nested copy names the same hash
			// the top level already fixed, so it is redundant: drop it and
			// record the rule break for a strict caller.
			if !top {
				p.deviations = append(p.deviations, "_sd_alg is inside a nested object. RFC 9901 §4.1.1 allows it only at the top level.")
			}
			continue
		}
		result[k] = p.value(v)
	}

	rawSD, present := obj["_sd"]
	if !present {
		return result
	}
	// RFC 9901 §4.2.4.1: "The _sd key MUST refer to an array of strings, each
	// string being a digest of a Disclosure or a decoy digest".
	entries, ok := rawSD.([]any)
	if !ok {
		p.deviations = append(p.deviations, `the "_sd" value is not an array, which RFC 9901 §4.2.4.1 requires, so its disclosures are skipped`)
		return result
	}

	localSeen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		digest, ok := entry.(string)
		if !ok {
			p.deviations = append(p.deviations, `an "_sd" array entry is not a string, which RFC 9901 §4.2.4.1 requires, so it is skipped`)
			continue
		}
		// A digest repeated in one _sd array would insert the same claim twice,
		// so the repeat is skipped. markSeen handles the same digest reached
		// through different objects, which is the mirrored-claims pattern.
		if localSeen[digest] {
			p.deviations = append(p.deviations, fmt.Sprintf("digest %s appears more than once in one _sd array, so the repeat is skipped", shortDigest(digest)))
			continue
		}
		localSeen[digest] = true
		p.markSeen(digest)
		disc, found := p.byDigest[digest]
		if !found {
			// Step 3.c.i: "If no such Disclosure can be found, the digest
			// MUST be ignored." That covers decoy digests (§4.2.5) and
			// claims the Holder withheld.
			continue
		}
		if disc.IsArrayEntry {
			// Step 3.c.ii.1 wants three elements (salt, claim name, value) here.
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s in an _sd array holds two elements, but RFC 9901 §7.1 expects three (salt, claim name, value), so it is skipped", shortDigest(digest)))
			continue
		}
		if disc.Name == "_sd" || disc.Name == "..." {
			// Step 3.c.ii.2: a disclosure MUST NOT be named _sd or ...
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s discloses a claim named %q, which RFC 9901 §7.1 does not allow, so it is skipped", shortDigest(digest), disc.Name))
			continue
		}
		if _, exists := result[disc.Name]; exists {
			// Step 3.c.ii.3: a disclosure MUST NOT redefine a claim that already
			// exists at this level (a signed vct, say). The existing value stays.
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s discloses claim %q, which already exists at this level (RFC 9901 §7.1 does not let a disclosure redefine an existing claim), so the existing value stays", shortDigest(digest), disc.Name))
			continue
		}
		p.used[digest] = true
		// Step 3.c.ii.5 recurses into the disclosed value, then 3.c.ii.4 inserts
		// it under the claim name.
		result[disc.Name] = p.value(disc.Value)
	}

	return result
}

// array processes one JSON array: each {"...": digest} placeholder is
// replaced by its disclosed value, and a placeholder with no Disclosure is
// dropped (§7.1 steps 3.c.iii and 3.d).
func (p *processor) array(arr []any) []any {
	result := make([]any, 0, len(arr))

	for _, item := range arr {
		digest, isPlaceholder, err := arrayElementDigest(item)
		if err != nil {
			p.deviations = append(p.deviations, err.Error()+", so the element is dropped")
			continue
		}
		if !isPlaceholder {
			result = append(result, p.value(item))
			continue
		}

		p.markSeen(digest)
		disc, found := p.byDigest[digest]
		if !found {
			// Step 3.d: "Remove all array elements for which the digest was
			// not found in the previous step." Leaving the placeholder in
			// place would present a digest to the application as if it were
			// the element's value.
			continue
		}
		if !disc.IsArrayEntry {
			// Step 3.c.iii.1 wants two elements (salt, value) here.
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s holds three elements but sits in an array element, where RFC 9901 §7.1 expects two (salt, value), so the element is dropped", shortDigest(digest)))
			continue
		}
		p.used[digest] = true
		// Step 3.c.iii.3 recurses into the value, then 3.c.iii.2 replaces the
		// array element with it.
		result = append(result, p.value(disc.Value))
	}

	return result
}

func (p *processor) value(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return p.object(val, false)
	case []any:
		return p.array(val)
	default:
		return v
	}
}

// markSeen records an embedded digest and enforces RFC 9901 §7.1 step 4: "If
// any digest value is encountered more than once in the Issuer-signed JWT
// payload (directly or recursively via other Disclosures), the SD-JWT MUST be
// rejected." §4.1 states the same rule for the Issuer: "The same digest value
// MUST NOT appear more than once in the SD-JWT."
// A digest reached through two objects (a mirrored credentialSubject copy)
// hits this rule but resolves the same disclosure into both. Lenient parsing
// records the break once as a deviation.
func (p *processor) markSeen(digest string) {
	if p.seen[digest] {
		if !p.reportedDuplicateDigest {
			p.reportedDuplicateDigest = true
			p.deviations = append(p.deviations, "the same disclosure digest appears more than once (the credential repeats its claims in a second object). RFC 9901 §4.1 does not allow this.")
		}
		return
	}
	p.seen[digest] = true
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
