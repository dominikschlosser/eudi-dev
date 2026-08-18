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

// The consent dialog lets the user override which credentials answer a
// presentation. The overrides reference the ConsentCredentialOptions the
// request offered: an option index per credential set and a credential per
// query id. ValidateConsentSelection checks an approval body against the
// offer before it is accepted, ApplyConsentSelection turns the accepted
// selection back into the matches the presentation is built from.

package wallet

import "fmt"

// ValidateConsentSelection checks that picks and set choices reference what
// the consent request offered.
func ValidateConsentSelection(options *ConsentCredentialOptions, picks map[string]string, setChoices []int) error {
	if len(picks) == 0 && len(setChoices) == 0 {
		return nil
	}
	if options == nil {
		return fmt.Errorf("this request offers no credential selection")
	}
	if len(setChoices) > len(options.Sets) {
		return fmt.Errorf("%d set choices for %d sets", len(setChoices), len(options.Sets))
	}
	answered := len(options.Sets) == 0
	for i, set := range options.Sets {
		choice := 0
		if i < len(setChoices) {
			choice = setChoices[i]
		}
		if choice == -1 {
			if !set.Optional {
				return fmt.Errorf("set %d is required and cannot be skipped", i)
			}
			continue
		}
		if choice < 0 || choice >= len(set.Options) {
			return fmt.Errorf("set %d has no option %d", i, choice)
		}
		answered = true
	}
	// A presentation carries at least one credential (OpenID4VP 1.0 §8.1),
	// so a selection must answer at least one set.
	if !answered {
		return fmt.Errorf("the selection must answer at least one credential set")
	}
	for qid, credID := range picks {
		query := findConsentQuery(options, qid)
		if query == nil {
			return fmt.Errorf("unknown credential query %q", qid)
		}
		if findConsentCandidate(query, credID) == nil {
			return fmt.Errorf("credential %s does not match query %q", credID, qid)
		}
	}
	return nil
}

// ApplyConsentSelection rebuilds the matches an approval chose from the
// offered options. An approval without overrides keeps the wallet's own
// selection, so auto-accept and untouched consents behave identically.
func ApplyConsentSelection(options *ConsentCredentialOptions, matches []CredentialMatch, result ConsentResult) []CredentialMatch {
	if options == nil || (len(result.Picks) == 0 && len(result.SetChoices) == 0) {
		// A copy: the claim filtering after approval writes into the
		// returned slice, and the published ConsentRequest keeps marshaling
		// its own MatchedCreds concurrently.
		return append([]CredentialMatch(nil), matches...)
	}

	var needed []string
	seen := make(map[string]bool)
	if len(options.Sets) > 0 {
		for i, set := range options.Sets {
			choice := 0
			if i < len(result.SetChoices) {
				choice = result.SetChoices[i]
			}
			if choice == -1 && set.Optional {
				continue
			}
			if choice < 0 || choice >= len(set.Options) {
				choice = 0
			}
			for _, qid := range set.Options[choice] {
				if !seen[qid] {
					seen[qid] = true
					needed = append(needed, qid)
				}
			}
		}
	} else {
		for _, query := range options.Queries {
			needed = append(needed, query.ID)
		}
	}

	out := make([]CredentialMatch, 0, len(needed))
	for _, qid := range needed {
		query := findConsentQuery(options, qid)
		if query == nil || len(query.Candidates) == 0 {
			continue
		}
		pick := &query.Candidates[0]
		if credID, ok := result.Picks[qid]; ok {
			if chosen := findConsentCandidate(query, credID); chosen != nil {
				pick = chosen
			}
		}
		out = append(out, *pick)
	}
	// A presentation carries at least one credential (OpenID4VP 1.0 §8.1),
	// so a selection that answers nothing keeps the wallet's choice.
	if len(out) == 0 {
		return matches
	}
	return out
}

func findConsentQuery(options *ConsentCredentialOptions, id string) *ConsentQueryOptions {
	for i := range options.Queries {
		if options.Queries[i].ID == id {
			return &options.Queries[i]
		}
	}
	return nil
}

func findConsentCandidate(query *ConsentQueryOptions, credentialID string) *CredentialMatch {
	for i := range query.Candidates {
		if query.Candidates[i].CredentialID == credentialID {
			return &query.Candidates[i]
		}
	}
	return nil
}
