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
	"crypto/x509"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/internal/validate"
)

// EvaluateDCQL matches stored credentials against a DCQL query (OID4VP 1.0 Section 6).
// It returns matched credentials grouped by query credential ID.
func (w *Wallet) EvaluateDCQL(query map[string]any) []CredentialMatch {
	credentials := w.GetCredentials()
	credQueries, _ := query["credentials"].([]any)

	log.Printf("[DCQL] Evaluating query: %d credential queries against %d stored credentials", len(credQueries), len(credentials))

	if findings := DCQLQueryFindings(query); len(findings) > 0 {
		for _, finding := range findings {
			log.Printf("[DCQL] Warning: %s", finding)
		}
		if w.ValidationMode == ValidationModeStrict {
			log.Printf("[DCQL] Result: 0 matches (strict mode treats a malformed query as an error)")
			return nil
		}
	}

	var matches []CredentialMatch

	for _, cq := range credQueries {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}

		queryID, _ := cqMap["id"].(string)
		queryFormat, _ := cqMap["format"].(string)

		for _, cred := range credentials {
			typeLabel := cred.VCT
			if typeLabel == "" {
				typeLabel = cred.DocType
			}

			if !matchesFormat(cred, queryFormat) {
				log.Printf("[DCQL]   query=%s: credential %s (%s) skipped: format mismatch (want %s, have %s)", queryID, typeLabel, cred.Format, queryFormat, cred.Format)
				continue
			}
			if !matchesMeta(cred, cqMap) {
				log.Printf("[DCQL]   query=%s: credential %s (%s) skipped: meta mismatch", queryID, typeLabel, cred.Format)
				continue
			}

			selection := w.selectClaims(cred, cqMap)
			if len(selection.missingRequired) > 0 {
				if w.ValidationMode == ValidationModeDebug && len(selection.selectedKeys) > 0 {
					log.Printf("[DCQL] Warning: query=%s: credential %s (%s) missing required claims %v in debug mode; continuing with selected claims %v",
						queryID, typeLabel, cred.Format, selection.missingRequired, selection.selectedKeys)
				} else {
					log.Printf("[DCQL]   query=%s: credential %s (%s) skipped: required claims not found: %v",
						queryID, typeLabel, cred.Format, selection.missingRequired)
					continue
				}
			}
			if !selection.match {
				log.Printf("[DCQL]   query=%s: credential %s (%s) skipped: no requested claims matched", queryID, typeLabel, cred.Format)
				continue
			}

			if taList, ok := cqMap["trusted_authorities"].([]any); ok && len(taList) > 0 {
				if !checkTrustedAuthorities(cred, taList) {
					log.Printf("[DCQL]   query=%s: credential %s (%s) skipped: not trusted by any trusted_authority", queryID, typeLabel, cred.Format)
					continue
				}
			}

			log.Printf("[DCQL]   query=%s: credential %s (%s) matched, selected claims: %v", queryID, typeLabel, cred.Format, selection.selectedKeys)
			matches = append(matches, CredentialMatch{
				QueryID:      queryID,
				CredentialID: cred.ID,
				Format:       cred.Format,
				VCT:          cred.VCT,
				DocType:      cred.DocType,
				Claims:       filterClaims(cred, selection.selectedKeys),
				SelectedKeys: selection.selectedKeys,
			})
		}
	}

	sortMatchesNewestFirst(matches, credentials)

	if w.PreferredFormat != "" {
		sortMatchesByPreferredFormat(matches, w.PreferredFormat)
	}

	matches = keepOnePresentationPerQuery(matches)

	// OID4VP 1.0 §6.4.2: "If credential_sets is not provided, the Verifier
	// requests presentations for all Credentials in credentials to be
	// returned." Otherwise the sets decide what is required and what is
	// optional, and only credentials referenced by a satisfied option are
	// returned.
	if credSets, ok := query["credential_sets"].([]any); ok && len(credSets) > 0 {
		log.Printf("[DCQL] Applying credential_sets constraints: %d sets, %d matches before", len(credSets), len(matches))
		matches = applyCredentialSets(matches, credSets, w.PreferredFormat)
		if matches == nil {
			log.Printf("[DCQL] credential_sets: no option of any set can be satisfied, returning no credentials")
		} else {
			log.Printf("[DCQL] credential_sets: %d matches after filtering", len(matches))
		}
	} else if missing := unmatchedCredentialQueries(credQueries, matches); len(missing) > 0 {
		// §6.4.2: "If the Wallet cannot deliver all non-optional Credentials
		// requested by the Verifier according to these rules, it MUST NOT
		// return any Credential(s)." Without credential_sets every entry in
		// credentials is non-optional, so answering with the subset the wallet
		// happens to hold discloses credentials the Verifier cannot use.
		log.Printf("[DCQL] Result: 0 matches (no credential answers %v, and every credential query is required without credential_sets)", missing)
		return nil
	}

	log.Printf("[DCQL] Result: %d matches", len(matches))
	return matches
}

// unmatchedCredentialQueries lists the credential query ids that no stored
// credential answers.
//
// A credential query that is not an object, or that carries no id, can never
// be answered either, and is reported under the position it holds in the
// credentials array.
func unmatchedCredentialQueries(credQueries []any, matches []CredentialMatch) []string {
	matched := make(map[string]bool, len(matches))
	for _, m := range matches {
		matched[m.QueryID] = true
	}

	var missing []string
	for i, cq := range credQueries {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			missing = append(missing, fmt.Sprintf("credentials[%d]", i))
			continue
		}
		id, _ := cqMap["id"].(string)
		if id == "" {
			missing = append(missing, fmt.Sprintf("credentials[%d]", i))
			continue
		}
		if !matched[id] {
			missing = append(missing, id)
		}
	}
	return missing
}

// DCQLQueryFindings reports where a DCQL query departs from what OID4VP 1.0 §6
// requires of it. Findings are collected in every validation mode. What the
// mode decides is what happens to them: strict refuses to answer the query,
// debug logs them and evaluates the query as far as it can so a developer can
// watch the rest of the exchange.
func DCQLQueryFindings(query map[string]any) []string {
	if query == nil {
		return nil
	}

	// §6: "credentials: REQUIRED. A non-empty array of Credential Queries as
	// defined in Section 6.1 that specify the requested Credentials."
	credQueries, ok := query["credentials"].([]any)
	if !ok || len(credQueries) == 0 {
		return []string{"dcql_query: credentials is required and must be a non-empty array"}
	}

	var findings []string
	seen := make(map[string]bool, len(credQueries))
	for i, cq := range credQueries {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			findings = append(findings, fmt.Sprintf("dcql_query: credentials[%d] must be an object", i))
			continue
		}

		// §6.1: "id: REQUIRED. [...] The value MUST be a non-empty string
		// consisting of alphanumeric, underscore (_), or hyphen (-)
		// characters. Within the Authorization Request, the same id MUST NOT
		// be present more than once."
		id, _ := cqMap["id"].(string)
		switch {
		case !isDCQLIdentifier(id):
			findings = append(findings, fmt.Sprintf(
				"dcql_query: credentials[%d].id must be a non-empty string of alphanumeric, underscore or hyphen characters, got %q", i, id))
		case seen[id]:
			findings = append(findings, fmt.Sprintf("dcql_query: credential query id %q is present more than once", id))
		default:
			seen[id] = true
		}

		label := id
		if label == "" {
			label = fmt.Sprintf("credentials[%d]", i)
		}

		// §6.1: "format: REQUIRED. A string that specifies the format of the
		// requested Credential."
		if f, _ := cqMap["format"].(string); f == "" {
			findings = append(findings, fmt.Sprintf("dcql_query: credential query %q is missing the required format", label))
		}

		// §6.1: "meta: REQUIRED. An object defining additional properties
		// requested by the Verifier that apply to the metadata and validity
		// data of the Credential. [...] If empty, no specific constraints are
		// placed on the metadata or validity of the requested Credential." An
		// empty object is therefore the way to place no constraints, and
		// leaving the member out is not.
		meta, present := cqMap["meta"]
		if !present {
			findings = append(findings, fmt.Sprintf("dcql_query: credential query %q is missing the required meta (use an empty object to place no constraints)", label))
		} else if _, ok := meta.(map[string]any); !ok {
			findings = append(findings, fmt.Sprintf("dcql_query: credential query %q has a meta that is not an object", label))
		}
	}
	return findings
}

// isDCQLIdentifier reports whether an id has the syntax OID4VP 1.0 §6.1 gives
// it: "a non-empty string consisting of alphanumeric, underscore (_), or
// hyphen (-) characters".
func isDCQLIdentifier(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// sortMatchesNewestFirst orders the candidates for each query id by when the
// credential was issued, newest first, so that the one kept for presentation
// is the most recent credential that answers the query. A renewed credential
// supersedes the one it replaces, and this is the order the wallet already
// lists credentials in. Credentials that state no issuance time sort last,
// and ties keep the order they arrived in.
func sortMatchesNewestFirst(matches []CredentialMatch, credentials []StoredCredential) {
	issued := make(map[string]time.Time, len(credentials))
	for _, c := range credentials {
		issued[c.ID] = CredentialIssuedAt(c)
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].QueryID != matches[j].QueryID {
			return false
		}
		a, b := issued[matches[i].CredentialID], issued[matches[j].CredentialID]
		if a.IsZero() != b.IsZero() {
			return b.IsZero()
		}
		return a.After(b)
	})
}

// keepOnePresentationPerQuery reduces the candidates for each query id to the
// single credential that will be presented for it.
//
// A DCQL credential query asks for one credential. OID4VP 1.0 lets a wallet
// return several for the same query id only when the query sets `multiple`,
// which this wallet does not implement, so anything past the first is not
// something a verifier asked for. Reducing here rather than at submission is
// what makes the choice visible: the consent dialog and the activity log are
// built from these matches, and they were reporting credentials that were
// never sent.
//
// Leaving it to submission also meant the wallet signed a presentation for
// every candidate and then wrote them all to one key of a map, so all but the
// last were built and thrown away, and which one survived was decided by map
// assignment order rather than by anything considered. A wallet holding two
// credentials of the same type presented whichever happened to be stored
// last.
func keepOnePresentationPerQuery(matches []CredentialMatch) []CredentialMatch {
	if len(matches) == 0 {
		return matches
	}
	seen := make(map[string]bool, len(matches))
	kept := matches[:0]
	for _, m := range matches {
		if seen[m.QueryID] {
			log.Printf("[DCQL]   query=%s: credential %s not presented: the query asks for one credential and a better candidate matched",
				m.QueryID, m.CredentialID)
			continue
		}
		seen[m.QueryID] = true
		kept = append(kept, m)
	}
	return kept
}

// sortMatchesByPreferredFormat moves the preferred format to the front within
// each query id, leaving everything else where it was.
//
// Both halves of the comparison are needed. Asking only whether i is the
// preferred format reports i before j and j before i when both are, which is
// not an ordering sort can work with: it reversed equally preferred matches
// instead of leaving them alone, so which credential a caller took first came
// down to how the sort happened to run.
func sortMatchesByPreferredFormat(matches []CredentialMatch, preferred string) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].QueryID != matches[j].QueryID {
			return false
		}
		return matches[i].Format == preferred && matches[j].Format != preferred
	})
}

type claimSelection struct {
	selectedKeys    []string
	missingRequired []string
	match           bool
}

// matchesFormat checks if a credential matches the requested format.
//
// OID4VP 1.0 §6.1 makes format REQUIRED, so an absent one is a malformed
// query rather than a wildcard. DCQLQueryFindings reports it, and strict mode
// refuses the query outright. What is left here is the debug-mode reading,
// where the flow carries on so a developer can see the rest of the exchange.
func matchesFormat(cred StoredCredential, queryFormat string) bool {
	if queryFormat == "" {
		return true
	}
	return cred.Format == queryFormat
}

// matchesMeta checks format-specific metadata (vct_values, doctype_value).
//
// meta is REQUIRED by §6.1 and an empty object is how a Verifier places no
// constraints, so an absent meta is reported by DCQLQueryFindings. As with
// format, treating it as unconstrained here is the debug-mode reading.
func matchesMeta(cred StoredCredential, cqMap map[string]any) bool {
	meta, ok := cqMap["meta"].(map[string]any)
	if !ok {
		return true
	}

	// SD-JWT: check vct_values
	if vctValues, ok := meta["vct_values"].([]any); ok {
		if cred.VCT == "" {
			return false
		}
		found := false
		for _, v := range vctValues {
			if s, ok := v.(string); ok && s == cred.VCT {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// mDoc: check doctype_value
	if docType, ok := meta["doctype_value"].(string); ok {
		if cred.DocType != docType {
			return false
		}
	}

	return true
}

// selectClaims determines which claims to disclose based on the query.
func (w *Wallet) selectClaims(cred StoredCredential, cqMap map[string]any) claimSelection {
	claimsQuery, ok := cqMap["claims"].([]any)
	if !ok || len(claimsQuery) == 0 {
		return claimSelection{match: true}
	}

	// Check claim_sets first (preference ordering)
	if claimSets, ok := cqMap["claim_sets"].([]any); ok && len(claimSets) > 0 {
		selected := selectFromClaimSets(cred, claimsQuery, claimSets)
		return claimSelection{
			selectedKeys: selected,
			match:        len(selected) > 0,
		}
	}

	// No claim_sets: include all requested claims that exist
	return selectAllRequestedClaims(cred, claimsQuery)
}

// selectFromClaimSets picks the first satisfiable claim_set (preference order).
// claim_sets entries reference claims by their "id" property (string).
func selectFromClaimSets(cred StoredCredential, claimsQuery []any, claimSets []any) []string {
	// Build index: claim id → Claims Query
	claimByID := buildClaimByID(claimsQuery)

	for _, cs := range claimSets {
		csArr, ok := cs.([]any)
		if !ok {
			continue
		}

		var selected []string
		satisfiable := true

		for _, ref := range csArr {
			id, ok := ref.(string)
			if !ok {
				satisfiable = false
				break
			}

			claimQuery := claimByID[id]
			if claimQuery == nil {
				satisfiable = false
				break
			}

			selector := claimSelectorFor(cred, claimQuery)
			if selector == "" {
				satisfiable = false
				break
			}
			selected = append(selected, selector)
		}

		if satisfiable && len(selected) > 0 {
			return selected
		}
	}

	return nil
}

// buildClaimByID builds a map of claim id → Claims Query from claims query entries.
func buildClaimByID(claimsQuery []any) map[string]map[string]any {
	byID := make(map[string]map[string]any)
	for _, cq := range claimsQuery {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}
		id, _ := cqMap["id"].(string)
		if id == "" {
			continue
		}
		if _, ok := cqMap["path"].([]any); !ok {
			continue
		}
		byID[id] = cqMap
	}
	return byID
}

// claimSelectorFor resolves one Claims Query against a credential and returns
// the selector to disclose, or "" when the credential does not answer it.
//
// §6.4.1: "When a Claims Query contains a restriction on the values of a
// claim, the Wallet SHOULD NOT return the claim if its value does not match
// according to the rules for values defined in Section 6.3, i.e., the claim
// should be treated the same as if it did not exist in the Credential." A
// value mismatch is therefore reported exactly the way a missing claim is.
func claimSelectorFor(cred StoredCredential, cqMap map[string]any) string {
	path, ok := cqMap["path"].([]any)
	if !ok {
		return ""
	}

	selector := claimSelectorFromPath(cred, path)
	if selector == "" {
		return ""
	}

	if values, ok := cqMap["values"].([]any); ok && len(values) > 0 {
		if !valuesConstraintSatisfied(claimValuesAtPath(cred, path), values) {
			return ""
		}
	}
	return selector
}

// selectAllRequestedClaims returns all requested claims that exist in the credential.
//
// §6.4.1: "If claims is present, but claim_sets is absent, the Verifier
// requests all claims listed in claims." Every listed claim is therefore
// required, and §6.3 defines no member by which a Verifier could mark one
// optional. Returns the selected claims plus the paths of the ones the
// credential cannot answer.
func selectAllRequestedClaims(cred StoredCredential, claimsQuery []any) claimSelection {
	var selected []string
	var missingRequired []string
	for _, cq := range claimsQuery {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}
		path, ok := cqMap["path"].([]any)
		if !ok {
			continue
		}

		if selector := claimSelectorFor(cred, cqMap); selector != "" {
			selected = append(selected, selector)
		} else {
			missingRequired = append(missingRequired, claimPathString(path))
		}
	}

	if len(selected) == 0 {
		return claimSelection{missingRequired: missingRequired}
	}
	return claimSelection{
		selectedKeys:    selected,
		missingRequired: missingRequired,
		match:           true,
	}
}

func claimSelectorFromPath(cred StoredCredential, path []any) string {
	if len(path) == 0 {
		return ""
	}

	if cred.Format == "mso_mdoc" {
		return claimKeyFromPath(cred, path)
	}

	key := claimKeyFromPath(cred, path)
	if key == "" {
		return ""
	}

	return claimPathString(path)
}

func claimPathString(path []any) string {
	if len(path) == 0 {
		return "<empty>"
	}

	var b strings.Builder
	for i, segment := range path {
		switch v := segment.(type) {
		case string:
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(v)
		case float64:
			b.WriteString("[")
			b.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
			b.WriteString("]")
		case nil:
			b.WriteString("[*]")
		default:
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString("?")
		}
	}
	return b.String()
}

// claimKeyFromPath resolves a DCQL claim path to a credential claim key.
// For SD-JWT: path is like ["given_name"] → key "given_name"
//
//	nested object: ["address", "street_address"] → validates subclaim exists, returns "address"
//	array wildcard: ["nationalities", null] → validates value is array, returns "nationalities"
//	array index:    ["nationalities", 0] → validates array has enough elements, returns "nationalities"
//
// For mDoc: path is like ["eu.europa.ec.eudi.pid.1", "given_name"] → key "eu.europa.ec.eudi.pid.1:given_name"
func claimKeyFromPath(cred StoredCredential, path []any) string {
	if len(path) == 0 {
		return ""
	}

	if cred.Format == "mso_mdoc" {
		return mdocClaimKeyFromPath(cred, path)
	}

	// SD-JWT
	key, ok := path[0].(string)
	if !ok {
		return ""
	}
	val, exists := cred.Claims[key]
	if !exists {
		return ""
	}

	if claimPathExists(val, path[1:]) {
		return key
	}

	return ""
}

// mdocClaimKeyFromPath applies a claims path pointer to an mdoc, per §7.2.1.
//
// The data element identifier is matched exactly. §7.2.1: "Select the data
// element referenced by the second component. If the data element does not
// exist in the Credential then abort processing and return an error." An
// identifier a Verifier did not ask for is a different data element, however
// close its meaning, and answering with it discloses something the request
// does not cover.
func mdocClaimKeyFromPath(cred StoredCredential, path []any) string {
	// §7.2.1: "If the claims path pointer does not contain exactly two
	// components or one of the components is not a string then abort
	// processing and return an error."
	if len(path) != 2 {
		return ""
	}
	namespace, ok := path[0].(string)
	if !ok {
		return ""
	}
	element, ok := path[1].(string)
	if !ok {
		return ""
	}

	key := namespace + ":" + element
	if _, exists := cred.Claims[key]; !exists {
		return ""
	}
	return key
}

// claimValuesAtPath returns the claims a claims path pointer selects (§7).
// Processing a pointer yields a set of claims, so an array wildcard
// contributes one entry per element.
func claimValuesAtPath(cred StoredCredential, path []any) []any {
	if len(path) == 0 {
		return nil
	}

	if cred.Format == "mso_mdoc" {
		key := mdocClaimKeyFromPath(cred, path)
		if key == "" {
			return nil
		}
		return []any{mdocValueAsJSON(cred.Claims[key])}
	}

	return selectJSONClaims(cred.Claims, path)
}

// selectJSONClaims applies a claims path pointer to a JSON-based credential,
// per §7.1: "A string value indicates that the respective key is to be
// selected, a null value indicates that all elements of the currently selected
// array(s) are to be selected; and a non-negative integer indicates that the
// respective index in an array is to be selected."
func selectJSONClaims(root map[string]any, path []any) []any {
	selection := []any{any(root)}

	for _, segment := range path {
		var next []any
		for _, value := range selection {
			switch seg := segment.(type) {
			case string:
				obj, ok := value.(map[string]any)
				if !ok {
					continue
				}
				if v, exists := obj[seg]; exists {
					next = append(next, v)
				}
			case nil:
				arr, ok := value.([]any)
				if !ok {
					continue
				}
				next = append(next, arr...)
			default:
				idx, ok := claimPathIndex(seg)
				if !ok {
					return nil
				}
				arr, isArr := value.([]any)
				if !isArr || idx >= len(arr) {
					continue
				}
				next = append(next, arr[idx])
			}
		}
		// §7.1: "If the set of elements currently selected is empty, abort
		// processing and return an error."
		if len(next) == 0 {
			return nil
		}
		selection = next
	}

	return selection
}

// claimPathIndex reads an array index segment. §7: "A claims path pointer MUST
// be a non-empty array of strings, nulls and non-negative integers", and JSON
// decoding hands those integers over as float64.
func claimPathIndex(segment any) (int, bool) {
	switch v := segment.(type) {
	case float64:
		if v < 0 || v != float64(int(v)) {
			return 0, false
		}
		return int(v), true
	case int:
		if v < 0 {
			return 0, false
		}
		return v, true
	default:
		return 0, false
	}
}

// mdocValueAsJSON converts an mdoc data element value to the JSON value that
// value matching compares against.
//
// §6.3: "If a Wallet implements value matching and the Credential being
// matched is an ISO mdoc-based credential, the CBOR value used for matching
// MUST first be converted to JSON, following the advice given in Section 6.1
// of [RFC8949]." That advice encodes a byte string as base64url and every CBOR
// integer as a JSON number.
func mdocValueAsJSON(value any) any {
	switch v := value.(type) {
	case []byte:
		return format.EncodeBase64URL(v)
	case time.Time:
		return v.UTC().Format(time.RFC3339)
	default:
		if n, ok := numericClaimValue(value); ok {
			return n
		}
		return value
	}
}

// valuesConstraintSatisfied reports whether a claim answers a values
// restriction.
//
// §6.3: "If the values property is present, the Wallet SHOULD return the claim
// only if the type and value of the claim both match exactly for at least one
// of the elements in the array."
func valuesConstraintSatisfied(selected []any, values []any) bool {
	for _, claim := range selected {
		for _, want := range values {
			if claimValueEquals(claim, want) {
				return true
			}
		}
	}
	return false
}

// claimValueEquals compares a claim against one entry of a values array. §6.3
// allows "strings, integers or boolean values" there, and demands that type and
// value both match, so a string never answers a number and a boolean never
// answers the integer 1.
func claimValueEquals(claim, want any) bool {
	switch expected := want.(type) {
	case string:
		got, ok := claim.(string)
		return ok && got == expected
	case bool:
		got, ok := claim.(bool)
		return ok && got == expected
	default:
		wantNum, ok := numericClaimValue(want)
		if !ok {
			return false
		}
		gotNum, ok := numericClaimValue(claim)
		return ok && gotNum == wantNum
	}
}

// numericClaimValue reports the numeric value of a claim or of a values entry.
// A JSON decoder hands over float64, while a CBOR decoder hands over the
// signed and unsigned integer types an mdoc data element carries.
func numericClaimValue(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
	}
}

func claimPathExists(value any, path []any) bool {
	if len(path) == 0 {
		return true
	}

	switch segment := path[0].(type) {
	case string:
		obj, ok := value.(map[string]any)
		if !ok {
			return false
		}
		next, exists := obj[segment]
		if !exists {
			return false
		}
		return claimPathExists(next, path[1:])
	case float64:
		arr, ok := value.([]any)
		if !ok {
			return false
		}
		idx := int(segment)
		if idx < 0 || idx >= len(arr) {
			return false
		}
		return claimPathExists(arr[idx], path[1:])
	case nil:
		arr, ok := value.([]any)
		if !ok {
			return false
		}
		if len(path) == 1 {
			return true
		}
		for _, item := range arr {
			if claimPathExists(item, path[1:]) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// filterClaims returns only the selected claims, keyed by their exact selector.
func filterClaims(cred StoredCredential, selectedKeys []string) map[string]any {
	filtered := make(map[string]any, len(selectedKeys))
	for _, k := range selectedKeys {
		if v, ok := claimValueBySelector(cred, k); ok {
			filtered[k] = v
		}
	}
	return filtered
}

func claimValueBySelector(cred StoredCredential, selector string) (any, bool) {
	if cred.Format == "mso_mdoc" {
		v, ok := cred.Claims[selector]
		return v, ok
	}

	path, ok := parseSDJWTSelector(selector)
	if !ok || len(path) == 0 {
		return nil, false
	}

	key, ok := path[0].(string)
	if !ok {
		return nil, false
	}
	value, ok := cred.Claims[key]
	if !ok {
		return nil, false
	}
	return claimValueAtPath(value, path[1:])
}

func parseSDJWTSelector(selector string) ([]any, bool) {
	if selector == "" {
		return nil, false
	}

	var path []any
	var name strings.Builder

	flushName := func() bool {
		if name.Len() == 0 {
			return false
		}
		path = append(path, name.String())
		name.Reset()
		return true
	}

	for i := 0; i < len(selector); {
		switch selector[i] {
		case '.':
			if name.Len() == 0 {
				if len(path) == 0 {
					return nil, false
				}
				i++
				continue
			}
			if !flushName() {
				return nil, false
			}
			i++
		case '[':
			flushName()
			end := strings.IndexByte(selector[i:], ']')
			if end <= 1 {
				return nil, false
			}
			content := selector[i+1 : i+end]
			if content == "*" {
				path = append(path, nil)
			} else {
				idx, err := strconv.Atoi(content)
				if err != nil {
					return nil, false
				}
				path = append(path, idx)
			}
			i += end + 1
		default:
			name.WriteByte(selector[i])
			i++
		}
	}

	if name.Len() > 0 {
		path = append(path, name.String())
	}

	return path, len(path) > 0
}

func claimValueAtPath(value any, path []any) (any, bool) {
	if len(path) == 0 {
		return value, true
	}

	switch segment := path[0].(type) {
	case string:
		obj, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := obj[segment]
		if !ok {
			return nil, false
		}
		return claimValueAtPath(next, path[1:])
	case int:
		arr, ok := value.([]any)
		if !ok || segment < 0 || segment >= len(arr) {
			return nil, false
		}
		return claimValueAtPath(arr[segment], path[1:])
	case nil:
		arr, ok := value.([]any)
		if !ok {
			return nil, false
		}
		if len(path) < 2 {
			return arr, true
		}
		rest := path[1:]
		var out []any
		for _, item := range arr {
			if v, ok := claimValueAtPath(item, rest); ok {
				out = append(out, v)
			}
		}
		return out, len(out) > 0
	default:
		return nil, false
	}
}

// applyCredentialSets filters matches to satisfy credential_sets constraints.
// When preferredFormat is set, options containing credentials of that format are tried first.
//
// It returns nil when nothing may be returned. §6.4.2: "To satisfy a
// Credential Set Query, the Wallet MUST return presentations of a set of
// Credentials that match to one of the options inside the Credential Set
// Query", and "If the Wallet cannot deliver all non-optional Credentials
// requested by the Verifier according to these rules, it MUST NOT return any
// Credential(s)." So a required set with no satisfiable option means no
// credentials, and sets that are all optional with no satisfiable option mean
// nothing was asked for that the wallet can answer, which is also no
// credentials rather than everything that happened to match.
func applyCredentialSets(matches []CredentialMatch, credSets []any, preferredFormat string) []CredentialMatch {
	// Group matches by query ID
	byQuery := make(map[string][]CredentialMatch)
	for _, m := range matches {
		byQuery[m.QueryID] = append(byQuery[m.QueryID], m)
	}

	// Build a map of query ID → format for preference sorting
	queryFormat := make(map[string]string)
	for qid, ms := range byQuery {
		if len(ms) > 0 {
			queryFormat[qid] = ms[0].Format
		}
	}

	// Track which query IDs are needed
	needed := make(map[string]bool)

	for _, cs := range credSets {
		csMap, ok := cs.(map[string]any)
		if !ok {
			continue
		}

		required := true
		if r, ok := csMap["required"].(bool); ok {
			required = r
		}

		options, ok := csMap["options"].([]any)
		if !ok {
			continue
		}

		// Reorder options to prefer the preferred format
		orderedOptions := options
		if preferredFormat != "" {
			orderedOptions = make([]any, len(options))
			copy(orderedOptions, options)
			sort.SliceStable(orderedOptions, func(i, j int) bool {
				return optionMatchesFormat(orderedOptions[i], queryFormat, preferredFormat) &&
					!optionMatchesFormat(orderedOptions[j], queryFormat, preferredFormat)
			})
		}

		// Try each option (array of credential query IDs)
		satisfied := false
		for _, opt := range orderedOptions {
			optArr, ok := opt.([]any)
			if !ok {
				continue
			}

			allAvailable := true
			for _, qid := range optArr {
				qidStr, ok := qid.(string)
				if !ok {
					allAvailable = false
					break
				}
				if _, has := byQuery[qidStr]; !has {
					allAvailable = false
					break
				}
			}

			if allAvailable {
				for _, qid := range optArr {
					if qidStr, ok := qid.(string); ok {
						needed[qidStr] = true
					}
				}
				satisfied = true
				break
			}
		}

		if required && !satisfied {
			return nil // required credential_set not satisfiable
		}
	}

	// No option of any set could be satisfied, so there is no set of
	// credentials to return.
	if len(needed) == 0 {
		return nil
	}

	// Filter to only needed matches (first match per query ID)
	var result []CredentialMatch
	used := make(map[string]bool)
	for _, m := range matches {
		if needed[m.QueryID] && !used[m.QueryID] {
			result = append(result, m)
			used[m.QueryID] = true
		}
	}
	return result
}

// optionMatchesFormat checks if a credential_sets option contains query IDs
// whose matches are all of the given format.
func optionMatchesFormat(opt any, queryFormat map[string]string, format string) bool {
	optArr, ok := opt.([]any)
	if !ok {
		return false
	}
	for _, qid := range optArr {
		qidStr, ok := qid.(string)
		if !ok {
			return false
		}
		if queryFormat[qidStr] == format {
			return true
		}
	}
	return false
}

// checkTrustedAuthorities validates that the credential's issuer certificate chain
// is trusted by at least one of the given trusted authorities.
// Each entry must have "type" and "values" (array) fields.
func checkTrustedAuthorities(cred StoredCredential, taList []any) bool {
	for _, taRaw := range taList {
		taMap, ok := taRaw.(map[string]any)
		if !ok {
			continue
		}
		taType, _ := taMap["type"].(string)

		// Collect trust list URLs from "values" (array, per spec)
		var urls []string
		if valuesRaw, ok := taMap["values"].([]any); ok {
			for _, v := range valuesRaw {
				if s, ok := v.(string); ok && s != "" {
					urls = append(urls, s)
				}
			}
		}

		switch taType {
		case "aki":
			if len(urls) == 0 {
				log.Printf("[DCQL]   trusted_authorities: aki entry missing values")
				continue
			}
			if checkAuthorityKeyIdentifiers(cred, urls) {
				return true
			}
		case "etsi_tl":
			if len(urls) == 0 {
				log.Printf("[DCQL]   trusted_authorities: etsi_tl entry missing values")
				continue
			}
			for _, u := range urls {
				if checkETSITrustList(cred, u) {
					return true
				}
			}
		default:
			log.Printf("[DCQL]   trusted_authorities: unsupported type %q", taType)
		}
	}
	return false
}

func checkAuthorityKeyIdentifiers(cred StoredCredential, values []string) bool {
	certs, err := extractCredentialCertificates(cred)
	if err != nil {
		log.Printf("[DCQL]   trusted_authorities: failed to extract certificate chain: %v", err)
		return false
	}
	if len(certs) == 0 {
		log.Printf("[DCQL]   trusted_authorities: credential contains no certificate chain")
		return false
	}

	allowed := make(map[string]struct{}, len(values))
	for _, v := range values {
		allowed[v] = struct{}{}
	}

	for _, cert := range certs {
		if len(cert.AuthorityKeyId) == 0 {
			continue
		}
		if _, ok := allowed[format.EncodeBase64URL(cert.AuthorityKeyId)]; ok {
			return true
		}
	}

	log.Printf("[DCQL]   trusted_authorities: no certificate in credential chain matched any requested aki")
	return false
}

func extractCredentialCertificates(cred StoredCredential) ([]*x509.Certificate, error) {
	switch cred.Format {
	case "dc+sd-jwt":
		token, err := sdjwt.Parse(cred.Raw)
		if err != nil {
			return nil, err
		}
		return extractX5CCertificates(token.Header)
	case "mso_mdoc":
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			return nil, err
		}
		return extractMDOCX5Chain(doc)
	default:
		return nil, nil
	}
}

func extractX5CCertificates(header map[string]any) ([]*x509.Certificate, error) {
	x5cRaw, ok := header["x5c"].([]any)
	if !ok || len(x5cRaw) == 0 {
		return nil, nil
	}

	certs := make([]*x509.Certificate, 0, len(x5cRaw))
	for _, entry := range x5cRaw {
		b64, ok := entry.(string)
		if !ok {
			return nil, nil
		}
		der, err := format.DecodeBase64Std(b64)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func extractMDOCX5Chain(doc *mdoc.Document) ([]*x509.Certificate, error) {
	if doc.IssuerAuth == nil || doc.IssuerAuth.UnprotectedHeader == nil {
		return nil, nil
	}

	x5chainRaw, ok := doc.IssuerAuth.UnprotectedHeader[int64(33)]
	if !ok {
		x5chainRaw, ok = doc.IssuerAuth.UnprotectedHeader[uint64(33)]
		if !ok {
			return nil, nil
		}
	}

	var certDERs [][]byte
	switch v := x5chainRaw.(type) {
	case []byte:
		certDERs = append(certDERs, v)
	case []any:
		for _, entry := range v {
			b, ok := entry.([]byte)
			if !ok {
				return nil, nil
			}
			certDERs = append(certDERs, b)
		}
	default:
		return nil, nil
	}

	certs := make([]*x509.Certificate, 0, len(certDERs))
	for _, der := range certDERs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// checkETSITrustList fetches an ETSI trust list and validates the credential's
// issuer certificate chain against it.
func checkETSITrustList(cred StoredCredential, trustListURL string) bool {
	tlRaw, err := format.FetchURL(trustListURL)
	// If fetch fails and URL contains host.docker.internal, retry with localhost
	// (verifier runs in Docker but wallet runs on the host).
	if err != nil && strings.Contains(trustListURL, "host.docker.internal") {
		fallbackURL := strings.Replace(trustListURL, "host.docker.internal", "localhost", 1)
		log.Printf("[DCQL]   trusted_authorities: retrying with %s", fallbackURL)
		tlRaw, err = format.FetchURL(fallbackURL)
	}
	if err != nil {
		log.Printf("[DCQL]   trusted_authorities: failed to fetch trust list %s: %v", trustListURL, err)
		return false
	}

	tl, err := trustlist.Parse(tlRaw)
	if err != nil {
		log.Printf("[DCQL]   trusted_authorities: failed to parse trust list: %v", err)
		return false
	}

	tlCerts := trustlist.ExtractPublicKeys(tl)
	if len(tlCerts) == 0 {
		log.Printf("[DCQL]   trusted_authorities: trust list contains no certificates")
		return false
	}

	switch cred.Format {
	case "dc+sd-jwt":
		token, err := sdjwt.Parse(cred.Raw)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: failed to parse SD-JWT: %v", err)
			return false
		}
		key, err := validate.ExtractAndValidateX5C(token.Header, tlCerts)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: x5c chain validation failed: %v", err)
			return false
		}
		return key != nil

	case "mso_mdoc":
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: failed to parse mDoc: %v", err)
			return false
		}
		key, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: x5chain validation failed: %v", err)
			return false
		}
		return key != nil

	default:
		log.Printf("[DCQL]   trusted_authorities: unsupported credential format %q for chain validation", cred.Format)
		return false
	}
}
