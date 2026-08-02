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
	"log"
	"sort"
	"strconv"
	"strings"

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

	// Sort matches so preferred format appears first per query ID
	if w.PreferredFormat != "" {
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].QueryID == matches[j].QueryID {
				return matches[i].Format == w.PreferredFormat
			}
			return false
		})
	}

	// Apply credential_sets constraints
	if credSets, ok := query["credential_sets"].([]any); ok {
		log.Printf("[DCQL] Applying credential_sets constraints: %d sets, %d matches before", len(credSets), len(matches))
		matches = applyCredentialSets(matches, credSets, w.PreferredFormat)
		if matches == nil {
			log.Printf("[DCQL] credential_sets: unsatisfiable required set")
		} else {
			log.Printf("[DCQL] credential_sets: %d matches after filtering", len(matches))
		}
	}

	log.Printf("[DCQL] Result: %d matches", len(matches))
	return matches
}

type claimSelection struct {
	selectedKeys    []string
	missingRequired []string
	match           bool
}

// matchesFormat checks if a credential matches the requested format.
func matchesFormat(cred StoredCredential, queryFormat string) bool {
	if queryFormat == "" {
		return true
	}
	return cred.Format == queryFormat
}

// matchesMeta checks format-specific metadata (vct_values, doctype_value).
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
	// Build index: claim id → claim path
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

			path := claimByID[id]
			if path == nil {
				satisfiable = false
				break
			}

			selector := claimSelectorFromPath(cred, path)
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

// buildClaimByID builds a map of claim id → path from claims query entries.
func buildClaimByID(claimsQuery []any) map[string][]any {
	byID := make(map[string][]any)
	for _, cq := range claimsQuery {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}
		id, _ := cqMap["id"].(string)
		if id == "" {
			continue
		}
		path, ok := cqMap["path"].([]any)
		if !ok {
			continue
		}
		byID[id] = path
	}
	return byID
}

// selectAllRequestedClaims returns all requested claims that exist in the credential.
// Per DCQL (OID4VP 1.0 Section 6), claims without claim_sets are required by default
// unless the individual claim entry has "required": false.
// Returns the selected claims plus any missing required claim paths.
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

		// Per DCQL spec: claims are required by default.
		required := true
		if r, ok := cqMap["required"].(bool); ok {
			required = r
		}

		selector := claimSelectorFromPath(cred, path)
		if selector != "" {
			selected = append(selected, selector)
		} else if required {
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

func mdocClaimKeyFromPath(cred StoredCredential, path []any) string {
	first, ok := path[0].(string)
	if !ok {
		return ""
	}

	// mDoc claims are flat elements in a namespace: ["namespace", "element"]
	if len(path) >= 2 {
		if elem, ok := path[1].(string); ok {
			for _, candidate := range mdocElementCandidates(elem) {
				key := first + ":" + candidate
				if _, exists := cred.Claims[key]; exists && len(path) == 2 {
					return key
				}
			}
		}
	}

	return ""
}

func mdocElementCandidates(name string) []string {
	switch name {
	case "place_of_birth":
		return []string{"place_of_birth", "birth_place"}
	default:
		return []string{name}
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
		if len(path) == 1 {
			return arr, true
		}
		var out []any
		for _, item := range arr {
			if v, ok := claimValueAtPath(item, path[1:]); ok {
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

	// If no credential_sets were defined or all optional, include everything
	if len(needed) == 0 {
		return matches
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
