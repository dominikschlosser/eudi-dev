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

// Package credtype names the EUDI credential types this tool knows and models
// the inheritance between them.
//
// A national PID extends the country-independent one by requirement: ARF
// v3.0.0 Annex 2, PID_14 says the vct "SHALL be urn:eudi:pid:1 for the type
// defined in this document or a domestic type that extends it". So a verifier
// asking for the general type is answered by the national credential, which is
// what Answers decides.
//
// The ARF does not say how that relationship is discovered. Its
// machine-readable form, Type Metadata with extends
// (draft-ietf-oauth-sd-jwt-vc-18 §4.4), is only something ARB_31 "SHOULD
// consider defining" and needs a retrievable document, which a URN vct is not.
// Extends therefore applies PID_14 directly.
//
// The aka_vcts claim (§2.2.2.2, new in draft-18) puts the statement in the
// credential itself. No EUDI rulebook requires it yet, so reading it is what
// makes this wallet work with issuers that adopt it.
//
// Inheritance says what a credential is, never who may issue it (§6.6:
// "Verifiers and Holders MUST NOT assume that any issuer who issues a
// credential extending a known type is authorized to do so").
package credtype

import "strings"

// The EUDI PID, country-independent and German. The German PID is a distinct
// SD-JWT VC type but not a distinct mdoc document type: PID_05 fixes the
// doctype at eu.europa.ec.eudi.pid.1 for every PID, and PID_06 puts national
// elements in a domestic namespace (eu.europa.ec.eudi.pid.de.1).
const (
	PIDVCT             = "urn:eudi:pid:1"
	GermanPIDVCT       = "urn:eudi:pid:de:1"
	PIDDocType         = "eu.europa.ec.eudi.pid.1"
	PIDNamespace       = PIDDocType
	GermanPIDNamespace = "eu.europa.ec.eudi.pid.de.1"
)

// AkaVCTsClaim is the SD-JWT VC claim naming the further types a credential
// is also of (draft-ietf-oauth-sd-jwt-vc-18 §2.2.2.2).
const AkaVCTsClaim = "aka_vcts"

// PIDVCTPrefix is the URN namespace every PID type lives in.
const PIDVCTPrefix = "urn:eudi:pid:"

// Extends returns the type vct extends, and whether there is one.
//
// It applies PID_14's rule rather than a list of known types, so every
// domestic PID type extends the country-independent one whether or not this
// tool has heard of the country. The segment after the urn:eudi:pid: prefix
// decides: a number names a version of the rulebook's own type, anything else
// names a country or region (the convention PID_06 uses for mdoc namespaces).
//
// Types outside that namespace state their relationships in aka_vcts.
func Extends(vct string) (string, bool) {
	rest, ok := strings.CutPrefix(vct, PIDVCTPrefix)
	if !ok || rest == "" {
		return "", false
	}
	country, _, _ := strings.Cut(rest, ":")
	if country == "" || isNumber(country) {
		return "", false
	}
	return PIDVCT, true
}

// isNumber reports whether s is a run of digits and nothing else.
func isNumber(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// Chain returns every type a credential of type vct is also of, vct first:
// the types its aka_vcts claim lists, then the types vct is known to extend.
// Duplicates are dropped and an empty vct yields an empty chain.
func Chain(vct string, akaVCTs []string) []string {
	if vct == "" {
		return nil
	}
	chain := []string{vct}
	seen := map[string]bool{vct: true}
	add := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		chain = append(chain, t)
	}
	for _, aka := range akaVCTs {
		add(aka)
	}
	// Walk the inheritance from every type reached so far, so a credential
	// naming only its immediate parent in aka_vcts still answers for that
	// parent's own parent. seen bounds the walk, so a rule that ever produced
	// a cycle would stop rather than hang.
	for i := 0; i < len(chain); i++ {
		if parent, ok := Extends(chain[i]); ok {
			add(parent)
		}
	}
	return chain
}

// Answers reports whether a credential of type vct, carrying akaVCTs, answers
// a request for the type requested.
func Answers(vct string, akaVCTs []string, requested string) bool {
	if requested == "" || vct == "" {
		return false
	}
	for _, t := range Chain(vct, akaVCTs) {
		if t == requested {
			return true
		}
	}
	return false
}

// AkaVCTs reads the aka_vcts claim of a decoded credential. Anything that is
// not a list of strings is ignored: a credential is free to be malformed, and
// a type it cannot state is simply a type it does not have.
func AkaVCTs(claims map[string]any) []string {
	raw, ok := claims[AkaVCTsClaim].([]any)
	if !ok {
		return nil
	}
	types := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			types = append(types, s)
		}
	}
	return types
}
