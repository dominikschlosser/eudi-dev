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
// A national PID is an extension of the country-independent one by
// requirement: ARF v3.0.0 Annex 2, PID_14 says the vct "SHALL be
// urn:eudi:pid:1 for the type defined in this document or a domestic type
// that extends it". So urn:eudi:pid:de:1 carries every attribute
// urn:eudi:pid:1 defines and adds the German ones, and a verifier asking for
// the general type is answered by the national credential, which is what
// Answers decides.
//
// What the ARF does not do is say how a Wallet Unit or a Relying Party is
// supposed to discover that relationship. The machine-readable form of it,
// an SD-JWT VC Type Metadata Document with an extends property
// (draft-ietf-oauth-sd-jwt-vc-18 §4.4), is only ARB_31 "SHOULD consider
// defining", and it needs the document to be retrievable, which a vct that is
// a URN is not. Extends therefore applies the rule PID_14 states directly,
// which is what resolves today's credentials.
//
// The aka_vcts claim (§2.2.2.2, new in draft-18 of 3 August 2026) closes that
// gap by putting the statement in the credential itself: "An SD-JWT VC
// containing the aka_vcts claim is a Verifiable Digital Credential of the type
// identified by the vct claim and, additionally, of each of the types
// identified by the values in the aka_vcts claim." No EUDI rulebook requires
// it yet and no real German PID carries it, so reading it is what makes this
// wallet work with issuers that adopt it, and writing it into the credentials
// this tool issues is how it shows the mechanism.
//
// Inheritance says what a credential is, never who may issue it
// (draft-ietf-oauth-sd-jwt-vc-18 §6.6: "Verifiers and Holders MUST NOT assume
// that any issuer who issues a credential extending a known type is authorized
// to do so"). Nothing here grants trust; issuer authorization is decided
// where it always was, by signature and trust list checks.
package credtype

import "strings"

// The EUDI PID, country-independent and German.
//
// The German PID is a distinct SD-JWT VC type but not a distinct mdoc
// document type. ISO/IEC 18013-5 has no inheritance between document types,
// and the ARF does not invent one: PID_05 fixes the doctype and namespace at
// eu.europa.ec.eudi.pid.1 for every PID, and PID_06 puts national elements in
// a domestic namespace built by appending the ISO 3166-1 alpha-2 code to it,
// with "eu.europa.ec.eudi.pid.de.1" as its own example for Germany.
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
// This is a rule rather than a list of known types, because the ARF states
// one: PID_14 says the vct "SHALL be a URN within the urn:eudi:pid: namespace"
// and "SHALL be urn:eudi:pid:1 for the type defined in this document or a
// domestic type that extends it". So every domestic PID type extends the
// country-independent one, whether or not this tool has heard of the country.
//
// What separates a domestic type from the country-independent one is the
// segment after the prefix: a number names a version of the type the rulebook
// defines (urn:eudi:pid:1, and whatever a later rulebook numbers), anything
// else names a country or region, the same convention PID_06 spells out for
// mdoc namespaces. urn:eudi:pid:de:1 is German, urn:eudi:pid:fr:1 is French,
// and neither had to be known here in advance.
//
// Types outside that namespace state their own relationships in aka_vcts,
// which is where the general mechanism lives (see AkaVCTs).
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
