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

// Package mock generates test credentials (SD-JWT and mDOC) with default EUDI PID claims.
package mock

import (
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/credtype"
)

// The EUDI PID types these claim sets belong to. The country-independent PID
// and the German one are separate SD-JWT VC types, where the German type
// extends the country-independent one (see internal/credtype). In mdoc they
// share a doctype and differ by the second namespace the German one uses.
const (
	// DefaultPIDVCT is the type of the country-independent EUDI PID.
	DefaultPIDVCT = credtype.PIDVCT
	// GermanPIDVCT is the type of the German PID.
	GermanPIDVCT = credtype.GermanPIDVCT
	// PIDNamespace is the mdoc namespace of the country-independent EUDI PID,
	// and also the doctype of both PIDs.
	PIDNamespace = credtype.PIDNamespace
	// GermanPIDNamespace is the mdoc namespace of the German additions.
	GermanPIDNamespace = credtype.GermanPIDNamespace
)

// DefaultClaims returns a minimal set of PID-like claims.
var DefaultClaims = map[string]any{
	"given_name":  "ERIKA",
	"family_name": "MUSTERMANN",
	"birthdate":   "1964-08-12",
}

// The country-independent claim sets below follow the attribute tables of the
// EUDI PID Rulebook, version 1.7, which lives in the attestation rulebooks
// catalog (github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog,
// rulebooks/pid/pid-rulebook.md) rather than in the ARF annex it was taken
// out of. The German ones follow the claim table of the German PID provider
// (https://demo.pid-provider.bundesdruckerei.de/credential-claims), which
// applies the German PID Rulebook.
//
// Both describe the same ERIKA MUSTERMANN test identity, so what separates
// them is the rulebook rather than the person: the German PID adds national
// attributes, and encodes some shared ones differently (a birth name under
// birth_name rather than birth_family_name, a street address with the house
// number folded in).
//
// Note that the data identifiers of the rulebook's own attribute table are
// not the identifiers of either encoding (its §2.1 says so), which is why
// birth_place appears here as place_of_birth in both, and why the SD-JWT and
// mdoc names differ from each other throughout.

// SDJWTPIDClaims holds the SD-JWT VC claims of the country-independent EUDI
// PID (vct urn:eudi:pid:1). address and place_of_birth are nested objects
// whose subclaims are individually disclosable, and nationalities is a
// selectively disclosable array.
var SDJWTPIDClaims = map[string]any{
	"family_name":       "MUSTERMANN",
	"given_name":        "ERIKA",
	"birthdate":         "1964-08-12",
	"birth_family_name": "GABLER",
	// ISO/IEC 5218: 0 unknown, 1 male, 2 female, 9 not applicable.
	"sex": 2,
	"place_of_birth": map[string]any{
		"locality": "BERLIN",
		"country":  "DE",
	},
	"address": map[string]any{
		// The rulebook keeps the house number out of the street, which is
		// where this differs from the German encoding.
		"street_address": "HEIDESTRAẞE",
		"house_number":   "17",
		"postal_code":    "51147",
		"locality":       "KÖLN",
		"region":         "NW",
		"country":        "DE",
	},
	"nationalities": []any{"DE"},
	// No age thresholds: the rulebook removed the age verification attributes
	// in version 1.1, following CIR 2024/2977. Germany keeps its own, which
	// is why they are in the German claim set and not here.
	"personal_administrative_number": "8172619283",
	"document_number":                "T220001293",
	"date_of_issuance":               PIDIssuanceDate(),
	"date_of_expiry":                 PIDExpiryDate(),
	"issuing_authority":              "DE",
	"issuing_country":                "DE",
}

// SDJWTGermanPIDClaims holds the SD-JWT VC claims of the German PID (vct
// urn:eudi:pid:de:1). Every claim the German claim table lists as present is
// here, including the ones it defines as always present but empty when the
// eID does not carry them (title, also_known_as). Claims it lists as unused
// (portrait, sex, email, phone number, document number, personal
// administrative number, issuing jurisdiction, issuance_date, trust_anchor,
// age_in_years, age_birth_year, birth given/family name, resident_address,
// resident_house_number) are absent, which is why this set is not a superset
// of the country-independent one.
var SDJWTGermanPIDClaims = map[string]any{
	// The country-independent type this credential is also of. A verifier
	// asking for urn:eudi:pid:1 is answered by this credential
	// (draft-ietf-oauth-sd-jwt-vc-18 §2.2.2.2).
	credtype.AkaVCTsClaim: []any{credtype.PIDVCT},

	"family_name": "MUSTERMANN",
	"given_name":  "ERIKA",
	"birth_name":  "GABLER",
	// Always present, and empty when the eID does not carry them.
	"title":          "",
	"also_known_as":  "",
	"birthdate":      "1964-08-12",
	"date_of_expiry": PIDExpiryDate(),
	// Derived from birthdate at issuance, which is why 65 is false while the
	// lower thresholds are true.
	"age_equal_or_over": map[string]any{
		"12": true,
		"14": true,
		"16": true,
		"18": true,
		"21": true,
		"65": false,
	},
	"place_of_birth": map[string]any{
		"locality": "BERLIN",
		// True only when the eID says the place of birth is unknown.
		"no_place_info": false,
	},
	"address": map[string]any{
		"street_address": "HEIDESTRAẞE 17",
		"postal_code":    "51147",
		"locality":       "KÖLN",
		"region":         "NW",
		"country":        "DE",
	},
	"nationalities":        []any{"DE"},
	"issuing_authority":    "DE",
	"issuing_country":      "DE",
	"source_document_type": "ID",
}

// MDOCPIDClaims holds the ISO 18013-5 elements of the country-independent
// EUDI PID (eu.europa.ec.eudi.pid.1). The same identity as SDJWTPIDClaims,
// under the attribute identifiers of the mdoc encoding: the address is flat
// here and carries its house number in the street, as the rulebook defines
// resident_street, while place_of_birth stays structured. All of it sits in
// the PID namespace, with no national additions.
var MDOCPIDClaims = map[string]any{
	"family_name":                    "MUSTERMANN",
	"given_name":                     "ERIKA",
	"birth_date":                     "1964-08-12",
	"family_name_birth":              "GABLER",
	"sex":                            2,
	"place_of_birth":                 map[string]any{"locality": "BERLIN", "country": "DE"},
	"nationality":                    []any{"DE"},
	"resident_street":                "HEIDESTRAẞE 17",
	"resident_postal_code":           "51147",
	"resident_city":                  "KÖLN",
	"resident_state":                 "NW",
	"resident_country":               "DE",
	"personal_administrative_number": "8172619283",
	"document_number":                "T220001293",
	"issuance_date":                  PIDIssuanceDate(),
	"expiry_date":                    PIDExpiryDate(),
	"issuing_authority":              "DE",
	"issuing_country":                "DE",
}

// MDOCGermanPIDClaims holds the ISO 18013-5 elements of the German PID. The
// doctype is the one of the country-independent PID, because ISO/IEC 18013-5
// has no inheritance between document types: what makes the credential German
// is the second namespace its national elements sit in, which claim keys
// carry as a "namespace:element" prefix.
var MDOCGermanPIDClaims = map[string]any{
	"family_name":          "MUSTERMANN",
	"given_name":           "ERIKA",
	"birth_date":           "1964-08-12",
	"expiry_date":          PIDExpiryDate(),
	"place_of_birth":       map[string]any{"locality": "BERLIN"},
	"nationality":          []any{"DE"},
	"resident_street":      "HEIDESTRAẞE 17",
	"resident_postal_code": "51147",
	"resident_city":        "KÖLN",
	"resident_state":       "NW",
	"resident_country":     "DE",
	"issuing_authority":    "DE",
	"issuing_country":      "DE",

	GermanPIDNamespace + ":birth_name":           "GABLER",
	GermanPIDNamespace + ":academic_title":       "",
	GermanPIDNamespace + ":also_known_as":        "",
	GermanPIDNamespace + ":no_place_info":        false,
	GermanPIDNamespace + ":age_over_12":          true,
	GermanPIDNamespace + ":age_over_14":          true,
	GermanPIDNamespace + ":age_over_16":          true,
	GermanPIDNamespace + ":age_over_18":          true,
	GermanPIDNamespace + ":age_over_21":          true,
	GermanPIDNamespace + ":age_over_65":          false,
	GermanPIDNamespace + ":source_document_type": "ID",
}

// PIDIssuanceDate is the day the PID was handed over. It is a calendar day
// with no time component.
func PIDIssuanceDate() string {
	return time.Now().UTC().Format(time.DateOnly)
}

// pidDateClaims are the claims whose value is a date computed at issuance,
// under the names each encoding gives them.
var pidDateClaims = map[string]func() string{
	"date_of_issuance": PIDIssuanceDate,
	"issuance_date":    PIDIssuanceDate,
	"date_of_expiry":   PIDExpiryDate,
	"expiry_date":      PIDExpiryDate,
}

// RefreshPIDDates recomputes the dated claims of a PID claim set in place.
//
// The claim sets above are package variables, so their dates are those of the
// moment the process started. That is invisible in a CLI run and wrong in a
// server that stays up: a wallet running for a month would hand out PIDs
// issued the day it booted, and expiring five years after that day rather
// than five years from now. Claims the set does not carry are not added,
// since the German PID deliberately has no issuance date.
func RefreshPIDDates(claims map[string]any) map[string]any {
	for name, value := range pidDateClaims {
		if _, ok := claims[name]; ok {
			claims[name] = value()
		}
	}
	return claims
}

// PIDExpiryDate is the administrative expiry of the PID: the German rulebook
// puts it five years after issuance (§10a (2) PAuswG), separate from the
// technical validity of the credential itself. It is a calendar day with no
// time component, and computed rather than fixed so the credential does not
// go stale on the shelf.
func PIDExpiryDate() string {
	return time.Now().UTC().AddDate(5, 0, 0).Format(time.DateOnly)
}
