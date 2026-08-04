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

import "time"

// DefaultPIDVCT is the default Verifiable Credential Type for German EUDI PIDs.
const DefaultPIDVCT = "urn:eudi:pid:de:1"

// PIDDENamespace holds the national additions of the German PID Rulebook.
// In mdoc those claims are namespaced, while SD-JWT keeps everything in one
// flat claim set.
const PIDDENamespace = "eu.europa.ec.eudi.pid.de.1"

// The claim sets below follow the claim table of the German PID provider
// (https://demo.pid-provider.bundesdruckerei.de/credential-claims), using the
// values of its ERIKA MUSTERMANN test identity. Every claim that table lists
// as present is here, including the ones it defines as always present but
// empty when the eID does not carry them (title, also_known_as). Claims it
// lists as unused (portrait, sex, email, phone number, document number,
// personal administrative number, issuing jurisdiction, issuance_date,
// trust_anchor, age_in_years, age_birth_year, birth given/family name,
// resident_address, resident_house_number) are absent.

// DefaultClaims returns a minimal set of PID-like claims.
var DefaultClaims = map[string]any{
	"given_name":  "ERIKA",
	"family_name": "MUSTERMANN",
	"birthdate":   "1964-08-12",
}

// SDJWTPIDClaims holds the SD-JWT VC claims of a German PID (vct
// urn:eudi:pid:de:1). address, place_of_birth and age_equal_or_over are
// nested objects whose subclaims are individually disclosable, and
// nationalities is a selectively disclosable array.
var SDJWTPIDClaims = map[string]any{
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

// MDOCPIDClaims holds the ISO 18013-5 elements of a German PID
// (eu.europa.ec.eudi.pid.1). The same identity as SDJWTPIDClaims, under the
// element identifiers of the mdoc encoding: the address is flat here, the age
// thresholds are individual booleans, and birth_place stays structured.
// Keys prefixed with a namespace go into that namespace, which is where the
// rulebook puts the national additions of the German PID.
var MDOCPIDClaims = map[string]any{
	"family_name":          "MUSTERMANN",
	"given_name":           "ERIKA",
	"birth_date":           "1964-08-12",
	"expiry_date":          PIDExpiryDate(),
	"birth_place":          map[string]any{"locality": "BERLIN"},
	"nationality":          []any{"DE"},
	"resident_street":      "HEIDESTRAẞE 17",
	"resident_postal_code": "51147",
	"resident_city":        "KÖLN",
	"resident_state":       "NW",
	"resident_country":     "DE",
	"issuing_authority":    "DE",
	"issuing_country":      "DE",

	PIDDENamespace + ":birth_name":           "GABLER",
	PIDDENamespace + ":academic_title":       "",
	PIDDENamespace + ":also_known_as":        "",
	PIDDENamespace + ":no_place_info":        false,
	PIDDENamespace + ":age_over_12":          true,
	PIDDENamespace + ":age_over_14":          true,
	PIDDENamespace + ":age_over_16":          true,
	PIDDENamespace + ":age_over_18":          true,
	PIDDENamespace + ":age_over_21":          true,
	PIDDENamespace + ":age_over_65":          false,
	PIDDENamespace + ":source_document_type": "ID",
}

// PIDExpiryDate is the administrative expiry of the PID: the German rulebook
// puts it five years after issuance (§10a (2) PAuswG), separate from the
// technical validity of the credential itself. It is a calendar day with no
// time component, and computed rather than fixed so the credential does not
// go stale on the shelf.
func PIDExpiryDate() string {
	return time.Now().UTC().AddDate(5, 0, 0).Format(time.DateOnly)
}

// PIDClaims is an alias for SDJWTPIDClaims for backward compatibility.
// Deprecated: Use SDJWTPIDClaims or MDOCPIDClaims depending on the credential format.
var PIDClaims = SDJWTPIDClaims
