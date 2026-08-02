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

// DefaultPIDVCT is the default Verifiable Credential Type for German EUDI PIDs.
const DefaultPIDVCT = "urn:eudi:pid:de:1"

// DefaultClaims returns a minimal set of PID-like claims.
var DefaultClaims = map[string]any{
	"given_name":  "ERIKA",
	"family_name": "MUSTERMANN",
	"birthdate":   "1984-08-12",
}

// SDJWTPIDClaims returns claims aligned with the current PID Rulebook's
// SD-JWT claim identifiers and the real German PID samples used in preprod.
// address, place_of_birth, and age_equal_or_over are nested objects with
// individually disclosable subclaims. nationalities is an array.
var SDJWTPIDClaims = map[string]any{
	"family_name": "MUSTERMANN",
	"given_name":  "ERIKA",
	"birthdate":   "1984-08-12",
	"age_equal_or_over": map[string]any{
		"18": true,
	},
	"age_in_years":      41,
	"age_birth_year":    1984,
	"birth_family_name": "GABLER",
	"birth_given_name":  "ERIKA",
	"place_of_birth": map[string]any{
		"locality": "BERLIN",
	},
	"address": map[string]any{
		"formatted":      "HEIDESTRAẞE 17, 51147 KÖLN, DE",
		"street_address": "HEIDESTRAẞE 17",
		"house_number":   "17",
		"locality":       "KÖLN",
		"postal_code":    "51147",
		"country":        "DE",
		"region":         "NW",
	},
	"nationalities":                  []any{"DE"},
	"sex":                            2,
	"email":                          "erika.mustermann@example.de",
	"phone_number":                   "+491701234567",
	"picture":                        "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2Q==",
	"date_of_issuance":               "2024-01-15",
	"date_of_expiry":                 "2029-01-15",
	"personal_administrative_number": "L01X00T47",
	"issuing_authority":              "DE",
	"issuing_country":                "DE",
	"document_number":                "TEST-PID-123456",
	"issuing_jurisdiction":           "DE-BE",
}

// MDOCPIDClaims returns claims aligned with the PID Rulebook's ISO 18013-5
// element identifiers and the real German PID samples used in preprod.
// mDoc claims stay flat at the namespace/element level, but individual element
// values such as birth_place can still be structured according to the rulebook.
var MDOCPIDClaims = map[string]any{
	"family_name":                    "MUSTERMANN",
	"given_name":                     "ERIKA",
	"birth_date":                     "1984-08-12",
	"age_over_18":                    true,
	"age_in_years":                   41,
	"age_birth_year":                 1984,
	"family_name_birth":              "GABLER",
	"given_name_birth":               "ERIKA",
	"birth_place":                    map[string]any{"locality": "BERLIN"},
	"nationality":                    []any{"DE"},
	"resident_address":               "HEIDESTRAẞE 17, 51147 KÖLN, DE",
	"resident_country":               "DE",
	"resident_state":                 "NW",
	"resident_city":                  "KÖLN",
	"resident_postal_code":           "51147",
	"resident_street":                "HEIDESTRAẞE 17",
	"resident_house_number":          "17",
	"personal_administrative_number": "L01X00T47",
	"sex":                            2,
	"email_address":                  "erika.mustermann@example.de",
	"mobile_phone_number":            "+491701234567",
	"expiry_date":                    "2029-01-15T00:00:00Z",
	"issuance_date":                  "2024-01-15T00:00:00Z",
	"issuing_authority":              "DE",
	"issuing_country":                "DE",
	"document_number":                "TEST-PID-123456",
	"issuing_jurisdiction":           "DE-BE",
}

// PIDClaims is an alias for SDJWTPIDClaims for backward compatibility.
// Deprecated: Use SDJWTPIDClaims or MDOCPIDClaims depending on the credential format.
var PIDClaims = SDJWTPIDClaims
