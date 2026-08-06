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

const (
	// TypeSDJWTVC is the typ header parameter of an SD-JWT VC.
	// draft-ietf-oauth-sd-jwt-vc-18 §2.2.1: "The Issuer MUST include the typ
	// header parameter in the SD-JWT. The typ value MUST use dc+sd-jwt."
	TypeSDJWTVC = "dc+sd-jwt"

	// TypeSDJWTVCLegacy is the value the same draft used from July 2023 until
	// November 2024. §2.2.1 keeps it alive: "In order to facilitate a
	// minimally disruptive transition, both vc+sd-jwt and dc+sd-jwt should be
	// accepted as the value of the typ header for a reasonable transitional
	// period."
	TypeSDJWTVCLegacy = "vc+sd-jwt"
)

// AcceptedVCTypes lists the typ header parameter values an SD-JWT VC may
// carry. The list is exactly two values, and anything else is not an SD-JWT
// VC, whatever else it may be.
func AcceptedVCTypes() []string {
	return []string{TypeSDJWTVC, TypeSDJWTVCLegacy}
}

// IsAcceptedVCType reports whether typ names an SD-JWT VC. The comparison is
// case-sensitive, as media type parameters carried in JOSE headers are
// matched verbatim.
func IsAcceptedVCType(typ string) bool {
	return typ == TypeSDJWTVC || typ == TypeSDJWTVCLegacy
}

// ValidateVCType checks the typ header parameter of an Issuer-signed JWT
// against the two accepted values. A credential that omits typ, or names
// something else, is not an SD-JWT VC per draft-ietf-oauth-sd-jwt-vc-18
// §2.2.1.
func ValidateVCType(header map[string]any) error {
	raw, present := header["typ"]
	if !present {
		return fmt.Errorf("no typ header parameter, want %s", TypeSDJWTVC)
	}
	typ, ok := raw.(string)
	if !ok {
		return fmt.Errorf("typ header parameter is not a string")
	}
	if !IsAcceptedVCType(typ) {
		return fmt.Errorf("typ header parameter is %q, want %s (or %s during the transition)", typ, TypeSDJWTVC, TypeSDJWTVCLegacy)
	}
	return nil
}
