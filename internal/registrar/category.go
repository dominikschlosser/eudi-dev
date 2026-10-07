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

package registrar

import "github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"

// Category is what the wallet, the registrar and the UI know about a
// credential category.
type Category struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// Entitlement registers a provider of the category (ETSI TS 119 475
	// V1.2.1 Annex A.2).
	Entitlement string `json:"entitlement"`
	// TrustRule is the ARF rule for validating a received credential with
	// the trusted list of its providers.
	TrustRule string `json:"trustRule"`
	// AttestationLoS is the default level of security of a catalogue entry
	// (TS11 v1.0 §4.3). A PID is issued at assurance level high, and the
	// test wallet treats QEAAs and PuB-EAAs the same way. The level of other
	// EAAs depends on their rulebook.
	AttestationLoS string `json:"attestationLoS"`
}

var categories = []Category{
	{ID: credtemplate.CategoryPID, Label: "PID", Description: "PID", Entitlement: PIDProviderEntitlement, TrustRule: "ARF ISSU_07", AttestationLoS: "iso_18045_high"},
	{ID: credtemplate.CategoryQEAA, Label: "QEAA", Description: "QEAA (qualified)", Entitlement: QEAAProviderEntitlement, TrustRule: "ARF ISSU_08", AttestationLoS: "iso_18045_high"},
	{ID: credtemplate.CategoryPubEAA, Label: "PuB-EAA", Description: "PuB-EAA (public body)", Entitlement: PubEAAProviderEntitlement, TrustRule: "ARF ISSU_09", AttestationLoS: "iso_18045_high"},
	{ID: credtemplate.CategoryEAA, Label: "EAA", Description: "EAA", Entitlement: NonQEAAProviderEntitlement, TrustRule: "ARF ISSU_10", AttestationLoS: "iso_18045_basic"},
}

// Categories lists the credential categories in the order of
// credtemplate.Categories.
func Categories() []Category {
	return append([]Category(nil), categories...)
}

// CategoryOf describes a category. An empty or unknown one is an EAA.
func CategoryOf(id string) Category {
	for _, c := range categories {
		if c.ID == id {
			return c
		}
	}
	return categories[len(categories)-1]
}

// CategoryOfEntitlement names the category of a provider entitlement.
func CategoryOfEntitlement(entitlement string) (string, bool) {
	for _, c := range categories {
		if c.Entitlement == entitlement {
			return c.ID, true
		}
	}
	return "", false
}
