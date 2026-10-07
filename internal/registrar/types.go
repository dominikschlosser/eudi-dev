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

// Package registrar implements the wallet's relying party registrar (ETSI TS 119 475,
// EC TS05) and its catalogue of attestations (EC TS11).
package registrar

// Entitlements of ETSI TS 119 475 V1.2.1 Annex A.2.
const (
	ServiceProviderEntitlement = "https://uri.etsi.org/19475/Entitlement/Service_Provider"
	QEAAProviderEntitlement    = "https://uri.etsi.org/19475/Entitlement/QEAA_Provider"
	NonQEAAProviderEntitlement = "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
	PubEAAProviderEntitlement  = "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider"
	PIDProviderEntitlement     = "https://uri.etsi.org/19475/Entitlement/PID_Provider"
)

// IssuerInfoEntry matches ETSI TS 119 472-3 issuer_info elements.
type IssuerInfoEntry struct {
	Format string `json:"format"`
	Data   any    `json:"data"`
}

// Identifier is a minimal TS5-compatible identifier object.
type Identifier struct {
	Identifier string `json:"identifier"`
	Type       string `json:"type,omitempty"`
}

// MultiLangString is a localised string as defined in TS5.
type MultiLangString struct {
	Lang    string `json:"lang"`
	Content string `json:"content"`
}

// SupervisoryAuthority is a supervisory authority record as defined in TS5.
type SupervisoryAuthority struct {
	Name    string   `json:"name"`
	Country string   `json:"country"`
	Email   []string `json:"email,omitempty"`
	Phone   []string `json:"phone,omitempty"`
	FormURI []string `json:"formURI,omitempty"`
}

// ProvidedAttestation describes an issued attestation type in TS5 terms.
type ProvidedAttestation struct {
	Format string         `json:"format"`
	Meta   map[string]any `json:"meta"`
}

// RegistrarDataset is the minimal subset of registrar data needed for
// issuer-authorization checks.
type RegistrarDataset struct {
	Identifier           []Identifier          `json:"identifier"`
	TradeName            string                `json:"tradeName,omitempty"`
	SupportURI           []string              `json:"supportURI,omitempty"`
	SrvDescription       []MultiLangString     `json:"srvDescription"`
	IsPSB                bool                  `json:"isPSB"`
	Entitlements         []string              `json:"entitlements"`
	ProvidesAttestations []ProvidedAttestation `json:"providesAttestations"`
	SupervisoryAuthority SupervisoryAuthority  `json:"supervisoryAuthority"`
	RegistryURI          string                `json:"registryURI"`
	IsIntermediary       bool                  `json:"isIntermediary"`
}

// registeredEntitlements are the entitlements of ETSI TS 119 475 V1.2.1 Annex
// A.2.
var registeredEntitlements = []string{
	ServiceProviderEntitlement,
	QEAAProviderEntitlement,
	NonQEAAProviderEntitlement,
	PubEAAProviderEntitlement,
	PIDProviderEntitlement,
	"https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider",
	"https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider",
	"https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider",
	"https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider",
	"https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider",
}

// providerEntitlements entitle a service to issue attestations, and its
// registration certificate lists them (ETSI TS 119 475 V1.2.1 GEN-5.2.4-05).
var providerEntitlements = []string{PIDProviderEntitlement, QEAAProviderEntitlement, PubEAAProviderEntitlement, NonQEAAProviderEntitlement}
