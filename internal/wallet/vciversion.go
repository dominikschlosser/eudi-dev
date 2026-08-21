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

import "fmt"

// VCIVersion selects which OpenID4VCI feature level the wallet uses as a
// client. The wallet speaks 1.0 either way; 1.1 adds the draft features listed
// in docs/spec-compliance.md, each of which is negotiated in metadata, so
// selecting it changes nothing against an issuer that offers none of them.
type VCIVersion string

const (
	// VCIVersion10 is OpenID4VCI 1.0, the published version and the default.
	VCIVersion10 VCIVersion = "1.0"

	// VCIVersion11 adds the parts of the 1.1 draft this wallet implements.
	VCIVersion11 VCIVersion = "1.1"
)

// ParseVCIVersion validates and normalizes the user-provided version.
func ParseVCIVersion(raw string) (VCIVersion, error) {
	switch VCIVersion(raw) {
	case "", VCIVersion10:
		return VCIVersion10, nil
	case VCIVersion11:
		return VCIVersion11, nil
	default:
		return "", fmt.Errorf("invalid OpenID4VCI version %q (must be '1.0' or '1.1')", raw)
	}
}

// UsesInteractiveAuthorization reports whether the wallet may use Interactive
// Authorization (OpenID4VCI 1.1 §6). §13.3 makes the endpoint's presence the
// server's half of that negotiation; this is the wallet's half.
func (v VCIVersion) UsesInteractiveAuthorization() bool {
	return v == VCIVersion11
}

// ABCADraft is the draft of OAuth 2.0 Attestation-Based Client Authentication
// this OpenID4VCI version pins: 1.0 pins draft-07 (its §14.7 says to keep
// using the pinned versions in preference to later ones), the 1.1 editor
// draft pins draft-08.
func (v VCIVersion) ABCADraft() int {
	if v == VCIVersion11 {
		return 8
	}
	return 7
}

// ABCALatestDraft is the newest published ABCA draft this wallet supports on
// top of the pinned ones. Its additions (the attest_jwt_client_auth_dpop
// method and the client_attestation_pop_methods_supported metadata) are
// negotiated through server metadata.
const ABCALatestDraft = 10
