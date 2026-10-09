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

// VCIVersion enables the documented 1.1 draft features when set to 1.1 and advertised by
// the issuer. Both versions support OpenID4VCI 1.0 flows.
type VCIVersion string

const (
	VCIVersion10 VCIVersion = "1.0"

	VCIVersion11 VCIVersion = "1.1"
)

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

// UsesInteractiveAuthorization requires wallet support and an advertised challenge
// endpoint (OpenID4VCI 1.1 §13.3).
func (v VCIVersion) UsesInteractiveAuthorization() bool {
	return v == VCIVersion11
}

// ABCADraft returns draft-07 for OpenID4VCI 1.0, because its references pin
// that draft (§14.7). The 1.1 editor's draft pins draft-08.
func (v VCIVersion) ABCADraft() int {
	if v == VCIVersion11 {
		return 8
	}
	return 7
}

// ABCALatestDraft is the newest ABCA draft. The wallet uses one of its methods
// only when the server metadata offers it.
const ABCALatestDraft = 10
