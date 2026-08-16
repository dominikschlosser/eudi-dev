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
// client.
//
// The wallet speaks OpenID4VCI 1.0, the published final version, and that does
// not change with this setting. What the setting decides is whether the wallet
// also uses what the 1.1 draft adds on top of it. Every one of those features
// is negotiated in metadata, so selecting 1.1 changes nothing at all against an
// issuer that publishes none of them: it is the wallet saying what it is
// willing to use, not what it demands.
//
// The features 1.1 selects are listed in docs/spec-compliance.md. Keeping them
// behind a version rather than a flag each is deliberate: 1.1 is a draft, and a
// test wallet should be able to say which document it is behaving like.
type VCIVersion string

const (
	// VCIVersion10 is OpenID4VCI 1.0, the published final version, and the
	// default.
	VCIVersion10 VCIVersion = "1.0"

	// VCIVersion11 adds the parts of the OpenID4VCI 1.1 draft this wallet
	// implements.
	VCIVersion11 VCIVersion = "1.1"
)

// ParseVCIVersion validates and normalizes the user-provided version. An empty
// value selects the default, as it does for the validation mode.
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
// Authorization (OpenID4VCI 1.1 §6) where an authorization server offers it.
// The endpoint's presence is the server's half of that negotiation ("the
// presence of authorization_challenge_endpoint is sufficient for a Wallet to
// determine that it can use Interactive Authorization", §13.3), and this is the
// wallet's half.
func (v VCIVersion) UsesInteractiveAuthorization() bool {
	return v == VCIVersion11
}
