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

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// OfferedCredential describes one credential configuration an issuer offers,
// as far as the offer and the issuer metadata reveal it.
type OfferedCredential struct {
	ID          string   `json:"id"`
	Format      string   `json:"format,omitempty"`
	VCT         string   `json:"vct,omitempty"`
	DocType     string   `json:"doctype,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Claims      []string `json:"claims,omitempty"`
	// Display is the appearance the issuer declares for this configuration, so
	// the consent dialog shows the card the user is about to accept. Its images
	// are fetched now through the policed client, the same defensive path the
	// issuance itself uses (unless --adhoc-display-images keeps the https URL for
	// the card to fetch on demand).
	Display *CredentialDisplay `json:"display,omitempty"`
}

// IssuanceOfferDetails is what the consent dialog shows about a credential
// offer: who is issuing, what is being issued, and how the flow will proceed.
// Everything beyond the offer itself comes from the issuer's metadata, which
// is optional, so every field degrades to empty rather than blocking consent.
type IssuanceOfferDetails struct {
	Issuer     string `json:"issuer"`
	IssuerName string `json:"issuer_name,omitempty"`
	IssuerLogo string `json:"issuer_logo,omitempty"`
	Grant      string `json:"grant,omitempty"`
	TxCode     bool   `json:"tx_code,omitempty"`
	TxCodeHint string `json:"tx_code_hint,omitempty"`
	// The three members OID4VCI 1.0 defines on tx_code, passed through so the
	// dialog can size and type its input and repeat the issuer's own wording.
	TxCodeInputMode   string              `json:"tx_code_input_mode,omitempty"`
	TxCodeLength      int                 `json:"tx_code_length,omitempty"`
	TxCodeDescription string              `json:"tx_code_description,omitempty"`
	Credentials       []OfferedCredential `json:"credentials,omitempty"`
	MetadataError     string              `json:"metadata_error,omitempty"`
	// OfferURI and ResolveError are set when an offer delivered by reference
	// could not be fetched, so the dialog can name the host and say why
	// nothing more is known.
	OfferURI     string `json:"offer_uri,omitempty"`
	ResolveError string `json:"resolve_error,omitempty"`
}

// describeCredentialOffer summarizes an offer for the consent dialog. It
// fetches the issuer metadata to resolve display names and claims. A failure
// there is recorded and the offer is still described from what it carries,
// because a user should not be blocked from deciding by an issuer that
// publishes no metadata.
func (w *Wallet) describeCredentialOffer(offer *oid4vc.CredentialOffer) *IssuanceOfferDetails {
	if offer == nil {
		return nil
	}
	details := &IssuanceOfferDetails{
		Issuer: offer.CredentialIssuer,
		Grant:  describeOfferGrant(offer.Grants),
	}
	if len(offer.Grants.TxCode) > 0 {
		details.TxCode = true
		details.TxCodeHint = describeTxCode(offer.Grants.TxCode)
		details.TxCodeInputMode, _ = offer.Grants.TxCode["input_mode"].(string)
		details.TxCodeDescription, _ = offer.Grants.TxCode["description"].(string)
		if length, ok := numericValue(offer.Grants.TxCode["length"]); ok {
			details.TxCodeLength = int(length)
		}
	}

	metadata, err := fetchIssuerMetadata(offer.CredentialIssuer)
	if err != nil {
		details.MetadataError = err.Error()
	} else {
		details.IssuerName, details.IssuerLogo = issuerDisplay(metadata)
	}

	for _, id := range offer.CredentialConfigurationIDs {
		details.Credentials = append(details.Credentials, w.describeConfiguration(metadata, id))
	}
	return details
}

func describeOfferGrant(grants oid4vc.OfferGrants) string {
	switch {
	case grants.PreAuthorizedCode != "":
		return "pre-authorized code"
	case grants.AuthorizationCode != "" || grants.IssuerState != "":
		return "authorization code"
	default:
		return ""
	}
}

// describeTxCode turns the tx_code object into something a person can act on.
func describeTxCode(txCode map[string]any) string {
	description, _ := txCode["description"].(string)
	if strings.TrimSpace(description) != "" {
		return description
	}
	mode, _ := txCode["input_mode"].(string)
	length, hasLength := numericValue(txCode["length"])
	switch {
	case hasLength && mode != "":
		return fmt.Sprintf("%d %s characters", int(length), mode)
	case hasLength:
		return fmt.Sprintf("%d characters", int(length))
	case mode != "":
		return mode
	}
	return ""
}

func numericValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}

// issuerDisplay picks the issuer's name and logo from its metadata.
func issuerDisplay(metadata map[string]any) (name, logo string) {
	entry, ok := firstDisplayEntry(metadata["display"])
	if !ok {
		return "", ""
	}
	name, _ = entry["name"].(string)
	if logoObj, ok := entry["logo"].(map[string]any); ok {
		logo, _ = logoObj["uri"].(string)
	}
	return name, logo
}

// describeConfiguration resolves one configuration id against the metadata.
// An id the issuer does not publish still yields an entry, so the dialog can
// show what was offered rather than silently dropping it.
func (w *Wallet) describeConfiguration(metadata map[string]any, id string) OfferedCredential {
	out := OfferedCredential{ID: id}
	configs, _ := metadata["credential_configurations_supported"].(map[string]any)
	config, _ := configs[id].(map[string]any)
	if config == nil {
		return out
	}
	out.Format, _ = config["format"].(string)
	out.VCT, _ = config["vct"].(string)
	out.DocType, _ = config["doctype"].(string)
	// What the credential is called and which claims it carries sit one level
	// down. OID4VCI 1.0 §12.2.4 puts them under credential_metadata: "Object
	// containing information relevant to the usage and display of issued
	// Credentials", holding the display array and the claims array. Reading them
	// off the configuration itself finds nothing at a conformant issuer, and the
	// consent dialog then names no credential and lists no claims.
	credentialMetadata, _ := config["credential_metadata"].(map[string]any)
	if entry, ok := firstDisplayEntry(credentialMetadata["display"]); ok {
		out.Name, _ = entry["name"].(string)
		out.Description, _ = entry["description"].(string)
	}
	out.Claims = configurationClaimNames(credentialMetadata["claims"])
	// The full appearance (colors, logo, card art), resolved the same way the
	// issued credential's is, so the consent dialog previews the card. Its
	// images go through the policed, capped, dimension-guarded fetch.
	out.Display = w.resolveCredentialDisplay(metadata, id)
	return out
}

// firstDisplayEntry returns the first entry of an OID4VCI display array.
// Locale negotiation is deliberately skipped: this is a developer tool, and
// showing the issuer's first declared name beats showing none.
func firstDisplayEntry(raw any) (map[string]any, bool) {
	entries, ok := raw.([]any)
	if !ok || len(entries) == 0 {
		return nil, false
	}
	entry, ok := entries[0].(map[string]any)
	return entry, ok
}

// configurationClaimNames lists the claims a configuration declares. OID4VCI
// 1.0 uses an array of objects with a "path", while earlier drafts used a
// nested object keyed by claim name. Both appear in the wild.
func configurationClaimNames(raw any) []string {
	switch claims := raw.(type) {
	case []any:
		var names []string
		for _, entry := range claims {
			claim, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			path, ok := claim["path"].([]any)
			if !ok || len(path) == 0 {
				continue
			}
			names = append(names, claimPathString(path))
		}
		return names
	case map[string]any:
		names := make([]string, 0, len(claims))
		for name := range claims {
			names = append(names, name)
		}
		sort.Strings(names)
		return names
	}
	return nil
}
