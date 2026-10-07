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
	"log"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustlist"
)

// catalogueEntryFor returns the catalogue entry that lists format with one of
// the types.
func (w *Wallet) catalogueEntryFor(format string, types []string) (registrar.CatalogAttestation, bool) {
	return catalogueEntryIn(w.Registrar().CatalogAttestations(w.RegistrarBase()), format, types)
}

func catalogueEntryIn(entries []registrar.CatalogAttestation, format string, types []string) (registrar.CatalogAttestation, bool) {
	for _, entry := range entries {
		if slices.ContainsFunc(entry.Credentials, func(c registrar.CatalogCredential) bool {
			return c.Format == format && slices.Contains(types, c.Type)
		}) {
			return entry, true
		}
	}
	return registrar.CatalogAttestation{}, false
}

// catalogueFindings names the offered attestations the catalogue doesn't list.
// No specification has the wallet check this, so these findings only warn.
func (w *Wallet) catalogueFindings(metadata map[string]any, configurations []string) []string {
	if !w.ARFChecks() {
		return nil
	}
	entries := w.Registrar().CatalogAttestations(w.RegistrarBase())
	var findings []string
	for _, o := range offeredAttestations(metadata, configurations) {
		if !o.known || len(o.types) == 0 {
			continue
		}
		if _, ok := catalogueEntryIn(entries, o.format, o.types); !ok {
			findings = append(findings, fmt.Sprintf("Attestation catalogue: the issuer offers %s (%s), and the catalogue has no entry for it. Add an entry to describe its schema and trusted list.", credentialTypeName(o.format, o.types), o.format))
		}
	}
	return findings
}

// reportCatalogueFindings warns in both modes.
func (w *Wallet) reportCatalogueFindings(issuer string, findings []string) {
	for _, f := range findings {
		log.Printf("[VCI] WARNING: %s", f)
		w.addProtocolWarning("issuance", "catalogue_finding", f, map[string]any{"issuer": issuer})
	}
}

// trustAnchorFindings validates the signature of a received credential with
// the trust anchors of its catalogue entry. ARF ISSU_07 has the wallet use the
// PID Provider LoTE, ISSU_08 and ISSU_09 the lists of QEAA and PuB-EAA
// Providers. ISSU_10 asks for the check whenever the wallet has the anchors, so
// an entry without an etsi_tl trusted list is not checked.
func (w *Wallet) trustAnchorFindings(cred StoredCredential) []string {
	if !w.ARFChecks() {
		return nil
	}
	types := []string{cred.VCT, cred.DocType}
	entry, ok := w.catalogueEntryFor(cred.Format, types)
	if !ok {
		return nil
	}
	rule := "ARF ISSU_08 to ISSU_10"
	if slices.ContainsFunc(types, credtype.IsPIDType) {
		rule = "ARF ISSU_07"
	}
	var problems []string
	for _, authority := range entry.Schema.TrustedAuthorities {
		// The wallet reads lists of trusted entities (ETSI TS 119 602) only.
		if authority.FrameworkType != "etsi_tl" || authority.IsLOTE == nil || !*authority.IsLOTE || authority.Value == "" {
			continue
		}
		err := w.validateWithTrustList(cred, authority.Value)
		if err == nil {
			return nil
		}
		problems = append(problems, fmt.Sprintf("%s (%v)", authority.Value, err))
	}
	if len(problems) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%s: the signature of the received %s does not validate with the trusted lists of its catalogue entry %q: %s", rule, credentialLabel(cred), entry.Name, strings.Join(problems, ", "))}
}

func (w *Wallet) validateWithTrustList(cred StoredCredential, url string) error {
	anchors, err := w.trustListAnchors(url)
	if err != nil {
		return err
	}
	key, err := credentialChainKey(cred, anchors)
	if err != nil {
		return err
	}
	var valid bool
	switch cred.Format {
	case "dc+sd-jwt":
		token, err := sdjwt.ParseLenient(cred.Raw)
		if err != nil {
			return err
		}
		valid = sdjwt.Verify(token, key).SignatureValid
	case "mso_mdoc":
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			return err
		}
		valid = mdoc.Verify(doc, key).SignatureValid
	}
	if !valid {
		return fmt.Errorf("the signature does not verify with the key of its certificate")
	}
	return nil
}

// trustListAnchors builds the wallet's own trusted lists in process, because
// the wallet may not serve them over HTTP. Other lists are fetched.
func (w *Wallet) trustListAnchors(url string) ([]trustlist.CertInfo, error) {
	if id, ok := strings.CutPrefix(url, w.RegistrarBase()+"/api/trustlists/"); ok {
		group, found := FindTrustListGroupForWallet(w, id, "", "")
		if !found {
			return nil, fmt.Errorf("the wallet has no trusted list %q", id)
		}
		jwt, err := GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, "/api/trustlists/"+group.ID)
		if err != nil {
			return nil, err
		}
		return parseTrustListAnchors(jwt)
	}
	return fetchTrustListCertificates(url, w.HTTPClient())
}

// checkReceivedCredentials runs the trust anchor check on every credential of
// a credential response before the wallet stores one. Each copy of a batch is
// signed on its own. In strict mode a failed check refuses the response (ARF
// ISSU_11b).
func (w *Wallet) checkReceivedCredentials(credResp map[string]any, issuer string) error {
	var findings []string
	for _, raw := range credentialStringsFromResponse(credResp) {
		findings = append(findings, w.trustAnchorFindings(receivedCredential(raw))...)
	}
	if len(findings) == 0 {
		return nil
	}
	return w.reportARFFindings(issuer, slices.Compact(findings), "the received credential fails the ARF checks")
}

// receivedCredential reads the format and type of a raw SD-JWT VC or mdoc.
func receivedCredential(raw string) StoredCredential {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "~") {
		token, err := sdjwt.ParseLenient(raw)
		if err != nil {
			return StoredCredential{}
		}
		return StoredCredential{Format: "dc+sd-jwt", VCT: stringClaim(token.Payload["vct"]), Raw: raw}
	}
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return StoredCredential{}
	}
	return StoredCredential{Format: "mso_mdoc", DocType: doc.DocType, Raw: raw}
}
