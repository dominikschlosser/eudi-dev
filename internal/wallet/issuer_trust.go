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
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/validate"
)

// catalogueEntryFor returns the catalogue entry that lists format with one of
// the types.
func (w *Wallet) catalogueEntryFor(format string, types []string) (registrar.CatalogAttestation, bool) {
	return catalogueEntryIn(w.Registrar().CatalogAttestations(), format, types)
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

// catalogueFindings reports offered attestations that are missing from the
// catalogue.
// No specification has the wallet check this, so these findings only warn.
func (w *Wallet) catalogueFindings(metadata map[string]any, configurations []string) []string {
	if !w.ARFChecks() {
		return nil
	}
	entries := w.Registrar().CatalogAttestations()
	var findings []string
	for _, o := range offeredAttestations(metadata, configurations, nil) {
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
// the trusted lists of its catalogue entry. The entry's category decides which
// rule applies. ARF ISSU_07, ISSU_08 and ISSU_09 have the wallet validate a
// PID, QEAA or PuB-EAA with the list of its providers, so an entry without a
// readable list is a finding. ISSU_10 asks for the check of an EAA only when
// the wallet has the anchors. PID and PuB-EAA lists on the list of trusted
// lists count too, because ETSI TS 119 602 V1.1.1 gives them a type (Annexes D
// and H).
func (w *Wallet) trustAnchorFindings(cred StoredCredential) []string {
	if !w.ARFChecks() {
		return nil
	}
	types := []string{cred.VCT, cred.DocType}
	entry, ok := w.catalogueEntryFor(cred.Format, types)
	if !ok {
		return nil
	}
	rule := registrar.CategoryOf(entry.Category).TrustRule
	eaa := rule == registrar.CategoryOf(credtemplate.CategoryEAA).TrustRule
	var candidates []trustedList
	for _, authority := range entry.Schema.TrustedAuthorities {
		// The wallet reads lists of trusted entities (ETSI TS 119 602) only.
		if authority.FrameworkType == "etsi_tl" && authority.IsLOTE != nil && *authority.IsLOTE && authority.Value != "" {
			list, err := w.readTrustedList(authority.Value)
			candidates = append(candidates, trustedList{URL: authority.Value, List: list, Err: err})
		}
	}
	if listType := categoryListType(entry.Category); listType != "" {
		for _, tl := range w.trustedLists() {
			linked := slices.ContainsFunc(candidates, func(c trustedList) bool { return c.URL == tl.URL })
			if tl.Err == nil && tl.List.SchemeInfo.LoTEType == listType && !linked {
				candidates = append(candidates, tl)
			}
		}
	}
	var problems []string
	read := false
	for _, c := range candidates {
		switch {
		case c.Err != nil && eaa:
			// ISSU_10 needs anchors, so the wallet only reports the list.
			w.addProtocolWarning("issuance", "trusted_list", fmt.Sprintf("The trusted list %s of the catalogue entry %q gives no anchors: %v", c.URL, entry.Name, c.Err), nil)
			continue
		case c.Err != nil:
			problems = append(problems, fmt.Sprintf("%s (%v)", c.URL, c.Err))
			continue
		}
		read = true
		err := validateWithAnchors(cred, serviceAnchors(c.List, issuanceServices))
		if err == nil {
			return nil
		}
		problems = append(problems, fmt.Sprintf("%s (%v)", c.URL, err))
	}
	switch {
	case !read && eaa:
		return nil
	case !read && len(problems) == 0:
		return []string{fmt.Sprintf("%s: the catalogue entry %q links no readable trusted list, so the wallet cannot validate the received %s", rule, entry.Name, credentialLabel(cred))}
	}
	return []string{fmt.Sprintf("%s: the signature of the received %s does not validate with the trusted lists of its catalogue entry %q: %s", rule, credentialLabel(cred), entry.Name, strings.Join(problems, ", "))}
}

// categoryListType is the ETSI TS 119 602 list type of a category, if it has
// one.
func categoryListType(category string) string {
	switch category {
	case credtemplate.CategoryPID:
		return pidTrustListType
	case credtemplate.CategoryPubEAA:
		return pubEAATrustListType
	}
	return ""
}

func validateWithAnchors(cred StoredCredential, anchors []trustlist.CertInfo) error {
	if len(anchors) == 0 {
		return fmt.Errorf("the trusted list names no issuance service")
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

// verifyTrustListSigner checks the JAdES signature of a trusted list (ETSI TS
// 119 602 V1.1.1 Annexes D.4 to H.4) and that its signer chains to one of the
// certificates: a trusted list operator, or the signer named by a pointer. The
// ARF has the wallet accept the provider trust anchors because of the list's
// signature (PPNot_05, TLPub_05, TLPub_07).
func verifyTrustListSigner(raw string, operators []*x509.Certificate) error {
	header, _, err := decodeCompactJWT(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("reading the trusted list: %w", err)
	}
	chain, err := validate.X5CCertificates(header)
	if err != nil || len(chain) == 0 {
		return errors.New("the trusted list has no x5c signer certificate")
	}
	if _, err := jws.Verify(strings.TrimSpace(raw), chain[0].PublicKey); err != nil {
		return errors.New("the trusted list's signature does not verify")
	}
	if err := verifyToAnchor(chain, operators); err != nil {
		return fmt.Errorf("the trusted list's signer does not chain to a trusted list operator: %w", err)
	}
	return nil
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
