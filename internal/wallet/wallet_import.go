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
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
)

// newCredentialID creates a short hex id for a stored credential, the way git
// names an object. It is long enough to stay unique in a wallet and short
// enough to show and type, and a command resolves it from an unambiguous
// prefix. It panics only if the system has no entropy.
func newCredentialID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("wallet: no entropy for a credential id: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ImportCredential auto-detects and imports a credential string.
// It returns a pointer to a copy of the newly imported credential, safe to
// use even after further mutations to w.Credentials.
func (w *Wallet) ImportCredential(raw string) (*StoredCredential, error) {
	return w.importCredential(raw, "", "")
}

// importPrimaryCredential imports the credential selectPrimaryCredential picked,
// bound to the proof key it names (its own, whichever key that is). Recording
// the key as the credential is imported keeps its key binding signable and, on a
// per-request clone, forwards the key to the real wallet with the credential.
func (w *Wallet) importPrimaryCredential(raw string, keys []*ecdsa.PrivateKey) (*StoredCredential, error) {
	return w.importCredential(raw, "", primaryBindingKeyPEM(raw, keys))
}

// importBatchCopy imports one copy of a batch, tied to the batch group and
// bound to its own key. The batch fields are set before the holder-binding note
// runs, so a copy bound to its own key is not flagged as one the wallet cannot
// present.
func (w *Wallet) importBatchCopy(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	return w.importCredential(raw, group, bindingKeyPEM)
}

func (w *Wallet) importCredential(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	cred, err := w.importDetectedFormat(strings.TrimSpace(raw), group, bindingKeyPEM)
	if err != nil {
		return nil, err
	}
	w.adoptOwnStatusEntry(cred)
	w.noteUnheldKeyBinding(cred)
	w.noteDIDIssuerKey(cred)
	return cred, nil
}

// credentialIssuerDID returns the DID a credential names as the key that
// signed it. An mdoc names its issuer by the certificate chain in the COSE
// header and never by a DID, so only the JWT-shaped formats are read.
func credentialIssuerDID(raw string) string {
	jwtPart := strings.TrimSpace(raw)
	if idx := strings.Index(jwtPart, "~"); idx >= 0 {
		jwtPart = jwtPart[:idx]
	}
	header, payload, _, err := format.ParseJWTParts(jwtPart)
	if err != nil {
		return ""
	}
	kid, _ := header["kid"].(string)
	iss, _ := payload["iss"].(string)
	return keys.DIDReference(kid, iss)
}

// noteDIDIssuerKey reports a credential whose issuer key is named by a DID.
// This toolkit resolves an issuer key through the x5c chain HAIP 1.0 §6.1.1
// requires or through the issuer metadata SD-JWT VC defines, so such a
// credential is stored with its signature unchecked and its status list
// unverifiable.
func (w *Wallet) noteDIDIssuerKey(cred *StoredCredential) {
	if w == nil || cred == nil {
		return
	}
	did := credentialIssuerDID(cred.Raw)
	if did == "" {
		return
	}
	details := map[string]any{
		"credential_id":  cred.ID,
		"format":         cred.Format,
		"issuer_key_did": did,
	}
	addStringDetail(details, "vct", cred.VCT)
	detail := fmt.Sprintf(
		"Credential %s names its issuer key by the DID %s. Nothing here resolves a DID (HAIP 1.0 §6.1.1 has the issuer's signing certificate travel in the x5c header), so this credential is kept with its issuer signature unverified, and a status list token signed the same way cannot be checked either.",
		credentialLabel(*cred), did)
	w.addProtocolWarning("wallet", "credential_issuer_key_is_a_did", detail, details)
	log.Printf("[Wallet] WARNING: %s", detail)
}

// importDetectedFormat stores a credential in whichever of the formats the
// wallet keeps it turns out to be. The batch group and per-copy binding key are
// carried in so they sit on the credential before it is appended, since that is
// when a per-request clone forwards it to the wallet it was made from.
func (w *Wallet) importDetectedFormat(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	// Try SD-JWT first (contains ~)
	if strings.Contains(raw, "~") {
		cred, err := w.importSDJWT(raw, group, bindingKeyPEM)
		if err != nil {
			return nil, err
		}
		log.Printf("[Wallet] Imported SD-JWT credential: vct=%s claims=%d disclosures=%d", cred.VCT, len(cred.Claims), len(cred.Disclosures))
		return cred, nil
	}

	// Try mDoc (base64url or hex encoded CBOR)
	detected := format.Detect(raw)
	if detected == format.FormatMDOC {
		cred, err := w.importMDoc(raw, group, bindingKeyPEM)
		if err != nil {
			return nil, err
		}
		log.Printf("[Wallet] Imported mDoc credential: docType=%s claims=%d", cred.DocType, len(cred.Claims))
		return cred, nil
	}

	// Try as plain JWT VC (3-part JWT without ~)
	if strings.Count(raw, ".") == 2 {
		cred, err := w.importPlainJWT(raw, group, bindingKeyPEM)
		if err != nil {
			return nil, err
		}
		log.Printf("[Wallet] Imported plain JWT credential: vct=%s claims=%d", cred.VCT, len(cred.Claims))
		return cred, nil
	}

	return nil, fmt.Errorf("unable to detect credential format (expected SD-JWT or mDoc)")
}

// adoptOwnStatusEntry records a status list entry for an imported credential
// that points at this wallet's own status list. The wallet is the holder of
// such a credential, not its issuer, but the list is still the one it serves:
// without the entry the credential would show up as externally governed and
// nothing could ever flip its bit. The demo issuer produces exactly this case.
func (w *Wallet) adoptOwnStatusEntry(cred *StoredCredential) {
	if w == nil || cred == nil {
		return
	}
	own := strings.TrimSpace(w.StatusListURL())
	if own == "" {
		return
	}
	ref := CredentialStatusRef(*cred)
	if ref == nil || ref.URI != own {
		return
	}
	if _, exists := w.StatusEntryFor(cred.ID); exists {
		return
	}
	w.registerStatusEntry(cred.ID, ref.Idx)
}

// appendCredential adds a credential to the wallet and returns a copy.
func (w *Wallet) appendCredential(cred StoredCredential) *StoredCredential {
	w.mu.Lock()
	w.Credentials = append(w.Credentials, cred)
	sink := w.credentialSink
	w.mu.Unlock()
	// A per-request clone (a profile override on an offer) holds its own
	// credential slice, so without forwarding, anything it collects would be
	// thrown away with the clone and the wallet would report an issuance it
	// did not keep.
	if sink != nil {
		sink(cred)
	}
	return &cred
}

// parseCredentialSDJWT decodes an issued or imported SD-JWT to suit the wallet
// mode. Strict refuses a credential that breaks RFC 9901, debug keeps it and
// records each break as a warning.
func (w *Wallet) parseCredentialSDJWT(raw string) (*sdjwt.Token, error) {
	token, err := sdjwt.ParseLenient(raw)
	if err != nil {
		return nil, err
	}
	// draft-ietf-oauth-sd-jwt-vc-18 §2.2.1 replaced the vc+sd-jwt media type
	// with dc+sd-jwt. The transitional value still decodes but is a deviation.
	var vcType []string
	if typ, _ := token.Header["typ"].(string); typ == sdjwt.TypeSDJWTVCLegacy {
		vcType = append(vcType, fmt.Sprintf("the typ header is %s, the transitional media type draft-ietf-oauth-sd-jwt-vc-18 §2.2.1 replaced with %s", sdjwt.TypeSDJWTVCLegacy, sdjwt.TypeSDJWTVC))
	}
	if w.Mode() == ValidationModeStrict {
		if all := append(append([]string{}, token.Deviations...), vcType...); len(all) > 0 {
			return nil, fmt.Errorf("%s", strings.Join(all, "; "))
		}
		return token, nil
	}
	w.recordCredentialDeviations("RFC 9901", token.Deviations)
	w.recordCredentialDeviations("draft-ietf-oauth-sd-jwt-vc-18", vcType)
	return token, nil
}

// recordCredentialDeviations logs a credential's spec deviations as one activity
// log entry, naming the count with the full list in the entry details.
func (w *Wallet) recordCredentialDeviations(spec string, deviations []string) {
	if len(deviations) == 0 {
		return
	}
	finding := "findings"
	if len(deviations) == 1 {
		finding = "finding"
	}
	detail := fmt.Sprintf("The credential deviates from %s (%d %s, see details)", spec, len(deviations), finding)
	w.addProtocolWarning("wallet", "credential_structure_deviation", detail,
		map[string]any{"deviations": deviations})
}

func (w *Wallet) importSDJWT(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	token, err := w.parseCredentialSDJWT(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing SD-JWT: %w", err)
	}

	cred := StoredCredential{
		ID:            newCredentialID(),
		Format:        "dc+sd-jwt",
		Raw:           raw,
		Claims:        token.ResolvedClaims,
		Disclosures:   token.Disclosures,
		BatchGroup:    group,
		BindingKeyPEM: bindingKeyPEM,
	}

	if vct, ok := token.Payload["vct"].(string); ok {
		cred.VCT = vct
	}

	stored := w.appendCredential(cred)
	_ = w.RegisterIssuedAttestation(IssuedAttestationSpec{Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType})
	return stored, nil
}

func (w *Wallet) importPlainJWT(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	_, payload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}

	cred := StoredCredential{
		ID:            newCredentialID(),
		Format:        "jwt_vc_json",
		Raw:           raw,
		Claims:        payload,
		BatchGroup:    group,
		BindingKeyPEM: bindingKeyPEM,
	}

	if vct, ok := payload["vct"].(string); ok && vct != "" {
		cred.VCT = vct
	} else {
		cred.VCT = jwtVCType(payload)
	}

	stored := w.appendCredential(cred)
	_ = w.RegisterIssuedAttestation(IssuedAttestationSpec{Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType})
	return stored, nil
}

// jwtVCType reads the credential type from a W3C JWT VC (jwt_vc_json), so the
// listing shows the type rather than the format. VC Data Model 1.1 carries the
// type array in the vc claim under the JWT encoding, and some issuers flatten it
// to the payload root. The specific type is the last entry that is not the base
// VerifiableCredential type.
func jwtVCType(payload map[string]any) string {
	types := payload["type"]
	if vc, ok := payload["vc"].(map[string]any); ok && vc["type"] != nil {
		types = vc["type"]
	}
	switch v := types.(type) {
	case string:
		if v != "VerifiableCredential" {
			return v
		}
	case []any:
		specific := ""
		for _, t := range v {
			if s, ok := t.(string); ok && s != "" && s != "VerifiableCredential" {
				specific = s
			}
		}
		return specific
	}
	return ""
}

func (w *Wallet) importMDoc(raw, group, bindingKeyPEM string) (*StoredCredential, error) {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing mDoc: %w", err)
	}
	// Strict refuses a credential the parser had to drop parts of, debug keeps it.
	if len(doc.Deviations) > 0 {
		if w.Mode() == ValidationModeStrict {
			return nil, fmt.Errorf("%s", strings.Join(doc.Deviations, "; "))
		}
		w.recordCredentialDeviations("ISO/IEC 18013-5", doc.Deviations)
	}

	claims := make(map[string]any)
	for ns, items := range doc.NameSpaces {
		for _, item := range items {
			claims[ns+":"+item.ElementIdentifier] = item.ElementValue
		}
	}

	cred := StoredCredential{
		ID:            newCredentialID(),
		Format:        "mso_mdoc",
		Raw:           raw,
		Claims:        claims,
		DocType:       doc.DocType,
		NameSpaces:    doc.NameSpaces,
		BatchGroup:    group,
		BindingKeyPEM: bindingKeyPEM,
	}

	stored := w.appendCredential(cred)
	_ = w.RegisterIssuedAttestation(IssuedAttestationSpec{Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType})
	return stored, nil
}

// ImportCredentialFromFile reads a file and imports the credential.
func (w *Wallet) ImportCredentialFromFile(path string) error {
	raw, err := format.ReadInput(path)
	if err != nil {
		return fmt.Errorf("reading credential file: %w", err)
	}
	_, err = w.ImportCredential(raw)
	return err
}

// Rehydrate re-populates non-serializable fields (Disclosures, NameSpaces) from Raw.
func (c *StoredCredential) Rehydrate() error {
	if c.Raw == "" {
		return nil
	}

	switch c.Format {
	case "dc+sd-jwt":
		token, err := sdjwt.ParseLenient(c.Raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		c.Disclosures = token.Disclosures
		if c.Claims == nil {
			c.Claims = token.ResolvedClaims
		}

	case "jwt_vc_json":
		if c.Claims == nil {
			_, payload, _, err := format.ParseJWTParts(c.Raw)
			if err != nil {
				return fmt.Errorf("parsing JWT: %w", err)
			}
			c.Claims = payload
		}

	case "mso_mdoc":
		doc, err := mdoc.Parse(c.Raw)
		if err != nil {
			return fmt.Errorf("parsing mDoc: %w", err)
		}
		c.NameSpaces = doc.NameSpaces
		if c.Claims == nil {
			claims := make(map[string]any)
			for ns, items := range doc.NameSpaces {
				for _, item := range items {
					claims[ns+":"+item.ElementIdentifier] = item.ElementValue
				}
			}
			c.Claims = claims
		}
	}

	return nil
}

// rememberRenewal records what re-requesting a credential from its issuer
// needs. Only an issuer that handed over a refresh token can be asked again,
// so without one nothing is stored and the credential expires.
func (w *Wallet) rememberRenewal(credentialID, refreshToken string, renewal CredentialRenewal) {
	if w == nil || refreshToken == "" || renewal.CredentialEndpoint == "" || renewal.TokenEndpoint == "" {
		return
	}
	renewal.RefreshToken = refreshToken

	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == credentialID {
			w.Credentials[i].Renewal = &renewal
			return
		}
	}
}

// logCredentialImport records an issued credential the same way from every
// issuance path, so the activity log does not depend on which flow produced
// the credential.
func (w *Wallet) logCredentialImport(imported *StoredCredential, raw, issuer string) {
	details := credentialImportLogDetails(imported, raw)
	details["issuer"] = issuer
	w.addProtocolLog("issuance", "credential_imported", fmt.Sprintf("Imported credential %s", imported.ID), true, details)
}
