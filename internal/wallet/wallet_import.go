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
	"strings"

	"github.com/google/uuid"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
)

// ImportCredential auto-detects and imports a credential string.
// It returns a pointer to a copy of the newly imported credential, safe to
// use even after further mutations to w.Credentials.
func (w *Wallet) ImportCredential(raw string) (*StoredCredential, error) {
	raw = strings.TrimSpace(raw)

	// Try SD-JWT first (contains ~)
	if strings.Contains(raw, "~") {
		cred, err := w.importSDJWT(raw)
		if err != nil {
			return nil, err
		}
		log.Printf("[Wallet] Imported SD-JWT credential: vct=%s claims=%d disclosures=%d", cred.VCT, len(cred.Claims), len(cred.Disclosures))
		return cred, nil
	}

	// Try mDoc (base64url or hex encoded CBOR)
	detected := format.Detect(raw)
	if detected == format.FormatMDOC {
		cred, err := w.importMDoc(raw)
		if err != nil {
			return nil, err
		}
		log.Printf("[Wallet] Imported mDoc credential: docType=%s claims=%d", cred.DocType, len(cred.Claims))
		return cred, nil
	}

	// Try as plain JWT VC (3-part JWT without ~)
	if strings.Count(raw, ".") == 2 {
		cred, err := w.importPlainJWT(raw)
		if err != nil {
			return nil, err
		}
		log.Printf("[Wallet] Imported plain JWT credential: vct=%s claims=%d", cred.VCT, len(cred.Claims))
		return cred, nil
	}

	return nil, fmt.Errorf("unable to detect credential format (expected SD-JWT or mDoc)")
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

func (w *Wallet) importSDJWT(raw string) (*StoredCredential, error) {
	token, err := sdjwt.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing SD-JWT: %w", err)
	}

	cred := StoredCredential{
		ID:          uuid.New().String(),
		Format:      "dc+sd-jwt",
		Raw:         raw,
		Claims:      token.ResolvedClaims,
		Disclosures: token.Disclosures,
	}

	if vct, ok := token.Payload["vct"].(string); ok {
		cred.VCT = vct
	}

	stored := w.appendCredential(cred)
	_ = w.RegisterIssuedAttestation(IssuedAttestationSpec{Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType})
	return stored, nil
}

func (w *Wallet) importPlainJWT(raw string) (*StoredCredential, error) {
	_, payload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}

	cred := StoredCredential{
		ID:     uuid.New().String(),
		Format: "jwt_vc_json",
		Raw:    raw,
		Claims: payload,
	}

	if vct, ok := payload["vct"].(string); ok {
		cred.VCT = vct
	}

	stored := w.appendCredential(cred)
	_ = w.RegisterIssuedAttestation(IssuedAttestationSpec{Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType})
	return stored, nil
}

func (w *Wallet) importMDoc(raw string) (*StoredCredential, error) {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing mDoc: %w", err)
	}

	claims := make(map[string]any)
	for ns, items := range doc.NameSpaces {
		for _, item := range items {
			claims[ns+":"+item.ElementIdentifier] = item.ElementValue
		}
	}

	cred := StoredCredential{
		ID:         uuid.New().String(),
		Format:     "mso_mdoc",
		Raw:        raw,
		Claims:     claims,
		DocType:    doc.DocType,
		NameSpaces: doc.NameSpaces,
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
		token, err := sdjwt.Parse(c.Raw)
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
// so without one nothing is stored and the credential simply expires.
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
