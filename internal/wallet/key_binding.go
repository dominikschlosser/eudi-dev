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
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// holderBinding is the key a credential's issuer bound it to: the one that
// signs the KB-JWT of an SD-JWT (RFC 9901 §4.3) and the DeviceSigned of an
// mdoc (ISO 18013-5 §9.1.3). Bound without a Key is a credential naming a key
// of a kind this wallet never holds (a cnf carrying only a kid, a JWK on
// another curve).
type holderBinding struct {
	Bound bool
	Key   *ecdsa.PublicKey
}

// heldBy reports whether the binding names the given key.
func (b holderBinding) heldBy(pub *ecdsa.PublicKey) bool {
	return b.Key != nil && pub != nil && b.Key.Equal(pub)
}

// credentialHolderBinding reads the holder binding out of a credential in any
// format the store keeps.
func credentialHolderBinding(raw string) holderBinding {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "~") || strings.Count(raw, ".") == 2 {
		return sdJWTHolderBinding(raw)
	}
	if format.Detect(raw) == format.FormatMDOC {
		return mdocHolderBinding(raw)
	}
	return holderBinding{}
}

// credentialBindsToKey reports whether the credential's holder binding key
// equals the given public key.
func credentialBindsToKey(raw string, pub *ecdsa.PublicKey) bool {
	return credentialHolderBinding(raw).heldBy(pub)
}

func sdJWTHolderBinding(raw string) holderBinding {
	jwtPart := raw
	if idx := strings.Index(raw, "~"); idx >= 0 {
		jwtPart = raw[:idx]
	}
	parts := strings.Split(jwtPart, ".")
	if len(parts) != 3 {
		return holderBinding{}
	}
	payloadJSON, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return holderBinding{}
	}
	var payload struct {
		Cnf *struct {
			JWK *confirmationJWK `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil || payload.Cnf == nil {
		return holderBinding{}
	}
	if payload.Cnf.JWK == nil {
		return holderBinding{Bound: true}
	}
	return holderBinding{Bound: true, Key: payload.Cnf.JWK.publicKey()}
}

func mdocHolderBinding(raw string) holderBinding {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return holderBinding{}
	}
	key, err := mdoc.DeviceKey(doc)
	if err != nil {
		return holderBinding{Bound: mdocNamesDeviceKey(doc)}
	}
	return holderBinding{Bound: true, Key: key}
}

// mdocNamesDeviceKey reports whether the MSO names a device key at all, which
// separates an mdoc issued without holder binding from one whose device key
// this build cannot read.
func mdocNamesDeviceKey(doc *mdoc.Document) bool {
	if doc == nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return false
	}
	_, ok := doc.IssuerAuth.MSO.DeviceKeyInfo["deviceKey"]
	return ok
}

// confirmationJWK is the cnf.jwk member of a credential payload.
type confirmationJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// publicKey returns the key the JWK describes, or nil for one this wallet
// could never hold (the holder key is on P-256).
func (j confirmationJWK) publicKey() *ecdsa.PublicKey {
	if j.Kty != "EC" || j.Crv != "P-256" || j.X == "" || j.Y == "" {
		return nil
	}
	x, err := format.DecodeBase64URL(j.X)
	if err != nil {
		return nil
	}
	y, err := format.DecodeBase64URL(j.Y)
	if err != nil {
		return nil
	}
	pub, err := format.ECPublicKeyFromCoords(elliptic.P256(), x, y)
	if err != nil {
		return nil
	}
	return pub
}

// keyBindingNotHeld reports a credential the wallet keeps but cannot present:
// its issuer bound it to a holder key this wallet does not have.
func (w *Wallet) keyBindingNotHeld(cred *StoredCredential) bool {
	if cred == nil {
		return false
	}
	// A batch copy is bound to its own key, which the wallet holds alongside
	// the holder key, so the copy's key is what its binding is checked against.
	signingKey, err := w.batchSigningKey(*cred)
	if err != nil || signingKey == nil {
		return false
	}
	binding := credentialHolderBinding(cred.Raw)
	return binding.Bound && !binding.heldBy(&signingKey.PublicKey)
}

// noteUnheldKeyBinding records in the activity log that a credential entering
// the store is bound to a key the wallet does not hold. The log is the one
// place every arrival path (import, issuance, renewal) is read through.
func (w *Wallet) noteUnheldKeyBinding(cred *StoredCredential) {
	if !w.keyBindingNotHeld(cred) {
		return
	}
	details := map[string]any{
		"credential_id": cred.ID,
		"format":        cred.Format,
		"wallet_key":    mock.KeyIDForPublicKey(&w.HolderKeyPair().PublicKey),
	}
	addStringDetail(details, "vct", cred.VCT)
	addStringDetail(details, "doctype", cred.DocType)
	if binding := credentialHolderBinding(cred.Raw); binding.Key != nil {
		details["binding_key"] = mock.KeyIDForPublicKey(binding.Key)
	}
	detail := fmt.Sprintf(
		"Credential %s is bound to a holder key this wallet does not hold. It can be shown and decoded, but a presentation of it would carry a key binding signature from the wrong key, which a verifier rejects.",
		credentialLabel(*cred))
	w.addProtocolWarning("wallet", "credential_key_binding_not_held", detail, details)
	log.Printf("[Wallet] WARNING: %s", detail)
}
