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
	"github.com/dominikschlosser/eudi-dev/v2/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v2/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/v2/internal/validate"
)

// Holder binding states a credential summary reports. A credential is
// presentable only in the this_wallet state: the other two name a key this
// wallet does not have.
const (
	holderBindingThisWallet = "this_wallet"
	holderBindingOtherKey   = "other_key"
	holderBindingNone       = "none"
)

func credentialIssuerIdentity(c StoredCredential) map[string]any {
	if c.Format == "mso_mdoc" {
		if identity := mdocIssuerCertIdentity(c.Raw); identity != nil {
			return identity
		}
	} else if iss := jwtIssuerClaim(c.Raw); iss != "" {
		return map[string]any{"kind": "iss", "value": iss}
	}
	// A DID is the last resort: nothing here resolves it.
	if did := credentialIssuerDID(c.Raw); did != "" {
		return map[string]any{"kind": "did", "value": did}
	}
	return nil
}

func jwtIssuerClaim(raw string) string {
	token, err := sdjwt.ParseLenient(raw)
	if err != nil || token == nil {
		return ""
	}
	iss, _ := token.Payload["iss"].(string)
	return iss
}

// Use the document signer's CommonName for display, falling back to its full subject.
func mdocIssuerCertIdentity(raw string) map[string]any {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return nil
	}
	certs, err := extractMDOCX5Chain(doc)
	if err != nil || len(certs) == 0 {
		return nil
	}
	value := certs[0].Subject.CommonName
	if value == "" {
		value = certs[0].Subject.String()
	}
	if value == "" {
		return nil
	}
	return map[string]any{"kind": "cert", "value": value}
}

// self_consistent means the signature verifies against embedded key material. It does
// not establish issuer trust (ADR-0009). Return nil if the algorithm cannot be
// determined.
func credentialSignatureState(c StoredCredential) map[string]any {
	if c.Format == "mso_mdoc" {
		return mdocSignatureState(c.Raw)
	}
	return jwtSignatureState(c.Raw)
}

// Verify only embedded key material here. Credential summaries must not fetch issuer
// metadata.
func jwtSignatureState(raw string) map[string]any {
	token, err := sdjwt.ParseLenient(raw)
	if err != nil || token == nil {
		return nil
	}
	result, _, err := validate.VerifyJWTSignatureOffline(token, nil, nil)
	if err != nil || result == nil || result.Algorithm == "" {
		return nil
	}
	return map[string]any{
		"algorithm":       result.Algorithm,
		"self_consistent": result.SignatureValid,
	}
}

// mdocSignatureState verifies an mdoc against its document signer leaf. When
// the mdoc carries no x5chain the algorithm is still read from the COSE header,
// so the summary reports what signed it even where self-consistency cannot be
// established.
func mdocSignatureState(raw string) map[string]any {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return nil
	}
	certs, err := extractMDOCX5Chain(doc)
	if err == nil && len(certs) > 0 {
		res := mdoc.Verify(doc, certs[0].PublicKey)
		if res.Algorithm == "" {
			return nil
		}
		return map[string]any{
			"algorithm":       res.Algorithm,
			"self_consistent": res.SignatureValid,
		}
	}
	// Verify sets the algorithm from the protected header before it needs the
	// key, so a nil key still yields the algorithm with self_consistent false.
	res := mdoc.Verify(doc, nil)
	if res.Algorithm == "" {
		return nil
	}
	return map[string]any{
		"algorithm":       res.Algorithm,
		"self_consistent": false,
	}
}

// credentialHolderBindingState reports which key a credential is bound to,
// relative to this wallet's holder key. Only this_wallet is presentable: the
// other two name a key the wallet cannot sign with.
func (w *Wallet) credentialHolderBindingState(c StoredCredential) string {
	binding := credentialHolderBinding(c.Raw)
	if !binding.Bound {
		return holderBindingNone
	}
	// A batch copy is bound to its own key, which the wallet holds alongside the
	// holder key, so the copy's key is what its binding is checked against.
	signingKey, err := w.batchSigningKey(c)
	if err != nil || signingKey == nil {
		return holderBindingOtherKey
	}
	if binding.heldBy(&signingKey.PublicKey) {
		return holderBindingThisWallet
	}
	return holderBindingOtherKey
}
