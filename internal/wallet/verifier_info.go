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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/validate"
)

// registrationCertificateTyp is the typ of an EUDI wallet-relying-party
// registration certificate (ETSI TS 119 475), the attestation this wallet
// reads a verifier's registered purpose from. It travels in a verifier_info
// entry whose format is "registration_cert" (ETSI TS 119 472-2), but the typ
// is what identifies the JWT, so entries are selected by it alone.
const registrationCertificateTyp = "rc-wrp+jwt"

// verifierInfoPurposes reads the purposes a verifier registered out of the
// registration certificates in a request's verifier_info (OpenID4VP 1.0
// §5.1: attestations that "support authorization decisions, inform Wallet
// policy enforcement, or enrich the End-User consent dialog"). The purpose of
// the data request is what the consent dialog needs.
//
// A certificate is recognized by its rc-wrp+jwt typ. Its sub is the
// registered legal entity identifier, not the request's client_id, so the
// only check made here is the certificate's signature against its own x5c
// leaf: a failure leaves a finding and hides the purpose. The chain is
// deliberately not anchored to a trust list, like every other x5c this
// wallet checks (see SECURITY.md). Entries of other formats and JWTs of
// other types are not this wallet's to read and are passed over.
func verifierInfoPurposes(payload map[string]any) (purposes []string, findings []string) {
	for _, entry := range verifierInfoEntries(payload) {
		data, _ := entry["data"].(string)
		if strings.Count(data, ".") != 2 {
			continue
		}
		header, claims, err := decodeCompactJWT(data)
		if err != nil {
			continue
		}
		if typ, _ := header["typ"].(string); typ != registrationCertificateTyp {
			continue
		}
		if key, err := validate.ExtractX5CLeafKey(header); err == nil && key != nil {
			if _, err := jws.Verify(data, key); err != nil {
				findings = append(findings, fmt.Sprintf("the registration certificate signature does not verify with its x5c leaf, so its purpose is not shown: %v", err))
				continue
			}
		}
		for _, purpose := range purposeStrings(claims["purpose"]) {
			if !containsPurpose(purposes, purpose) {
				purposes = append(purposes, purpose)
			}
		}
	}
	return purposes, findings
}

// consentPurposes reads the verifier's registered purposes for the consent
// dialog and logs the certificates that could not be used. A request sent as
// plain parameters has no payload document, so its verifier_info survives
// only as the raw parameter. A signed request's outer parameters stay
// ignored (OID4VP 1.0 §5.10.1).
func (w *Wallet) consentPurposes(scope string, authReq *AuthorizationRequestParams) []string {
	if authReq == nil {
		return nil
	}
	payload := authReq.RequestPayload
	if payload == nil && authReq.RequestObject == nil && strings.TrimSpace(authReq.VerifierInfo) != "" {
		payload = map[string]any{"verifier_info": authReq.VerifierInfo}
	}
	purposes, findings := verifierInfoPurposes(payload)
	for _, finding := range findings {
		w.AddWarning(scope, finding, nil)
	}
	return purposes
}

// SignRegistrationCertificateJWT signs a relying-party registration
// certificate (typ rc-wrp+jwt) with the given key, carrying the signer's leaf
// certificate in x5c. The demo verifier and issuer present one so the wallet
// they run beside has a purpose to show.
func SignRegistrationCertificateJWT(claims map[string]any, signingKey *ecdsa.PrivateKey, signerCerts []*x509.Certificate) (string, error) {
	header := map[string]any{
		"alg": "ES256",
		"typ": registrationCertificateTyp,
	}
	if x5c := buildJWSX5C(signerCerts); len(x5c) > 0 {
		header["x5c"] = x5c
	}
	return signJSONWebSignature(claims, signingKey, header)
}

// verifierInfoEntries reads the verifier_info array out of a request payload.
// Over plain request parameters the array arrives JSON-encoded in a string.
func verifierInfoEntries(payload map[string]any) []map[string]any {
	if payload == nil {
		return nil
	}
	raw := payload["verifier_info"]
	if encoded, ok := raw.(string); ok && encoded != "" {
		var decoded any
		if err := json.Unmarshal([]byte(encoded), &decoded); err == nil {
			raw = decoded
		}
	}
	list, _ := raw.([]any)
	entries := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if entry, ok := item.(map[string]any); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

// purposeStrings renders a purpose claim: one or more localized entries
// ({lang, value} in the certificate profile, {lang, content} in the TS5 data
// model it is gathered from), where English is preferred and the first entry
// stands in without it. A plain string is taken as it is.
func purposeStrings(raw any) []string {
	switch value := raw.(type) {
	case string:
		if v := strings.TrimSpace(value); v != "" {
			return []string{v}
		}
	case []any:
		var plain []string
		var first, english string
		for _, item := range value {
			switch entry := item.(type) {
			case string:
				if v := strings.TrimSpace(entry); v != "" {
					plain = append(plain, v)
				}
			case map[string]any:
				text, _ := entry["value"].(string)
				if text == "" {
					text, _ = entry["content"].(string)
				}
				text = strings.TrimSpace(text)
				if text == "" {
					continue
				}
				if first == "" {
					first = text
				}
				if lang, _ := entry["lang"].(string); strings.HasPrefix(strings.ToLower(lang), "en") && english == "" {
					english = text
				}
			}
		}
		if english != "" {
			return append(plain, english)
		}
		if first != "" {
			return append(plain, first)
		}
		return plain
	}
	return nil
}

func containsPurpose(purposes []string, purpose string) bool {
	for _, p := range purposes {
		if p == purpose {
			return true
		}
	}
	return false
}

// decodeCompactJWT decodes the header and payload of a compact JWT without
// verifying it. Verification, where possible, is the caller's step.
func decodeCompactJWT(compact string) (header, payload map[string]any, err error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("not a compact JWT")
	}
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("parsing JWT payload: %w", err)
	}
	return header, payload, nil
}
