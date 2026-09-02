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

package mock

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

// SplitClaimsByNamespace groups claims by namespace. A key of the form
// "namespace:element" goes into that namespace, everything else into
// defaultNamespace. The German PID needs this: its national additions live in
// eu.europa.ec.eudi.pid.de.1 while the rest stays in eu.europa.ec.eudi.pid.1.
func SplitClaimsByNamespace(claims map[string]any, defaultNamespace string) map[string]map[string]any {
	out := make(map[string]map[string]any)
	for key, value := range claims {
		ns, name := defaultNamespace, key
		if i := strings.Index(key, ":"); i > 0 {
			ns, name = key[:i], key[i+1:]
		}
		if out[ns] == nil {
			out[ns] = make(map[string]any)
		}
		out[ns][name] = value
	}
	if len(out) == 0 {
		out[defaultNamespace] = map[string]any{}
	}
	return out
}

// fullDatePattern matches an ISO 8601 calendar date with no time component.
var fullDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// cborDateValue wraps date-shaped strings in the CBOR tags ISO 18013-5 uses
// for them: full-date (tag 1004) for YYYY-MM-DD and tdate (tag 0) for a
// timestamp. Real PIDs encode birth_date and expiry_date this way, and a
// verifier that type-checks the element sees a plain text string otherwise.
func cborDateValue(v any) any {
	switch val := v.(type) {
	case string:
		if fullDatePattern.MatchString(val) {
			return cbor.Tag{Number: 1004, Content: val}
		}
		if _, err := time.Parse(time.RFC3339, val); err == nil {
			return cbor.Tag{Number: 0, Content: val}
		}
		return val
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			out[k] = cborDateValue(item)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = cborDateValue(item)
		}
		return out
	default:
		return v
	}
}

// MDOCConfig holds options for generating a mock mDOC credential.
type MDOCConfig struct {
	DocType   string
	Namespace string
	Claims    map[string]any
	// NamespaceClaims optionally maps namespaces to their claims. When set,
	// Namespace and Claims are ignored and each namespace is emitted
	// separately in the MSO and IssuerSigned structures.
	NamespaceClaims map[string]map[string]any
	Key             *ecdsa.PrivateKey
	HolderKey       *ecdsa.PublicKey    // optional: adds deviceKeyInfo to MSO
	ExpiresIn       time.Duration       // validity duration; defaults to 30 days if zero
	ValidFrom       *time.Time          // optional: override validFrom (defaults to now)
	StatusListURI   string              // optional: status list URI for revocation
	StatusListIdx   int                 // optional: index in the status list
	CertChain       []*x509.Certificate // optional: x5chain certificate chain [leaf, CA]
	// KeepTrustAnchor embeds the chain as given, keeping a terminal
	// self-signed root that is otherwise stripped from x5chain.
	KeepTrustAnchor bool
	// OmitValidityInfo drops the MSO validityInfo, which ISO 18013-5 requires,
	// for testing how a verifier handles an mdoc that states no validity period.
	OmitValidityInfo bool
	// OmitDigestAlgorithm drops the MSO digestAlgorithm, which ISO 18013-5
	// requires, for testing how a verifier handles its absence. The digests are
	// still computed with SHA-256.
	OmitDigestAlgorithm bool
}

// GenerateMDOC creates a mock mDOC (IssuerSigned) credential.
func GenerateMDOC(cfg MDOCConfig) (string, error) {
	now := time.Now().UTC().Truncate(time.Second)
	expiresIn := cfg.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 30 * 24 * time.Hour
	}
	validFrom := now
	if cfg.ValidFrom != nil {
		validFrom = cfg.ValidFrom.UTC().Truncate(time.Second)
	}
	validUntil := now.Add(expiresIn)

	namespaceClaims := cfg.NamespaceClaims
	if namespaceClaims == nil {
		namespaceClaims = SplitClaimsByNamespace(cfg.Claims, cfg.Namespace)
	}

	// Build IssuerSignedItems and compute value digests per namespace.
	// Digest IDs stay unique across all namespaces.
	tag24ItemsByNS := make(map[string]any, len(namespaceClaims))
	valueDigestsByNS := make(map[string]any, len(namespaceClaims))

	var digestID uint64
	for ns, claims := range namespaceClaims {
		var tag24Items []cbor.RawMessage
		valueDigests := make(map[uint64][]byte)
		for name, value := range claims {
			random := make([]byte, 16)
			if _, err := rand.Read(random); err != nil {
				return "", fmt.Errorf("generating random: %w", err)
			}

			item := map[string]any{
				"digestID":          digestID,
				"random":            random,
				"elementIdentifier": name,
				"elementValue":      cborDateValue(value),
			}

			itemBytes, err := cbor.Marshal(item)
			if err != nil {
				return "", fmt.Errorf("encoding IssuerSignedItem: %w", err)
			}

			// Wrap in Tag 24 (embedded CBOR)
			tag24 := cbor.Tag{
				Number:  24,
				Content: itemBytes,
			}
			tag24Bytes, err := cbor.Marshal(tag24)
			if err != nil {
				return "", fmt.Errorf("encoding Tag-24: %w", err)
			}

			tag24Items = append(tag24Items, tag24Bytes)

			digest := sha256.Sum256(tag24Bytes)
			valueDigests[digestID] = digest[:]
			digestID++
		}
		tag24ItemsByNS[ns] = tag24Items
		valueDigestsByNS[ns] = valueDigests
	}

	// Build MSO (Mobile Security Object)
	mso := map[string]any{
		"version":      "1.0",
		"docType":      cfg.DocType,
		"valueDigests": valueDigestsByNS,
	}
	if !cfg.OmitDigestAlgorithm {
		mso["digestAlgorithm"] = "SHA-256"
	}
	if !cfg.OmitValidityInfo {
		mso["validityInfo"] = map[string]any{
			"signed":     cbor.Tag{Number: 0, Content: now.Format(time.RFC3339)},
			"validFrom":  cbor.Tag{Number: 0, Content: validFrom.Format(time.RFC3339)},
			"validUntil": cbor.Tag{Number: 0, Content: validUntil.Format(time.RFC3339)},
		}
	}

	if cfg.StatusListURI != "" {
		mso["status"] = map[string]any{
			"status_list": map[string]any{
				"uri": cfg.StatusListURI,
				"idx": cfg.StatusListIdx,
			},
		}
	}

	if cfg.HolderKey != nil {
		xBytes, yBytes, err := format.ECPublicCoords(cfg.HolderKey)
		if err != nil {
			return "", fmt.Errorf("encoding holder key: %w", err)
		}

		// COSE_Key: kty=2 (EC2), crv=1 (P-256), x, y
		// Using COSE key labels: 1=kty, -1=crv, -2=x, -3=y
		coseKey := map[any]any{
			int64(1):  int64(2), // kty: EC2
			int64(-1): int64(1), // crv: P-256
			int64(-2): xBytes,   // x coordinate
			int64(-3): yBytes,   // y coordinate
		}

		mso["deviceKeyInfo"] = map[string]any{
			"deviceKey": coseKey,
		}
	}

	msoBytes, err := cbor.Marshal(mso)
	if err != nil {
		return "", fmt.Errorf("encoding MSO: %w", err)
	}

	taggedMSOBytes, err := cbor.Marshal(cbor.Tag{Number: 24, Content: msoBytes})
	if err != nil {
		return "", fmt.Errorf("encoding Tag-24 MSO: %w", err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, cfg.Key)
	if err != nil {
		return "", fmt.Errorf("creating COSE signer: %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Payload = taggedMSOBytes

	// x5chain (label 33) carries the leaf and any intermediates, never the
	// root. A reader gets the trust anchor from its trust list, and a chain
	// that carries its own root proves nothing to anyone who does not already
	// have it. KeepTrustAnchor embeds a provided chain as given anyway.
	chain := cfg.CertChain
	if !cfg.KeepTrustAnchor {
		chain = WithoutSelfSignedTrustAnchor(chain)
	}
	if len(chain) > 0 {
		if len(chain) == 1 {
			msg.Headers.Unprotected[int64(33)] = chain[0].Raw
		} else {
			certDERs := make([][]byte, 0, len(chain))
			for _, cert := range chain {
				certDERs = append(certDERs, cert.Raw)
			}
			msg.Headers.Unprotected[int64(33)] = certDERs
		}
	}

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return "", fmt.Errorf("COSE signing: %w", err)
	}

	issuerAuthBytes, err := msg.MarshalCBOR()
	if err != nil {
		return "", fmt.Errorf("encoding COSE_Sign1: %w", err)
	}
	issuerAuthBytes, err = format.StripCBORTag(issuerAuthBytes, 18)
	if err != nil {
		return "", fmt.Errorf("normalizing COSE_Sign1 tag: %w", err)
	}

	issuerSigned := map[string]any{
		"nameSpaces": tag24ItemsByNS,
		"issuerAuth": cbor.RawMessage(issuerAuthBytes),
	}

	issuerSignedBytes, err := cbor.Marshal(issuerSigned)
	if err != nil {
		return "", fmt.Errorf("encoding IssuerSigned: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(issuerSignedBytes), nil
}
