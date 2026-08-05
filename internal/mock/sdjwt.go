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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jws"
)

// SDJWTConfig holds options for generating a mock SD-JWT credential.
type SDJWTConfig struct {
	Issuer        string
	VCT           string
	ExpiresIn     time.Duration
	NotBefore     *time.Time // optional: sets nbf claim
	Claims        map[string]any
	Key           *ecdsa.PrivateKey
	HolderKey     *ecdsa.PublicKey    // optional: adds cnf claim for holder binding
	StatusListURI string              // optional: status list URI for revocation
	StatusListIdx int                 // optional: index in the status list
	CertChain     []*x509.Certificate // optional: x5c certificate chain [leaf, CA]
	// AlwaysDisclosed lists claims that are embedded plainly instead of
	// becoming selective disclosures. Entries name top-level claims
	// ("family_name") or nested subclaims via dotted paths
	// ("address.country"). A top-level entry embeds the whole claim value
	// plainly. A dotted entry embeds that subclaim plainly inside its
	// parent's disclosure value. Entries that match no claim are ignored.
	AlwaysDisclosed []string
}

// GenerateSDJWT creates a mock SD-JWT credential. By default all claims are
// selectively disclosable. Claims listed in AlwaysDisclosed go plainly into
// the payload instead.
// Map values produce nested disclosures (subclaims with their own _sd array).
// Slice values produce array element disclosures ({"...": digest} entries).
func GenerateSDJWT(cfg SDJWTConfig) (string, error) {
	if cfg.Key == nil {
		return "", fmt.Errorf("signing key is required")
	}

	now := time.Now()

	always := make(map[string]bool, len(cfg.AlwaysDisclosed))
	for _, path := range cfg.AlwaysDisclosed {
		if p := strings.TrimSpace(path); p != "" {
			always[p] = true
		}
	}

	// Generate disclosures and compute digests
	var disclosures []string
	var digests []string
	plain := make(map[string]any)

	for name, value := range cfg.Claims {
		if always[name] {
			plain[name] = value
			continue
		}

		claimDisclosures, claimValue, err := makeDisclosure(name, value, name, always)
		if err != nil {
			return "", err
		}
		disclosures = append(disclosures, claimDisclosures...)

		// The top-level disclosure for this claim
		topDisc, topDigest, err := createDisclosure(name, claimValue)
		if err != nil {
			return "", err
		}
		disclosures = append(disclosures, topDisc)
		digests = append(digests, topDigest)
	}

	// Build payload
	payload := map[string]any{
		"iss":     cfg.Issuer,
		"iat":     now.Unix(),
		"exp":     now.Add(cfg.ExpiresIn).Unix(),
		"vct":     cfg.VCT,
		"_sd_alg": "sha-256",
		"_sd":     digests,
	}
	for name, value := range plain {
		payload[name] = value
	}

	if cfg.NotBefore != nil {
		payload["nbf"] = cfg.NotBefore.Unix()
	}

	// Add holder binding (cnf claim with JWK)
	if cfg.HolderKey != nil {
		payload["cnf"] = map[string]any{
			"jwk": PublicKeyJWKMap(cfg.HolderKey),
		}
	}

	// Add status list reference (non-disclosed)
	if cfg.StatusListURI != "" {
		payload["status"] = map[string]any{
			"status_list": map[string]any{
				"uri": cfg.StatusListURI,
				"idx": cfg.StatusListIdx,
			},
		}
	}

	// Build header
	header := map[string]any{
		"alg": "ES256",
		"typ": "dc+sd-jwt",
		"kid": KeyIDForPublicKey(&cfg.Key.PublicKey),
	}

	if len(cfg.CertChain) > 0 {
		var x5c []string
		for _, cert := range WithoutSelfSignedTrustAnchor(cfg.CertChain) {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		if len(x5c) > 0 {
			header["x5c"] = x5c
		}
	}

	// Encode header and payload
	jwt, err := jws.Sign(header, payload, cfg.Key)
	if err != nil {
		return "", err
	}

	// Assemble: header.payload.sig~disc1~disc2~
	return jwt + "~" + strings.Join(disclosures, "~") + "~", nil
}

// makeDisclosure handles nested structures. It returns any sub-disclosures and
// the (possibly transformed) value to use in the parent disclosure.
// For plain values, it returns no sub-disclosures and the value as-is.
// For map values, it creates sub-disclosures and returns an object with _sd.
// For slice values, it creates element disclosures and returns an array with {"...": digest}.
// path is the dotted path of the claim. Subclaims whose path is in always are
// embedded plainly in the transformed value instead of becoming disclosures.
func makeDisclosure(name string, value any, path string, always map[string]bool) (subDisclosures []string, transformedValue any, err error) {
	switch v := value.(type) {
	case map[string]any:
		// Nested object: create disclosures for each subclaim
		var subDigests []string
		obj := make(map[string]any)
		for subName, subValue := range v {
			subPath := path + "." + subName
			if always[subPath] {
				obj[subName] = subValue
				continue
			}
			subSub, transformed, err := makeDisclosure(subName, subValue, subPath, always)
			if err != nil {
				return nil, nil, err
			}
			subDisclosures = append(subDisclosures, subSub...)
			disc, digest, err := createDisclosure(subName, transformed)
			if err != nil {
				return nil, nil, err
			}
			subDisclosures = append(subDisclosures, disc)
			subDigests = append(subDigests, digest)
		}
		if len(subDigests) > 0 {
			obj["_sd"] = subDigests
		}
		return subDisclosures, obj, nil

	case []any:
		// Array: create element disclosures for each item
		var elements []any
		for _, item := range v {
			disc, digest, err := createArrayElementDisclosure(item)
			if err != nil {
				return nil, nil, err
			}
			subDisclosures = append(subDisclosures, disc)
			elements = append(elements, map[string]any{"...": digest})
		}
		transformedValue = elements
		return subDisclosures, transformedValue, nil

	default:
		// Plain value: no sub-disclosures needed
		return nil, value, nil
	}
}

// createDisclosure creates a named disclosure [salt, name, value] and returns
// the encoded disclosure string and its digest.
func createDisclosure(name string, value any) (encoded string, digest string, err error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("generating salt: %w", err)
	}

	disclosure := []any{format.EncodeBase64URL(salt), name, value}
	discJSON, err := json.Marshal(disclosure)
	if err != nil {
		return "", "", fmt.Errorf("marshaling disclosure: %w", err)
	}

	enc := format.EncodeBase64URL(discJSON)
	h := sha256.Sum256([]byte(enc))
	return enc, format.EncodeBase64URL(h[:]), nil
}

// createArrayElementDisclosure creates an array element disclosure [salt, value]
// and returns the encoded disclosure string and its digest.
func createArrayElementDisclosure(value any) (encoded string, digest string, err error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("generating salt: %w", err)
	}

	disclosure := []any{format.EncodeBase64URL(salt), value}
	discJSON, err := json.Marshal(disclosure)
	if err != nil {
		return "", "", fmt.Errorf("marshaling disclosure: %w", err)
	}

	enc := format.EncodeBase64URL(discJSON)
	h := sha256.Sum256([]byte(enc))
	return enc, format.EncodeBase64URL(h[:]), nil
}
