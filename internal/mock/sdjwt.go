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
	"sort"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jws"
)

// SDJWTConfig holds options for generating a mock SD-JWT credential.
type SDJWTConfig struct {
	Issuer    string
	VCT       string
	ExpiresIn time.Duration
	// IssuedAt overrides the issuance instant iat carries and exp counts
	// from. An issuer that hands out several copies of one credential rounds
	// it, so the copies do not share the precise issuance second (RFC 9901
	// §10.1). Nil issues at now.
	IssuedAt      *time.Time
	NotBefore     *time.Time // optional: sets nbf claim
	Claims        map[string]any
	Key           *ecdsa.PrivateKey
	HolderKey     *ecdsa.PublicKey    // optional: adds cnf claim for holder binding
	StatusListURI string              // optional: status list URI for revocation
	StatusListIdx int                 // optional: index in the status list
	CertChain     []*x509.Certificate // optional: x5c certificate chain [leaf, CA]
	// KeepTrustAnchor embeds the chain as given, keeping a terminal
	// self-signed root that is otherwise stripped from x5c.
	KeepTrustAnchor bool
	// AlwaysDisclosed lists claims embedded plainly instead of becoming
	// selective disclosures, as top-level names ("family_name") or dotted
	// paths ("address.country"). Entries matching no claim are ignored.
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
	if cfg.IssuedAt != nil {
		now = *cfg.IssuedAt
	}

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
		if err := checkClaimName(name); err != nil {
			return "", err
		}
		if always[name] || forcePlainClaims[name] {
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
	}
	// RFC 9901 §4.2.4.1 allows an empty _sd array but recommends omitting the
	// key, and SD-JWT VC §2.2.2.5 requires it: "An SD-JWT VC MAY have no
	// selectively disclosable claims. In that case, the SD-JWT VC MUST NOT
	// contain the _sd claim in the JWT body."
	if len(digests) > 0 {
		payload["_sd"] = hideDigestOrder(digests)
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

	// Build header. SD-JWT VC §2.2.1: "The Issuer MUST include the typ header
	// parameter in the SD-JWT. The typ value MUST use dc+sd-jwt."
	header := map[string]any{
		"alg": "ES256",
		"typ": "dc+sd-jwt",
		"kid": KeyIDForPublicKey(&cfg.Key.PublicKey),
	}

	if len(cfg.CertChain) > 0 {
		chain := cfg.CertChain
		if !cfg.KeepTrustAnchor {
			chain = WithoutSelfSignedTrustAnchor(chain)
		}
		var x5c []string
		for _, cert := range chain {
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

	// RFC 9901 §4 orders the parts JWT, tilde, disclosures each followed by a
	// tilde, then the optional KB-JWT. Its ABNF permits no empty component, so
	// a credential with no disclosures is jwt~ and not jwt~~.
	var serialized strings.Builder
	serialized.WriteString(jwt)
	serialized.WriteString("~")
	for _, d := range disclosures {
		serialized.WriteString(d)
		serialized.WriteString("~")
	}
	return serialized.String(), nil
}

// forcePlainClaims are the claim names embedded plainly even when the caller
// asks for everything to be selectively disclosable. SD-JWT VC §2.2.2.3 lists
// most of them (iss, nbf, exp, cnf, vct, vct#integrity, aka_vcts, status). iat
// joins them because this generator writes one itself, and a disclosure for a
// name already present alongside _sd is rejectable under RFC 9901 §7.1.
var forcePlainClaims = map[string]bool{
	"iss":           true,
	"nbf":           true,
	"exp":           true,
	"cnf":           true,
	"vct":           true,
	"vct#integrity": true,
	"aka_vcts":      true,
	"status":        true,
	"iat":           true,
}

// checkClaimName refuses the keys RFC 9901 reserves for the selective
// disclosure machinery: a disclosure name "MUST NOT be _sd, ..., or a claim
// name existing in the object as a permanently disclosed claim" (§4.2.1), and
// §4.1.1 reserves _sd_alg for the top level of the payload.
func checkClaimName(name string) error {
	switch name {
	case "_sd", "_sd_alg", "...":
		return fmt.Errorf("claim name %q is reserved by RFC 9901 and cannot be used as a credential claim", name)
	}
	return nil
}

// hideDigestOrder returns the digests in an order independent of the claim
// order. RFC 9901 §4.2.4.1: "The Issuer MUST hide the original order of the
// claims in the array [...] e.g., by sorting it alphanumerically or randomly".
func hideDigestOrder(digests []string) []string {
	sorted := make([]string, len(digests))
	copy(sorted, digests)
	sort.Strings(sorted)
	return sorted
}

// makeDisclosure handles nested structures, returning any sub-disclosures and
// the value to use in the parent disclosure: the value as-is for plain values,
// an object with _sd for maps, an array of {"...": digest} for slices.
// Subclaims whose dotted path is in always are embedded plainly.
func makeDisclosure(name string, value any, path string, always map[string]bool) (subDisclosures []string, transformedValue any, err error) {
	switch v := value.(type) {
	case map[string]any:
		// Nested object: create disclosures for each subclaim
		var subDigests []string
		obj := make(map[string]any)
		for subName, subValue := range v {
			if err := checkClaimName(subName); err != nil {
				return nil, nil, err
			}
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
			obj["_sd"] = hideDigestOrder(subDigests)
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
