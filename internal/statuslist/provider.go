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

package statuslist

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// StatusListConfig holds parameters for generating a status list JWT.
type StatusListConfig struct {
	// URI is the status list token URI, used as the "sub" claim (REQUIRED per draft-ietf-oauth-status-list).
	URI string
	// Issuer is the "iss" claim value.
	Issuer string
	// TTL is the time-to-live in seconds for caching (RECOMMENDED per spec). Defaults to 43200 (12h).
	TTL int
	// CertChain, if provided, is included as x5c header for certificate chain validation.
	CertChain []*x509.Certificate
}

// GenerateStatusListJWT creates a signed status list JWT (draft-ietf-oauth-status-list) from a bitstring.
func GenerateStatusListJWT(bitstring []byte, signingKey *ecdsa.PrivateKey, cfg StatusListConfig) (string, error) {
	// zlib-compress the bitstring
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", fmt.Errorf("creating zlib writer: %w", err)
	}
	if _, err := w.Write(bitstring); err != nil {
		return "", fmt.Errorf("compressing bitstring: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("closing zlib writer: %w", err)
	}

	lst := format.EncodeBase64URL(buf.Bytes())

	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 43200 // 12 hours default
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = "https://issuer.example"
	}

	now := time.Now()
	payload := map[string]any{
		"sub": cfg.URI,
		"iss": issuer,
		"iat": now.Unix(),
		"exp": now.Add(24 * time.Hour).Unix(),
		"ttl": ttl,
		"status_list": map[string]any{
			"bits": 1,
			"lst":  lst,
		},
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "statuslist+jwt",
	}

	// The public half of the signing key, so a relying party that resolves
	// keys from the token itself can verify without a certificate path.
	// Token Status List leaves key resolution to the deployment (§11.3) and
	// requires only `typ` in the header (§5.1), and `jwk` is a registered
	// JOSE header (RFC 7515 §4.1.3), so this is additive. It is derived from
	// the signing key rather than passed in, which is what keeps it from
	// ever disagreeing with the x5c leaf below.
	header["jwk"] = mock.PublicKeyJWKMap(&signingKey.PublicKey)

	// The trust anchor must not travel in x5c: a relying party has it out of
	// band, and a chain that carries its own root proves nothing. HAIP 6.1
	// rejects a status list token whose chain includes it, and the rest of
	// this wallet already strips it from every other JWS it signs.
	if chain := mock.WithoutSelfSignedTrustAnchor(cfg.CertChain); len(chain) > 0 {
		x5c := make([]string, 0, len(chain))
		for _, cert := range chain {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		header["x5c"] = x5c
	}

	return jws.Sign(header, payload, signingKey)
}
