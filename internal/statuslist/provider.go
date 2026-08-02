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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
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

	if len(cfg.CertChain) > 0 {
		var x5c []string
		for _, cert := range cfg.CertChain {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		header["x5c"] = x5c
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling payload: %w", err)
	}

	headerB64 := format.EncodeBase64URL(headerJSON)
	payloadB64 := format.EncodeBase64URL(payloadJSON)

	sigInput := headerB64 + "." + payloadB64
	h := sha256.Sum256([]byte(sigInput))

	r, s, err := ecdsa.Sign(rand.Reader, signingKey, h[:])
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}

	keySize := (signingKey.Curve.Params().BitSize + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	sigB64 := format.EncodeBase64URL(sig)

	return headerB64 + "." + payloadB64 + "." + sigB64, nil
}
