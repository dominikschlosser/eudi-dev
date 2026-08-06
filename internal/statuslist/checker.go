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
	"compress/flate"
	"compress/zlib"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jws"
)

// ExtractStatusRef extracts the status list reference from SD-JWT claims or mDOC MSO status.
func ExtractStatusRef(claims map[string]any) *StatusRef {
	status, ok := claims["status"].(map[string]any)
	if !ok {
		return nil
	}
	sl, ok := status["status_list"].(map[string]any)
	if !ok {
		return nil
	}

	ref := &StatusRef{}
	if uri, ok := sl["uri"].(string); ok {
		ref.URI = uri
	}
	switch v := sl["idx"].(type) {
	case float64:
		ref.Idx = int(v)
	case int64:
		ref.Idx = int(v)
	case int:
		ref.Idx = v
	}

	if ref.URI == "" {
		return nil
	}
	return ref
}

// Check fetches the status list and checks the credential's status.
func Check(ref *StatusRef) (*StatusResult, error) {
	return CheckWithOptions(ref, CheckOptions{})
}

// CheckWithOptions fetches the status list and checks the credential's status.
// When TrustListCerts are provided, it also validates the status list JWT's x5c
// certificate chain against the trust list and verifies the signature.
func CheckWithOptions(ref *StatusRef, opts CheckOptions) (*StatusResult, error) {
	result := &StatusResult{
		URI:   ref.URI,
		Index: ref.Idx,
	}

	// Fetch status list JWT
	req, err := http.NewRequest("GET", ref.URI, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/statuslist+jwt")

	resp, err := format.HTTPClientForURL(ref.URI).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching status list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status list returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	jwtStr := strings.TrimSpace(string(body))
	parts := strings.SplitN(jwtStr, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid status list JWT format")
	}

	// Parse header
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding status list header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing status list header: %w", err)
	}

	// Validate x5c chain and verify signature if trust list certs provided
	if len(opts.TrustListCerts) > 0 {
		sigValid, info := verifyStatusListSignature(header, parts, opts.TrustListCerts)
		result.SignatureValid = &sigValid
		result.SignatureInfo = info
	}

	// Parse payload
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding status list payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("parsing status list payload: %w", err)
	}

	sl, ok := payload["status_list"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no status_list in JWT payload")
	}

	bits := 1
	if b, ok := sl["bits"].(float64); ok {
		bits = int(b)
	}
	result.BitsPerEntry = bits

	lst, ok := sl["lst"].(string)
	if !ok {
		return nil, fmt.Errorf("no lst in status_list")
	}

	// Decode and decompress the bitstring
	compressed, err := format.DecodeBase64URL(lst)
	if err != nil {
		return nil, fmt.Errorf("decoding lst: %w", err)
	}

	decompressed, err := zlibDecompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompressing status list: %w", err)
	}

	// Extract status value
	status, err := extractStatus(decompressed, ref.Idx, bits)
	if err != nil {
		return nil, err
	}

	result.Status = status
	result.IsValid = status == 0

	return result, nil
}

// verifyStatusListSignature validates the x5c chain against trust list certs and
// verifies the JWT signature using the leaf certificate's public key.
func verifyStatusListSignature(header map[string]any, parts []string, trustCerts []TrustCert) (bool, string) {
	// Extract x5c from header
	x5cRaw, ok := header["x5c"].([]any)
	if !ok || len(x5cRaw) == 0 {
		return false, "no x5c header in status list JWT"
	}

	// Parse certificates from x5c
	var certs []*x509.Certificate
	for _, entry := range x5cRaw {
		b64, ok := entry.(string)
		if !ok {
			return false, "x5c entry is not a string"
		}
		der, err := format.DecodeBase64Std(b64)
		if err != nil {
			return false, fmt.Sprintf("decoding x5c certificate: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return false, fmt.Sprintf("parsing x5c certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	leaf := certs[0]

	// Build root pool from trust list certs
	roots := x509.NewCertPool()
	for _, tc := range trustCerts {
		tlCert, err := x509.ParseCertificate(tc.Raw)
		if err != nil {
			continue
		}
		roots.AddCert(tlCert)
	}

	// Build intermediate pool from x5c chain (all except leaf)
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	// Validate chain
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return false, fmt.Sprintf("x5c chain not trusted: %v", err)
	}

	// Verify JWT signature using leaf's public key. The accepted algorithms
	// stay narrower than the toolkit's shared set on purpose: a status list
	// token is spec-constrained, and widening it here would quietly start
	// accepting lists this check used to refuse.
	alg, _ := header["alg"].(string)
	switch alg {
	case "ES256", "ES384":
	default:
		return false, fmt.Sprintf("unsupported algorithm: %s", alg)
	}
	if !jws.Valid(parts[0]+"."+parts[1]+"."+parts[2], leaf.PublicKey) {
		return false, fmt.Sprintf("%s signature verification failed", alg)
	}

	return true, fmt.Sprintf("x5c chain valid, signed by %s", leaf.Subject.CommonName)
}

func zlibDecompress(data []byte) ([]byte, error) {
	// Try zlib first (with header)
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err == nil {
		defer r.Close()
		return io.ReadAll(r)
	}

	// Fall back to raw DEFLATE
	fr := flate.NewReader(bytes.NewReader(data))
	defer fr.Close()
	return io.ReadAll(fr)
}

// extractStatus reads one entry out of the decompressed bitstring.
//
// Both idx and bits arrive from documents somebody else wrote: idx from the
// credential's own status claim and bits from the fetched status list. A
// negative idx used to reach the shift below and panic with "negative shift
// amount", which a credential could therefore do to whoever checked whether
// it was revoked. A bits value outside the four the specification allows
// produced a mask that read the whole byte and reported it as a status.
func extractStatus(bitstring []byte, idx, bits int) (int, error) {
	if idx < 0 {
		return 0, fmt.Errorf("status list index %d is negative", idx)
	}
	switch bits {
	case 1, 2, 4, 8:
	default:
		return 0, fmt.Errorf("status list declares %d bits per entry, which is not one of 1, 2, 4 or 8", bits)
	}

	bitPos := idx * bits
	byteIdx := bitPos / 8
	bitOffset := bitPos % 8

	if byteIdx >= len(bitstring) {
		return 0, fmt.Errorf("index %d out of range (bitstring length: %d bytes)", idx, len(bitstring))
	}

	mask := (1 << bits) - 1
	value := (int(bitstring[byteIdx]) >> bitOffset) & mask

	return value, nil
}
