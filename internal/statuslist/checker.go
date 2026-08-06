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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
)

// clockSkew is how far the local clock may run ahead of the Status Issuer's
// before a still-valid Status List Token is called expired. The specification
// names no tolerance. A minute of allowance keeps ordinary clock drift from
// reporting every credential in an ecosystem as unresolvable.
const clockSkew = time.Minute

// ExtractStatusRef extracts the status list reference from SD-JWT claims or
// mDOC MSO status.
//
// A credential with no status claim at all returns nil. A credential that
// carries a status_list object which does not meet Section 6.2 ("idx:
// REQUIRED ... uri: REQUIRED") returns a reference with Invalid set, so the
// caller reports a broken reference rather than a missing one.
func ExtractStatusRef(claims map[string]any) *StatusRef {
	status, ok := claims["status"].(map[string]any)
	if !ok {
		return nil
	}
	sl, ok := status["status_list"].(map[string]any)
	if !ok {
		return nil
	}

	uri, _ := sl["uri"].(string)
	if uri == "" {
		return &StatusRef{Invalid: "the status_list reference has no uri claim"}
	}

	rawIdx, present := sl["idx"]
	if !present {
		return &StatusRef{URI: uri, Invalid: "the status_list reference has no idx claim"}
	}
	idx, ok := asInt(rawIdx)
	if !ok {
		return &StatusRef{URI: uri, Invalid: fmt.Sprintf("the status_list idx claim is not an integer (%T)", rawIdx)}
	}
	if idx < 0 {
		return &StatusRef{URI: uri, Invalid: fmt.Sprintf("the status_list idx claim is %d, which is not a non-negative integer", idx)}
	}
	return &StatusRef{URI: uri, Idx: idx}
}

// asInt reads an integer out of a decoded JSON or CBOR value. JSON numbers
// arrive as float64, CBOR ones as int64 or uint64, so the same claim has a
// different Go type depending on which representation the credential used.
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		if n > 1<<62 {
			return 0, false
		}
		return int(n), true
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

// Check fetches the status list and checks the credential's status.
func Check(ref *StatusRef) (*StatusResult, error) {
	return CheckWithOptions(ref, CheckOptions{})
}

// CheckWithOptions fetches the Status List Token referenced by a credential
// and reports the status at the credential's index.
//
// Every step Section 8.3 requires runs here, and a failure of any of them is
// returned as an error rather than as a result a caller has to remember to
// inspect: "If any of these checks fails, no statement about the status of
// the Referenced Token can be made and the Referenced Token SHOULD be
// rejected."
func CheckWithOptions(ref *StatusRef, opts CheckOptions) (*StatusResult, error) {
	if ref == nil {
		return nil, fmt.Errorf("no status list reference")
	}
	if ref.Invalid != "" {
		return nil, fmt.Errorf("invalid status list reference: %s", ref.Invalid)
	}
	if ref.URI == "" {
		return nil, fmt.Errorf("status list reference has no uri")
	}
	if ref.Idx < 0 {
		return nil, fmt.Errorf("status list index %d is negative", ref.Idx)
	}

	body, contentType, err := fetchStatusListToken(ref.URI)
	if err != nil {
		return nil, err
	}

	tokenFormat, formatWarning := detectFormat(contentType, body)

	var tok *statusListToken
	switch tokenFormat {
	case FormatCWT:
		tok, err = parseCWTStatusListToken(body, opts)
	default:
		tok, err = parseJWTStatusListToken(body, opts)
	}
	if err != nil {
		return nil, err
	}
	if formatWarning != "" {
		tok.warnings = append(tok.warnings, formatWarning)
	}

	if err := tok.validate(ref, opts); err != nil {
		return nil, err
	}

	decompressed, rawDeflate, err := zlibDecompress(tok.lst)
	if err != nil {
		return nil, fmt.Errorf("decompressing status list: %w", err)
	}
	if rawDeflate {
		// Section 4.1 requires the ZLIB data format around the DEFLATE
		// stream. A bare DEFLATE stream is still read, because refusing it
		// would only hide the deployments that produce one, but it is a
		// conformance problem the caller gets told about.
		tok.warnings = append(tok.warnings, "the status list is raw DEFLATE without the ZLIB header required by section 4.1")
	}

	status, err := extractStatus(decompressed, ref.Idx, tok.bits)
	if err != nil {
		return nil, err
	}

	signatureValid := true
	return &StatusResult{
		URI:            ref.URI,
		Index:          ref.Idx,
		Status:         status,
		StatusName:     StatusName(status),
		IsValid:        status == 0,
		BitsPerEntry:   tok.bits,
		Format:         tok.format,
		Subject:        tok.subject,
		SignatureValid: &signatureValid,
		SignatureInfo:  tok.signatureInfo,
		TrustAnchored:  tok.trustAnchored,
		Warnings:       tok.warnings,
	}, nil
}

// fetchStatusListToken performs the Section 8.1 request and returns the raw
// token body together with the declared content type.
func fetchStatusListToken(uri string) ([]byte, string, error) {
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	// Both representations are acceptable. An mdoc ecosystem serves its
	// status lists as CWT, and a client that asks only for the JWT form
	// cannot resolve those lists at all.
	req.Header.Set("Accept", MediaTypeJWT+", "+MediaTypeCWT)

	resp, err := format.HTTPClientForURL(uri).Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetching status list: %w", err)
	}
	defer resp.Body.Close()

	// Section 8.2: "A successful response that contains a Status List Token
	// MUST use an HTTP status code in the 2xx range." A Status Provider
	// behind a cache or a proxy answers 203 or 206 and is just as successful.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, "", fmt.Errorf("status list returned HTTP %d", resp.StatusCode)
	}

	body, err := format.ReadRemoteBody(resp.Body, "status list")
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}
	return body, resp.Header.Get("Content-Type"), nil
}

// detectFormat picks the representation from the response content type,
// falling back to the shape of the body.
//
// Section 8.2 makes the content type mandatory ("the Status Provider MUST use
// the following content-type"), so a response that declares something else,
// or nothing, is a conformance problem worth naming even when the body is
// still readable.
func detectFormat(contentType string, body []byte) (string, string) {
	mediaType := ""
	if contentType != "" {
		if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
			mediaType = strings.ToLower(strings.TrimSpace(parsed))
		}
	}
	switch mediaType {
	case MediaTypeJWT:
		return FormatJWT, ""
	case MediaTypeCWT:
		return FormatCWT, ""
	}

	sniffed := FormatCWT
	if looksLikeCompactJWS(body) {
		sniffed = FormatJWT
	}
	if contentType == "" {
		return sniffed, fmt.Sprintf("the status list response declared no Content-Type, section 8.2 requires %s or %s", MediaTypeJWT, MediaTypeCWT)
	}
	return sniffed, fmt.Sprintf("the status list response declared Content-Type %q, section 8.2 requires %s or %s", contentType, MediaTypeJWT, MediaTypeCWT)
}

// looksLikeCompactJWS reports whether the body is the JWS Compact
// Serialization rather than the binary COSE encoding of a CWT.
func looksLikeCompactJWS(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if bytes.Count(trimmed, []byte(".")) != 2 {
		return false
	}
	for _, b := range trimmed {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// statusListToken is a Status List Token in either representation, parsed and
// with its signature already verified.
type statusListToken struct {
	format        string
	subject       string
	issuedAt      *time.Time
	expiresAt     *time.Time
	bits          int
	lst           []byte
	signatureInfo string
	trustAnchored bool
	warnings      []string
}

// validate applies the Section 8.3 claim checks that do not depend on the
// bitstring itself.
func (t *statusListToken) validate(ref *StatusRef, opts CheckOptions) error {
	// Section 8.3: "The subject claim (sub or 2) of the Status List Token
	// MUST be equal to the uri claim in the status_list object of the
	// Referenced Token". Without this any Status List Token from a trusted
	// Status Issuer answers for any credential, so one list whose index N is
	// zero un-revokes every credential that happens to sit at index N.
	if t.subject == "" {
		return fmt.Errorf("the status list token has no subject claim, which section 5.1 and 5.2 require")
	}
	if t.subject != ref.URI {
		return fmt.Errorf("the status list token's subject %q is not the uri %q the credential references", t.subject, ref.URI)
	}

	// Section 5.1: "iat: REQUIRED. ... The iat (issued at) claim MUST specify
	// the time at which the Status List Token was issued."
	if t.issuedAt == nil {
		return fmt.Errorf("the status list token has no issued at claim, which section 5.1 and 5.2 require")
	}

	// Section 8.3: "If the expiration time is defined (exp or 4), it MUST be
	// checked if the Status List Token is expired". An unchecked exp lets a
	// copy of the list taken before a credential was revoked answer for that
	// credential forever.
	now := opts.now()
	if t.expiresAt != nil {
		if now.After(t.expiresAt.Add(clockSkew)) {
			return fmt.Errorf("the status list token expired at %s", t.expiresAt.UTC().Format(time.RFC3339))
		}
	} else {
		t.warnings = append(t.warnings, "the status list token has no exp claim, which section 5.1 and 5.2 recommend")
	}
	if t.issuedAt.After(now.Add(clockSkew)) {
		t.warnings = append(t.warnings, fmt.Sprintf("the status list token is issued at %s, which is in the future", t.issuedAt.UTC().Format(time.RFC3339)))
	}

	// Section 4.2 and 4.3: "bits: REQUIRED ... The allowed values for bits are
	// 1, 2, 4, and 8." Defaulting a missing or unreadable bits to 1 reads a
	// wider list at the wrong offsets, so every entry past the first byte
	// comes back as some other credential's status.
	switch t.bits {
	case 1, 2, 4, 8:
	case 0:
		return fmt.Errorf("the status list has no bits member, which section 4.2 and 4.3 require")
	default:
		return fmt.Errorf("the status list declares %d bits per entry, which is not one of 1, 2, 4 or 8", t.bits)
	}
	if len(t.lst) == 0 {
		return fmt.Errorf("the status list has no lst member, which section 4.2 and 4.3 require")
	}
	return nil
}

// keyCandidates is the outcome of resolving the key that signed a Status List
// Token, as described in Section 11.3.
type keyCandidates struct {
	keys     []crypto.PublicKey
	info     string
	anchored bool
	warning  string
}

// resolveKeys picks the verification keys for a Status List Token.
//
// Section 5.1 and 5.2 both state that "Relying Parties MUST reject JWTs with
// an invalid signature", with no exception for a Relying Party that has no
// trust list. Verification therefore always runs. A caller-supplied trust
// anchor only decides whether the key is also trusted, which is reported
// separately so a status that was verified against the token's own key is
// never mistaken for one anchored in a trust list.
func resolveKeys(certs []*x509.Certificate, embedded []crypto.PublicKey, opts CheckOptions) (*keyCandidates, error) {
	if len(opts.TrustListCerts) > 0 {
		if len(certs) == 0 {
			return nil, fmt.Errorf("the status list token carries no certificate chain to validate against the trust list")
		}
		leaf, err := verifyChain(certs, opts.TrustListCerts)
		if err != nil {
			return nil, err
		}
		return &keyCandidates{
			keys:     []crypto.PublicKey{leaf.PublicKey},
			info:     fmt.Sprintf("x5c chain valid, signed by %s", leaf.Subject.CommonName),
			anchored: true,
		}, nil
	}

	if len(opts.Keys) > 0 {
		return &keyCandidates{
			keys:     opts.Keys,
			info:     "signed by a key the caller resolved out of band",
			anchored: true,
		}, nil
	}

	if len(certs) > 0 {
		return &keyCandidates{
			keys:    []crypto.PublicKey{certs[0].PublicKey},
			info:    fmt.Sprintf("signed by the token's own certificate for %s", certs[0].Subject.CommonName),
			warning: "the status list token's certificate chain was not validated against a trust list",
		}, nil
	}

	if len(embedded) > 0 {
		return &keyCandidates{
			keys:    embedded,
			info:    "signed by the key the token carries in its own header",
			warning: "the status list token was verified with the key it carries itself, which proves nothing about who issued it",
		}, nil
	}

	return nil, fmt.Errorf("no key to verify the status list token with: it carries no certificate chain and no public key, and no trust list or key was supplied")
}

// verifyChain validates a certificate chain against the trust list and
// returns the leaf.
func verifyChain(certs []*x509.Certificate, trustCerts []TrustCert) (*x509.Certificate, error) {
	roots := x509.NewCertPool()
	for _, tc := range trustCerts {
		tlCert, err := x509.ParseCertificate(tc.Raw)
		if err != nil {
			continue
		}
		roots.AddCert(tlCert)
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	leaf := certs[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("the status list token's certificate chain is not trusted: %w", err)
	}
	return leaf, nil
}

// parseJWTStatusListToken parses and verifies a Status List Token in JWT
// format (Section 5.1).
func parseJWTStatusListToken(body []byte, opts CheckOptions) (*statusListToken, error) {
	compact := strings.TrimSpace(string(body))
	parts := strings.SplitN(compact, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("the status list token is not a JWS compact serialization")
	}

	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding status list header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing status list header: %w", err)
	}

	// Section 5.1: "typ: REQUIRED. The JWT type MUST be statuslist+jwt."
	// Without it a JWT minted for some other purpose, and signed by a key the
	// Relying Party already trusts, is accepted as a status list.
	typ, _ := header["typ"].(string)
	if !isStatusListTyp(typ, TypJWT) {
		if typ == "" {
			return nil, fmt.Errorf("the status list token has no typ header, section 5.1 requires %q", TypJWT)
		}
		return nil, fmt.Errorf("the status list token has typ %q, section 5.1 requires %q", typ, TypJWT)
	}

	certs, err := certsFromX5C(header["x5c"])
	if err != nil {
		return nil, err
	}
	var embedded []crypto.PublicKey
	if jwkMap, ok := header["jwk"]; ok {
		if key, err := publicKeyFromJWK(jwkMap); err == nil {
			embedded = append(embedded, key)
		}
	}

	candidates, err := resolveKeys(certs, embedded, opts)
	if err != nil {
		return nil, err
	}

	// The accepted algorithms stay narrower than the toolkit's shared set on
	// purpose: a status list token is spec-constrained, and widening it here
	// would quietly start accepting lists this check refuses.
	alg, _ := header["alg"].(string)
	switch alg {
	case "ES256", "ES384":
	default:
		return nil, fmt.Errorf("the status list token is signed with %q, which is not one of the accepted algorithms ES256 and ES384", alg)
	}

	verified := false
	for _, key := range candidates.keys {
		if jws.Valid(compact, key) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("the status list token's %s signature does not verify", alg)
	}

	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding status list payload: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("parsing status list payload: %w", err)
	}

	tok := &statusListToken{
		format:        FormatJWT,
		signatureInfo: candidates.info,
		trustAnchored: candidates.anchored,
	}
	if candidates.warning != "" {
		tok.warnings = append(tok.warnings, candidates.warning)
	}
	tok.subject, _ = payload["sub"].(string)
	tok.issuedAt = unixClaim(payload["iat"])
	tok.expiresAt = unixClaim(payload["exp"])
	if ttl, present := payload["ttl"]; present {
		if n, ok := asInt(ttl); !ok || n <= 0 {
			tok.warnings = append(tok.warnings, "the status list token's ttl claim is not a positive number, which section 5.1 requires")
		}
	}

	sl, ok := payload["status_list"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the status list token has no status_list claim, which section 5.1 requires")
	}
	if b, present := sl["bits"]; present {
		if n, ok := asInt(b); ok {
			tok.bits = n
		} else {
			return nil, fmt.Errorf("the status list bits member is not an integer (%T)", b)
		}
	}
	if lst, ok := sl["lst"].(string); ok {
		decoded, err := format.DecodeBase64URL(lst)
		if err != nil {
			return nil, fmt.Errorf("decoding lst: %w", err)
		}
		tok.lst = decoded
	}
	return tok, nil
}

// isStatusListTyp compares a typ header against the required value. RFC 7515
// section 4.1.9 allows the "application/" prefix to be omitted, so both
// spellings denote the same media type.
func isStatusListTyp(typ, want string) bool {
	typ = strings.ToLower(strings.TrimSpace(typ))
	return typ == want || typ == "application/"+want
}

// certsFromX5C parses the certificate chain out of an x5c header.
func certsFromX5C(raw any) ([]*x509.Certificate, error) {
	entries, ok := raw.([]any)
	if !ok || len(entries) == 0 {
		return nil, nil
	}
	var certs []*x509.Certificate
	for _, entry := range entries {
		b64, ok := entry.(string)
		if !ok {
			return nil, fmt.Errorf("an x5c entry in the status list token is not a string")
		}
		der, err := format.DecodeBase64Std(b64)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// publicKeyFromJWK reads a public key out of a decoded jwk header.
func publicKeyFromJWK(raw any) (crypto.PublicKey, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	return keys.ParseJWK(data)
}

// unixClaim reads a NumericDate claim.
func unixClaim(v any) *time.Time {
	n, ok := asInt(v)
	if !ok {
		return nil
	}
	t := time.Unix(int64(n), 0)
	return &t
}

// maxBitstringBytes caps the decompressed status list. At one bit per entry
// this is over a billion credentials, so no honest list comes near it.
const maxBitstringBytes = 16 << 20

// zlibDecompress inflates the status list bitstring under a cap. The second
// return value reports whether the ZLIB header Section 4.1 requires was
// missing and a raw DEFLATE stream was read instead.
//
// The compressed bytes come from a URL in the credential's own status claim,
// so whoever minted the credential chooses them, and deflate happily turns a
// few hundred kilobytes into hundreds of megabytes. Reading that without a
// limit let a credential decide how much memory the party checking it would
// allocate, which the demo verifier does for every presentation it is shown.
func zlibDecompress(data []byte) ([]byte, bool, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err == nil {
		defer r.Close()
		out, err := readBounded(r)
		return out, false, err
	}

	fr := flate.NewReader(bytes.NewReader(data))
	defer fr.Close()
	out, err := readBounded(fr)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func readBounded(r io.Reader) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxBitstringBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxBitstringBytes {
		return nil, fmt.Errorf("status list decompresses to more than %d bytes", maxBitstringBytes)
	}
	return out, nil
}

// extractStatus reads one entry out of the decompressed bitstring.
//
// Both idx and bits arrive from documents somebody else wrote: idx from the
// credential's own status claim and bits from the fetched status list. A
// negative idx reaching the shift below panics with "negative shift amount",
// which a credential could therefore do to whoever checked whether it was
// revoked. A bits value outside the four the specification allows produces a
// mask that reads the whole byte and reports it as a status.
//
// The range check runs against idx itself rather than against idx*bits: the
// product overflows for an idx a credential is free to choose, and a wrapped
// negative product passes a check written on the byte offset and then panics
// on the negative index.
func extractStatus(bitstring []byte, idx, bits int) (int, error) {
	if idx < 0 {
		return 0, fmt.Errorf("status list index %d is negative", idx)
	}
	switch bits {
	case 1, 2, 4, 8:
	default:
		return 0, fmt.Errorf("status list declares %d bits per entry, which is not one of 1, 2, 4 or 8", bits)
	}

	entries := len(bitstring) * 8 / bits
	if idx >= entries {
		return 0, fmt.Errorf("index %d is out of range, the status list holds %d entries in %d bytes", idx, entries, len(bitstring))
	}

	bitPos := idx * bits
	byteIdx := bitPos / 8
	bitOffset := bitPos % 8

	mask := (1 << bits) - 1
	return (int(bitstring[byteIdx]) >> bitOffset) & mask, nil
}
