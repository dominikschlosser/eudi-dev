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
	"crypto/ecdsa"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// handcraftedToken signs a status list token from explicit header and payload
// maps, so a test can leave out or corrupt exactly one member.
func handcraftedToken(t *testing.T, key *ecdsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	full := map[string]any{"alg": "ES256", "typ": TypJWT, "jwk": mock.PublicKeyJWKMap(&key.PublicKey)}
	for k, v := range header {
		if v == nil {
			delete(full, k)
			continue
		}
		full[k] = v
	}
	token, err := jws.Sign(full, payload, key)
	if err != nil {
		t.Fatalf("signing the status list token: %v", err)
	}
	return token
}

// zlibLST returns the base64url of a zlib-compressed bitstring, the lst
// member of Section 4.2.
func zlibLST(t *testing.T, bitstring []byte) string {
	t.Helper()
	compressed, err := compressBitstring(bitstring)
	if err != nil {
		t.Fatalf("compressing: %v", err)
	}
	return format.EncodeBase64URL(compressed)
}

// serveToken serves a fixed body with a fixed content type and status code.
func serveToken(t *testing.T, status int, contentType, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Section 8.3: "The subject claim (sub or 2) of the Status List Token MUST be
// equal to the uri claim in the status_list object of the Referenced Token".
// Without the comparison, any status list token a relying party trusts
// answers for any credential.
func TestCheck_RejectsSubjectThatIsNotTheReferencedURI(t *testing.T) {
	key := mustGenerateKey(t)
	// The substituted list says everyone is valid, and it says so about a
	// different list than the one the credential points at.
	token := handcraftedToken(t, key, nil, map[string]any{
		"sub":         "https://elsewhere.example/statuslists/9",
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(time.Hour).Unix(),
		"status_list": map[string]any{"bits": 1, "lst": zlibLST(t, make([]byte, 16))},
	})
	srv := serveToken(t, 200, MediaTypeJWT, token)

	_, err := Check(&StatusRef{URI: srv.URL, Idx: 3})
	if err == nil {
		t.Fatal("a status list token for a different URI was accepted for this credential")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Errorf("error = %v, want it to name the subject mismatch", err)
	}
}

// A token with no sub at all is equally unusable: Section 5.1 makes it
// REQUIRED.
func TestCheck_RejectsTokenWithoutSubject(t *testing.T) {
	key := mustGenerateKey(t)
	token := handcraftedToken(t, key, nil, map[string]any{
		"iat":         time.Now().Unix(),
		"status_list": map[string]any{"bits": 1, "lst": zlibLST(t, make([]byte, 16))},
	})
	srv := serveToken(t, 200, MediaTypeJWT, token)

	if _, err := Check(&StatusRef{URI: srv.URL, Idx: 0}); err == nil {
		t.Fatal("a status list token without a subject claim was accepted")
	}
}

// Section 5.1: "The JWT MUST be secured using a cryptographic signature or MAC
// algorithm. Relying Parties MUST reject JWTs with an invalid signature."
// There is no exception for a relying party without a trust list.
func TestCheck_RejectsBadSignatureWithoutATrustList(t *testing.T) {
	key := mustGenerateKey(t)
	other := mustGenerateKey(t)
	// The token advertises the other key but is signed with this one, so the
	// key it resolves to does not verify it.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := handcraftedToken(t, key, map[string]any{"jwk": mock.PublicKeyJWKMap(&other.PublicKey)}, map[string]any{
			"sub":         srv.URL,
			"iat":         time.Now().Unix(),
			"exp":         time.Now().Add(time.Hour).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": zlibLST(t, make([]byte, 16))},
		})
		w.Header().Set("Content-Type", MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()

	if _, err := Check(&StatusRef{URI: srv.URL, Idx: 0}); err == nil {
		t.Fatal("a status list token whose signature does not verify was accepted")
	}
}

// A token that carries no key material at all cannot be verified by anyone,
// so it supports no statement about a credential.
func TestCheck_RejectsTokenWithNoResolvableKey(t *testing.T) {
	key := mustGenerateKey(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := handcraftedToken(t, key, map[string]any{"jwk": nil}, map[string]any{
			"sub":         srv.URL,
			"iat":         time.Now().Unix(),
			"exp":         time.Now().Add(time.Hour).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": zlibLST(t, make([]byte, 16))},
		})
		w.Header().Set("Content-Type", MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()

	_, err := Check(&StatusRef{URI: srv.URL, Idx: 0})
	if err == nil {
		t.Fatal("a status list token with no key to verify it against was accepted")
	}
	if !strings.Contains(err.Error(), "no key to verify") {
		t.Errorf("error = %v, want it to name the missing key", err)
	}
}

// A Status Provider naming its key by a DID gets an error naming the DID.
// Section 11.3 leaves key resolution to the ecosystem, and this one resolves
// a Status Issuer through x5c.
func TestCheck_NamesADIDItCannotResolve(t *testing.T) {
	key := mustGenerateKey(t)
	const did = "did:key:z6MkuR4XP7DmHiEzKK46ypK2RyZ3XgqQCz1DHw7XtMg3CEuf"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := handcraftedToken(t, key, map[string]any{"kid": did, "jwk": nil}, map[string]any{
			"sub":         srv.URL,
			"iat":         time.Now().Unix(),
			"exp":         time.Now().Add(time.Hour).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": zlibLST(t, make([]byte, 16))},
		})
		w.Header().Set("Content-Type", MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()

	_, err := Check(&StatusRef{URI: srv.URL, Idx: 0})
	if err == nil {
		t.Fatal("a status list token naming its key by a DID was accepted")
	}
	if !strings.Contains(err.Error(), did) {
		t.Errorf("error = %v, want it to name the DID %s", err, did)
	}
}

// A verified signature that was not anchored anywhere is reported as such, so
// a caller can tell a self-asserted list from a trusted one.
func TestCheck_ReportsAnUnanchoredKeyAsAWarning(t *testing.T) {
	key := mustGenerateKey(t)
	srv := jwtServer(t, key, 1, make([]byte, 16), nil)

	result, err := Check(&StatusRef{URI: srv.URL, Idx: 0})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.TrustAnchored {
		t.Error("a key taken from the token itself must not be reported as trust anchored")
	}
	if len(result.Warnings) == 0 {
		t.Error("expected a warning about the unanchored key")
	}
}

// Section 8.3: "If the expiration time is defined (exp or 4), it MUST be
// checked if the Status List Token is expired". An unchecked exp lets a copy
// of the list captured before a credential was revoked keep answering for it.
func TestCheck_RejectsExpiredToken(t *testing.T) {
	key := mustGenerateKey(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issued := time.Now().Add(-48 * time.Hour)
		token := handcraftedToken(t, key, nil, map[string]any{
			"sub":         srv.URL,
			"iat":         issued.Unix(),
			"exp":         issued.Add(time.Hour).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": zlibLST(t, make([]byte, 16))},
		})
		w.Header().Set("Content-Type", MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()

	_, err := Check(&StatusRef{URI: srv.URL, Idx: 0})
	if err == nil {
		t.Fatal("an expired status list token was accepted")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error = %v, want it to say the token expired", err)
	}
}

// Section 5.1: "iat: REQUIRED."
func TestCheck_RejectsTokenWithoutIssuedAt(t *testing.T) {
	key := mustGenerateKey(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := handcraftedToken(t, key, nil, map[string]any{
			"sub":         srv.URL,
			"exp":         time.Now().Add(time.Hour).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": zlibLST(t, make([]byte, 16))},
		})
		w.Header().Set("Content-Type", MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()

	_, err := Check(&StatusRef{URI: srv.URL, Idx: 0})
	if err == nil {
		t.Fatal("a status list token without iat was accepted")
	}
	if !strings.Contains(err.Error(), "issued at") {
		t.Errorf("error = %v, want it to name the missing iat", err)
	}
}

// Section 5.1: "typ: REQUIRED. The JWT type MUST be statuslist+jwt." Without
// the check, any JWT signed by a key the relying party already trusts (an
// issued credential, an access token) can stand in for a status list.
func TestCheck_RejectsWrongOrMissingTyp(t *testing.T) {
	key := mustGenerateKey(t)
	for _, tc := range []struct {
		name string
		typ  any
	}{
		{"missing", nil},
		{"a credential type", "vc+sd-jwt"},
		{"plain JWT", "JWT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := handcraftedToken(t, key, map[string]any{"typ": tc.typ}, map[string]any{
					"sub":         srv.URL,
					"iat":         time.Now().Unix(),
					"exp":         time.Now().Add(time.Hour).Unix(),
					"status_list": map[string]any{"bits": 1, "lst": zlibLST(t, make([]byte, 16))},
				})
				w.Header().Set("Content-Type", MediaTypeJWT)
				_, _ = w.Write([]byte(token))
			}))
			defer srv.Close()

			_, err := Check(&StatusRef{URI: srv.URL, Idx: 0})
			if err == nil {
				t.Fatal("a token that is not a status list token was accepted as one")
			}
			if !strings.Contains(err.Error(), "typ") {
				t.Errorf("error = %v, want it to name the typ header", err)
			}
		})
	}
}

// RFC 7515 section 4.1.9 allows the "application/" prefix to be omitted, so
// the long spelling denotes the same media type and must be accepted.
func TestCheck_AcceptsTypWithTheApplicationPrefix(t *testing.T) {
	key := mustGenerateKey(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := handcraftedToken(t, key, map[string]any{"typ": MediaTypeJWT}, map[string]any{
			"sub":         srv.URL,
			"iat":         time.Now().Unix(),
			"exp":         time.Now().Add(time.Hour).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": zlibLST(t, make([]byte, 16))},
		})
		w.Header().Set("Content-Type", MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()

	if _, err := Check(&StatusRef{URI: srv.URL, Idx: 0}); err != nil {
		t.Fatalf("application/statuslist+jwt must be accepted as typ: %v", err)
	}
}

// Section 4.2: "bits: REQUIRED". A missing or unreadable bits is refused, not
// defaulted to 1, because the wrong width reads other credentials' entries.
func TestCheck_RejectsMissingOrUnreadableBits(t *testing.T) {
	key := mustGenerateKey(t)
	for _, tc := range []struct {
		name string
		list map[string]any
	}{
		{"no bits member", map[string]any{"lst": "placeholder"}},
		{"bits as a string", map[string]any{"bits": "2", "lst": "placeholder"}},
		{"bits of three", map[string]any{"bits": 3, "lst": "placeholder"}},
		{"no lst member", map[string]any{"bits": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				list := map[string]any{}
				for k, v := range tc.list {
					list[k] = v
				}
				if _, ok := list["lst"]; ok {
					list["lst"] = zlibLST(t, make([]byte, 16))
				}
				token := handcraftedToken(t, key, nil, map[string]any{
					"sub":         srv.URL,
					"iat":         time.Now().Unix(),
					"exp":         time.Now().Add(time.Hour).Unix(),
					"status_list": list,
				})
				w.Header().Set("Content-Type", MediaTypeJWT)
				_, _ = w.Write([]byte(token))
			}))
			defer srv.Close()

			if _, err := Check(&StatusRef{URI: srv.URL, Idx: 0}); err == nil {
				t.Fatal("a status list that does not meet section 4.2 was read anyway")
			}
		})
	}
}

// Section 6.2 makes idx REQUIRED. A missing idx is refused, not read as
// index 0.
func TestExtractStatusRef_RequiresIdx(t *testing.T) {
	ref := ExtractStatusRef(map[string]any{
		"status": map[string]any{
			"status_list": map[string]any{"uri": "https://example.com/statuslists/1"},
		},
	})
	if ref == nil {
		t.Fatal("a present but malformed status_list must not be reported as absent")
	}
	if ref.Invalid == "" {
		t.Fatalf("a status_list without idx was accepted as %+v", ref)
	}
	if _, err := CheckWithOptions(ref, CheckOptions{}); err == nil {
		t.Error("checking an invalid reference must fail rather than fetch")
	}
}

func TestExtractStatusRef_RejectsNonIntegerAndNegativeIdx(t *testing.T) {
	for _, idx := range []any{"0", 1.5, float64(-1), int64(-7), true} {
		ref := ExtractStatusRef(map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{"uri": "https://example.com/statuslists/1", "idx": idx},
			},
		})
		if ref == nil || ref.Invalid == "" {
			t.Errorf("idx %#v was accepted as %+v", idx, ref)
		}
	}
}

// idx*bits overflows for an index a credential is free to choose, so the
// bounds check has to run on idx itself.
func TestExtractStatus_DoesNotOverflowOnAHugeIndex(t *testing.T) {
	bitstring := make([]byte, 16)
	for _, tc := range []struct {
		name string
		idx  int
		bits int
	}{
		{"max int at one bit", math.MaxInt, 1},
		{"max int at eight bits", math.MaxInt, 8},
		{"product wraps to negative", math.MaxInt/4 + 1, 8},
		{"product wraps to zero", math.MaxInt/2 + 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on idx=%d bits=%d: %v", tc.idx, tc.bits, r)
				}
			}()
			if _, err := extractStatus(bitstring, tc.idx, tc.bits); err == nil {
				t.Errorf("idx=%d bits=%d was read as an entry of a %d byte list", tc.idx, tc.bits, len(bitstring))
			}
		})
	}
}

// The same index arriving through a credential must be refused end to end
// rather than taking down the party resolving the status.
func TestCheck_DoesNotPanicOnAHugeCredentialIndex(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("resolving a status panicked: %v", r)
		}
	}()
	key := mustGenerateKey(t)
	srv := jwtServer(t, key, 8, make([]byte, 16), nil)

	if _, err := Check(&StatusRef{URI: srv.URL, Idx: math.MaxInt/4 + 1}); err == nil {
		t.Error("an index far past the end of the list was read as an entry")
	}
}

// Section 8.2: "A successful response that contains a Status List Token MUST
// use an HTTP status code in the 2xx range." A Status Provider behind a cache
// or proxy answers 203.
func TestCheck_AcceptsAny2xx(t *testing.T) {
	key := mustGenerateKey(t)
	for _, code := range []int{200, 202, 203, 206} {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := GenerateStatusListJWT(make([]byte, 16), key, StatusListConfig{URI: srv.URL})
			if err != nil {
				t.Errorf("GenerateStatusListJWT: %v", err)
				return
			}
			w.Header().Set("Content-Type", MediaTypeJWT)
			w.WriteHeader(code)
			_, _ = w.Write([]byte(token))
		}))
		if _, err := Check(&StatusRef{URI: srv.URL, Idx: 0}); err != nil {
			t.Errorf("HTTP %d: %v", code, err)
		}
		srv.Close()
	}
}

// Section 8.2 makes the response content type mandatory. A response that
// declares something else is still read, and the caller is warned.
func TestCheck_WarnsAboutTheContentType(t *testing.T) {
	key := mustGenerateKey(t)
	for _, tc := range []struct {
		name        string
		contentType string
	}{
		{"none at all", ""},
		{"plain JWT", "application/jwt"},
		{"text", "text/plain; charset=utf-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token, err := GenerateStatusListJWT(make([]byte, 16), key, StatusListConfig{URI: srv.URL})
				if err != nil {
					t.Errorf("GenerateStatusListJWT: %v", err)
					return
				}
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				} else {
					w.Header()["Content-Type"] = nil
				}
				_, _ = w.Write([]byte(token))
			}))
			defer srv.Close()

			result, err := Check(&StatusRef{URI: srv.URL, Idx: 0})
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if !hasWarning(result.Warnings, "Content-Type") {
				t.Errorf("warnings = %v, want one naming the content type", result.Warnings)
			}
		})
	}
}

// A correctly declared content type produces no such warning.
func TestCheck_DoesNotWarnAboutTheCorrectContentType(t *testing.T) {
	key := mustGenerateKey(t)
	srv := jwtServer(t, key, 1, make([]byte, 16), nil)
	result, err := Check(&StatusRef{URI: srv.URL, Idx: 0})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if hasWarning(result.Warnings, "Content-Type") {
		t.Errorf("warnings = %v, want none about the content type", result.Warnings)
	}
}

// Section 4.1 requires the ZLIB data format around the DEFLATE stream. A bare
// DEFLATE stream is still read, and the caller is warned.
func TestCheck_ReportsRawDeflateAsAWarning(t *testing.T) {
	key := mustGenerateKey(t)
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	bitstring := make([]byte, 16)
	bitstring[0] = 1 << 2
	if _, err := fw.Write(bitstring); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	lst := format.EncodeBase64URL(buf.Bytes())

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := handcraftedToken(t, key, nil, map[string]any{
			"sub":         srv.URL,
			"iat":         time.Now().Unix(),
			"exp":         time.Now().Add(time.Hour).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": lst},
		})
		w.Header().Set("Content-Type", MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()

	result, err := Check(&StatusRef{URI: srv.URL, Idx: 2})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.Status != 1 {
		t.Errorf("status = %d, want 1", result.Status)
	}
	if !hasWarning(result.Warnings, "raw DEFLATE") {
		t.Errorf("warnings = %v, want one naming the missing ZLIB header", result.Warnings)
	}
}

// Section 7.1 gives every status value a name. A suspended credential (0x02,
// "usually temporary") is reported apart from a permanently invalid one, and
// an unregistered value apart from both.
func TestStatusName(t *testing.T) {
	for _, tc := range []struct {
		value int
		want  string
	}{
		{0, "VALID"},
		{1, "INVALID"},
		{2, "SUSPENDED"},
		{3, "APPLICATION_SPECIFIC(0x03)"},
		{0x0C, "APPLICATION_SPECIFIC(0x0C)"},
		{0x0F, "APPLICATION_SPECIFIC(0x0F)"},
		{4, "UNKNOWN(0x04)"},
		{0x10, "UNKNOWN(0x10)"},
		{255, "UNKNOWN(0xFF)"},
	} {
		if got := StatusName(tc.value); got != tc.want {
			t.Errorf("StatusName(%d) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

// A two-bit list must report SUSPENDED by name all the way out of the
// checker.
func TestCheck_ReportsSuspendedByName(t *testing.T) {
	key := mustGenerateKey(t)
	bitstring := make([]byte, 16)
	bitstring[0] = 0b10 << 2 // index 1, two bits per entry, value 2
	srv := jwtServer(t, key, 2, bitstring, nil)

	result, err := Check(&StatusRef{URI: srv.URL, Idx: 1})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.Status != 2 || result.StatusName != "SUSPENDED" {
		t.Errorf("status = %d %q, want 2 SUSPENDED", result.Status, result.StatusName)
	}
	if result.IsValid {
		t.Error("a suspended credential is not valid")
	}
}

func hasWarning(warnings []string, substring string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substring) {
			return true
		}
	}
	return false
}

// Section 8.1 content negotiation: a client that asks for the CWT form gets
// it, and everything else keeps getting the JWT form.
func TestNegotiateMediaType(t *testing.T) {
	for _, tc := range []struct {
		accept string
		want   string
	}{
		{"", MediaTypeJWT},
		{MediaTypeJWT, MediaTypeJWT},
		{MediaTypeCWT, MediaTypeCWT},
		{"application/statuslist+cwt, application/statuslist+jwt;q=0.5", MediaTypeCWT},
		{"application/statuslist+jwt, application/statuslist+cwt;q=0.5", MediaTypeJWT},
		{MediaTypeJWT + ", " + MediaTypeCWT, MediaTypeJWT},
		{"*/*", MediaTypeJWT},
		{"application/json", MediaTypeJWT},
		{"application/statuslist+cwt;q=0.9, */*;q=0.1", MediaTypeCWT},
	} {
		if got := NegotiateMediaType(tc.accept); got != tc.want {
			t.Errorf("NegotiateMediaType(%q) = %q, want %q", tc.accept, got, tc.want)
		}
	}
}
