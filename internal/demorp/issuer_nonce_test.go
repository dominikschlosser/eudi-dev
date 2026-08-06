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

package demorp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// A wallet built to OpenID4VCI 1.0 never reads c_nonce from the token
// response, because the final specification removed it. Without a Nonce
// Endpoint such a wallet has nowhere to get the challenge it must sign, so
// every credential request it makes is refused for a nonce mismatch it cannot
// do anything about. That is what a real wallet hit against the demo issuer.
func TestIssuerMetadataAdvertisesTheNonceEndpoint(t *testing.T) {
	d, _, _ := newDemoRP(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil)
	rec := httptest.NewRecorder()
	d.IssuerHandler().ServeHTTP(rec, req)

	var metadata map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("decoding metadata: %v", err)
	}
	endpoint, _ := metadata["nonce_endpoint"].(string)
	if endpoint == "" {
		t.Fatal("issuer metadata advertises no nonce_endpoint")
	}
	if !strings.HasSuffix(endpoint, "/nonce") {
		t.Errorf("nonce_endpoint = %q, want it to end in /nonce", endpoint)
	}
}

func TestNonceEndpoint(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.IssuerHandler()

	get := func() (string, *httptest.ResponseRecorder) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/nonce", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding nonce response: %v (%s)", err, rec.Body.String())
		}
		nonce, _ := resp["c_nonce"].(string)
		return nonce, rec
	}

	nonce, rec := get()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if nonce == "" {
		t.Fatal("the nonce endpoint returned no c_nonce")
	}
	// A challenge a cache could hand to somebody else is not a challenge.
	if store := rec.Header().Get("Cache-Control"); !strings.Contains(store, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", store)
	}

	second, _ := get()
	if second == nonce {
		t.Error("the nonce endpoint handed out the same challenge twice")
	}

	if !d.nonceIssued(nonce) {
		t.Error("a nonce this issuer handed out was not recognised")
	}
	if d.nonceIssued("never-issued") {
		t.Error("a nonce nobody issued was accepted")
	}
	if d.nonceIssued("") {
		t.Error("an empty nonce was accepted")
	}
}

func TestNonceIssuedRejectsAnExpiredNonce(t *testing.T) {
	d, _, _ := newDemoRP(t)

	d.mu.Lock()
	d.nonces["stale"] = time.Now().Add(-time.Minute)
	d.mu.Unlock()

	if d.nonceIssued("stale") {
		t.Error("an expired nonce was accepted")
	}
}

// proofJWT builds an openid4vci-proof+jwt carrying the given nonce.
func proofJWT(t *testing.T, nonce string) string {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"aud": "https://issuer.example", "iat": time.Now().Unix()}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	compact, err := jws.Sign(map[string]any{
		"alg": "ES256",
		"typ": "openid4vci-proof+jwt",
		"jwk": mock.SigningJWKMap(&key.PublicKey),
	}, payload, key)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestVerifyProofJWTAcceptsBothNonceSources(t *testing.T) {
	d, _, _ := newDemoRP(t)

	// The Nonce Endpoint, which is where a wallet built to 1.0 looks.
	endpointNonce := "from-the-endpoint"
	d.mu.Lock()
	d.nonces[endpointNonce] = time.Now().Add(time.Minute)
	d.mu.Unlock()

	t.Run("a nonce from the nonce endpoint", func(t *testing.T) {
		if _, err := verifyProofJWT(proofJWT(t, endpointNonce), "token-c-nonce", d.nonceIssued); err != nil {
			t.Errorf("a nonce from the nonce endpoint was refused: %v", err)
		}
	})

	// The token response c_nonce, which the drafts specified and older
	// wallets still use.
	t.Run("the c_nonce from the token response", func(t *testing.T) {
		if _, err := verifyProofJWT(proofJWT(t, "token-c-nonce"), "token-c-nonce", d.nonceIssued); err != nil {
			t.Errorf("the token response c_nonce was refused: %v", err)
		}
	})

	t.Run("a nonce from neither", func(t *testing.T) {
		_, err := verifyProofJWT(proofJWT(t, "invented"), "token-c-nonce", d.nonceIssued)
		if err == nil {
			t.Fatal("a nonce this issuer never handed out was accepted")
		}
		if !strings.Contains(err.Error(), "not one this issuer handed out") {
			t.Errorf("error = %q", err)
		}
	})

	// The failure a real wallet hit. The message has to point at the fix
	// rather than report a mismatch against a value the wallet never saw.
	t.Run("no nonce at all", func(t *testing.T) {
		_, err := verifyProofJWT(proofJWT(t, ""), "token-c-nonce", d.nonceIssued)
		if err == nil {
			t.Fatal("a proof with no nonce was accepted")
		}
		if !strings.Contains(err.Error(), "nonce endpoint") {
			t.Errorf("error = %q, want it to point at the nonce endpoint", err)
		}
	})
}

func TestVerifyProofJWTRejectsBadProofs(t *testing.T) {
	d, _, _ := newDemoRP(t)

	t.Run("not a JWT", func(t *testing.T) {
		if _, err := verifyProofJWT("nonsense", "n", d.nonceIssued); err == nil {
			t.Error("something that is not a JWT was accepted")
		}
	})

	t.Run("no jwk in the header", func(t *testing.T) {
		key, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		compact, err := jws.Sign(map[string]any{"alg": "ES256"}, map[string]any{"nonce": "n"}, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyProofJWT(compact, "n", d.nonceIssued); err == nil {
			t.Error("a proof without an embedded jwk was accepted")
		}
	})

	t.Run("a signature made by another key", func(t *testing.T) {
		other, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		signing, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		// The header names one key, the signature is made with another.
		compact, err := jws.Sign(map[string]any{
			"alg": "ES256",
			"typ": "openid4vci-proof+jwt",
			"jwk": mock.SigningJWKMap(&other.PublicKey),
		}, map[string]any{"nonce": "n"}, signing)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyProofJWT(compact, "n", d.nonceIssued); err == nil {
			t.Error("a proof whose signature does not match its jwk was accepted")
		}
	})

	t.Run("a signature that is not valid base64", func(t *testing.T) {
		parts := strings.Split(proofJWT(t, "n"), ".")
		if _, err := verifyProofJWT(parts[0]+"."+parts[1]+".!!!", "n", d.nonceIssued); err == nil {
			t.Error("an unreadable signature was accepted")
		}
	})

	t.Run("a header that is not JSON", func(t *testing.T) {
		bad := base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".e30.AAAA"
		if _, err := verifyProofJWT(bad, "n", d.nonceIssued); err == nil {
			t.Error("a header that is not JSON was accepted")
		}
	})
}
