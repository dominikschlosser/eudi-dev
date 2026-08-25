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
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

// fakeSDJWT builds an unsigned SD-JWT-shaped credential with the given cnf key.
// Binding-key matching only reads the payload, so the signature is a dummy.
func fakeSDJWT(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	header := format.EncodeBase64URL([]byte(`{"alg":"ES256","typ":"dc+sd-jwt"}`))
	payloadMap := map[string]any{
		"vct": "urn:example:pid",
		"cnf": map[string]any{"jwk": mock.SigningJWKMap(pub)},
	}
	payloadJSON, err := json.Marshal(payloadMap)
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}
	payload := format.EncodeBase64URL(payloadJSON)
	return header + "." + payload + ".c2ln~"
}

func TestWellKnownURLTrailingSlash(t *testing.T) {
	cases := []struct {
		issuer   string
		wkType   string
		expected string
	}{
		// RFC 8414: strip terminating "/" for OAuth AS metadata
		{"https://example.com/test/a/alias/", "oauth-authorization-server", "https://example.com/.well-known/oauth-authorization-server/test/a/alias"},
		{"https://example.com/test/a/alias", "oauth-authorization-server", "https://example.com/.well-known/oauth-authorization-server/test/a/alias"},
		{"https://example.com/", "oauth-authorization-server", "https://example.com/.well-known/oauth-authorization-server"},
		{"https://example.com", "oauth-authorization-server", "https://example.com/.well-known/oauth-authorization-server"},
		// OID4VCI 1.0 §12.2.2: preserve the credential issuer path verbatim
		{"https://example.com/test/a/alias/", "openid-credential-issuer", "https://example.com/.well-known/openid-credential-issuer/test/a/alias/"},
		{"https://example.com/test/a/alias", "openid-credential-issuer", "https://example.com/.well-known/openid-credential-issuer/test/a/alias"},
	}
	for _, tc := range cases {
		got, err := wellKnownURL(tc.issuer, tc.wkType)
		if err != nil {
			t.Fatalf("wellKnownURL(%q, %q): %v", tc.issuer, tc.wkType, err)
		}
		if got != tc.expected {
			t.Errorf("wellKnownURL(%q, %q) = %q, want %q", tc.issuer, tc.wkType, got, tc.expected)
		}
	}
}

func TestAdvertisedBatchSize(t *testing.T) {
	if got := advertisedBatchSize(map[string]any{}); got != 0 {
		t.Errorf("no batch metadata: got %d, want 0", got)
	}
	metadata := map[string]any{
		"batch_credential_issuance": map[string]any{"batch_size": float64(10)},
	}
	if got := advertisedBatchSize(metadata); got != 10 {
		t.Errorf("batch_size 10: got %d", got)
	}
}

func TestIssuanceProofKeys(t *testing.T) {
	holder := testKey(t)

	keys, err := issuanceProofKeys(holder, map[string]any{}, "")
	if err != nil {
		t.Fatalf("issuanceProofKeys: %v", err)
	}
	if len(keys) != 1 || keys[0] != holder {
		t.Fatalf("without batch metadata expected only the holder key, got %d keys", len(keys))
	}

	metadata := map[string]any{
		"batch_credential_issuance": map[string]any{"batch_size": float64(10)},
	}
	keys, err = issuanceProofKeys(holder, metadata, "")
	if err != nil {
		t.Fatalf("issuanceProofKeys with batch: %v", err)
	}
	// batch_size 10 is capped to the wallet's own ceiling.
	if len(keys) != maxBatchProofKeys {
		t.Fatalf("expected %d proof keys, got %d", maxBatchProofKeys, len(keys))
	}
	if keys[0] != holder {
		t.Fatal("holder key must be first")
	}
	if keys[1].PublicKey.Equal(&holder.PublicKey) {
		t.Fatal("batch key must differ from holder key")
	}
}

func TestSelectPrimaryCredentialReversedOrder(t *testing.T) {
	holder := testKey(t)
	ephemeral := testKey(t)
	holderCred := fakeSDJWT(t, &holder.PublicKey)
	ephemeralCred := fakeSDJWT(t, &ephemeral.PublicKey)

	// Credentials returned in reverse order of the proofs
	resp := map[string]any{
		"credentials": []any{
			map[string]any{"credential": ephemeralCred},
			map[string]any{"credential": holderCred},
		},
	}
	got, err := selectPrimaryCredential(resp, []*ecdsa.PrivateKey{holder, ephemeral})
	if err != nil {
		t.Fatalf("selectPrimaryCredential: %v", err)
	}
	if got != holderCred {
		t.Fatal("expected the holder-key-bound credential to be selected")
	}
}

func TestSelectPrimaryCredentialUnknownKey(t *testing.T) {
	holder := testKey(t)
	stranger := testKey(t)
	resp := map[string]any{
		"credentials": []any{
			map[string]any{"credential": fakeSDJWT(t, &stranger.PublicKey)},
			map[string]any{"credential": fakeSDJWT(t, &holder.PublicKey)},
		},
	}
	_, err := selectPrimaryCredential(resp, []*ecdsa.PrivateKey{holder, testKey(t)})
	if err == nil {
		t.Fatal("expected error for credential bound to an unknown key")
	}
}

func TestSelectPrimaryCredentialSingle(t *testing.T) {
	holder := testKey(t)
	cred := fakeSDJWT(t, &holder.PublicKey)
	resp := map[string]any{"credentials": []any{map[string]any{"credential": cred}}}
	got, err := selectPrimaryCredential(resp, []*ecdsa.PrivateKey{holder})
	if err != nil {
		t.Fatalf("selectPrimaryCredential: %v", err)
	}
	if got != cred {
		t.Fatal("expected the single credential to be selected")
	}
}

// An issuer that advertises batch_credential_issuance makes the wallet send
// several proofs, but OpenID4VCI 1.0 lets it issue fewer credentials. A single
// credential is imported even when it is bound to a proof key other than the
// holder key, rather than being refused (its card then reads as bound to another
// key). The credential is bound to an ephemeral proof key here, which the old
// matching path refused, so this guards the leniency.
func TestSelectPrimaryCredentialSingleNotHolderBound(t *testing.T) {
	holder := testKey(t)
	ephemeral := testKey(t)
	cred := fakeSDJWT(t, &ephemeral.PublicKey)
	resp := map[string]any{"credentials": []any{map[string]any{"credential": cred}}}
	keys := []*ecdsa.PrivateKey{holder, ephemeral, testKey(t)}
	got, err := selectPrimaryCredential(resp, keys)
	if err != nil {
		t.Fatalf("a single credential should be imported even when it is not holder-bound: %v", err)
	}
	if got != cred {
		t.Fatal("expected the single credential to be imported")
	}
}

// A single credential the issuer bound to an ephemeral proof key (rather than
// the holder key) stays presentable: the wallet records that key against it, so
// its key binding is signed with the key its cnf names.
func TestSingleCredentialBoundToEphemeralKeyIsPresentable(t *testing.T) {
	w := generateTestWallet(t)
	ephemeral := testKey(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), ephemeral}
	cred := fakeSDJWT(t, &ephemeral.PublicKey)
	imported, err := w.ImportCredential(cred)
	if err != nil {
		t.Fatalf("importing: %v", err)
	}
	resp := map[string]any{"credentials": []any{map[string]any{"credential": cred}}}
	w.storeBatchSiblings(imported, resp, keys, nil)

	stored, ok := w.GetCredential(imported.ID)
	if !ok {
		t.Fatal("the imported credential is missing")
	}
	signer, err := w.batchSigningKey(stored)
	if err != nil {
		t.Fatalf("resolving the signing key: %v", err)
	}
	if !signer.PublicKey.Equal(&ephemeral.PublicKey) {
		t.Fatal("expected the credential to sign its key binding with the ephemeral proof key it is bound to")
	}
}

func TestMdocBindsToKey(t *testing.T) {
	holder := testKey(t)
	issuer := testKey(t)
	other := testKey(t)

	cred, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    map[string]any{"family_name": "Doe"},
		Key:       issuer,
		HolderKey: &holder.PublicKey,
	})
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}

	if !credentialBindsToKey(cred, &holder.PublicKey) {
		t.Fatal("mdoc should bind to its device key")
	}
	if credentialBindsToKey(cred, &other.PublicKey) {
		t.Fatal("mdoc must not bind to a different key")
	}
}

func TestFirstJWKSkipsUnusableKeys(t *testing.T) {
	usable := map[string]any{
		"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
		"kid": "usable", "x": "8Yrbbg", "y": "V2Ki0w",
	}
	jwks := map[string]any{
		"keys": []any{
			map[string]any{"kty": "AKP", "alg": "ML-KEM-9999", "kid": "unusable-pq-enc-key", "use": "enc", "pub": "cGxhY2Vob2xkZXI"},
			map[string]any{"kty": "OIDF-CONFORMANCE-UNSUPPORTED", "alg": "OIDF-CONFORMANCE-UNSUPPORTED", "kid": "unusable-unknown-enc-key", "use": "enc"},
			usable,
		},
	}
	got := firstJWK(jwks)
	if got == nil {
		t.Fatal("expected the usable key to be found")
	}
	if kid, _ := got["kid"].(string); kid != "usable" {
		t.Fatalf("expected kid 'usable', got %q", kid)
	}

	// Signing-only EC keys must be skipped too
	jwks = map[string]any{
		"keys": []any{
			map[string]any{"kty": "EC", "crv": "P-256", "use": "sig", "kid": "sig-key", "x": "8Yrbbg", "y": "V2Ki0w"},
		},
	}
	if got := firstJWK(jwks); got != nil {
		t.Fatalf("expected no usable key, got %v", got)
	}
}

// An issuer that advertises a batch may issue fewer credentials than the proofs
// sent and need not bind any of them to the holder key (each key binds to at
// most one Credential). Two credentials bound to ephemeral proof keys, none to
// the holder key, are accepted and the first is taken as the primary.
func TestSelectPrimaryCredentialFewerThanAdvertisedNoneHolderBound(t *testing.T) {
	holder := testKey(t)
	eph1, eph2 := testKey(t), testKey(t)
	first := fakeSDJWT(t, &eph1.PublicKey)
	second := fakeSDJWT(t, &eph2.PublicKey)
	resp := map[string]any{"credentials": []any{
		map[string]any{"credential": first},
		map[string]any{"credential": second},
	}}
	keys := []*ecdsa.PrivateKey{holder, eph1, eph2, testKey(t), testKey(t)}
	got, err := selectPrimaryCredential(resp, keys)
	if err != nil {
		t.Fatalf("a partial batch bound to ephemeral keys should be accepted: %v", err)
	}
	if got != first {
		t.Fatal("expected the first credential to be the primary when none is holder-bound")
	}
}

// The copies of a partial batch the issuer bound to ephemeral keys (none to the
// holder key) are stored under one batch group, each signing its key binding
// with the key its cnf names.
func TestPartialBatchNoneHolderBoundIsStoredAndPresentable(t *testing.T) {
	w := generateTestWallet(t)
	eph1, eph2 := testKey(t), testKey(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, eph1, eph2}
	resp := map[string]any{"credentials": []any{
		map[string]any{"credential": fakeSDJWT(t, &eph1.PublicKey)},
		map[string]any{"credential": fakeSDJWT(t, &eph2.PublicKey)},
	}}
	primaryRaw, err := selectPrimaryCredential(resp, keys)
	if err != nil {
		t.Fatalf("selectPrimaryCredential: %v", err)
	}
	imported, err := w.ImportCredential(primaryRaw)
	if err != nil {
		t.Fatalf("importing the primary: %v", err)
	}
	w.storeBatchSiblings(imported, resp, keys, nil)

	var batch []StoredCredential
	for _, c := range w.GetCredentials() {
		if c.BatchGroup != "" {
			batch = append(batch, c)
		}
	}
	if len(batch) != 2 {
		t.Fatalf("expected 2 copies stored as a batch, got %d", len(batch))
	}
	if batch[0].BatchGroup != batch[1].BatchGroup {
		t.Fatal("the two copies should share one batch group")
	}
	for _, c := range batch {
		signer, err := w.batchSigningKey(c)
		if err != nil {
			t.Fatalf("resolving the signing key: %v", err)
		}
		if !credentialBindsToKey(c.Raw, &signer.PublicKey) {
			t.Fatal("a batch copy must sign its key binding with the key its cnf names")
		}
	}
}
