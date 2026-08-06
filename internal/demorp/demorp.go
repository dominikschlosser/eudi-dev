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

// Package demorp provides a minimal demo issuer (OpenID4VCI) and demo
// verifier (OpenID4VP) that run against the wallet server they are mounted
// on. They exist so a wallet deployment (in particular the shared public
// demo) can demonstrate complete protocol flows out of the box: the issuer
// hands out credential offers redeemable by any OID4VCI wallet, and the
// verifier requests and cryptographically verifies presentations.
//
// Both are deliberately small: on the issuer side a pre-authorized code
// grant plus an authorization code grant served by the issuer itself as
// authorization server (one hardcoded demo account), plain-parameter
// authorization requests with direct_post on the verifier side, SD-JWT VC
// only. Credentials are signed with the wallet's
// issuer key under a leaf certificate issued by the wallet CA, so the
// wallet's own trust list covers them and verification closes the loop
// without extra trust setup.
package demorp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/jws"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

const (
	// entryTTL bounds how long offers, tokens, and verification requests
	// live. Everything is in-memory and demo-scoped.
	entryTTL = 10 * time.Minute
	// maxEntries caps each state map so anonymous visitors cannot grow
	// memory without bound between TTL sweeps.
	maxEntries = 500
	// maxBodyBytes caps request bodies on all POST endpoints.
	maxBodyBytes = 64 << 10
)

// DemoRP holds the shared state of the demo issuer and verifier.
type DemoRP struct {
	wallet  *wallet.Wallet
	baseURL func() string
	// onWalletChange persists the wallet after the issuer changed something in
	// it, which so far means reserving a status list index.
	onWalletChange func()

	mu       sync.Mutex
	offers   map[string]*offerState
	tokens   map[string]*offerState
	requests map[string]*requestState
	// Authorization code flow state: pushed authorization requests by
	// request_uri, and the codes issued from them once the user signed in.
	authRequests map[string]*authRequestState
	codes        map[string]*authRequestState
}

// New creates the demo issuer/verifier pair. baseURL returns the public
// origin of the wallet server (no trailing slash), e.g. https://eudi-test.dev
// or http://localhost:8085.
func New(w *wallet.Wallet, baseURL func() string) *DemoRP {
	return &DemoRP{
		wallet:       w,
		baseURL:      func() string { return strings.TrimRight(baseURL(), "/") },
		offers:       make(map[string]*offerState),
		tokens:       make(map[string]*offerState),
		requests:     make(map[string]*requestState),
		authRequests: make(map[string]*authRequestState),
		codes:        make(map[string]*authRequestState),
	}
}

// SetOnWalletChange registers the callback that persists the wallet after the
// demo issuer changed it. Call before serving.
func (d *DemoRP) SetOnWalletChange(fn func()) {
	d.onWalletChange = fn
}

func (d *DemoRP) saveWallet() {
	if d.onWalletChange != nil {
		d.onWalletChange()
	}
}

func randToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("reading random bytes: %v", err))
	}
	return hex.EncodeToString(b)
}

// pruneLocked removes expired entries. Callers hold d.mu.
func (d *DemoRP) pruneLocked() {
	now := time.Now()
	for id, o := range d.offers {
		if now.After(o.expires) {
			delete(d.offers, id)
		}
	}
	for tok, o := range d.tokens {
		if now.After(o.expires) {
			delete(d.tokens, tok)
		}
	}
	for id, r := range d.requests {
		if now.After(r.expires) {
			delete(d.requests, id)
		}
	}
	for uri, a := range d.authRequests {
		if now.After(a.expires) {
			delete(d.authRequests, uri)
		}
	}
	for code, a := range d.codes {
		if now.After(a.expires) || a.codeUsed {
			delete(d.codes, code)
		}
	}
}

// compactJWT is a decoded compact JWT with the raw parts needed for
// signature verification.
type compactJWT struct {
	header       map[string]any
	payload      map[string]any
	signature    []byte
	signingInput string
}

func parseCompactJWT(raw string) (*compactJWT, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWT")
	}
	decode := func(part string, target *map[string]any) error {
		data, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, target)
	}
	jwt := &compactJWT{signingInput: parts[0] + "." + parts[1]}
	if err := decode(parts[0], &jwt.header); err != nil {
		return nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	if err := decode(parts[1], &jwt.payload); err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT signature: %w", err)
	}
	jwt.signature = sig
	return jwt, nil
}

// verifyES256 checks a JOSE ES256 signature. The parsed form keeps the
// signing input and the decoded signature rather than the string they came
// from, so the compact form is put back together for the shared verifier.
func verifyES256(pub *ecdsa.PublicKey, signingInput string, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	return jws.Valid(signingInput+"."+base64.RawURLEncoding.EncodeToString(sig), pub)
}

// holderKeyFromJWK converts a JWK map (e.g. a proof header jwk or a cnf.jwk
// claim) into an ECDSA public key.
func holderKeyFromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	data, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	pub, err := keys.ParseJWK(data)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("only EC keys are supported")
	}
	return ecPub, nil
}

func writeJSON(w http.ResponseWriter, status int, doc any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(doc)
}
