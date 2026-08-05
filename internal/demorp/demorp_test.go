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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/statuslist"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

func newDemoRP(t *testing.T) (*DemoRP, *wallet.Wallet, *ecdsa.PrivateKey) {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	return New(w, func() string { return "http://demo.example" }), w, holderKey
}

func doJSON(t *testing.T, h http.Handler, method, target, body string, header map[string]string) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	doc := map[string]any{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s %s: parsing response %q: %v", method, target, rec.Body.String(), err)
		}
	}
	return rec.Code, doc
}

// signES256 creates a JOSE compact JWT signed with the given key.
func signES256(t *testing.T, key *ecdsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	encode := func(doc map[string]any) string {
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshaling: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signingInput := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func holderJWK(t *testing.T, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	jwk := map[string]any{}
	for k, v := range mock.PublicKeyJWKMap(&key.PublicKey) {
		jwk[k] = v
	}
	return jwk
}

func TestIssuerPreAuthFlow(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.IssuerHandler()

	code, offerDoc := doJSON(t, h, "POST", "/api/offers", "", nil)
	if code != http.StatusCreated {
		t.Fatalf("creating offer: %d %v", code, offerDoc)
	}
	offerURI := offerDoc["offer_uri"].(string)
	id := offerURI[strings.LastIndex(offerURI, "/")+1:]

	code, offer := doJSON(t, h, "GET", "/offer/"+id, "", nil)
	if code != http.StatusOK {
		t.Fatalf("fetching offer: %d %v", code, offer)
	}
	grants := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)
	preAuthCode := grants["pre-authorized_code"].(string)

	form := url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {preAuthCode}}
	code, tokenDoc := doJSON(t, h, "POST", "/token", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if code != http.StatusOK {
		t.Fatalf("token request: %d %v", code, tokenDoc)
	}
	accessToken := tokenDoc["access_token"].(string)
	cNonce := tokenDoc["c_nonce"].(string)

	proof := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holderJWK(t, holderKey)},
		map[string]any{"aud": "http://demo.example/issuer", "iat": time.Now().Unix(), "nonce": cNonce},
	)
	body := fmt.Sprintf(`{"credential_configuration_id":%q,"proofs":{"jwt":[%q]}}`, ticketConfigurationID, proof)
	code, credDoc := doJSON(t, h, "POST", "/credential", body, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Content-Type":  "application/json",
	})
	if code != http.StatusOK {
		t.Fatalf("credential request: %d %v", code, credDoc)
	}
	creds := credDoc["credentials"].([]any)
	raw := creds[0].(map[string]any)["credential"].(string)

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("parsing issued credential: %v", err)
	}
	if vct := token.ResolvedClaims["vct"]; vct != TicketVCT {
		t.Errorf("vct = %v, want %s", vct, TicketVCT)
	}
	if _, ok := token.Payload["cnf"].(map[string]any); !ok {
		t.Error("issued credential has no cnf claim")
	}
	if _, ok := token.Header["x5c"]; !ok {
		t.Error("issued credential has no x5c chain")
	}
}

func TestIssuerRejectsWrongNonce(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.IssuerHandler()

	_, offerDoc := doJSON(t, h, "POST", "/api/offers", "", nil)
	offerURI := offerDoc["offer_uri"].(string)
	id := offerURI[strings.LastIndex(offerURI, "/")+1:]
	_, offer := doJSON(t, h, "GET", "/offer/"+id, "", nil)
	grants := offer["grants"].(map[string]any)[preAuthGrant].(map[string]any)
	form := url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {grants["pre-authorized_code"].(string)}}
	_, tokenDoc := doJSON(t, h, "POST", "/token", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	proof := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holderJWK(t, holderKey)},
		map[string]any{"aud": "http://demo.example/issuer", "iat": time.Now().Unix(), "nonce": "wrong"},
	)
	body := fmt.Sprintf(`{"proofs":{"jwt":[%q]}}`, proof)
	code, doc := doJSON(t, h, "POST", "/credential", body, map[string]string{
		"Authorization": "Bearer " + tokenDoc["access_token"].(string),
		"Content-Type":  "application/json",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("credential request with wrong nonce: %d %v, want 400", code, doc)
	}
}

// newIssuanceWallet builds a wallet that enforces HAIP on issuance.
func newIssuanceWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	w.RequireHAIP = true
	return w
}

func jsonString(v string) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// presentTicket builds a full SD-JWT+KB presentation for the given request
// parameters, exactly as a wallet would.
func presentTicket(t *testing.T, d *DemoRP, holderKey *ecdsa.PrivateKey, clientID, nonce string) string {
	t.Helper()
	credential, err := d.signTicket(&holderKey.PublicKey, "", false)
	if err != nil {
		t.Fatalf("signing ticket: %v", err)
	}
	return presentCredential(t, holderKey, credential, clientID, nonce)
}

// presentCredential builds an SD-JWT+KB presentation of the given credential.
func presentCredential(t *testing.T, holderKey *ecdsa.PrivateKey, credential, clientID, nonce string) string {
	t.Helper()
	// Present with all disclosures: credential already ends with ~.
	prefix := credential
	if !strings.HasSuffix(prefix, "~") {
		prefix += "~"
	}
	digest := sha256.Sum256([]byte(prefix))
	kb := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "kb+jwt"},
		map[string]any{
			"iat":     time.Now().Unix(),
			"aud":     clientID,
			"nonce":   nonce,
			"sd_hash": base64.RawURLEncoding.EncodeToString(digest[:]),
		},
	)
	return prefix + kb
}

func TestVerifierFlow(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")
	nonce := params.Get("nonce")
	clientID := params.Get("client_id")
	if id == "" || nonce == "" || !strings.HasPrefix(clientID, "x509_hash:") {
		t.Fatalf("unexpected authorization parameters: %v", params)
	}
	if got := params.Get("response_mode"); got != "direct_post.jwt" {
		t.Errorf("response_mode = %q, want direct_post.jwt", got)
	}

	presentation := presentTicket(t, d, holderKey, clientID, nonce)
	if code := postPresentation(t, h, id, "ticket", presentation); code != http.StatusOK {
		t.Fatalf("presentation response = %d, want 200", code)
	}

	code, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if code != http.StatusOK || status["status"] != "verified" {
		t.Fatalf("request status = %d %v, want verified", code, status)
	}
	claims := status["claims"].(map[string]any)
	if claims["event"] != "EUDI Interop Fest" {
		t.Errorf("verified claims = %v, want the ticket event", claims)
	}
}

func TestVerifierRejectsWrongNonce(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")

	presentation := presentTicket(t, d, holderKey, params.Get("client_id"), "wrong-nonce")
	postPresentation(t, h, id, "ticket", presentation)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "failed" {
		t.Fatalf("status = %v, want failed on nonce mismatch", status["status"])
	}
}

// serveStatusList starts a status list endpoint where index 0 is valid and
// index 1 is revoked, signed by the wallet's issuer key under its CA chain.
func serveStatusList(t *testing.T, d *DemoRP, w *wallet.Wallet) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(nil)
	chain, err := w.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/statuslist", func(rw http.ResponseWriter, r *http.Request) {
		jwt, err := statuslist.GenerateStatusListJWT([]byte{0b00000010}, w.IssuerKey, statuslist.StatusListConfig{
			URI:       srv.URL + "/statuslist",
			Issuer:    srv.URL,
			CertChain: chain,
		})
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		rw.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = rw.Write([]byte(jwt))
	})
	srv.Config.Handler = mux
	return srv
}

// signTicketWithStatus mints a ticket carrying a status list reference.
func signTicketWithStatus(t *testing.T, d *DemoRP, holderKey *ecdsa.PrivateKey, uri string, idx int) string {
	t.Helper()
	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:        d.issuerID(),
		VCT:           TicketVCT,
		ExpiresIn:     24 * time.Hour,
		Claims:        ticketClaims(""),
		Key:           d.wallet.IssuerKey,
		HolderKey:     &holderKey.PublicKey,
		CertChain:     chain,
		StatusListURI: uri,
		StatusListIdx: idx,
	})
	if err != nil {
		t.Fatalf("signing ticket: %v", err)
	}
	return raw
}

// TestVerifierRejectsRevokedCredential guards the gap that made the demo
// verifier report all checks green for a credential the wallet had revoked:
// it verified signatures but never resolved the status list.
func TestVerifierRejectsRevokedCredential(t *testing.T) {
	d, w, holderKey := newDemoRP(t)
	statusSrv := serveStatusList(t, d, w)
	defer statusSrv.Close()
	h := d.VerifierHandler()

	for _, tc := range []struct {
		name       string
		idx        int
		wantStatus string
	}{
		{"valid entry", 0, "verified"},
		{"revoked entry", 1, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, params := startVerification(t, h, "ticket")

			credential := signTicketWithStatus(t, d, holderKey, statusSrv.URL+"/statuslist", tc.idx)
			presentation := presentCredential(t, holderKey, credential, params.Get("client_id"), params.Get("nonce"))
			postPresentation(t, h, id, "ticket", presentation)

			_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
			if status["status"] != tc.wantStatus {
				t.Fatalf("status = %v, want %v (checks: %v)", status["status"], tc.wantStatus, status["checks"])
			}
		})
	}
}

// startVerification creates a request and returns its id and parameters.
// startVerification creates a request and returns its id plus the parameters
// of the signed request object. The demo verifier is HAIP-compliant, so the
// authorization parameters live inside the JAR served from request_uri rather
// than in the URL: the tests have to fetch and parse it exactly as the wallet
// does.
func startVerification(t *testing.T, h http.Handler, kind string) (string, url.Values) {
	t.Helper()
	_, doc := doJSON(t, h, "POST", "/api/requests", `{"type":"`+kind+`"}`, map[string]string{"Content-Type": "application/json"})
	walletURL, err := url.Parse(doc["wallet_url"].(string))
	if err != nil {
		t.Fatalf("parsing wallet_url: %v", err)
	}
	requestURI := walletURL.Query().Get("request_uri")
	if requestURI == "" {
		t.Fatalf("expected a request_uri in %s", walletURL)
	}
	payload := fetchRequestObject(t, h, requestURI)

	params := url.Values{}
	for _, name := range []string{"client_id", "response_type", "response_mode", "response_uri", "nonce", "state"} {
		if v, ok := payload[name].(string); ok {
			params.Set(name, v)
		}
	}
	return params.Get("state"), params
}

// fetchRequestObject GETs the JAR and returns its (unverified) payload.
func fetchRequestObject(t *testing.T, h http.Handler, requestURI string) map[string]any {
	t.Helper()
	parsed, err := url.Parse(requestURI)
	if err != nil {
		t.Fatalf("parsing request_uri: %v", err)
	}
	// The handler is mounted with the /verifier prefix stripped.
	path := strings.TrimPrefix(parsed.Path, "/verifier")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/oauth-authz-req+jwt" {
		t.Errorf("request object Content-Type = %q", ct)
	}
	parts := strings.Split(strings.TrimSpace(rec.Body.String()), ".")
	if len(parts) != 3 {
		t.Fatalf("request object is not a compact JWS: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding request object payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("parsing request object payload: %v", err)
	}
	return payload
}

// responseEncryptionKey pulls the verifier's public encryption key out of the
// request object's client_metadata.
func responseEncryptionKey(t *testing.T, payload map[string]any) (*ecdsa.PublicKey, string) {
	t.Helper()
	meta, ok := payload["client_metadata"].(map[string]any)
	if !ok {
		t.Fatal("request object has no client_metadata")
	}
	jwks, ok := meta["jwks"].(map[string]any)
	if !ok {
		t.Fatal("client_metadata has no jwks")
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("client_metadata jwks has no keys")
	}
	jwk, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatal("jwks key is not an object")
	}
	if alg, _ := jwk["alg"].(string); alg != "ECDH-ES" {
		t.Errorf("jwk alg = %q, want ECDH-ES (the wallet rejects a JWK without it)", alg)
	}
	xb, err := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
	if err != nil {
		t.Fatalf("decoding jwk x: %v", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(jwk["y"].(string))
	if err != nil {
		t.Fatalf("decoding jwk y: %v", err)
	}
	kid, _ := jwk["kid"].(string)
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, kid
}

// postPresentation submits a presentation the way a HAIP wallet does: the
// response is a JWE encrypted to the verifier's per-request key.
func postPresentation(t *testing.T, h http.Handler, id, queryID, presentation string) int {
	t.Helper()
	return postPresentationTo(t, h, id, id, queryID, presentation)
}

// postPresentationTo allows the state inside the encrypted payload to differ
// from the request being posted to, which is what proves the binding.
func postPresentationTo(t *testing.T, h http.Handler, requestID, state, queryID, presentation string) int {
	t.Helper()
	payload := fetchRequestObject(t, h, "/request/"+requestID)
	pub, kid := responseEncryptionKey(t, payload)

	body, err := json.Marshal(map[string]any{
		"vp_token": map[string][]string{queryID: {presentation}},
		"state":    state,
	})
	if err != nil {
		t.Fatalf("building response payload: %v", err)
	}
	jwe, _, err := wallet.EncryptJWE(body, pub, kid, "ECDH-ES", "A128GCM", nil, nil)
	if err != nil {
		t.Fatalf("encrypting response: %v", err)
	}

	code, _ := doJSON(t, h, "POST", "/response/"+requestID, url.Values{"response": {jwe}}.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	return code
}

// TestVerifierRejectsWrongCredentialType: the wallet decides what to send, so
// the verifier has to enforce the type it asked for. A PID answering a ticket
// request must not verify.
func TestVerifierRejectsWrongCredentialType(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")

	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	pid, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    d.issuerID(),
		VCT:       PIDVCT, // not the requested ticket type
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika", "family_name": "Mustermann"},
		Key:       d.wallet.IssuerKey,
		HolderKey: &holderKey.PublicKey,
		CertChain: chain,
	})
	if err != nil {
		t.Fatalf("signing pid: %v", err)
	}

	presentation := presentCredential(t, holderKey, pid, params.Get("client_id"), params.Get("nonce"))
	postPresentation(t, h, id, "ticket", presentation)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "failed" {
		t.Fatalf("status = %v, want failed for a mismatched vct (checks: %v)", status["status"], status["checks"])
	}
}

// TestVerifierRejectsReplay: the nonce is fixed per request, so a captured
// response would verify again unless the request is single use.
func TestVerifierRejectsReplay(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")
	presentation := presentTicket(t, d, holderKey, params.Get("client_id"), params.Get("nonce"))

	if code := postPresentation(t, h, id, "ticket", presentation); code != http.StatusOK {
		t.Fatalf("first response = %d, want 200", code)
	}
	if code := postPresentation(t, h, id, "ticket", presentation); code != http.StatusConflict {
		t.Fatalf("replayed response = %d, want 409", code)
	}

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "verified" {
		t.Fatalf("replay must not change the original result, got %v", status["status"])
	}
}

// An unanswered request must stop reporting "pending" once it expires: the
// verifier page polls while pending, so a request that never expires makes an
// abandoned tab poll forever.
func TestVerifierRequestExpires(t *testing.T) {
	d, _, _ := newDemoRP(t)
	h := d.VerifierHandler()

	id, _ := startVerification(t, h, "ticket")

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "pending" {
		t.Fatalf("fresh request status = %v, want pending", status["status"])
	}

	d.mu.Lock()
	d.requests[id].expires = time.Now().Add(-time.Second)
	d.mu.Unlock()

	code, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if code != http.StatusOK || status["status"] != "expired" {
		t.Fatalf("expired request status = %d %v, want 200 expired", code, status["status"])
	}
}

// A result that already exists must survive past the expiry window: the
// wallet redirects the browser back to the page, and that page must still be
// able to show what happened.
func TestVerifierKeepsResultOfAnsweredRequest(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")
	presentation := presentTicket(t, d, holderKey, params.Get("client_id"), params.Get("nonce"))
	if code := postPresentation(t, h, id, "ticket", presentation); code != http.StatusOK {
		t.Fatalf("presentation response = %d, want 200", code)
	}

	d.mu.Lock()
	d.requests[id].expires = time.Now().Add(-time.Second)
	d.mu.Unlock()

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want the verified result to survive expiry", status["status"])
	}
}

// TestVerifierRejectsInjectedDisclosure models a malicious holder: they own
// the key binding key, so they can append a disclosure and re-sign a matching
// sd_hash. Only the "every disclosure is referenced" rule catches it.
func TestVerifierRejectsInjectedDisclosure(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")

	credential, err := d.signTicket(&holderKey.PublicKey, "", false)
	if err != nil {
		t.Fatalf("signing ticket: %v", err)
	}

	// A well-formed disclosure the issuer never created.
	forged, err := json.Marshal([]any{"injectedsalt", "tier", "vip-forged"})
	if err != nil {
		t.Fatalf("building disclosure: %v", err)
	}
	tampered := credential + base64.RawURLEncoding.EncodeToString(forged) + "~"

	// Re-sign the key binding over the tampered presentation, so sd_hash,
	// nonce and audience all still check out.
	digest := sha256.Sum256([]byte(tampered))
	kb := signES256(t, holderKey,
		map[string]any{"alg": "ES256", "typ": "kb+jwt"},
		map[string]any{
			"iat":     time.Now().Unix(),
			"aud":     params.Get("client_id"),
			"nonce":   params.Get("nonce"),
			"sd_hash": base64.RawURLEncoding.EncodeToString(digest[:]),
		},
	)
	postPresentation(t, h, id, "ticket", tampered+kb)

	_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
	if status["status"] != "failed" {
		t.Fatalf("status = %v, want failed for an injected disclosure (checks: %v)", status["status"], status["checks"])
	}
	checks := status["checks"].([]any)
	last := checks[len(checks)-1].(map[string]any)
	if last["ok"] != false || !strings.Contains(last["name"].(string), "referenced") {
		t.Fatalf("expected the disclosure reference check to fail, got %v", last)
	}
}

// serveDemoStack runs the wallet and the demo verifier on one origin, the way
// `wallet serve` mounts them, so a request can be driven end to end over real
// HTTP.
func serveDemoStack(t *testing.T, w *wallet.Wallet) (*DemoRP, *httptest.Server) {
	t.Helper()
	srv := wallet.NewServer(w, 0, nil)

	var base string
	d := New(w, func() string { return base })

	mux := http.NewServeMux()
	mux.Handle("/verifier/", http.StripPrefix("/verifier", d.VerifierHandler()))
	mux.Handle("/issuer/", http.StripPrefix("/issuer", d.IssuerHandler()))
	// The well-known segment comes before the issuer path, so both metadata
	// documents live at the server root.
	mux.HandleFunc("GET /.well-known/openid-credential-issuer/issuer", d.IssuerMetadataHandler())
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/issuer", d.AuthorizationServerMetadataHandler())
	mux.Handle("/", srv.Handler())

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	base = ts.URL
	w.BaseURL = ts.URL
	// The authorization code flow needs a client identity and a redirect
	// target on this origin, which is what demo mode configures.
	if w.VCIRedirectURI == "" {
		w.VCIRedirectURI = ts.URL + "/callback"
	}
	if w.VCIClientID == "" {
		w.VCIClientID = ts.URL
	}
	return d, ts
}

// The point of the exercise: the built-in demo verifier must satisfy HAIP, so
// that enforcing it on the public demo does not break the demo itself. This
// drives a real request through a wallet with RequireHAIP on. Signed request
// object fetched over request_uri, x509_hash client id, encrypted response —
// and expects a verified presentation at the end.
func TestVerifierIsHAIPCompliantEndToEnd(t *testing.T) {
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	w.RequireHAIP = true
	w.ValidationMode = wallet.ValidationModeStrict
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}

	_, ts := serveDemoStack(t, w)

	created := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"pid"}`)
	id, _ := created["id"].(string)
	walletURL, _ := created["wallet_url"].(string)
	if id == "" || walletURL == "" {
		t.Fatalf("unexpected create response: %v", created)
	}

	resp, err := ts.Client().Get(walletURL)
	if err != nil {
		t.Fatalf("driving the authorization request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode < 300 {
		t.Fatalf("authorize returned %d: %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "HAIP 1.0 compliance check failed") {
		t.Fatalf("the demo verifier is not HAIP-compliant: %s", body)
	}

	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error: %v, checks: %v)", status["status"], status["error"], status["checks"])
	}
	claims, _ := status["claims"].(map[string]any)
	if claims["family_name"] != "MUSTERMANN" {
		t.Errorf("verified claims = %v, want the PID holder", claims)
	}
}

// The same wallet must still reject a verifier that ignores the profile,
// which is what makes enforcement worth anything.
func TestHAIPEnforcementRejectsPlainRequest(t *testing.T) {
	holderKey, _ := mock.GenerateKey()
	issuerKey, _ := mock.GenerateKey()
	w := wallet.New(holderKey, issuerKey, true)
	w.RequireHAIP = true
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}
	_, ts := serveDemoStack(t, w)

	// A plain direct_post request with a redirect_uri client id: exactly what
	// the demo verifier used to send.
	params := url.Values{
		"client_id":     {"redirect_uri:" + ts.URL + "/nowhere"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {ts.URL + "/nowhere"},
		"nonce":         {"n-0S6_WzA2Mj"},
		"dcql_query":    {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["` + PIDVCT + `"]},"claims":[{"path":["given_name"]}]}]}`},
	}
	resp, err := ts.Client().Get(ts.URL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("driving the plain request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain request returned %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "HAIP") {
		t.Errorf("expected a HAIP violation, got: %s", body)
	}
}

func postJSONTo(t *testing.T, target, body string) map[string]any {
	t.Helper()
	resp, err := http.Post(target, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	doc := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("POST %s: decoding response: %v", target, err)
	}
	return doc
}

func getJSONFrom(t *testing.T, target string) map[string]any {
	t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	doc := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("GET %s: decoding response: %v", target, err)
	}
	return doc
}

// A pre-authorized code offer is conformant: HAIP 1.0 §4 requires an issuer
// to support the authorization code flow, not to use it for everything, and
// scopes pushed authorization requests to the authorization endpoint. So the
// wallet accepts one even with enforcement on, and only the transport rule
// applies to it.
func TestIssuanceHAIPAcceptsPreAuthorizedOffer(t *testing.T) {
	legacy := httptest.NewServer(legacyIssuerHandler(t))
	t.Cleanup(legacy.Close)

	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	offerURI := "openid-credential-offer://?credential_offer=" +
		url.QueryEscape(`{"credential_issuer":"`+legacy.URL+`","credential_configuration_ids":["legacy"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc"}}}`)

	result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(offerURI)+`}`)
	errText, _ := result["error"].(string)
	// It fails at the issuer's own token endpoint, not on the profile.
	if strings.Contains(errText, "HAIP") {
		t.Errorf("a pre-authorized code offer must not be rejected by HAIP enforcement, got %q", errText)
	}
}

// The demo issuer is its own authorization server, so the whole HAIP
// authorization code flow has to work against it: pushed authorization
// request with a wallet attestation and DPoP, a login the user completes
// while the wallet waits, PKCE, code exchange, DPoP-bound credential request.
//
// The point of the test is the ordering. The offer is created with nobody
// signed in. Authentication happens during redemption, at the authorization
// endpoint, which is where the authorization code flow puts it.
func TestIssuerAuthorizationCodeFlowEndToEnd(t *testing.T) {
	w := newIssuanceWallet(t)
	w.RequireHAIP = true
	w.ValidationMode = wallet.ValidationModeStrict
	_, ts := serveDemoStack(t, w)

	created := postJSONTo(t, ts.URL+"/issuer/api/offers?grant=authorization_code", "")
	schemeURI, _ := created["scheme_uri"].(string)
	if schemeURI == "" {
		t.Fatalf("unexpected offer response: %v", created)
	}

	// The wallet never opens a browser itself, so redeeming the offer answers
	// with the URL the user has to sign in at and leaves the flow running.
	accepted := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
	if accepted["status"] != "authorization_required" {
		t.Fatalf("redeeming the offer did not ask for a sign-in: %v", accepted)
	}
	authURL, _ := accepted["authorization_url"].(string)
	offerID, _ := accepted["offer_id"].(string)
	if !strings.Contains(authURL, "/issuer/authorize") || !strings.Contains(authURL, "request_uri=") {
		t.Fatalf("unexpected authorization URL %q", authURL)
	}
	if offerID == "" {
		t.Fatal("the wallet gave no offer id to follow the flow at")
	}

	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	page, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("opening the authorization URL: %v", err)
	}
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in") {
		t.Fatalf("the authorization endpoint did not ask for a login: %d %s", page.StatusCode, truncate(string(body)))
	}
	requestURI := requestURIFromLoginPage(t, string(body))

	login, err := client.PostForm(ts.URL+"/issuer/authorize", url.Values{
		"request_uri": {requestURI},
		"username":    {"alice"},
		"password":    {"alice"},
	})
	if err != nil {
		t.Fatalf("signing in: %v", err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusFound {
		t.Fatalf("login returned %d, want a redirect back to the wallet", login.StatusCode)
	}
	callback := login.Header.Get("Location")
	if !strings.Contains(callback, "code=") {
		t.Fatalf("login redirect %q carries no authorization code", callback)
	}
	// The browser follows the redirect. That is what resumes the flow.
	cb, err := client.Get(callback)
	if err != nil {
		t.Fatalf("following the callback: %v", err)
	}
	cb.Body.Close()

	deadline := time.Now().Add(20 * time.Second)
	for {
		status := getJSONFrom(t, ts.URL+"/api/offers/"+offerID)
		state, _ := status["status"].(string)
		if state == "completed" {
			break
		}
		if state == "failed" {
			t.Fatalf("the authorization code flow failed: %v", status["error"])
		}
		if time.Now().After(deadline) {
			t.Fatalf("the issuance never completed after the login, last status %v", status)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The ticket carries the authenticated account, which is only knowable
	// if the login actually drove the flow.
	var ticket *wallet.StoredCredential
	for _, c := range w.GetCredentials() {
		if c.VCT == TicketVCT {
			credential := c
			ticket = &credential
		}
	}
	if ticket == nil {
		t.Fatal("no demo ticket was stored in the wallet")
	}
	if got := ticket.Claims["given_name"]; got != demoAccountGivenName {
		t.Errorf("ticket given_name = %v, want %q from the logged-in account", got, demoAccountGivenName)
	}
}

// requestURIFromLoginPage reads the hidden field that ties the login form back
// to the pushed authorization request.
func requestURIFromLoginPage(t *testing.T, page string) string {
	t.Helper()
	const marker = `name="request_uri" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("login page carries no request_uri field: %s", truncate(page))
	}
	rest := page[i+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("malformed request_uri field: %s", truncate(rest))
	}
	return rest[:end]
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// Without a wallet attestation the authorization server must refuse the
// pushed authorization request: that is the client authentication HAIP
// requires, and the demo issuer is the worked example of checking it.
func TestPushedAuthorizationRequestRequiresWalletAttestation(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {ts.URL},
		"redirect_uri":          {ts.URL + "/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	clientKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	// A valid DPoP proof, so what is left missing is the wallet attestation.
	dpop := signES256(t, clientKey,
		map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": holderJWK(t, clientKey)},
		map[string]any{"htm": "POST", "htu": ts.URL + "/issuer/par", "iat": time.Now().Unix(), "jti": "par-1"},
	)
	req, err := http.NewRequest("POST", ts.URL+"/issuer/par", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpop)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("pushing the authorization request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		t.Fatalf("PAR without client authentication was accepted: %s", body)
	}
	if !strings.Contains(string(body), "attestation") {
		t.Errorf("expected the error to name the missing attestation, got %s", body)
	}
}

// legacyIssuerHandler serves just enough metadata for the offer to be parsed.
func legacyIssuerHandler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"credential_issuer":                   "http://" + r.Host,
			"credential_endpoint":                 "http://" + r.Host + "/credential",
			"token_endpoint":                      "http://" + r.Host + "/token",
			"credential_configurations_supported": map[string]any{"legacy": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:legacy"}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
	})
	return mux
}

// An offer carrying a profile override runs on a per-request clone of the
// wallet. The credential it collects still has to land in the real wallet:
// the clone holds its own credential slice, so without forwarding, issuance
// would report success and store nothing.
func TestIssuanceWithOverrideStillStoresTheCredential(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	before := len(w.GetCredentials())
	created := postJSONTo(t, ts.URL+"/issuer/api/offers", "")
	schemeURI, _ := created["scheme_uri"].(string)

	// haip:true is what the server already does, so the only difference here
	// is that the request is served by a clone.
	result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`,"haip":true}`)
	if result["error"] != nil {
		t.Fatalf("accepting the offer failed: %v", result["error"])
	}

	after := w.GetCredentials()
	if len(after) != before+1 {
		t.Fatalf("wallet holds %d credentials, want %d: the clone's import was lost", len(after), before+1)
	}
	var found bool
	for _, c := range after {
		if c.VCT == TicketVCT {
			found = true
		}
	}
	if !found {
		t.Error("the issued ticket is not in the wallet")
	}
}

// A ticket offered without the status toggle carries no status reference at
// all, which is what makes the toggle worth having.
func TestIssuerOffersTicketWithoutStatusByDefault(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	ticket := redeemDemoTicket(t, w, ts, "")
	if _, ok := ticket.Claims["status"]; ok {
		t.Errorf("ticket carries a status claim without the toggle: %v", ticket.Claims["status"])
	}
	if _, managed := w.StatusEntryFor(ticket.ID); managed {
		t.Error("the wallet registered a status entry for a ticket without one")
	}
}

// TestIssuerOffersRevocableTicket is the whole point of the status toggle: a
// ticket issued with a status reference lands in the wallet as a credential
// the wallet governs, verifies at the demo verifier, and stops verifying once
// it is revoked there.
func TestIssuerOffersRevocableTicket(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	ticket := redeemDemoTicket(t, w, ts, "?status=true")
	ref := wallet.CredentialStatusRef(*ticket)
	if ref == nil {
		t.Fatalf("ticket carries no status reference: %v", ticket.Claims)
	}
	if ref.URI != w.StatusListURL() {
		t.Errorf("status uri = %q, want the wallet's own list %q", ref.URI, w.StatusListURL())
	}
	// Without an entry of its own the wallet could never flip the bit, and the
	// Revoke button would not even appear.
	entry, managed := w.StatusEntryFor(ticket.ID)
	if !managed {
		t.Fatal("the wallet did not adopt the status entry of the ticket it issued to itself")
	}
	if entry.Index != ref.Idx {
		t.Errorf("adopted index = %d, want the one in the credential %d", entry.Index, ref.Idx)
	}

	if got := presentDemoTicket(t, ts); got["status"] != "verified" {
		t.Fatalf("a fresh ticket did not verify: %v (checks: %v)", got, got["checks"])
	}

	if _, ok := w.SetCredentialStatus(ticket.ID, 1); !ok {
		t.Fatal("revoking the ticket failed")
	}
	result := presentDemoTicket(t, ts)
	if result["status"] != "failed" {
		t.Fatalf("a revoked ticket still verified: %v (checks: %v)", result, result["checks"])
	}
	if !strings.Contains(fmt.Sprint(result["error"]), "revoked") {
		t.Errorf("verification failed for the wrong reason: %v", result["error"])
	}
}

// Two tickets issued with a status reference must land on different indices,
// or revoking one would revoke the other.
func TestIssuerReservesOneStatusIndexPerTicket(t *testing.T) {
	w := newIssuanceWallet(t)
	_, ts := serveDemoStack(t, w)

	first := wallet.CredentialStatusRef(*redeemDemoTicket(t, w, ts, "?status=true"))
	second := wallet.CredentialStatusRef(*redeemDemoTicket(t, w, ts, "?status=true"))
	if first == nil || second == nil {
		t.Fatalf("a ticket carries no status reference: %v %v", first, second)
	}
	if first.Idx == second.Idx {
		t.Errorf("both tickets sit on status index %d", first.Idx)
	}
}

// A wallet with no status list URL cannot mint a status reference, so the
// offer is refused rather than silently handing out a ticket without one.
func TestIssuerRefusesStatusOfferWithoutAStatusList(t *testing.T) {
	d, _, _ := newDemoRP(t)
	code, doc := doJSON(t, d.IssuerHandler(), "POST", "/api/offers?status=true", "", nil)
	if code != http.StatusConflict {
		t.Fatalf("creating the offer = %d %v, want 409", code, doc)
	}
}

// Reserving an index changes wallet state that every wallet API request
// reloads from disk, so it has to be persisted right away.
func TestIssuerPersistsTheReservedStatusIndex(t *testing.T) {
	d, w, holderKey := newDemoRP(t)
	w.BaseURL = "http://demo.example"
	saves := 0
	d.SetOnWalletChange(func() { saves++ })

	if _, err := d.signTicket(&holderKey.PublicKey, "", false); err != nil {
		t.Fatalf("signing a ticket without a status reference: %v", err)
	}
	if saves != 0 {
		t.Errorf("a ticket without a status reference saved the wallet %d times", saves)
	}
	if _, err := d.signTicket(&holderKey.PublicKey, "", true); err != nil {
		t.Fatalf("signing a ticket with a status reference: %v", err)
	}
	if saves != 1 {
		t.Errorf("the wallet was saved %d times after reserving an index, want 1", saves)
	}
}

// The authorization code flow mints a second state for the same offer, so the
// choice made when the offer was created has to survive the sign-in.
func TestAuthorizationCodeOfferKeepsTheStatusChoice(t *testing.T) {
	d, w, _ := newDemoRP(t)
	w.BaseURL = "http://demo.example"
	h := d.IssuerHandler()

	code, doc := doJSON(t, h, "POST", "/api/offers?grant=authorization_code&status=true", "", nil)
	if code != http.StatusCreated {
		t.Fatalf("creating the offer: %d %v", code, doc)
	}
	offerURI := doc["offer_uri"].(string)
	_, offer := doJSON(t, h, "GET", "/offer/"+offerURI[strings.LastIndex(offerURI, "/")+1:], "", nil)
	grants := offer["grants"].(map[string]any)[authCodeGrant].(map[string]any)
	issuerState := grants["issuer_state"].(string)

	if !d.offerWantsStatus(issuerState) {
		t.Error("the status choice was lost between the offer and its issuer_state")
	}
	if d.offerWantsStatus("some-other-state") {
		t.Error("an unknown issuer_state must not inherit a status choice")
	}
}

// redeemDemoTicket creates a demo issuer offer with the given query string,
// redeems it through the wallet, and returns the stored ticket.
func redeemDemoTicket(t *testing.T, w *wallet.Wallet, ts *httptest.Server, query string) *wallet.StoredCredential {
	t.Helper()
	created := postJSONTo(t, ts.URL+"/issuer/api/offers"+query, "")
	schemeURI, _ := created["scheme_uri"].(string)
	if schemeURI == "" {
		t.Fatalf("unexpected offer response: %v", created)
	}
	known := make(map[string]bool)
	for _, c := range w.GetCredentials() {
		known[c.ID] = true
	}

	result := postJSONTo(t, ts.URL+"/api/offers", `{"uri":`+jsonString(schemeURI)+`}`)
	if result["error"] != nil {
		t.Fatalf("accepting the offer failed: %v", result["error"])
	}
	for _, c := range w.GetCredentials() {
		if c.VCT == TicketVCT && !known[c.ID] {
			ticket := c
			return &ticket
		}
	}
	t.Fatal("the issued ticket is not in the wallet")
	return nil
}

// presentDemoTicket drives one demo verifier ticket request through the
// wallet and returns the verification result.
func presentDemoTicket(t *testing.T, ts *httptest.Server) map[string]any {
	t.Helper()
	created := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"ticket"}`)
	id, _ := created["id"].(string)
	walletURL, _ := created["wallet_url"].(string)
	if id == "" || walletURL == "" {
		t.Fatalf("unexpected create response: %v", created)
	}
	resp, err := ts.Client().Get(walletURL)
	if err != nil {
		t.Fatalf("driving the authorization request: %v", err)
	}
	resp.Body.Close()
	return getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
}
