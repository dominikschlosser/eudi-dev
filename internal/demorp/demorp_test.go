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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// presentTicket builds a full SD-JWT+KB presentation for the given request
// parameters, exactly as a wallet would.
func presentTicket(t *testing.T, d *DemoRP, holderKey *ecdsa.PrivateKey, clientID, nonce string) string {
	t.Helper()
	credential, err := d.signTicket(&holderKey.PublicKey)
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

	code, reqDoc := doJSON(t, h, "POST", "/api/requests", `{"type":"ticket"}`, map[string]string{"Content-Type": "application/json"})
	if code != http.StatusCreated {
		t.Fatalf("creating request: %d %v", code, reqDoc)
	}
	walletURL, err := url.Parse(reqDoc["wallet_url"].(string))
	if err != nil {
		t.Fatalf("parsing wallet_url: %v", err)
	}
	params := walletURL.Query()
	id := params.Get("state")
	nonce := params.Get("nonce")
	clientID := params.Get("client_id")
	if id == "" || nonce == "" || !strings.HasPrefix(clientID, "redirect_uri:") {
		t.Fatalf("unexpected authorization parameters: %v", params)
	}

	presentation := presentTicket(t, d, holderKey, clientID, nonce)
	vpToken, err := json.Marshal(map[string][]string{"ticket": {presentation}})
	if err != nil {
		t.Fatalf("building vp_token: %v", err)
	}
	form := url.Values{"vp_token": {string(vpToken)}, "state": {id}}
	code, respDoc := doJSON(t, h, "POST", "/response/"+id, form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if code != http.StatusOK {
		t.Fatalf("presentation response: %d %v", code, respDoc)
	}
	if redirect := respDoc["redirect_uri"].(string); !strings.Contains(redirect, "result="+id) {
		t.Errorf("redirect_uri = %q, want result reference", redirect)
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

	_, reqDoc := doJSON(t, h, "POST", "/api/requests", `{"type":"ticket"}`, map[string]string{"Content-Type": "application/json"})
	walletURL, _ := url.Parse(reqDoc["wallet_url"].(string))
	params := walletURL.Query()
	id := params.Get("state")

	presentation := presentTicket(t, d, holderKey, params.Get("client_id"), "wrong-nonce")
	vpToken, _ := json.Marshal(map[string][]string{"ticket": {presentation}})
	form := url.Values{"vp_token": {string(vpToken)}}
	doJSON(t, h, "POST", "/response/"+id, form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

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
		Claims:        ticketClaims(),
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
			_, reqDoc := doJSON(t, h, "POST", "/api/requests", `{"type":"ticket"}`, map[string]string{"Content-Type": "application/json"})
			walletURL, _ := url.Parse(reqDoc["wallet_url"].(string))
			params := walletURL.Query()
			id := params.Get("state")

			credential := signTicketWithStatus(t, d, holderKey, statusSrv.URL+"/statuslist", tc.idx)
			presentation := presentCredential(t, holderKey, credential, params.Get("client_id"), params.Get("nonce"))
			vpToken, _ := json.Marshal(map[string][]string{"ticket": {presentation}})
			form := url.Values{"vp_token": {string(vpToken)}}
			doJSON(t, h, "POST", "/response/"+id, form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

			_, status := doJSON(t, h, "GET", "/api/requests/"+id, "", nil)
			if status["status"] != tc.wantStatus {
				t.Fatalf("status = %v, want %v (checks: %v)", status["status"], tc.wantStatus, status["checks"])
			}
		})
	}
}

// startVerification creates a request and returns its id and parameters.
func startVerification(t *testing.T, h http.Handler, kind string) (string, url.Values) {
	t.Helper()
	_, doc := doJSON(t, h, "POST", "/api/requests", `{"type":"`+kind+`"}`, map[string]string{"Content-Type": "application/json"})
	walletURL, err := url.Parse(doc["wallet_url"].(string))
	if err != nil {
		t.Fatalf("parsing wallet_url: %v", err)
	}
	params := walletURL.Query()
	return params.Get("state"), params
}

func postPresentation(t *testing.T, h http.Handler, id, queryID, presentation string) int {
	t.Helper()
	vpToken, err := json.Marshal(map[string][]string{queryID: {presentation}})
	if err != nil {
		t.Fatalf("building vp_token: %v", err)
	}
	code, _ := doJSON(t, h, "POST", "/response/"+id, url.Values{"vp_token": {string(vpToken)}}.Encode(),
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

// TestVerifierRejectsInjectedDisclosure models a malicious holder: they own
// the key binding key, so they can append a disclosure and re-sign a matching
// sd_hash. Only the "every disclosure is referenced" rule catches it.
func TestVerifierRejectsInjectedDisclosure(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()

	id, params := startVerification(t, h, "ticket")

	credential, err := d.signTicket(&holderKey.PublicKey)
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
