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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

// customTestWallet is a demo wallet holding the default PID, with neither HAIP
// nor strict validation, so both signed and unsigned custom requests present.
func customTestWallet(t *testing.T) *wallet.Wallet {
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
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}
	return w
}

// driveWallet plays the wallet's side of a request by fetching the wallet URL,
// which the demo wallet answers by presenting.
func driveWallet(t *testing.T, ts *httptest.Server, walletURL string) {
	t.Helper()
	resp, err := ts.Client().Get(walletURL)
	if err != nil {
		t.Fatalf("driving the authorization request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("authorize returned %d: %s", resp.StatusCode, body)
	}
}

// customNationalities reads the nationalities the verifier saw under the first
// custom credential query.
func customNationalities(t *testing.T, status map[string]any) []any {
	t.Helper()
	claims, ok := status["claims"].(map[string]any)
	if !ok {
		t.Fatalf("no claims in status: %v", status)
	}
	cred, ok := claims["cred_0"].(map[string]any)
	if !ok {
		t.Fatalf("no cred_0 in claims: %v", claims)
	}
	nats, ok := cred["nationalities"].([]any)
	if !ok {
		t.Fatalf("nationalities is not an array: %v", cred["nationalities"])
	}
	return nats
}

func createCustom(t *testing.T, ts *httptest.Server, body string) string {
	t.Helper()
	created := postJSONTo(t, ts.URL+"/verifier/api/requests", body)
	id, _ := created["id"].(string)
	walletURL, _ := created["wallet_url"].(string)
	if id == "" || walletURL == "" {
		t.Fatalf("unexpected create response: %v", created)
	}
	driveWallet(t, ts, walletURL)
	return id
}

// A custom request whose path names an array of selectively disclosable
// elements but neither null nor an index discloses the array with no elements
// (OpenID4VP 1.0 §7.1). The wallet discloses correctly, so the verifier sees
// an empty array.
func TestVerifierCustomRequestBareArrayDisclosesEmpty(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	id := createCustom(t, ts, `{"type":"custom","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["nationalities"]]}]}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	if nats := customNationalities(t, status); len(nats) != 0 {
		t.Errorf("disclosed nationalities = %v, want an empty array", nats)
	}
}

// Ending the path with null selects every element, so the same request built
// with a null path discloses the elements.
func TestVerifierCustomRequestNullArrayDisclosesElements(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	id := createCustom(t, ts, `{"type":"custom","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["nationalities",null]]}]}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	nats := customNationalities(t, status)
	if len(nats) != 1 || nats[0] != "NL" {
		t.Errorf("disclosed nationalities = %v, want [NL]", nats)
	}
}

// A custom request can ask for an mdoc credential, which exercises the
// mso_mdoc branch of the generic verification (doctype and element names).
func TestVerifierCustomRequestMDoc(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	id := createCustom(t, ts, `{"type":"custom","credentials":[{"format":"mso_mdoc","doctype":"`+PIDDocType+`","claims":[["`+PIDDocType+`","given_name"]]}]}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	claims, _ := status["claims"].(map[string]any)
	cred, _ := claims["cred_0"].(map[string]any)
	if cred["given_name"] == nil {
		t.Errorf("disclosed mdoc claims = %v, want given_name", cred)
	}
}

func clientIDOf(walletURL string) string {
	u, err := url.Parse(walletURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("client_id")
}

// signingKeyPEM makes a self-signed EC certificate and returns the private key
// and the certificate as one PEM bundle, the shape the custom builder accepts.
func signingKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Custom Verifier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A caller-supplied signing key (an EC key and its certificate as PEM) signs the
// request object, and the client id is derived from that certificate rather than
// the demo's own. A malformed bundle is a client error.
func TestVerifierCustomRequestSigningKey(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	defaultDoc := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"custom","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["given_name"]]}]}`)
	defaultURL, _ := defaultDoc["wallet_url"].(string)

	body := `{"type":"custom","signing_key":` + jsonString(signingKeyPEM(t)) + `,"credentials":[{"format":"dc+sd-jwt","vct":"` + PIDVCT + `","claims":[["given_name"]]}]}`
	customDoc := postJSONTo(t, ts.URL+"/verifier/api/requests", body)
	customURL, _ := customDoc["wallet_url"].(string)
	if customURL == "" {
		t.Fatalf("no wallet_url for a custom signing key: %v", customDoc)
	}
	if clientIDOf(customURL) == clientIDOf(defaultURL) {
		t.Errorf("client_id did not change with a custom signing key: %q", clientIDOf(customURL))
	}

	resp, err := http.Post(ts.URL+"/verifier/api/requests", "application/json",
		strings.NewReader(`{"type":"custom","signing_key":"not a pem","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["given_name"]]}]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed signing_key returned %d, want 400", resp.StatusCode)
	}
}

// A custom request under the redirect_uri prefix is delivered unsigned as plain
// query parameters, and the wallet still presents to it.
func TestVerifierCustomRequestRedirectURIUnsigned(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	id := createCustom(t, ts, `{"type":"custom","client_id_scheme":"redirect_uri","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["given_name"]]}]}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	claims, _ := status["claims"].(map[string]any)
	cred, _ := claims["cred_0"].(map[string]any)
	if cred["given_name"] == nil {
		t.Errorf("disclosed claims = %v, want given_name", cred)
	}
}
