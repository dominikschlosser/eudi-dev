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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// interactiveIssuer is a stand-in authorization server and credential issuer
// that asks for a presentation before it issues (OpenID4VCI 1.1 §6).
type interactiveIssuer struct {
	t *testing.T

	url        string
	credential string

	// interaction is what the server asks for in its Interaction Required
	// Response, and openid4vpRequest is what it sends with it.
	interaction      string
	openid4vpRequest map[string]any

	// satisfiedImmediately answers the first request with a code.
	// interactionsToAsk is how many interactions to require before the code
	// (one by default). challengeError answers with that document instead.
	satisfiedImmediately bool
	interactionsToAsk    int
	challengeError       map[string]any

	// what the wallet sent, for assertions
	initialForm      url.Values
	intermediateForm url.Values
	tokenForm        url.Values
	challengeRounds  int
	sessionsSeen     []string
}

const interactiveTestNonce = "ia-nonce-1"

func (s *interactiveIssuer) dcqlQuery() map[string]any {
	return map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
			},
		},
	}
}

func (s *interactiveIssuer) handler() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			writeTestJSON(rw, map[string]any{
				"credential_issuer":     s.url,
				"authorization_servers": []string{s.url},
				"credential_endpoint":   s.url + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "scope": "test-scope"},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			writeTestJSON(rw, map[string]any{
				"issuer":                            s.url,
				"token_endpoint":                    s.url + "/token",
				"authorization_challenge_endpoint":  s.url + "/authorize-challenge",
				"require_interactive_authorization": true,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/authorize-challenge":
			s.handleChallenge(rw, r)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			body, _ := io.ReadAll(r.Body)
			s.tokenForm, _ = url.ParseQuery(string(body))
			writeTestJSON(rw, map[string]any{
				"access_token": "interactive-access-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-c-nonce",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/credential":
			writeTestJSON(rw, map[string]any{"credentials": []any{map[string]any{"credential": s.credential}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}
}

func (s *interactiveIssuer) handleChallenge(rw http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	s.challengeRounds++
	s.sessionsSeen = append(s.sessionsSeen, form.Get("auth_session"))
	if s.challengeRounds == 1 {
		s.initialForm = form
	} else {
		s.intermediateForm = form
	}

	if s.challengeError != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(rw).Encode(s.challengeError)
		return
	}

	asked := s.interactionsToAsk
	if asked == 0 && !s.satisfiedImmediately {
		asked = 1
	}
	if s.challengeRounds > asked {
		writeTestJSON(rw, map[string]any{"authorization_code": "interactive-code"})
		return
	}

	// A new auth_session with every response, which §5.3.1 of the
	// first-party-apps specification allows and clients must follow.
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusForbidden)
	response := map[string]any{
		"error":                     errorInsufficientAuthorization,
		"interaction_type_required": s.interaction,
		"auth_session":              fmt.Sprintf("session-%d", s.challengeRounds),
	}
	if s.openid4vpRequest != nil {
		response["openid4vp_request"] = s.openid4vpRequest
	}
	_ = json.NewEncoder(rw).Encode(response)
}

func writeTestJSON(rw http.ResponseWriter, body map[string]any) {
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(body)
}

// newInteractiveIssuer starts a server that requires a presentation, and points
// the wallet's HTTP client at it.
func newInteractiveIssuer(t *testing.T, w *Wallet) *interactiveIssuer {
	t.Helper()

	issuer := &interactiveIssuer{t: t, interaction: interactionTypePresentation}
	issuer.credential = generateTestCredential(t, w)
	issuer.openid4vpRequest = map[string]any{
		"response_type": "vp_token",
		"response_mode": "ia_post",
		"nonce":         interactiveTestNonce,
		"dcql_query":    issuer.dcqlQuery(),
	}

	server := httptest.NewServer(issuer.handler())
	t.Cleanup(server.Close)
	issuer.url = server.URL

	oldClient := httpClient
	httpClient = server.Client()
	t.Cleanup(func() { httpClient = oldClient })

	return issuer
}

func interactiveOfferURI(issuerURL string) string {
	offer := map[string]any{
		"credential_issuer":            issuerURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{"issuer_state": "issuer-state-1"},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
}

func newInteractiveWallet(t *testing.T) *Wallet {
	t.Helper()
	w := generateTestWalletWithPID(t)
	w.AutoAccept = true
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "wallet-client"
	return w
}

// The whole exchange of §6: the wallet asks the challenge endpoint, is told a
// presentation is required, presents a credential it holds, and gets an
// authorization code it exchanges for the credential being issued.
func TestInteractiveAuthorizationIssuesAfterAPresentation(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)

	result, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}
	if issuer.challengeRounds != 2 {
		t.Errorf("challenge rounds = %d, want 2", issuer.challengeRounds)
	}

	// §6.1.1: the initial request says what the wallet can do, and carries the
	// ordinary authorization request parameters.
	if got := issuer.initialForm.Get("interaction_types_supported"); got != interactionTypePresentation {
		t.Errorf("interaction_types_supported = %q, want %q", got, interactionTypePresentation)
	}
	if got := issuer.initialForm.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, want code", got)
	}
	if got := issuer.initialForm.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if got := issuer.initialForm.Get("scope"); got != "test-scope" {
		t.Errorf("scope = %q, want test-scope", got)
	}
	// A wallet with no redirect_uri configured is fine here: nothing is
	// redirected anywhere.
	if got := issuer.initialForm.Get("redirect_uri"); got != "" {
		t.Errorf("redirect_uri = %q, want it absent", got)
	}

	// §6.1.2: the intermediate request carries the session and the response.
	if got := issuer.intermediateForm.Get("auth_session"); got != "session-1" {
		t.Errorf("auth_session = %q, want session-1", got)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(issuer.intermediateForm.Get("openid4vp_response")), &response); err != nil {
		t.Fatalf("openid4vp_response is not a JSON object: %v", err)
	}
	vpToken, ok := response["vp_token"].(map[string]any)
	if !ok {
		t.Fatalf("openid4vp_response has no vp_token object: %v", response)
	}
	presentations, ok := vpToken["pid"].([]any)
	if !ok || len(presentations) == 0 {
		t.Fatalf("vp_token has no presentation for the query: %v", vpToken)
	}

	// Appendix A.3.5: the Key Binding JWT is bound to the challenge endpoint.
	kb := keyBindingClaims(t, presentations[0].(string))
	wantAudience := "ia:" + issuer.url + "/authorize-challenge"
	if got, _ := kb["aud"].(string); got != wantAudience {
		t.Errorf("key binding aud = %q, want %q", got, wantAudience)
	}
	if got, _ := kb["nonce"].(string); got != interactiveTestNonce {
		t.Errorf("key binding nonce = %q, want %q", got, interactiveTestNonce)
	}

	// Section 6 of the first-party-apps specification: no redirect_uri was in
	// the authorization request, so none is in the token request.
	if got := issuer.tokenForm.Get("code"); got != "interactive-code" {
		t.Errorf("token request code = %q, want interactive-code", got)
	}
	if got := issuer.tokenForm.Get("redirect_uri"); got != "" {
		t.Errorf("token request redirect_uri = %q, want it absent", got)
	}
	if issuer.tokenForm.Get("code_verifier") == "" {
		t.Error("token request carried no code_verifier")
	}
}

// An authorization server that is satisfied straight away answers the initial
// request with a code (Section 5.2.1 of the first-party-apps specification),
// and nothing is presented.
func TestInteractiveAuthorizationTakesACodeWithoutAnInteraction(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.satisfiedImmediately = true

	result, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}
	if issuer.challengeRounds != 1 {
		t.Errorf("challenge rounds = %d, want 1", issuer.challengeRounds)
	}
}

// The conversation runs for as many interactions as the server asks for, and
// §5.3.1 of the first-party-apps specification says clients "MUST NOT assume
// that auth_session values are static", so each request carries the value from
// the response before it.
func TestInteractiveAuthorizationFollowsSeveralRoundsAndARotatingSession(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.interactionsToAsk = 3

	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if issuer.challengeRounds != 4 {
		t.Errorf("challenge rounds = %d, want 4 (three interactions and the code)", issuer.challengeRounds)
	}
	want := []string{"", "session-1", "session-2", "session-3"}
	if len(issuer.sessionsSeen) != len(want) {
		t.Fatalf("auth_session values seen = %v, want %v", issuer.sessionsSeen, want)
	}
	for i, session := range want {
		if issuer.sessionsSeen[i] != session {
			t.Errorf("request %d carried auth_session %q, want %q", i+1, issuer.sessionsSeen[i], session)
		}
	}
}

// A server that keeps asking is walked away from rather than followed forever.
func TestInteractiveAuthorizationStopsAfterTooManyRounds(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.interactionsToAsk = maxInteractiveAuthorizationRounds + 5

	_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err == nil {
		t.Fatal("expected the wallet to give up")
	}
	if !strings.Contains(err.Error(), "did not finish") {
		t.Errorf("error = %v, want it to say the exchange did not finish", err)
	}
	if issuer.challengeRounds != maxInteractiveAuthorizationRounds {
		t.Errorf("challenge rounds = %d, want %d", issuer.challengeRounds, maxInteractiveAuthorizationRounds)
	}
}

// §6.2.2 defines missing_interaction_type for a wallet that offered no type the
// server can work with. Any Authorization Challenge Error Response ends the
// flow with what the server said.
func TestInteractiveAuthorizationReportsAChallengeError(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.challengeError = map[string]any{
		"error":             "missing_interaction_type",
		"error_description": "interaction_types_supported is missing 'urn:openid:dcp:ia:auth_via_web'",
	}

	_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err == nil {
		t.Fatal("expected the challenge error to end the flow")
	}
	if !strings.Contains(err.Error(), "missing_interaction_type") {
		t.Errorf("error = %v, want it to carry the server's error code", err)
	}
	if !strings.Contains(err.Error(), "auth_via_web") {
		t.Errorf("error = %v, want it to carry the server's description", err)
	}
}

// The feature level decides, not the server: the same server offering the same
// endpoint gets the redirect flow from a wallet at 1.0. It has no
// authorization_endpoint, so the flow stops rather than silently doing
// something else.
func TestInteractiveAuthorizationIsNotUsedAtFeatureLevel10(t *testing.T) {
	w := newInteractiveWallet(t)
	w.VCIVersion = VCIVersion10
	w.VCIRedirectURI = "https://wallet.example/callback"
	issuer := newInteractiveIssuer(t, w)

	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err == nil {
		t.Fatal("expected the redirect flow to fail against a server that only offers the challenge endpoint")
	}
	if issuer.challengeRounds != 0 {
		t.Errorf("wallet called the challenge endpoint %d times at feature level 1.0", issuer.challengeRounds)
	}
	if !hasInteractiveAuthorizationNote(w, "--vci-version 1.1") {
		t.Errorf("no log entry named the declined offer, log: %v", w.Log)
	}
}

// HAIP 1.0 profiles the channels a Verifier sends an Authorization Request
// over, and says nothing about a presentation made inside an OpenID4VCI 1.1 §6
// exchange. Holding one to its response_mode and signed-request rules would
// stop a HAIP wallet using the feature at all, which is what strict mode makes
// visible here. The public demo runs HAIP.
func TestInteractiveAuthorizationIsNotHeldToHAIPChannelRules(t *testing.T) {
	w := newInteractiveWallet(t)
	w.RequireHAIP = true
	w.ValidationMode = ValidationModeStrict
	issuer := newInteractiveIssuer(t, w)

	result, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err != nil {
		t.Fatalf("a HAIP wallet in strict mode could not use interactive authorization: %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}
	for _, entry := range w.GetLog() {
		if strings.Contains(entry.Detail, "HAIP:") {
			t.Errorf("HAIP finding reported against an interactive authorization presentation: %s", entry.Detail)
		}
	}
}

// §6.2.1: "If a Wallet receives an interaction_type_required value that it
// does not support, it MUST abort the issuance process."
func TestInteractiveAuthorizationAbortsOnAnUnsupportedInteraction(t *testing.T) {
	tests := []struct {
		name        string
		interaction string
		wantIn      string
	}{
		{name: "web", interaction: interactionTypeAuthViaWeb, wantIn: interactionTypeAuthViaWeb},
		{name: "unknown", interaction: "urn:example:ia:smartcard", wantIn: "unsupported interaction type"},
		{name: "missing", interaction: "", wantIn: "without naming its type"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newInteractiveWallet(t)
			issuer := newInteractiveIssuer(t, w)
			issuer.interaction = tc.interaction
			issuer.openid4vpRequest = nil

			_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
			if err == nil {
				t.Fatal("expected the issuance to abort")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantIn)
			}
			if issuer.challengeRounds != 1 {
				t.Errorf("challenge rounds = %d, want the wallet to stop after the first", issuer.challengeRounds)
			}
		})
	}
}

// §6.2.1.1 allows ia_post and ia_post.jwt and nothing else, because the
// response goes back to the challenge endpoint.
func TestInteractiveAuthorizationRefusesAnotherResponseMode(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.openid4vpRequest["response_mode"] = "direct_post"
	issuer.openid4vpRequest["response_uri"] = issuer.url + "/response"

	_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
	if err == nil {
		t.Fatal("expected a request with response_mode direct_post to be refused")
	}
	if !strings.Contains(err.Error(), "response_mode") {
		t.Errorf("error = %v, want it to name the response_mode", err)
	}
}

// §6.2.1.1: "If expected_origins is present, it MUST contain only the derived
// Origin of the Authorization Challenge Endpoint." §6.2.1.5 makes this the
// wallet's defence against one authorization server forwarding another's
// request.
func TestInteractiveAuthorizationChecksExpectedOrigins(t *testing.T) {
	t.Run("a foreign origin is refused", func(t *testing.T) {
		w := newInteractiveWallet(t)
		issuer := newInteractiveIssuer(t, w)
		issuer.openid4vpRequest["expected_origins"] = []any{"https://elsewhere.example"}

		_, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url))
		if err == nil {
			t.Fatal("expected a forwarded request to be refused")
		}
		if !strings.Contains(err.Error(), "expected_origins") {
			t.Errorf("error = %v, want it to name expected_origins", err)
		}
	})

	t.Run("the endpoint's own origin is accepted", func(t *testing.T) {
		w := newInteractiveWallet(t)
		issuer := newInteractiveIssuer(t, w)
		issuer.openid4vpRequest["expected_origins"] = []any{derivedOrigin(issuer.url)}

		if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
			t.Fatalf("ProcessCredentialOffer() error = %v", err)
		}
	})
}

// A wallet that holds nothing the server asked for answers the interaction
// with an OpenID4VP error rather than going quiet, which is what §6.2.1.1
// provides for. The server then decides what to do about it.
func TestInteractiveAuthorizationReportsThatItHoldsNothingMatching(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.openid4vpRequest["dcql_query"] = map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:example:nothing-here"}},
			},
		},
	}

	// The stub answers the intermediate request with a code regardless, so the
	// assertion is about what the wallet sent, not about how it ended.
	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(issuer.intermediateForm.Get("openid4vp_response")), &response); err != nil {
		t.Fatalf("openid4vp_response is not a JSON object: %v", err)
	}
	if got, _ := response["error"].(string); got != "access_denied" {
		t.Errorf("openid4vp_response error = %q, want access_denied", got)
	}
	if _, ok := response["vp_token"]; ok {
		t.Error("openid4vp_response carried a vp_token as well as an error")
	}
}

// §6.2.1.1: with ia_post.jwt the response is encrypted, and the draft's
// example shows it travelling as {"response": ...} inside openid4vp_response.
func TestInteractiveAuthorizationEncryptsWithIAPostJWT(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	issuer.openid4vpRequest["response_mode"] = "ia_post.jwt"
	issuer.openid4vpRequest["client_metadata"] = map[string]any{
		"jwks": map[string]any{
			"keys": []any{encryptionJWKForTest(t)},
		},
	}

	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(issuer.intermediateForm.Get("openid4vp_response")), &response); err != nil {
		t.Fatalf("openid4vp_response is not a JSON object: %v", err)
	}
	jwe, _ := response["response"].(string)
	if jwe == "" {
		t.Fatalf("openid4vp_response carried no encrypted response: %v", response)
	}
	if len(strings.Split(jwe, ".")) != 5 {
		t.Errorf("response is not a compact JWE: %q", format.Truncate(jwe, 60))
	}
	if _, ok := response["vp_token"]; ok {
		t.Error("openid4vp_response carried the vp_token in the clear as well")
	}
}

func encryptionJWKForTest(t *testing.T) map[string]any {
	t.Helper()

	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating an encryption key: %v", err)
	}
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"use": "enc",
		"alg": "ECDH-ES",
		"kid": "issuer-encryption-key",
		"x":   format.EncodeBase64URL(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y":   format.EncodeBase64URL(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

// keyBindingClaims decodes the Key Binding JWT of an SD-JWT presentation.
func keyBindingClaims(t *testing.T, presentation string) map[string]any {
	t.Helper()

	parts := strings.Split(presentation, "~")
	kbJWT := parts[len(parts)-1]
	segments := strings.Split(kbJWT, ".")
	if len(segments) != 3 {
		t.Fatalf("presentation has no key binding JWT: %q", format.Truncate(presentation, 80))
	}
	payload, err := format.DecodeBase64URL(segments[1])
	if err != nil {
		t.Fatalf("decoding key binding payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parsing key binding payload: %v", err)
	}
	return claims
}
