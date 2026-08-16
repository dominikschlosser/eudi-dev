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
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

// interactiveTestWallet is a wallet at the feature level that uses Interactive
// Authorization, holding the PID the demo issuer asks for.
func interactiveTestWallet(t *testing.T) *wallet.Wallet {
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
	w.VCIVersion = wallet.VCIVersion11
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}
	return w
}

// The whole of OpenID4VCI 1.1 §6 between this toolkit's own wallet and its own
// issuer: the wallet asks the Authorization Challenge Endpoint, the issuer
// answers that a PID must be presented first, the wallet presents one, the
// issuer verifies it as a Verifier would, and only then hands over the
// authorization code the credential is collected with. No browser is involved.
func TestInteractiveAuthorizationEndToEnd(t *testing.T) {
	w := interactiveTestWallet(t)
	d, ts := serveDemoStack(t, w)

	offer := postJSONTo(t, ts.URL+"/issuer/api/offers?grant="+authCodeGrant+"&authorization="+authorizationPresentation, `{}`)
	uri, _ := offer["scheme_uri"].(string)
	if uri == "" {
		t.Fatalf("unexpected offer response: %v", offer)
	}

	before := len(w.GetCredentials())
	result, err := w.ProcessCredentialOffer(uri)
	if err != nil {
		t.Fatalf("redeeming the offer through interactive authorization: %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected an imported credential")
	}
	if got := len(w.GetCredentials()); got != before+1 {
		t.Errorf("credential count = %d, want %d", got, before+1)
	}

	// The ticket names the holder of the PID that was presented, which is the
	// only thing that authorized this issuance.
	issued, ok := w.GetCredential(result.CredentialID)
	if !ok {
		t.Fatalf("credential %s is not in the wallet", result.CredentialID)
	}
	if got, _ := issued.Claims["family_name"].(string); got != "MUSTERMANN" {
		t.Errorf("issued credential family_name = %q, want the presented holder", got)
	}

	// The issuer verified a presentation bound to its challenge endpoint.
	if got := d.challengeEndpoint(); !strings.HasSuffix(got, "/issuer/authorize-challenge") {
		t.Errorf("challenge endpoint = %q", got)
	}
	for _, entry := range w.GetLog() {
		details := entry.Details
		if details == nil {
			continue
		}
		if details["event"] == "interactive_authorization_presentation" {
			return
		}
	}
	t.Errorf("no log entry recorded the presentation, log: %v", w.GetLog())
}

// The issuer decides per offer. An offer that wants the browser sign-in tells
// a wallet using interactive authorization so with redirect_to_web (Section
// 5.2.2.1.1 of the first-party-apps specification), which is what keeps both
// flows reachable from one demo.
func TestOfferCanAskForTheBrowserSignInInstead(t *testing.T) {
	w := interactiveTestWallet(t)
	_, ts := serveDemoStack(t, w)

	offer := postJSONTo(t, ts.URL+"/issuer/api/offers?grant="+authCodeGrant+"&authorization="+authorizationBrowser, `{}`)
	uri, _ := offer["scheme_uri"].(string)
	if uri == "" {
		t.Fatalf("unexpected offer response: %v", offer)
	}

	// The wallet publishes the sign-in URL rather than finishing on its own,
	// which is the redirect flow taking over.
	authCh, unsubscribe := w.SubscribeAuthorization()
	defer unsubscribe()
	done := make(chan error, 1)
	go func() {
		_, err := w.ProcessCredentialOffer(uri)
		done <- err
	}()

	select {
	case authURL := <-authCh:
		if !strings.Contains(authURL, "/issuer/authorize") {
			t.Errorf("sign-in URL = %q, want the issuer's authorization endpoint", authURL)
		}
		if !strings.Contains(authURL, "request_uri=") {
			t.Errorf("sign-in URL = %q, want the pushed request the challenge endpoint handed back", authURL)
		}
	case err := <-done:
		t.Fatalf("the flow ended without asking for a sign-in: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the sign-in URL")
	}

	for _, entry := range w.GetLog() {
		if entry.Details != nil && entry.Details["event"] == "interactive_authorization_redirect_to_web" {
			return
		}
	}
	t.Errorf("no log entry recorded the handover to the browser, log: %v", w.GetLog())
}

// A wallet at 1.0 is offered the same credential by the same issuer and takes
// the redirect flow, so the feature level is the only thing that decides.
func TestInteractiveAuthorizationIsNotOfferedAtFeatureLevel10(t *testing.T) {
	w := interactiveTestWallet(t)
	w.VCIVersion = wallet.VCIVersion10
	d, _ := serveDemoStack(t, w)

	metadata := d.authorizationServerMetadata()
	if _, published := metadata["authorization_challenge_endpoint"]; published {
		t.Error("the demo issuer published a challenge endpoint to a 1.0 wallet")
	}
	// require_interactive_authorization is never published: the redirect flow
	// works here too, so this server does not only accept the interactive one.
	if _, published := metadata["require_interactive_authorization"]; published {
		t.Error("the demo issuer claims to require interactive authorization")
	}
}

// §6.2.2: a wallet that offers no interaction type this server can work with
// is told which one is missing, rather than being asked for one it cannot do.
func TestAuthorizationChallengeReportsAMissingInteractionType(t *testing.T) {
	w := interactiveTestWallet(t)
	_, ts := serveDemoStack(t, w)

	form := "response_type=code&client_id=some-wallet&code_challenge=x&code_challenge_method=S256" +
		"&interaction_types_supported=" + interactionTypeAuthViaWebURN
	resp, err := ts.Client().Post(ts.URL+"/issuer/authorize-challenge", "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatalf("calling the challenge endpoint: %v", err)
	}
	defer resp.Body.Close()

	// The DPoP proof and client attestation are checked first, so this is not
	// expected to reach the interaction type on a bare request: what matters is
	// that it is refused with a reason rather than accepted.
	if resp.StatusCode == 200 {
		t.Error("the challenge endpoint accepted a request offering no supported interaction type")
	}
}

// interactionTypeAuthViaWebURN is the browser interaction this issuer does not
// implement, used here to build a request that offers nothing usable.
const interactionTypeAuthViaWebURN = "urn%3Aopenid%3Adcp%3Aia%3Aauth_via_web"
