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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An interactive issuance reads a credential_offer_uri twice: once to tell
// the consent dialog what is being offered, and once when the user approves.
// OpenID4VCI 1.0 §4.1.3 allows both, since the wallet fetches "unless it is
// already cached", but an issuer that consumes the offer on first read
// answers the second with an error. The offer already resolved for the dialog
// is what the user approved, so the flow continues with it and says so.
func TestApprovingAnOfferSurvivesASingleUseOfferURI(t *testing.T) {
	w := generateTestWallet(t)

	var offerFetches int
	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		offerViaURI:     true,
		oneShotOfferURI: true,
		onOfferFetch:    func() { offerFetches++ },
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	// What the consent dialog does: resolve the offer so it can name what is
	// being offered.
	consentReq, _, err := prepareIssuanceConsentRequest(offerURI, "")
	if err != nil {
		t.Fatalf("preparing the consent request: %v", err)
	}
	if consentReq.ResolvedOffer == nil {
		t.Fatal("the consent dialog resolved no offer to carry into the approval")
	}

	// What approving does: run the offer, whose second read of the URI the
	// issuer refuses.
	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{
		ResolvedOffer: consentReq.ResolvedOffer,
	})
	if err != nil {
		t.Fatalf("issuance failed on an offer the wallet had already resolved: %v", err)
	}
	if result.CredentialID == "" {
		t.Error("no credential was imported")
	}
	if offerFetches != 2 {
		t.Errorf("the offer URI was read %d times, want the dialog's read and the approval's attempt", offerFetches)
	}

	// The issuer's behavior is worth reporting: it is why a second wallet
	// reading the same offer would fail.
	var warned bool
	for _, entry := range w.GetLog() {
		if entry.Severity == severityWarning && strings.Contains(entry.Detail, "credential_offer_uri") {
			warned = true
		}
	}
	if !warned {
		t.Error("nothing in the activity log says the offer could not be read again")
	}
}

// Without an offer resolved earlier there is nothing to fall back on, so a
// failing read is still the end of the flow.
func TestAnUnreadableOfferURIStillFailsWithoutAResolvedOffer(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{offerViaURI: true, oneShotOfferURI: true})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	// The first read consumes the offer, so this stands in for a wallet that
	// never saw it.
	if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
		t.Fatalf("the first read should succeed: %v", err)
	}
	if _, err := w.ProcessCredentialOffer(offerURI); err == nil {
		t.Fatal("an offer the wallet cannot read and never resolved was accepted")
	}
}

// The wallet UI's path: the offer arrives, the dialog resolves it, the user
// approves, and the issuer refuses to serve the offer again. The approval
// carries what the dialog resolved, so the issuance completes.
func TestApproveRequestCompletesWhenTheIssuerServesTheOfferOnce(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{offerViaURI: true, oneShotOfferURI: true})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, nil)

	consentReq, _, err := prepareIssuanceConsentRequest(offerURI, "")
	if err != nil {
		t.Fatalf("preparing the consent request: %v", err)
	}
	w.CreateConsentRequest(consentReq)

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.awaitOfferConsent(noopResponseWriter{}, consentReq, "test issuer", false, "")
	}()

	consentReq.ResultCh <- ConsentResult{Approved: true}
	submission := <-consentReq.SubmissionCh
	<-done

	if submission.Error != "" {
		t.Fatalf("approving an offer the issuer serves once failed: %s", submission.Error)
	}
	if len(w.GetCredentials()) != 1 {
		t.Errorf("got %d credentials, want the approved one", len(w.GetCredentials()))
	}
}

// The user approves what the dialog described. An offer URI that answers the
// approval with a different issuer does not get to redirect the issuance:
// nothing asked the user about that one.
func TestASwappedOfferDoesNotReplaceTheApprovedOne(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		offerViaURI: true,
		secondOffer: map[string]any{
			"credential_issuer":            "https://elsewhere.example",
			"credential_configuration_ids": []string{"other-config"},
			"grants": map[string]any{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
					"pre-authorized_code": "someone-elses-code",
				},
			},
		},
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	consentReq, _, err := prepareIssuanceConsentRequest(offerURI, "")
	if err != nil {
		t.Fatalf("preparing the consent request: %v", err)
	}

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{
		ResolvedOffer: consentReq.ResolvedOffer,
	})
	if err != nil {
		t.Fatalf("issuance failed: %v", err)
	}
	if result.Issuer != srv.URL {
		t.Errorf("issued from %s, want the approved issuer %s", result.Issuer, srv.URL)
	}

	var warned bool
	for _, entry := range w.GetLog() {
		if entry.Severity == severityWarning && strings.Contains(entry.Detail, "elsewhere.example") {
			warned = true
		}
	}
	if !warned {
		t.Error("nothing in the activity log says the offer changed")
	}
}

// An issuer that answers a spent offer with an error body and HTTP 200 is the
// same case as one that answers with a status code: there is no offer in that
// response, so the approved one stands.
func TestAnOfferRereadWithoutAnIssuerKeepsTheApprovedOne(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		offerViaURI: true,
		secondOffer: map[string]any{"error": "offer_expired", "error_description": "already consumed"},
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	consentReq, _, err := prepareIssuanceConsentRequest(offerURI, "")
	if err != nil {
		t.Fatalf("preparing the consent request: %v", err)
	}

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{
		ResolvedOffer: consentReq.ResolvedOffer,
	})
	if err != nil {
		t.Fatalf("issuance failed on an offer answered with an error body: %v", err)
	}
	if result.CredentialID == "" {
		t.Error("no credential was imported")
	}

	var warned bool
	for _, entry := range w.GetLog() {
		if entry.Severity == severityWarning && strings.Contains(entry.Detail, "credential_offer_uri") {
			warned = true
		}
	}
	if !warned {
		t.Error("nothing in the activity log says the offer could not be read again")
	}
}

// The fallback belongs to an approved issuance. An offer submitted through
// the API or accepted automatically carries none, so nothing can stand in for
// a read that failed.
func TestUnattendedIssuanceCarriesNoApprovedOffer(t *testing.T) {
	w := generateTestWallet(t)
	w.AutoAccept = true

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{offerViaURI: true, oneShotOfferURI: true})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, nil)
	rec := httptest.NewRecorder()
	server.processOfferURI(rec, offerURI, "", "", false, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("the first, unattended run failed: %d %s", rec.Code, rec.Body.String())
	}

	// The offer is spent now, and an unattended run has nothing to fall back
	// on, so this one has to fail rather than reuse anything.
	rec = httptest.NewRecorder()
	server.processOfferURI(rec, offerURI, "", "", false, true)
	if rec.Code == http.StatusOK {
		t.Fatalf("a spent offer was accepted without anyone approving it: %s", rec.Body.String())
	}
}
