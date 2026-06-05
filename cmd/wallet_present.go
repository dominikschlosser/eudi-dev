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

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"

	"github.com/dominikschlosser/oid4vc-dev/internal/config"
	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

// dispatchOID4Opts holds options for dispatching an OID4VP/VCI URI.
type dispatchOID4Opts struct {
	port              int
	autoAccept        bool
	sessionTranscript string
	txCode            string
	haip              bool
	mode              string
}

// dispatchURI detects the URI type and dispatches to the appropriate wallet flow.
func dispatchURI(uri string, opts dispatchOID4Opts) error {
	detected := format.Detect(uri)

	switch detected {
	case format.FormatOID4VP:
		w, store, err := loadWallet()
		if err != nil {
			return err
		}
		if err := applyValidationMode(w, opts.mode); err != nil {
			return err
		}
		if opts.autoAccept {
			w.AutoAccept = true
		}
		if opts.haip {
			w.RequireHAIP = true
		}
		if err := applySessionTranscriptMode(w, opts.sessionTranscript); err != nil {
			return err
		}
		handled, err := tryPresentViaRunningServer(uri, opts)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
		port, err := resolvePresentationPort(opts.port, opts.autoAccept)
		if err != nil {
			return err
		}
		return runPresent(w, store, uri, port)

	case format.FormatOID4VCI:
		return processCredentialOffer(uri, opts.txCode)

	default:
		return fmt.Errorf("unable to detect URI type (expected openid4vp://, openid-credential-offer://, or similar): %s", format.Truncate(uri, 80))
	}
}

// runPresent handles an OID4VP authorization request: evaluates credentials,
// optionally shows a consent UI, creates VP tokens, and submits the response.
func runPresent(w *wallet.Wallet, store *wallet.WalletStore, uri string, port int) error {
	parsed, err := wallet.ParseAuthorizationRequestWithOptions(uri, oid4vc.ParseOptions{
		FetchRequestURI: wallet.MakeFetchRequestURI(w, nil),
	})
	if err != nil {
		return fmt.Errorf("parsing authorization request: %w", err)
	}

	findings, err := wallet.ValidatePresentationRequest(w.ValidationMode, parsed.ClientID, parsed.RequestObject, wallet.GetResponseURI(parsed))
	if err != nil {
		return err
	}
	for _, warning := range findings {
		yellow := color.New(color.FgYellow)
		yellow.Printf("  WARNING: %s\n", warning)
		w.AddLog("presentation", fmt.Sprintf("request validation warning: %s", warning), false)
	}

	requiresVP := wallet.ResponseTypeRequiresVP(parsed.ResponseType)

	// Evaluate DCQL
	var matches []wallet.CredentialMatch
	if parsed.DCQLQuery != nil && requiresVP {
		matches = w.EvaluateDCQL(parsed.DCQLQuery)
	}

	if requiresVP && len(matches) == 0 {
		return fmt.Errorf("no matching credentials found for the DCQL query")
	}

	responseURI := parsed.ResponseURI
	if responseURI == "" {
		responseURI = parsed.RedirectURI
	}
	authReq := authorizationRequestParamsFromParsed(parsed, responseURI, "cli")
	requestDetails := wallet.PresentationSubmissionLogDetails(authReq, w, nil, nil, "", nil)
	requestDetails["event"] = "presentation_request"
	requestDetails["direction"] = "inbound"
	requestDetails["source"] = "cli"
	w.AddLogDetails("presentation", fmt.Sprintf("Received presentation request from %s", parsed.ClientID), true, requestDetails)

	dim := color.New(color.Faint)

	// Start server so the trust list is available during verification
	setLocalPresentationIssuerURL(w, port)
	srv := wallet.NewServer(w, port, nil)
	if err := configureIssuerTLSCertificate(srv, store, w.IssuerURL); err != nil {
		return err
	}
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		return fmt.Errorf("starting server: %w", err)
	}
	defer srv.Shutdown()

	dim.Println("───────────────────────────────────────")
	yellow := color.New(color.FgYellow)
	yellow.Printf("  Verifier: %s\n", parsed.ClientID)
	fmt.Printf("  Trust List:  %s/api/trustlist\n", addr)
	dim.Printf("               http://host.docker.internal:%d/api/trustlist\n", port)
	for _, m := range matches {
		fmt.Printf("  Credential: %s (%s)\n", m.Format, typeLabel(m.VCT, m.DocType, m.Format))
		fmt.Printf("  Disclosing: %v\n", m.SelectedKeys)
	}

	// Wait for consent if not auto-accepting
	matches, submissionCh, denied := waitForConsent(w, matches, parsed, responseURI, addr, dim)
	if denied {
		return nil
	}

	dim.Println("───────────────────────────────────────")

	// Create and submit VP tokens
	err = submitPresentation(w, store, matches, parsed, responseURI, submissionCh, dim)
	if err != nil {
		return err
	}

	return nil
}

func setLocalPresentationIssuerURL(w *wallet.Wallet, port int) {
	port = effectivePresentationPort(port)
	w.IssuerURL = wallet.LocalIssuerURL(port+1, false)
}

func resolvePresentationPort(port int, autoAccept bool) (int, error) {
	port = effectivePresentationPort(port)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err == nil {
		_ = ln.Close()
		return port, nil
	}

	if !autoAccept {
		return port, nil
	}

	fallback, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("resolving temporary auto-accept port after %d was busy: %w", port, err)
	}
	fallbackPort := fallback.Addr().(*net.TCPAddr).Port
	if err := fallback.Close(); err != nil {
		return 0, fmt.Errorf("closing temporary auto-accept listener: %w", err)
	}
	yellow := color.New(color.FgYellow)
	yellow.Printf("  Note: port %d is already in use; auto-accept will use temporary port %d\n", port, fallbackPort)
	return fallbackPort, nil
}

func tryPresentViaRunningServer(uri string, opts dispatchOID4Opts) (bool, error) {
	if !opts.autoAccept {
		return false, nil
	}

	port := effectivePresentationPort(opts.port)
	baseURL := fmt.Sprintf("http://localhost:%d", port)
	if !isRunningWalletServer(baseURL) {
		return false, nil
	}

	payload := map[string]any{
		"uri":         uri,
		"auto_accept": true,
	}
	if opts.sessionTranscript != "" {
		payload["session_transcript"] = opts.sessionTranscript
	}
	if opts.haip {
		payload["haip"] = true
	}
	if opts.mode != "" {
		payload["mode"] = opts.mode
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("marshaling running-wallet request: %w", err)
	}

	resp, err := http.Post(baseURL+"/api/presentations", "application/json", bytes.NewReader(body))
	if err != nil {
		return true, fmt.Errorf("submitting presentation to running wallet server: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Status           string                  `json:"status"`
		Error            string                  `json:"error"`
		ErrorDescription string                  `json:"error_description"`
		Response         wallet.DirectPostResult `json:"response"`
		VPTokenKeys      []string                `json:"vp_token_keys"`
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, fmt.Errorf("reading running-wallet response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return true, fmt.Errorf("running wallet server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return true, fmt.Errorf("decoding running-wallet response: %w", err)
	}

	switch result.Status {
	case "submitted":
		if jsonOutput {
			fmt.Println(string(raw))
			return true, nil
		}
		green := color.New(color.FgGreen)
		green.Printf("  Submitted: %s\n", wallet.FormatDirectPostResult(&result.Response))
		if len(result.VPTokenKeys) > 0 {
			fmt.Printf("  VP tokens: %v\n", result.VPTokenKeys)
		}
		return true, nil
	case "denied":
		return true, fmt.Errorf("presentation denied")
	case "no_match":
		if result.Error != "" {
			return true, fmt.Errorf("%s", result.Error)
		}
		return true, fmt.Errorf("no matching credentials found")
	case "error":
		if result.ErrorDescription != "" {
			return true, fmt.Errorf("%s: %s", result.Error, result.ErrorDescription)
		}
		if result.Error != "" {
			return true, fmt.Errorf("%s", result.Error)
		}
		return true, fmt.Errorf("running wallet server returned an authorization error")
	default:
		if result.Error != "" {
			return true, fmt.Errorf("%s", result.Error)
		}
		return true, fmt.Errorf("unexpected running-wallet response status %q", result.Status)
	}
}

func isRunningWalletServer(baseURL string) bool {
	resp, err := http.Get(baseURL + "/api/log")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func effectivePresentationPort(port int) int {
	if port > 0 {
		return port
	}
	return config.DefaultWalletPort
}

// waitForConsent shows a consent UI and waits for the user's decision.
// Returns the (potentially updated) matches, a submission channel for UI feedback,
// and whether the presentation was denied or timed out.
func waitForConsent(w *wallet.Wallet, matches []wallet.CredentialMatch, parsed *oid4vc.AuthorizationRequest, responseURI, addr string, dim *color.Color) ([]wallet.CredentialMatch, chan wallet.SubmissionResult, bool) {
	if w.AutoAccept {
		return matches, nil, false
	}

	consentReq := &wallet.ConsentRequest{
		ID:           uuid.New().String(),
		Type:         "presentation",
		MatchedCreds: matches,
		Status:       "pending",
		ResultCh:     make(chan wallet.ConsentResult, 1),
		SubmissionCh: make(chan wallet.SubmissionResult, 1),
		CreatedAt:    time.Now(),
		ClientID:     parsed.ClientID,
		Nonce:        parsed.Nonce,
		ResponseURI:  responseURI,
		DCQLQuery:    parsed.DCQLQuery,
	}

	w.CreateConsentRequest(consentReq)

	fmt.Printf("  Consent UI: %s\n", addr)
	dim.Println("───────────────────────────────────────")
	fmt.Println("Waiting for consent decision...")

	openBrowser(addr)

	select {
	case result := <-consentReq.ResultCh:
		if !result.Approved {
			fmt.Println("Presentation denied.")
			return nil, nil, true
		}
		if result.SelectedClaims != nil {
			for i, m := range matches {
				if selectedKeys, ok := result.SelectedClaims[m.CredentialID]; ok {
					matches[i].SelectedKeys = selectedKeys
				}
			}
		}
	case <-time.After(config.ConsentTimeout):
		fmt.Println("Consent timeout.")
		return nil, nil, true
	}

	return matches, consentReq.SubmissionCh, false
}

// submitPresentation creates VP tokens, submits them to the verifier, and prints the result.
func submitPresentation(w *wallet.Wallet, store *wallet.WalletStore, matches []wallet.CredentialMatch, parsed *oid4vc.AuthorizationRequest, responseURI string, submissionCh chan wallet.SubmissionResult, dim *color.Color) error {
	params := wallet.PresentationParams{
		Nonce:         parsed.Nonce,
		ClientID:      parsed.ClientID,
		ResponseURI:   responseURI,
		ResponseMode:  parsed.ResponseMode,
		RequestObject: parsed.RequestObject,
	}
	vpResult, err := w.CreateVPTokenMap(matches, params)
	if err != nil {
		w.AddLog("presentation", fmt.Sprintf("VP token creation failed: %v", err), false)
		if submissionCh != nil {
			submissionCh <- wallet.SubmissionResult{Error: err.Error()}
		}
		return fmt.Errorf("creating VP tokens: %w", err)
	}

	// Submit to verifier (encrypts if direct_post.jwt with encryption key)
	// Create self-issued id_token if requested
	var idToken string
	if wallet.ResponseTypeContains(parsed.ResponseType, "id_token") {
		idToken, err = w.CreateSelfIssuedIDToken(parsed.Nonce, parsed.ClientID)
		if err != nil {
			return fmt.Errorf("creating self-issued id_token: %w", err)
		}
	}

	authReq := authorizationRequestParamsFromParsed(parsed, responseURI, "cli")
	responseDetails := wallet.PresentationResponseLogDetails(authReq, w, matches, vpResult, idToken, responseURI)
	responseDetails["event"] = "presentation_response"
	w.AddLogDetails("presentation", fmt.Sprintf("Sending presentation response to %s", parsed.ClientID), true, responseDetails)

	result, err := w.SubmitPresentation(vpResult, idToken, parsed.State, responseURI, params)
	if err != nil {
		w.AddLog("presentation", fmt.Sprintf("Submission failed: %v", err), false)
		if submissionCh != nil {
			submissionCh <- wallet.SubmissionResult{Error: err.Error()}
		}
		return fmt.Errorf("submitting presentation: %w", err)
	}

	// Print result and notify UI
	submission := wallet.SubmissionResult{
		RedirectURI: result.RedirectURI,
		StatusCode:  result.StatusCode,
	}

	if result.StatusCode >= 400 {
		red := color.New(color.FgRed)
		red.Printf("  Error: %s\n", wallet.FormatDirectPostResult(result))
		fmt.Printf("  Body:  %s\n", result.Body)
		submission.Error = result.Body
		w.AddLog("presentation", fmt.Sprintf("Verifier %s rejected: %s", parsed.ClientID, result.Body), false)
	} else {
		green := color.New(color.FgGreen)
		green.Printf("  Submitted: %s\n", wallet.FormatDirectPostResult(result))
	}
	resultDetails := map[string]any{
		"event":          "verifier_response",
		"direction":      "inbound",
		"source":         "cli",
		"client_id":      parsed.ClientID,
		"response_mode":  parsed.ResponseMode,
		"state":          parsed.State,
		"submission_uri": responseURI,
		"status_code":    result.StatusCode,
	}
	if result.RedirectURI != "" {
		resultDetails["redirect_uri"] = result.RedirectURI
	}
	if result.Body != "" {
		resultDetails["response_body"] = result.Body
	}
	w.AddLogDetails("presentation", fmt.Sprintf("Verifier result from %s: %s", parsed.ClientID, wallet.FormatDirectPostResult(result)), result.StatusCode < 400, resultDetails)
	dim.Println("───────────────────────────────────────")

	if submissionCh != nil {
		submissionCh <- submission
	}

	if err := store.Save(w); err != nil {
		fmt.Fprintf(os.Stderr, "warning: saving wallet: %v\n", err)
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	}

	return nil
}

func authorizationRequestParamsFromParsed(parsed *oid4vc.AuthorizationRequest, responseURI, source string) *wallet.AuthorizationRequestParams {
	return &wallet.AuthorizationRequestParams{
		ClientID:       parsed.ClientID,
		ResponseType:   parsed.ResponseType,
		ResponseMode:   parsed.ResponseMode,
		Nonce:          parsed.Nonce,
		State:          parsed.State,
		RedirectURI:    parsed.RedirectURI,
		ResponseURI:    responseURI,
		ClientMetadata: parsed.ClientMetadata,
		DCQLQuery:      parsed.DCQLQuery,
		RequestObject:  parsed.RequestObject,
		RequestPayload: wallet.RequestPayload(parsed.RequestObject, parsed.FullJSON),
		Source:         source,
	}
}

// processCredentialOffer fetches and stores a credential from an OID4VCI offer URI.
func processCredentialOffer(uri string, txCode string) error {
	w, store, err := loadWallet()
	if err != nil {
		return err
	}

	if txCode != "" {
		w.TxCode = txCode
	}

	result, err := w.ProcessCredentialOffer(uri)
	if err != nil {
		return fmt.Errorf("processing credential offer: %w", err)
	}

	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}

	fmt.Printf("Received %s credential from %s (ID: %s)\n", result.Format, result.Issuer, result.CredentialID)
	if result.VerificationDetail != "" {
		fmt.Printf("Verification: %s", result.VerificationDetail)
		if result.VerificationStatus != "" {
			fmt.Printf(" [%s]", result.VerificationStatus)
		}
		fmt.Println()
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	}

	return nil
}
