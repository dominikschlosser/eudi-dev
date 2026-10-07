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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/output"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

type dispatchOID4Opts struct {
	port              int
	portExplicit      bool
	autoAccept        bool
	sessionTranscript string
	txCode            string
	haip              bool
	arf               bool
	relyingPartyCAs   []string
	trustListCAs      []string
	mode              string
	// keyAttestationLevel is what a key attestation claims (see
	// Wallet.KeyAttestationLevel).
	keyAttestationLevel string
	// docker serves the presentation trust and status lists under
	// host.docker.internal. A verifier in a container can reach them there, and
	// the status list token subject matches the URI in the credential.
	docker bool
	// resolvedOffer is the offer a transaction code prompt already read from the
	// URI. Issuance falls back to it when reading the URI again fails.
	resolvedOffer *oid4vc.CredentialOffer
}

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
		if err := applyARFOptions(w, opts.arf, opts.relyingPartyCAs, opts.trustListCAs); err != nil {
			return err
		}
		w.KeyAttestationLevel = opts.keyAttestationLevel
		if err := applySessionTranscriptMode(w, opts.sessionTranscript); err != nil {
			return err
		}
		if err := w.EnsureRequestEncryptionKey(); err != nil {
			return err
		}
		handled, err := tryPresentViaRunningServer(uri, opts)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
		port, err := resolvePresentationPort(opts.port, opts.autoAccept, opts.portExplicit)
		if err != nil {
			return err
		}
		return runPresent(w, store, uri, port, opts.docker)

	case format.FormatOID4VCI:
		return processCredentialOffer(uri, opts)

	default:
		return fmt.Errorf("unable to detect URI type (expected openid4vp://, openid-credential-offer://, or similar): %s", format.Truncate(uri, 80))
	}
}

func runPresent(w *wallet.Wallet, store *wallet.WalletStore, uri string, port int, docker bool) error {
	parsed, err := wallet.ParseAuthorizationRequestWithOptions(uri, oid4vc.ParseOptions{
		FetchRequestURI: wallet.MakeFetchRequestURI(w, nil),
	})
	if err != nil {
		return fmt.Errorf("parsing authorization request: %w", err)
	}

	responseURI := wallet.GetResponseURI(parsed)
	authReq := authorizationRequestParamsFromParsed(parsed, responseURI, "cli")
	w.PrepareARFChecks(authReq)
	findings, err := wallet.ValidateAuthorizationRequest(w.ValidationMode, w.RequireHAIP, w.RequireARF, authReq)
	if err != nil {
		return err
	}
	for _, warning := range findings {
		yellow := color.New(color.FgYellow)
		yellow.Fprintf(humanOut(), "  WARNING: %s\n", warning)
		w.AddLog("presentation", fmt.Sprintf("request validation warning: %s", warning), false)
	}

	requiresVP := wallet.ResponseTypeRequiresVP(parsed.ResponseType)

	var matches []wallet.CredentialMatch
	if parsed.DCQLQuery != nil && requiresVP {
		matches = w.EvaluateDCQL(parsed.DCQLQuery)
	}

	if requiresVP && len(matches) == 0 {
		return fmt.Errorf("no matching credentials found for the DCQL query")
	}

	requestDetails := wallet.PresentationSubmissionLogDetails(authReq, w, nil, nil, "", nil)
	requestDetails["event"] = "presentation_request"
	requestDetails["direction"] = "inbound"
	requestDetails["source"] = "cli"
	w.AddLogDetails("presentation", fmt.Sprintf("Received presentation request from %s", parsed.ClientID), true, requestDetails)

	dim := color.New(color.Faint)

	// Start server so the trust list is available during verification
	setLocalPresentationIssuerURL(w, port, docker)
	srv := wallet.NewServer(w, port, nil)
	if err := configureIssuerTLSCertificate(srv, store, w.IssuerURL); err != nil {
		return err
	}
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		return fmt.Errorf("starting server: %w", err)
	}
	defer srv.Shutdown()

	_, _ = dim.Fprintln(humanOut(), "───────────────────────────────────────")
	yellow := color.New(color.FgYellow)
	yellow.Fprintf(humanOut(), "  Verifier: %s\n", parsed.ClientID)
	fmt.Fprintf(humanOut(), "  Trust List:  %s/api/trustlist\n", addr)
	dim.Fprintf(humanOut(), "               http://host.docker.internal:%d/api/trustlist\n", port)
	for _, m := range matches {
		fmt.Fprintf(humanOut(), "  Credential: %s (%s)\n", m.Format, typeLabel(m.VCT, m.DocType, m.Format))
		fmt.Fprintf(humanOut(), "  Disclosing: %v\n", m.SelectedKeys)
	}

	matches, submissionCh, err := waitForConsent(w, matches, parsed, responseURI, addr, dim)
	if err != nil {
		return err
	}

	_, _ = dim.Fprintln(humanOut(), "───────────────────────────────────────")

	err = submitPresentation(w, store, matches, parsed, responseURI, submissionCh, dim)
	if err != nil {
		return err
	}

	return nil
}

func setLocalPresentationIssuerURL(w *wallet.Wallet, port int, docker bool) {
	port = effectivePresentationPort(port)
	w.IssuerURL = wallet.LocalIssuerURL(port+1, docker)
}

func resolvePresentationPort(port int, autoAccept bool, portExplicit bool) (int, error) {
	port = effectivePresentationPort(port)

	if presentationPortPairAvailable(port) {
		return port, nil
	}

	if !portExplicit {
		fallbackPort, err := findFreePresentationPortPair(port + 1)
		if err != nil {
			return 0, err
		}
		yellow := color.New(color.FgYellow)
		yellow.Fprintf(humanOut(), "  Note: port %d/%d is already in use (using temporary port %d)\n", port, port+1, fallbackPort)
		return fallbackPort, nil
	}

	if !autoAccept {
		return port, nil
	}

	fallbackPort, err := findFreePresentationPortPair(port + 1)
	if err != nil {
		return 0, fmt.Errorf("resolving temporary auto-accept port after %d was busy: %w", port, err)
	}
	yellow := color.New(color.FgYellow)
	yellow.Fprintf(humanOut(), "  Note: port %d is already in use (auto-accept uses temporary port %d)\n", port, fallbackPort)
	return fallbackPort, nil
}

func presentationPortPairAvailable(port int) bool {
	httpListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = httpListener.Close()

	httpsListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+1))
	if err != nil {
		return false
	}
	_ = httpsListener.Close()
	return true
}

func findFreePresentationPortPair(start int) (int, error) {
	for candidate := start; candidate <= start+100; candidate++ {
		if presentationPortPairAvailable(candidate) {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("could not find free adjacent presentation ports near %d", start)
}

func tryPresentViaRunningServer(uri string, opts dispatchOID4Opts) (bool, error) {
	var baseURL string
	for _, candidate := range runningWalletServerBaseURLs(opts) {
		if isRunningWalletServer(candidate) {
			baseURL = candidate
			break
		}
	}
	if baseURL == "" {
		return false, nil
	}

	if err := checkRemoteOutboundFlags(); err != nil {
		return true, err
	}
	// A running wallet validates with its own --arf setting and relying party CAs.
	if opts.arf || len(opts.relyingPartyCAs) > 0 || len(opts.trustListCAs) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: the wallet running at %s uses its own --arf, --relying-party-ca and --trust-list-ca settings, not these flags\n", baseURL)
	}
	payload := runningWalletPresentationPayload(uri, opts)

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

	// The document prints before any error (ADR 0020).
	if jsonOutput {
		fmt.Println(string(raw))
	}
	switch result.Status {
	case "submitted":
		if !jsonOutput {
			green := color.New(color.FgGreen)
			green.Fprintf(humanOut(), "  Submitted: %s\n", wallet.FormatDirectPostResult(&result.Response))
			if len(result.VPTokenKeys) > 0 {
				fmt.Fprintf(humanOut(), "  VP tokens: %v\n", result.VPTokenKeys)
			}
		}
		return true, verifierRejection(&result.Response)
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

func runningWalletPresentationPayload(uri string, opts dispatchOID4Opts) map[string]any {
	payload := map[string]any{
		"uri": uri,
	}
	if opts.autoAccept {
		payload["auto_accept"] = true
	}
	if opts.sessionTranscript != "" && opts.sessionTranscript != string(wallet.SessionTranscriptOID4VP) {
		payload["session_transcript"] = opts.sessionTranscript
	}
	if opts.haip {
		payload["haip"] = true
	}
	if opts.mode != "" && opts.mode != string(wallet.ValidationModeDebug) {
		payload["mode"] = opts.mode
	}
	return payload
}

func runningWalletServerBaseURLs(opts dispatchOID4Opts) []string {
	seen := map[string]bool{}
	add := func(url string, urls []string) []string {
		if strings.TrimSpace(url) == "" || seen[url] {
			return urls
		}
		seen[url] = true
		return append(urls, url)
	}

	var urls []string
	if !opts.portExplicit {
		urls = add(registeredWalletListenerBaseURL(), urls)
	}
	urls = add(fmt.Sprintf("http://localhost:%d", effectivePresentationPort(opts.port)), urls)
	return urls
}

func registeredWalletListenerBaseURL() string {
	raw, err := os.ReadFile(filepath.Join(config.BaseDir(), "url-handler.sh"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "LISTENER=") {
			continue
		}
		value := strings.TrimPrefix(line, "LISTENER=")
		value = strings.Trim(value, `"'`)
		if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
			return value
		}
	}
	return ""
}

func registeredWalletListenerPort() int {
	raw := registeredWalletListenerBaseURL()
	if raw == "" {
		return 0
	}
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0
	}
	return port
}

func defaultWalletCommandPort() int {
	if port := registeredWalletListenerPort(); port > 0 {
		return port
	}
	return config.DefaultWalletPort
}

func walletPortFromBaseURL(raw string) int {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0
	}
	return port
}

func isLocalWalletIssuerURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return u.Scheme == "https" && (u.Hostname() == "localhost" || u.Hostname() == "host.docker.internal")
}

// A Docker hostname may be intentional. Only realign localhost issuer URLs to the
// registered listener.
func isLocalhostIssuerURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Hostname() == "localhost"
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

// waitForConsent shows a consent UI and waits for the user's decision. It
// returns the matches with the user's changes and a channel that reports the
// submission back to the UI. A denial or a timeout returns an error.
func waitForConsent(w *wallet.Wallet, matches []wallet.CredentialMatch, parsed *oid4vc.AuthorizationRequest, responseURI, addr string, dim *color.Color) ([]wallet.CredentialMatch, chan wallet.SubmissionResult, error) {
	if w.AutoAccept {
		return matches, nil, nil
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

	fmt.Fprintf(humanOut(), "  Consent UI: %s\n", addr)
	_, _ = dim.Fprintln(humanOut(), "───────────────────────────────────────")
	fmt.Fprintln(humanOut(), "Waiting for consent decision...")

	if !noOpen {
		openBrowser(addr)
	}

	select {
	case result := <-consentReq.ResultCh:
		if !result.Approved {
			consentReq.SubmissionCh <- wallet.SubmissionResult{}
			return nil, nil, fmt.Errorf("presentation denied")
		}
		if result.SelectedClaims != nil {
			for i, m := range matches {
				if selectedKeys, ok := result.SelectedClaims[m.CredentialID]; ok {
					matches[i].SelectedKeys = selectedKeys
				}
			}
		}
	case <-time.After(config.ConsentTimeout):
		return nil, nil, fmt.Errorf("consent timeout")
	}

	return matches, consentReq.SubmissionCh, nil
}

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
	result, err := w.SubmitPresentation(vpResult, idToken, parsed.State, responseURI, params, func(response *wallet.AuthorizationResponseEnvelope) {
		w.AddLogPayload("presentation", fmt.Sprintf("Sending presentation response to %s", parsed.ClientID), true, responseDetails, wallet.PresentationLogPayload(response))
	})
	if err != nil {
		w.AddLogPayload("presentation", fmt.Sprintf("Submission failed: %v", err), false, nil, wallet.VerifierResponseErrorPayload(err))
		if submissionCh != nil {
			submissionCh <- wallet.SubmissionResult{Error: err.Error()}
		}
		return fmt.Errorf("submitting presentation: %w", err)
	}

	submission := wallet.SubmissionResult{
		RedirectURI: result.RedirectURI,
		StatusCode:  result.StatusCode,
	}

	if result.StatusCode >= 400 {
		red := color.New(color.FgRed)
		red.Fprintf(humanOut(), "  Error: %s\n", wallet.FormatDirectPostResult(result))
		fmt.Fprintf(humanOut(), "  Body:  %s\n", result.Body)
		submission.Error = result.Body
		w.AddLog("presentation", fmt.Sprintf("Verifier %s rejected: %s", parsed.ClientID, result.Body), false)
	} else {
		green := color.New(color.FgGreen)
		green.Fprintf(humanOut(), "  Submitted: %s\n", wallet.FormatDirectPostResult(result))
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
	_, _ = dim.Fprintln(humanOut(), "───────────────────────────────────────")

	followVerifierRedirect(result.RedirectURI, submissionCh != nil)

	if submissionCh != nil {
		submissionCh <- submission
	}

	if err := store.Save(w); err != nil {
		fmt.Fprintf(os.Stderr, "warning: saving wallet: %v\n", err)
	}

	// POST /api/presentations on a running wallet returns the same document.
	if jsonOutput {
		vpTokenKeys := []string{}
		if vpResult != nil && len(vpResult.QueryIDs()) > 0 {
			vpTokenKeys = vpResult.QueryIDs()
		}
		output.PrintJSON(map[string]any{
			"status":        "submitted",
			"redirect_uri":  result.RedirectURI,
			"response":      result,
			"vp_token_keys": vpTokenKeys,
		})
	}
	return verifierRejection(result)
}

// verifierRejection fails the command when the verifier rejected the
// presentation (ADR 0020).
func verifierRejection(result *wallet.DirectPostResult) error {
	if result.StatusCode >= 400 {
		return fmt.Errorf("the verifier rejected the presentation: %s", wallet.FormatDirectPostResult(result))
	}
	return nil
}

func authorizationRequestParamsFromParsed(parsed *oid4vc.AuthorizationRequest, responseURI, source string) *wallet.AuthorizationRequestParams {
	return &wallet.AuthorizationRequestParams{
		ClientID:         parsed.ClientID,
		ResponseType:     parsed.ResponseType,
		ResponseMode:     parsed.ResponseMode,
		Nonce:            parsed.Nonce,
		State:            parsed.State,
		RedirectURI:      parsed.RedirectURI,
		ResponseURI:      responseURI,
		Scope:            parsed.Scope,
		RequestURIMethod: parsed.RequestURIMethod,
		RequestURI:       parsed.RequestURI,
		ClientMetadata:   parsed.ClientMetadata,
		DCQLQuery:        parsed.DCQLQuery,
		RequestObject:    parsed.RequestObject,
		RequestPayload:   wallet.RequestPayload(parsed.RequestObject, parsed.FullJSON),
		Source:           source,
	}
}

func processCredentialOffer(uri string, opts dispatchOID4Opts) error {
	w, store, err := loadWallet()
	if err != nil {
		return err
	}
	w.KeyAttestationLevel = opts.keyAttestationLevel
	if err := applyValidationMode(w, opts.mode); err != nil {
		return err
	}
	if opts.haip {
		w.RequireHAIP = true
	}
	if err := applyARFOptions(w, opts.arf, opts.relyingPartyCAs, opts.trustListCAs); err != nil {
		return err
	}

	result, err := w.ProcessCredentialOfferWithOptions(uri, wallet.OfferOptions{TxCode: opts.txCode, ResolvedOffer: opts.resolvedOffer})
	if err != nil {
		return fmt.Errorf("processing credential offer: %w", err)
	}

	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}

	printIssuanceResult(result)
	return nil
}

// printIssuanceResult reports a one-shot issuance. With --json, stdout carries
// only the result (ADR 0020).
func printIssuanceResult(result *wallet.IssuanceResult) {
	if result.Pending {
		// Without a wallet server nothing collects a deferred credential
		// later, so say so.
		fmt.Fprintf(humanOut(), "Issuer %s deferred the credential (transaction %s, retry every %s)\n",
			result.Issuer, result.TransactionID, result.RetryInterval)
		fmt.Fprintln(humanOut(), "Run 'eudi wallet serve' and accept the offer there to have the wallet collect it in the background.")
	} else {
		fmt.Fprintf(humanOut(), "Received %s credential from %s (ID: %s)\n", result.Format, result.Issuer, result.CredentialID)
		if result.VerificationDetail != "" {
			fmt.Fprintf(humanOut(), "Verification: %s", result.VerificationDetail)
			if result.VerificationStatus != "" {
				fmt.Fprintf(humanOut(), " [%s]", result.VerificationStatus)
			}
			fmt.Fprintln(humanOut())
		}
	}
	if jsonOutput {
		output.PrintJSON(result)
	}
}

// OpenID4VP 1.0 section 8.2 returns the browser to the verifier. Print the redirect
// URL, but open it only for an interactive CLI when the consent tab is not already
// navigating there.
func followVerifierRedirect(redirectURI string, browserWaiting bool) {
	if redirectURI == "" {
		return
	}
	fmt.Fprintf(humanOut(), "  Continue at: %s\n", redirectURI)
	if stdinIsTerminal() && navigatesHere(browserWaiting) {
		openBrowser(redirectURI)
	}
}

// Navigate only when no browser tab owns the flow. PAR request_uri values can be used
// once (RFC 9126 §4), and verifier redirect sessions are consumed after use (OpenID4VP
// 1.0 §13.3, steps 7 to 10). A second navigation can fail.
func navigatesHere(browserWaiting bool) bool {
	return !noOpen && !browserWaiting
}

// applyARFOptions turns on --arf and loads the PEM files of
// --relying-party-ca and --trust-list-ca.
func applyARFOptions(w *wallet.Wallet, arf bool, relyingPartyCAs, trustListCAs []string) error {
	if arf {
		w.RequireARF = true
	}
	var err error
	if w.RelyingPartyCAPEM, err = loadPEMCertificates("relying-party-ca", relyingPartyCAs); err != nil {
		return err
	}
	w.TrustListCAPEM, err = loadPEMCertificates("trust-list-ca", trustListCAs)
	return err
}

// loadPEMCertificates reads the PEM files of a CA flag into one bundle.
func loadPEMCertificates(flag string, paths []string) ([]byte, error) {
	var bundle []byte
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading --%s: %w", flag, err)
		}
		if !x509.NewCertPool().AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("--%s %s holds no PEM certificate", flag, path)
		}
		bundle = append(append(bundle, data...), '\n')
	}
	return bundle, nil
}
