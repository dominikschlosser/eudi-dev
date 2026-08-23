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

// Output helpers for the wallet management commands. They format the wallet
// server's API document shapes, which both walletService backends produce,
// so managing the local store and a remote instance print identically. The
// remote-only operations that have no local equivalent (accept flows and the
// deprecated generate-pid) live here too.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/output"
	"github.com/dominikschlosser/eudi-dev/internal/remote"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
)

func docString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// docNumber reads a number out of a wallet document. The same document is
// built by both backends, but one travels through JSON (where every number is
// a float64) and the other is handed over in this process with its Go type
// intact. Reading only float64 makes a listing disagree with itself depending
// on which backend answered.
func docNumber(m map[string]any, key string) (float64, bool) {
	switch v := m[key].(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		parsed, err := v.Float64()
		return parsed, err == nil
	}
	return 0, false
}

func docCredLabel(cred map[string]any) string {
	if vct := docString(cred, "vct"); vct != "" {
		return vct
	}
	if doctype := docString(cred, "doctype"); doctype != "" {
		return doctype
	}
	return docString(cred, "format")
}

// warnAboutCredential reports what an imported credential cannot do: be
// presented, because the wallet does not hold the key it is bound to, or be
// verified, because its issuer key is named by a DID. Both go to stderr so a
// JSON listing stays machine-readable.
func warnAboutCredential(cred map[string]any) {
	if notHeld, _ := cred["key_binding_not_held"].(bool); notHeld {
		fmt.Fprintln(os.Stderr, "Warning: this credential is bound to a holder key the wallet does not hold. It can be listed and decoded, but presenting it fails the verifier's key binding check.")
	}
	if did, _ := cred["issuer_key_did"].(string); did != "" {
		fmt.Fprintf(os.Stderr, "Warning: this credential names its issuer key by the DID %s. Nothing here resolves a DID (HAIP 1.0 §6.1.1 puts the issuer's signing certificate in x5c), so its issuer signature is not verified.\n", did)
	}
}

func printCredentialList(creds []map[string]any, deferred []map[string]any) error {
	if len(creds) == 0 && len(deferred) == 0 {
		fmt.Println("No credentials stored.")
		return nil
	}
	if jsonOutput {
		out := map[string]any{"credentials": creds}
		if len(deferred) > 0 {
			out["deferred"] = deferred
		}
		data, err := json.Marshal(out)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tFORMAT\tTYPE\tCLAIMS\tVALID\tSTATUS")
	for _, cred := range creds {
		claims, _ := cred["claims"].(map[string]any)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			docString(cred, "id"), docString(cred, "format"), docCredLabel(cred), len(claims),
			credValidityLabel(cred), credStatusLabel(cred))
	}
	for _, entry := range deferred {
		// The credential type when the issuer's metadata named one, so a
		// waiting row reads like a delivered one. The configuration id is an
		// issuer's internal name and only a fallback.
		label := docCredLabel(entry)
		if label == "" {
			label = docString(entry, "credential_configuration_id")
		}
		if label == "" {
			label = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t-\t-\t%s\n",
			docString(entry, "id"), docString(entry, "format"), label, "deferred")
	}
	return tw.Flush()
}

// printDeferredDoc reports where a deferred issuance stands: who owes the
// credential, and when the wallet asks next.
func printDeferredDoc(entry map[string]any) error {
	if jsonOutput {
		data, err := json.MarshalIndent(entry, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	fmt.Println("Status:         deferred (the issuer has not handed it over yet)")
	fmt.Printf("Issuer:         %s\n", docString(entry, "issuer"))
	if credType := docCredLabel(entry); credType != "" && credType != docString(entry, "format") {
		fmt.Printf("Type:           %s\n", credType)
	}
	if configID := docString(entry, "credential_configuration_id"); configID != "" {
		fmt.Printf("Configuration:  %s\n", configID)
	}
	if credFormat := docString(entry, "format"); credFormat != "" {
		fmt.Printf("Format:         %s\n", credFormat)
	}
	fmt.Printf("Transaction:    %s\n", docString(entry, "transaction_id"))
	fmt.Printf("Retry interval: %s\n", docString(entry, "interval"))
	if next := docString(entry, "next_attempt_at"); next != "" {
		if parsed, err := time.Parse(time.RFC3339, next); err == nil {
			fmt.Printf("Next attempt:   %s\n", parsed.Local().Format(time.Kitchen))
		}
	}
	if attempts, ok := docNumber(entry, "attempts"); ok && attempts > 0 {
		fmt.Printf("Attempts:       %d\n", int(attempts))
	}
	if lastErr := docString(entry, "last_error"); lastErr != "" {
		fmt.Printf("Last error:     %s\n", lastErr)
	}
	return nil
}

// credStatusLabel summarizes revocation state and protection for the list,
// e.g. "active, protected". Empty when the wallet knows neither.
func credStatusLabel(cred map[string]any) string {
	var parts []string
	if status, ok := cred["status"].(map[string]any); ok {
		value, hasValue := docNumber(status, "status")
		switch {
		case hasValue && value == 1:
			parts = append(parts, "revoked")
		case hasValue:
			parts = append(parts, "active")
		case status["uri"] != nil:
			// Referenced somewhere else: this wallet cannot resolve it here.
			parts = append(parts, "external")
		}
	}
	if protected, _ := cred["protected"].(bool); protected {
		parts = append(parts, "protected")
	}
	// A batch reads as one credential here too, marked with its copy count so
	// the rotation of copies is not a surprise (the list shows the holder copy).
	if batch, _ := cred["batch"].(bool); batch {
		if size, ok := docNumber(cred, "batch_size"); ok && size >= 2 {
			parts = append(parts, fmt.Sprintf("batch of %d", int(size)))
		} else {
			parts = append(parts, "batch")
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// credExpiry reads the expiry every credential listing carries. A credential
// that states no lifetime has none, which is not the same as an expired one.
func credExpiry(cred map[string]any) (time.Time, bool) {
	raw := docString(cred, "expires_at")
	if raw == "" {
		return time.Time{}, false
	}
	when, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return when, true
}

// credValidityLabel is the list column: how much longer the credential is
// good for, in the one unit worth reading. It floors, so it never claims more
// time than there is.
func credValidityLabel(cred map[string]any) string {
	when, ok := credExpiry(cred)
	if !ok {
		return "-"
	}
	remaining := time.Until(when)
	if remaining <= 0 {
		return "expired"
	}
	switch {
	case remaining >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(remaining.Hours()/24))
	case remaining >= 2*time.Hour:
		return fmt.Sprintf("%dh", int(remaining.Hours()))
	case remaining >= time.Minute:
		return fmt.Sprintf("%dm", int(remaining.Minutes()))
	default:
		return "<1m"
	}
}

func printCredentialDoc(cred map[string]any, decoded bool) error {
	raw := docString(cred, "raw")
	if !decoded {
		// The documented contract of this form is the credential string and
		// nothing else, so that it can be piped.
		fmt.Println(raw)
		return nil
	}
	// The decoded payload states the expiry as a Unix timestamp, which is not
	// an answer to "is this still good".
	if !jsonOutput {
		when, hasExpiry := credExpiry(cred)
		isBatch, _ := cred["batch"].(bool)
		if hasExpiry {
			validity := "expired " + when.Local().Format(time.RFC1123)
			if time.Until(when) > 0 {
				validity = "valid for " + credValidityLabel(cred) + ", until " + when.Local().Format(time.RFC1123)
			}
			fmt.Printf("Validity: %s\n", validity)
		}
		if isBatch {
			copies := "several copies"
			if size, ok := docNumber(cred, "batch_size"); ok && size >= 2 {
				copies = fmt.Sprintf("%d copies", int(size))
			}
			fmt.Printf("Batch:    yes (the wallet holds %s and presents an unused one each time)\n", copies)
		}
		if hasExpiry || isBatch {
			fmt.Println()
		}
	}
	opts := output.Options{JSON: jsonOutput, NoColor: noColor, Verbose: verbose}
	switch docString(cred, "format") {
	case "dc+sd-jwt":
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return err
		}
		output.PrintSDJWT(token, opts)
	case "mso_mdoc":
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return err
		}
		output.PrintMDOC(doc, opts)
	case "jwt_vc_json":
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return err
		}
		output.PrintJWT(token, opts)
	}
	return nil
}

func remoteGeneratePID(c *remote.Client, claims map[string]any, vct string) error {
	if err := c.GeneratePID(claims, vct); err != nil {
		return err
	}
	fmt.Println("Generated default EUDI PID credentials (SD-JWT + mDoc)")
	return nil
}

func remoteAccept(c *remote.Client, uri, txCode string, interactive bool) error {
	isVCI := isCredentialOfferURI(uri)
	// Open the wallet UI so the consent dialog it is about to show is visible,
	// naming the page so the request submitted below reaches it. A shared
	// wallet then opens the dialog there rather than offering it to everyone.
	if interactive && !noOpen {
		owner := remote.NewOwnerToken()
		target := strings.TrimRight(c.BaseURL, "/") + "/?focus=overview&owner=" + url.QueryEscape(owner)
		if openBrowser(target) {
			c.ActingFor(owner)
		} else {
			fmt.Printf("Waiting for consent at: %s\n", strings.TrimRight(c.BaseURL, "/"))
		}
	}
	var result map[string]any
	var err error
	if isVCI {
		result, err = c.AcceptOffer(uri, txCode, interactive)
	} else {
		result, err = c.Present(uri, interactive)
	}
	if err != nil {
		return err
	}
	if status, _ := result["status"].(string); status == "authorization_required" {
		result, err = completeSignIn(c, result)
		if err != nil {
			return err
		}
	}
	data, marshalErr := json.MarshalIndent(result, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	fmt.Println(string(data))
	return nil
}

// signInPollInterval is how often the CLI asks how a sign-in went. The wait
// itself is bounded by config.AuthorizationCallbackWait, the same span the
// flow being watched uses.
const signInPollInterval = 2 * time.Second

// completeSignIn handles an offer the issuer wants the user to sign in for.
// The wallet cannot do this itself (on a hosted one the browser that matters
// is here, not there), so it hands over the URL and keeps the flow open. The
// sign-in redirects back to the wallet, which finishes the issuance.
func completeSignIn(c *remote.Client, pending map[string]any) (map[string]any, error) {
	authURL, _ := pending["authorization_url"].(string)
	offerID, _ := pending["offer_id"].(string)
	if authURL == "" || offerID == "" {
		return nil, fmt.Errorf("wallet asked for a sign-in but did not say where")
	}

	fmt.Fprintf(os.Stderr, "Sign in to continue: %s\n", authURL)
	if opensSignInHere(c) {
		openBrowser(authURL)
	}

	deadline := time.Now().Add(config.AuthorizationCallbackWait)
	for {
		time.Sleep(signInPollInterval)
		status, err := c.OfferStatus(offerID)
		if err != nil {
			return nil, fmt.Errorf("checking the offer: %w", err)
		}
		switch state, _ := status["status"].(string); state {
		case "authorization_required":
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("gave up waiting for the sign-in at %s", authURL)
			}
		case "failed":
			msg, _ := status["error"].(string)
			return nil, fmt.Errorf("issuance failed after sign-in: %s", msg)
		default:
			if result, ok := status["result"].(map[string]any); ok {
				return result, nil
			}
			return status, nil
		}
	}
}

// isCredentialOfferURI reports whether a URI is an OID4VCI credential offer
// (matching the wallet UI's detection).
func isCredentialOfferURI(uri string) bool {
	return strings.Contains(uri, "credential_offer") ||
		strings.HasPrefix(uri, "openid-credential-offer://") ||
		strings.HasPrefix(uri, "haip-vci://")
}

// opensSignInHere reports whether this process navigates to the authorization
// URL itself. A client that named a page does not: the wallet sends that page
// there.
func opensSignInHere(c *remote.Client) bool {
	return navigatesHere(c.ActsForAPage())
}
