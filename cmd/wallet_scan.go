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
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/internal/qr"
)

// resolveTxCode returns the transaction code for an offer. A code passed on
// the command line wins. Otherwise, if the offer requires one and there is a
// terminal to type it into, ask: the issuer delivers it out of band, so the
// person running the command is the only source.
//
// Anything that goes wrong (not a VCI offer, an offer that cannot be fetched,
// no terminal) leaves the code empty and lets the flow run, because the
// issuer's own error is clearer than a guess.
func resolveTxCode(uri, given string) string {
	if strings.TrimSpace(given) != "" {
		return given
	}
	if !isCredentialOfferURI(uri) || !stdinIsTerminal() {
		return given
	}
	reqType, parsed, err := oid4vc.Parse(uri)
	if err != nil || reqType != oid4vc.TypeVCI {
		return given
	}
	offer, ok := parsed.(*oid4vc.CredentialOffer)
	if !ok || len(offer.Grants.TxCode) == 0 {
		return given
	}

	prompt := "Transaction code"
	if hint := describeTxCodePrompt(offer.Grants.TxCode); hint != "" {
		prompt += " (" + hint + ")"
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return given
	}
	return strings.TrimSpace(line)
}

// describeTxCodePrompt summarizes a tx_code object for the prompt.
func describeTxCodePrompt(txCode map[string]any) string {
	if description, _ := txCode["description"].(string); strings.TrimSpace(description) != "" {
		return strings.TrimSpace(description)
	}
	mode, _ := txCode["input_mode"].(string)
	length := 0
	switch n := txCode["length"].(type) {
	case float64:
		length = int(n)
	case int:
		length = n
	}
	switch {
	case length > 0 && mode != "":
		return fmt.Sprintf("%d %s characters", length, mode)
	case length > 0:
		return fmt.Sprintf("%d characters", length)
	default:
		return mode
	}
}

// stdinIsTerminal reports whether there is someone to answer a prompt.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// acceptOID4URI processes an OID4VP presentation request or OID4VCI credential
// offer the way `wallet accept` does. It resolves any transaction code, then
// routes to a running or remote wallet when one is configured, which shows its
// own consent dialog unless the user asked to auto-accept (the same as the
// local flow and the macOS URL handler); otherwise it runs the local flow.
// `wallet scan` shares it, so a scanned request behaves exactly like a supplied
// one.
func acceptOID4URI(uri string, opts dispatchOID4Opts) error {
	opts.txCode = resolveTxCode(uri, opts.txCode)
	if c, err := remoteClientIfConfigured(); err != nil {
		return err
	} else if c != nil {
		return remoteAccept(c, uri, opts.txCode, !opts.autoAccept)
	}
	return dispatchURI(uri, opts)
}

func walletAcceptCmd() *cobra.Command {
	var (
		port              int
		autoAccept        bool
		sessionTranscript string
		txCode            string
		haip              bool
	)

	cmd := &cobra.Command{
		Use:   "accept <uri>",
		Short: "Accept and process an OID4VP presentation request or OID4VCI credential offer",
		Long: `Auto-detects the URI type and dispatches to the appropriate flow:

  - openid4vp://, haip-vp://, eudi-openid4vp://     →  OID4VP presentation
  - openid-credential-offer://, haip-vci://         →  OID4VCI credential issuance

For OID4VP requests, the wallet evaluates the DCQL query, shows a consent UI
(unless --auto-accept), and submits a VP token to the verifier.

For OID4VCI offers, the wallet fetches the credential from the issuer and
stores it locally. A running wallet server reloads the same wallet store at
request boundaries, so later presentation requests see the new credential.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return acceptOID4URI(args[0], dispatchOID4Opts{
				port:              port,
				portExplicit:      cmd.Flags().Changed("port"),
				autoAccept:        autoAccept,
				sessionTranscript: sessionTranscript,
				txCode:            txCode,
				haip:              haip,
				mode:              walletValidationMode,
			})
		},
	}

	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Server port for OID4VP (serves trust list and consent UI)")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "Auto-approve OID4VP presentations")
	cmd.Flags().StringVar(&sessionTranscript, "session-transcript", "oid4vp", "mDoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	cmd.Flags().StringVar(&txCode, "tx-code", "", "Transaction code for OID4VCI pre-authorized code flow")
	cmd.Flags().BoolVar(&haip, "haip", false, "Enforce HAIP 1.0 on presentations (x509_hash, direct_post.jwt, DCQL, JAR, ES256) and on credential offers (https issuer; authorization code offers also need PAR, PKCE S256, DPoP, client auth)")
	return cmd
}

func walletScanCmd() *cobra.Command {
	var (
		port              int
		screen            bool
		autoAccept        bool
		sessionTranscript string
		txCode            string
		haip              bool
	)

	cmd := &cobra.Command{
		Use:   "scan [image-file]",
		Short: "Scan QR code and auto-detect flow (accept/import)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var content string
			var err error

			if screen {
				content, err = qr.ScanScreen()
			} else if len(args) > 0 {
				content, err = qr.ScanFile(args[0])
			} else {
				return fmt.Errorf("provide an image file or use --screen")
			}

			if err != nil {
				return fmt.Errorf("scanning QR: %w", err)
			}

			fmt.Printf("Scanned: %s\n\n", content)

			detected := format.Detect(content)

			// For credential formats, import into the managed wallet
			if detected == format.FormatSDJWT || detected == format.FormatMDOC || detected == format.FormatJWT {
				svc, err := managedWallet()
				if err != nil {
					return err
				}
				imported, err := svc.ImportCredential(content)
				if err != nil {
					return err
				}
				fmt.Printf("Imported %s credential (%s)\n", docString(imported, "format"), docCredLabel(imported))
				return nil
			}

			// For OID4 URIs, accept the scanned request exactly like `wallet
			// accept`: route to a running or remote wallet when one is
			// configured, otherwise run the local flow.
			return acceptOID4URI(content, dispatchOID4Opts{
				port:              port,
				portExplicit:      cmd.Flags().Changed("port"),
				autoAccept:        autoAccept,
				sessionTranscript: sessionTranscript,
				txCode:            txCode,
				haip:              haip,
				mode:              walletValidationMode,
			})
		},
	}

	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Server port (serves trust list and consent UI)")
	cmd.Flags().BoolVar(&screen, "screen", false, "Interactive screen capture (macOS)")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "Auto-approve presentations")
	cmd.Flags().StringVar(&sessionTranscript, "session-transcript", "oid4vp", "mDoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	cmd.Flags().StringVar(&txCode, "tx-code", "", "Transaction code for OID4VCI pre-authorized code flow")
	cmd.Flags().BoolVar(&haip, "haip", false, "Enforce HAIP 1.0 on presentations (x509_hash, direct_post.jwt, DCQL, JAR, ES256) and on credential offers (https issuer; authorization code offers also need PAR, PKCE S256, DPoP, client auth)")
	return cmd
}
