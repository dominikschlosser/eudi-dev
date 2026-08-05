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
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/remote"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

var walletDir string
var templatesDir string
var walletValidationMode string

var walletCmd = &cobra.Command{
	Use:   "wallet",
	Short: "Manage a local testing wallet for OID4VP/OID4VCI flows",
	Long:  "Stateful wallet with file persistence. Supports credential management, OID4VP presentations, OID4VCI issuance, QR scanning, and URL scheme registration.",
}

func init() {
	walletCmd.PersistentFlags().StringVar(&walletDir, "wallet-dir", "", "Wallet storage directory (default ~/.eudi-dev/wallet/, legacy ~/.oid4vc-dev/wallet/ keeps working)")
	walletCmd.PersistentFlags().StringVar(&remoteFlag, "remote", "", "Manage a remote wallet server at this URL for this invocation (\"local\" forces the local store)")
	walletCmd.PersistentFlags().StringVar(&templatesDir, "templates-dir", "", "Credential template directory (default <wallet-dir>/templates/)")
	walletCmd.PersistentFlags().StringVar(&walletValidationMode, "mode", string(wallet.ValidationModeDebug), "Wallet validation mode: 'debug' (default) or 'strict'")
	walletCmd.AddCommand(walletServeCmd())
	walletCmd.AddCommand(walletListCmd())
	walletCmd.AddCommand(walletShowCmd())
	walletCmd.AddCommand(walletImportCmd())
	walletCmd.AddCommand(walletRemoveCmd())
	walletCmd.AddCommand(walletGeneratePIDCmd())
	walletCmd.AddCommand(walletAcceptCmd())
	walletCmd.AddCommand(walletScanCmd())
	walletCmd.AddCommand(walletLogsCmd())
	walletCmd.AddCommand(walletDeferredCmd())
	walletCmd.AddCommand(walletRegisterCmd())
	walletCmd.AddCommand(walletUnregisterCmd())
	walletCmd.AddCommand(walletTrustListCmd())
	walletCmd.AddCommand(walletCACertCmd())
	walletCmd.AddCommand(walletTLSCertCmd())
	walletCmd.AddCommand(walletInfoCmd())
	walletCmd.AddCommand(walletInstancesCmd())

	// Deprecated aliases (hidden from help)
	presentAlias := &cobra.Command{
		Use:        "present <uri>",
		Short:      "Deprecated: use 'wallet accept' instead",
		Hidden:     true,
		Deprecated: "use 'wallet accept' instead",
		Args:       cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Delegate to accept
			acceptCmd, _, _ := walletCmd.Find([]string{"accept"})
			acceptCmd.SetArgs(args)
			return acceptCmd.RunE(acceptCmd, args)
		},
	}
	walletCmd.AddCommand(presentAlias)

	listenAlias := &cobra.Command{
		Use:        "listen",
		Short:      "Deprecated: use 'wallet serve --register' instead",
		Hidden:     true,
		Deprecated: "use 'wallet serve --register' instead",
		RunE: func(cmd *cobra.Command, args []string) error {
			serveCmd, _, _ := walletCmd.Find([]string{"serve"})
			_ = serveCmd.Flags().Set("register", "true")
			return serveCmd.RunE(serveCmd, args)
		},
	}
	walletCmd.AddCommand(listenAlias)

	// Shell completion for knowable values
	_ = walletCmd.RegisterFlagCompletionFunc("remote", completeRemoteFlag)
	_ = walletCmd.RegisterFlagCompletionFunc("mode", staticCompletion("debug", "strict"))
	_ = walletCmd.MarkPersistentFlagDirname("wallet-dir")
	_ = walletCmd.MarkPersistentFlagDirname("templates-dir")

	rootCmd.AddCommand(walletCmd)
}

// loadStore creates a WalletStore from the --wallet-dir flag.
func loadStore() *wallet.WalletStore {
	return wallet.NewWalletStore(walletDir)
}

// loadWallet loads the wallet from the store, creating it if needed.
func loadWallet() (*wallet.Wallet, *wallet.WalletStore, error) {
	store := loadStore()
	w, err := store.LoadOrCreate()
	if err != nil {
		return nil, nil, fmt.Errorf("loading wallet: %w", err)
	}
	if templatesDir != "" {
		w.TemplatesDir = templatesDir
	}
	if err := applyValidationMode(w, walletValidationMode); err != nil {
		return nil, nil, err
	}
	return w, store, nil
}

func applyValidationMode(w *wallet.Wallet, raw string) error {
	mode, err := wallet.ParseValidationMode(raw)
	if err != nil {
		return err
	}
	w.ValidationMode = mode
	return nil
}

// warnIssuedEndpointsOffline notes after a direct (unrouted) issuance that
// the issuer and status list URLs embedded in the new credential only
// resolve once a wallet server runs for this wallet directory.
func warnIssuedEndpointsOffline(store *wallet.WalletStore, w *wallet.Wallet) {
	if strings.TrimSpace(w.IssuerURL) == "" {
		return
	}
	if remote.InstanceForWalletDir(store.Dir, 300*time.Millisecond) != nil {
		return
	}
	fmt.Fprintf(os.Stderr, "Note: the embedded issuer and status list URLs point at %s. They resolve once `%s wallet serve` runs.\n", w.IssuerURL, binaryName())
}

func deriveWalletIssuerURL(port int, baseURL string, docker bool) (string, error) {
	if baseURL != "" {
		// An https base URL means a TLS terminator already serves the wallet
		// on that origin. Issuer metadata, status list and trust list can
		// live there directly instead of on a second self-signed listener.
		if u, err := url.Parse(strings.TrimSpace(baseURL)); err == nil && strings.EqualFold(u.Scheme, "https") {
			return strings.TrimRight(strings.TrimSpace(baseURL), "/"), nil
		}
		return wallet.IssuerURLFromBaseURL(baseURL, port+1)
	}
	return wallet.LocalIssuerURL(port+1, docker), nil
}

// issuerServedByBaseURL reports whether the issuer origin equals the base
// URL, i.e. no separate HTTPS listener is needed because an external TLS
// terminator serves both.
func issuerServedByBaseURL(issuerURL, baseURL string) bool {
	trim := func(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }
	return trim(issuerURL) != "" && trim(issuerURL) == trim(baseURL)
}

func configureIssuerTLSCertificate(srv *wallet.Server, store *wallet.WalletStore, issuerURL string) error {
	cert, err := store.LoadOrCreateIssuerTLSCertificateForURL(issuerURL)
	if err != nil {
		return fmt.Errorf("loading issuer TLS certificate: %w", err)
	}
	srv.SetIssuerTLSCertificate(cert)
	return nil
}

// --- wallet list ---

func walletListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			creds, err := svc.Credentials()
			if err != nil {
				return err
			}
			// A deferred credential is not in the store yet but is on its way.
			// Leaving it out makes a running issuance look like one that
			// never happened.
			deferred, err := svc.DeferredIssuances()
			if err != nil {
				return err
			}
			return printCredentialList(creds, deferred)
		},
	}
}

// --- wallet show ---

func walletShowCmd() *cobra.Command {
	var decoded bool
	cmd := &cobra.Command{
		Use:               "show <id>",
		Short:             "Show a stored credential",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeCredentialIDs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			// A deferred issuance answers to its own id, so show where it
			// stands instead of "credential not found".
			deferred, derr := svc.DeferredIssuances()
			if derr == nil {
				for _, entry := range deferred {
					if docString(entry, "id") == args[0] {
						return printDeferredDoc(entry)
					}
				}
			}
			cred, err := svc.Credential(args[0])
			if err != nil {
				return err
			}
			return printCredentialDoc(cred, decoded)
		},
	}
	cmd.Flags().BoolVar(&decoded, "decoded", false, "Show human-readable decoded output instead of raw")
	return cmd
}

// --- wallet import ---

func walletImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import [file-or-raw]",
		Short: "Import credential to store",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := "-" // stdin by default
			if len(args) > 0 {
				input = args[0]
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			raw, err := format.ReadInputRaw(input)
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			imported, err := svc.ImportCredential(raw)
			if err != nil {
				return err
			}
			claims, _ := imported["claims"].(map[string]any)
			fmt.Printf("Imported %s credential (%s) with %d claims\n", docString(imported, "format"), docCredLabel(imported), len(claims))
			return nil
		},
	}
}

// --- wallet remove ---

func walletRemoveCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:               "remove <id>",
		Short:             "Remove credential by ID",
		ValidArgsFunction: completeCredentialIDs,
		Args: func(cmd *cobra.Command, args []string) error {
			if all {
				if len(args) != 0 {
					return fmt.Errorf("--all does not take a credential ID")
				}
				return nil
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if all {
				count, err := svc.RemoveAllCredentials()
				if err != nil {
					return err
				}
				fmt.Printf("Removed %d credential(s)\n", count)
				return nil
			}
			if err := svc.RemoveCredential(args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed credential %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Remove all stored credentials")
	return cmd
}

// --- wallet register ---

func walletRegisterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                "register [wallet-serve-flags...]",
		Short:              "Register OS URL scheme handlers (openid4vp://, haip-vp://, openid-credential-offer://, haip-vci://)",
		Long:               "Stores the provided arguments and replays them as 'wallet serve ...' when the OS URL handler needs to auto-start the wallet listener.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if arg == "-h" || arg == "--help" {
					return cmd.Help()
				}
			}
			opts, err := walletRegisterOptions(args)
			if err != nil {
				return err
			}
			opts.ServeArgs = append(walletRegisterInheritedServeArgs(cmd), opts.ServeArgs...)
			return wallet.RegisterURLSchemes(opts)
		},
	}
	return cmd
}

func walletRegisterInheritedServeArgs(cmd *cobra.Command) []string {
	args := []string{}
	visitChangedPersistentFlags(cmd, func(flag *pflag.Flag) {
		if flag.Name == "wallet-dir" || flag.Name == "mode" {
			args = append(args, "--"+flag.Name, flag.Value.String())
		}
	})
	return args
}

func visitChangedPersistentFlags(cmd *cobra.Command, visit func(*pflag.Flag)) {
	parents := []*cobra.Command{}
	for parent := cmd.Parent(); parent != nil; parent = parent.Parent() {
		parents = append(parents, parent)
	}
	for i := len(parents) - 1; i >= 0; i-- {
		parents[i].PersistentFlags().Visit(visit)
	}
}

func walletRegisterOptions(args []string) (wallet.RegisterOptions, error) {
	port := config.DefaultWalletPort
	autoAccept := false

	flags := pflag.NewFlagSet("wallet-register", pflag.ContinueOnError)
	flags.ParseErrorsWhitelist.UnknownFlags = true
	flags.IntVar(&port, "port", config.DefaultWalletPort, "")
	flags.BoolVar(&autoAccept, "auto-accept", false, "")
	if err := flags.Parse(args); err != nil {
		return wallet.RegisterOptions{}, fmt.Errorf("parsing wallet serve arguments for registration: %w", err)
	}

	return wallet.RegisterOptions{
		ListenerPort: port,
		AutoAccept:   autoAccept,
		ServeArgs:    append([]string(nil), args...),
	}, nil
}

// --- wallet unregister ---

func walletUnregisterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unregister",
		Short: "Remove OS URL scheme handlers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return wallet.UnregisterURLSchemes()
		},
	}
}

// --- wallet trust-list ---

// trustListPath builds the endpoint a selection resolves to, so the URL the
// command prints and the one it fetches cannot drift apart.
func trustListPath(id, vct, docType string) string {
	if id != "" {
		return "/api/trustlists/" + url.PathEscape(id)
	}
	query := url.Values{}
	if vct != "" {
		query.Set("vct", vct)
	}
	if docType != "" {
		query.Set("doctype", docType)
	}
	if encoded := query.Encode(); encoded != "" {
		return "/api/trustlist?" + encoded
	}
	return "/api/trustlist"
}

func walletTrustListCmd() *cobra.Command {
	var (
		port    int
		docker  bool
		urlOnly bool
		list    bool
		id      string
		vct     string
		docType string
	)

	cmd := &cobra.Command{
		Use:   "trust-list",
		Short: "Print the trust list JWT for this wallet (or just the URL)",
		Long: `Generates and prints the ETSI trust list JWT containing the wallet's issuer certificate.
The output can be piped to a file or used directly with --trust-list in the validate command.

Without selection flags, this prints the same legacy PID-first trust list as /api/trustlist.
Use --id, --vct, or --doctype to select a specific trust-list profile.
Use --list to see which profiles this wallet serves.
Use --url to print only the trust list URL for a running wallet server instead.

Every profile carries the same certificate, the wallet's own CA. They differ in
what they declare it to be, so pick the one matching what is being verified.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if id != "" && (vct != "" || docType != "") {
				return fmt.Errorf("--id cannot be combined with --vct or --doctype")
			}
			if list && (id != "" || vct != "" || docType != "" || urlOnly) {
				return fmt.Errorf("--list prints every profile, so it takes no selection flags")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// The trust list belongs to the wallet that serves it, and every
			// wallet has its own CA. Reading the local store while the CLI is
			// pointed at a remote one would print an anchor that validates
			// nothing it issues.
			client, err := remoteClientIfConfigured()
			if err != nil {
				return err
			}

			if list {
				return printTrustListIndex(client)
			}

			if urlOnly {
				path := trustListPath(id, vct, docType)
				switch {
				case client != nil:
					fmt.Printf("%s%s\n", client.BaseURL, path)
				case docker:
					fmt.Printf("http://host.docker.internal:%d%s\n", port, path)
				default:
					fmt.Printf("http://localhost:%d%s\n", port, path)
				}
				return nil
			}

			if client != nil {
				jwt, err := client.TrustList(id, vct, docType)
				if err != nil {
					return err
				}
				fmt.Println(jwt)
				return nil
			}

			w, _, err := loadWallet()
			if err != nil {
				return err
			}

			if w.CAKey == nil || len(w.CertChain) < 2 {
				return fmt.Errorf("wallet has no CA certificate chain")
			}
			group, ok := wallet.FindTrustListGroupForWallet(w, id, vct, docType)
			if !ok {
				return fmt.Errorf("wallet has no matching trust-list profile")
			}
			path := "/api/trustlist"
			if id != "" {
				path = "/api/trustlists/" + group.ID
			}
			jwt, err := wallet.GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, path)
			if err != nil {
				return fmt.Errorf("generating trust list: %w", err)
			}

			fmt.Println(jwt)
			return nil
		},
	}

	cmd.Flags().BoolVar(&urlOnly, "url", false, "Print only the trust list URL (for a running wallet server)")
	cmd.Flags().BoolVar(&list, "list", false, "List the trust list profiles this wallet serves instead of printing one")
	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Wallet server port (used with --url)")
	cmd.Flags().BoolVar(&docker, "docker", false, "Use host.docker.internal instead of localhost (used with --url)")
	cmd.Flags().StringVar(&id, "id", "", "Trust-list profile ID to print, for example 'pid', 'wallet-provider' or 'local'")
	cmd.Flags().StringVar(&vct, "vct", "", "Select the trust list covering this SD-JWT VCT")
	cmd.Flags().StringVar(&docType, "doctype", "", "Select the trust list covering this mdoc docType")
	return cmd
}

// certificateExportFormat maps the --pem/--jwks flags to the certificate
// export format shared by the walletService backends: PEM is the default,
// JWKS is a document with the leaf public key and the chain as x5c.
func certificateExportFormat(asPEM, asJWKS bool) (string, error) {
	if asPEM && asJWKS {
		return "", fmt.Errorf("--pem and --jwks are mutually exclusive")
	}
	if asJWKS {
		return "jwks", nil
	}
	return "pem", nil
}

// writeCertificateExport writes exported certificate data to --out (printing
// the path) or to stdout.
func writeCertificateExport(cmd *cobra.Command, kind string, data []byte, outPath string) error {
	if outPath != "" {
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			return fmt.Errorf("writing wallet %s certificate: %w", kind, err)
		}
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), outPath); err != nil {
			return fmt.Errorf("writing wallet %s certificate path: %w", kind, err)
		}
		return nil
	}
	if _, err := fmt.Fprint(cmd.OutOrStdout(), string(data)); err != nil {
		return fmt.Errorf("writing wallet %s certificate: %w", kind, err)
	}
	return nil
}

func walletCACertCmd() *cobra.Command {
	var (
		outPath string
		asPEM   bool
		asJWKS  bool
	)

	cmd := &cobra.Command{
		Use:   "ca-cert",
		Short: "Print or export the shared wallet CA certificate",
		Long: `Loads or creates the shared wallet CA certificate and prints it as PEM.
All wallets under the same wallet base directory use this CA for trust lists,
status list x5c chains, issuer-metadata x5c chains, and HTTPS wallet endpoints.

Use --jwks to export the certificate as a JWKS document (public key with x5c
chain).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			certFormat, err := certificateExportFormat(asPEM, asJWKS)
			if err != nil {
				return err
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			certData, err := svc.Certificate("ca", certFormat, walletCertOptions{})
			if err != nil {
				return err
			}
			return writeCertificateExport(cmd, "CA", certData, outPath)
		},
	}

	cmd.Flags().StringVar(&outPath, "out", "", "Write the shared wallet CA certificate to a file instead of stdout")
	cmd.Flags().BoolVar(&asPEM, "pem", false, "Output as PEM (the default)")
	cmd.Flags().BoolVar(&asJWKS, "jwks", false, "Output as JWKS (public key with x5c chain)")
	return cmd
}

func walletTLSCertCmd() *cobra.Command {
	var (
		port    int
		baseURL string
		docker  bool
		outPath string
		asPEM   bool
		asJWKS  bool
	)

	cmd := &cobra.Command{
		Use:   "tls-cert",
		Short: "Print or export the wallet TLS leaf certificate used by HTTPS wallet endpoints",
		Long: `Loads or creates the HTTPS leaf certificate used by the wallet's HTTPS endpoints.
Use this to inspect or export the exact server certificate presented by the wallet.
Use 'wallet ca-cert' when you want one trust root for all spawned wallets.

Use --jwks to export the certificate as a JWKS document (public key with x5c
chain).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			certFormat, err := certificateExportFormat(asPEM, asJWKS)
			if err != nil {
				return err
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			certData, err := svc.Certificate("tls", certFormat, walletCertOptions{port: port, baseURL: baseURL, docker: docker})
			if err != nil {
				return err
			}
			return writeCertificateExport(cmd, "TLS", certData, outPath)
		},
	}

	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Wallet server port (certificate will match HTTPS wallet endpoints on port+1)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Base URL used to derive the HTTPS wallet host")
	cmd.Flags().BoolVar(&docker, "docker", false, "Use host.docker.internal instead of localhost when deriving the HTTPS wallet host")
	cmd.Flags().StringVar(&outPath, "out", "", "Write the wallet TLS certificate to a file instead of stdout")
	cmd.Flags().BoolVar(&asPEM, "pem", false, "Output as PEM (the default)")
	cmd.Flags().BoolVar(&asJWKS, "jwks", false, "Output as JWKS (public key with x5c chain)")
	return cmd
}

// --- helpers ---

// typeLabel returns the best human-readable type label from a VCT or DocType,
// falling back to the format string if both are empty.
func typeLabel(vct, docType, fmt_ string) string {
	if vct != "" {
		return vct
	}
	if docType != "" {
		return docType
	}
	return fmt_
}

func credLabel(c wallet.StoredCredential) string {
	return typeLabel(c.VCT, c.DocType, c.Format)
}

func parseClaimsOverrides(flag string) (map[string]any, error) {
	if flag == "" {
		return nil, nil
	}
	var overrides map[string]any
	if err := json.Unmarshal([]byte(flag), &overrides); err != nil {
		return nil, fmt.Errorf("parsing --claims JSON: %w", err)
	}
	return overrides, nil
}

func applySessionTranscriptMode(w *wallet.Wallet, mode string) error {
	switch mode {
	case "oid4vp", "":
		w.SessionTranscript = wallet.SessionTranscriptOID4VP
	case "iso":
		w.SessionTranscript = wallet.SessionTranscriptISO
	default:
		return fmt.Errorf("invalid --session-transcript value %q (must be 'iso' or 'oid4vp')", mode)
	}
	return nil
}

// openBrowser hands a URL to the user's browser.
//
// The scheme is checked here rather than at the call sites. Some of these URLs
// come from a remote wallet's response, and `open` launches file:// paths and
// any registered application scheme, not just web pages. The wallet validates
// these URLs before it answers, but that is a peer on the network and this is
// the process that acts on the answer.
func openBrowser(rawURL string) {
	if !isWebURL(rawURL) {
		fmt.Fprintf(os.Stderr, "refusing to open %q: only http and https URLs\n", rawURL)
		return
	}
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", rawURL).Start()
	case "linux":
		_ = exec.Command("xdg-open", rawURL).Start()
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	}
}

// isWebURL reports whether a URL can be navigated to safely. url.Parse counts
// javascript: and data: as absolute, so the scheme has to be named.
func isWebURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || !u.IsAbs() {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme == "http" || scheme == "https"
}

func loadWalletECKey(path, label string) (*ecdsa.PrivateKey, error) {
	if path != "" {
		privKey, err := keys.LoadPrivateKey(path)
		if err != nil {
			return nil, fmt.Errorf("loading %s key: %w", label, err)
		}
		ecKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("--%s key must be an EC private key (P-256)", label)
		}
		return ecKey, nil
	}

	key, err := mock.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", label, err)
	}

	fmt.Fprintf(os.Stderr, "Generated ephemeral %s key\n", label)
	return key, nil
}

// printTrustListIndex lists the profiles a wallet serves. Without it the ids
// are only discoverable by reading /api/trustlists, so a caller has to guess
// which one covers what it is verifying.
func printTrustListIndex(client *remote.Client) error {
	var entries []map[string]any
	if client != nil {
		remoteEntries, err := client.TrustLists()
		if err != nil {
			return err
		}
		entries = remoteEntries
	} else {
		w, _, err := loadWallet()
		if err != nil {
			return err
		}
		data, err := json.Marshal(wallet.BuildTrustListIndexEntries(w, w.IssuerURL))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &entries); err != nil {
			return err
		}
	}

	if jsonOutput {
		// The same shape as GET /api/trustlists, so a caller parsing one
		// parses the other.
		data, err := json.MarshalIndent(map[string]any{"trust_lists": entries}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	if len(entries) == 0 {
		fmt.Println("No trust list profiles.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tDEFAULT\tCATEGORY\tPATH")
	for _, entry := range entries {
		str := func(key string) string {
			v, _ := entry[key].(string)
			return v
		}
		def := ""
		if isDefault, _ := entry["default"].(bool); isDefault {
			def = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", str("id"), def, str("category"), str("path"))
	}
	return tw.Flush()
}
