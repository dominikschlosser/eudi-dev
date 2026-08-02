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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/remote"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
	"github.com/dominikschlosser/eudi-dev/internal/web"
)

func walletServeCmd() *cobra.Command {
	var (
		port                    int
		autoAccept              bool
		credFiles               []string
		pid                     bool
		keyPath                 string
		issuerKey               string
		sessionTranscript       string
		register                bool
		noRegister              bool
		statusList              bool
		baseURL                 string
		docker                  bool
		preferredFormat         string
		requireEncryptedRequest bool
		haip                    bool
		vciClientID             string
		vciRedirectURI          string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start wallet HTTP server with web UI, OID4VP endpoints, and optional URL scheme handling",
		Long: `Start a persistent wallet server with a web UI for managing credentials and handling OID4VP/OID4VCI flows.

Capabilities:
  - Web UI for credential management, issuing, and consent
  - OID4VP authorization endpoint (/authorize)
  - Legacy PID-first trust list endpoint (/api/trustlist)
  - Trust-list index endpoint (/api/trustlists)
  - Request logging with timestamps
  - Browser-based consent UI for incoming requests

Use --register to also register OS URL scheme handlers (openid4vp://, haip-vp://, openid-credential-offer://, haip-vci://)
so the wallet automatically receives incoming protocol requests.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store := loadStore()
			w, err := store.LoadOrCreate()
			if err != nil {
				return fmt.Errorf("loading wallet: %w", err)
			}
			if templatesDir != "" {
				w.TemplatesDir = templatesDir
			}
			if err := applyValidationMode(w, walletValidationMode); err != nil {
				return err
			}

			// Override keys if explicitly provided
			if keyPath != "" {
				holderKey, err := loadWalletECKey(keyPath, "holder")
				if err != nil {
					return err
				}
				w.HolderKey = holderKey
			}
			if issuerKey != "" {
				ik, err := loadWalletECKey(issuerKey, "issuer")
				if err != nil {
					return err
				}
				w.IssuerKey = ik
			}

			if autoAccept {
				w.AutoAccept = true
			}

			if err := applySessionTranscriptMode(w, sessionTranscript); err != nil {
				return err
			}

			if preferredFormat != "" {
				w.PreferredFormat = preferredFormat
			}

			if requireEncryptedRequest {
				encKey, err := mock.GenerateKey()
				if err != nil {
					return fmt.Errorf("generating request encryption key: %w", err)
				}
				w.RequireEncryptedRequest = true
				w.RequestEncryptionKey = encKey
			}

			if haip {
				w.RequireHAIP = true
			}
			if vciClientID != "" {
				w.VCIClientID = vciClientID
			}
			if vciRedirectURI != "" {
				w.VCIRedirectURI = vciRedirectURI
			}

			if cmd.Flags().Changed("base-url") {
				w.BaseURL = baseURL
			} else if statusList && strings.TrimSpace(w.BaseURL) == "" {
				if baseURL == "" {
					if docker {
						baseURL = fmt.Sprintf("http://host.docker.internal:%d", port)
					} else {
						baseURL = fmt.Sprintf("http://localhost:%d", port)
					}
				}
				w.BaseURL = baseURL
			}

			if cmd.Flags().Changed("base-url") || cmd.Flags().Changed("docker") || strings.TrimSpace(w.IssuerURL) == "" {
				issuerBaseURL := baseURL
				if issuerBaseURL == "" && cmd.Flags().Changed("base-url") {
					issuerBaseURL = w.BaseURL
				}
				w.IssuerURL, err = deriveWalletIssuerURL(port, issuerBaseURL, docker)
				if err != nil {
					return err
				}
			}

			if pid {
				if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
					return fmt.Errorf("generating PID credentials: %w", err)
				}
				if err := store.Save(w); err != nil {
					return fmt.Errorf("saving wallet: %w", err)
				}
			}

			for _, path := range credFiles {
				if err := w.ImportCredentialFromFile(path); err != nil {
					return fmt.Errorf("importing credential %s: %w", path, err)
				}
			}
			if len(credFiles) > 0 {
				if err := store.Save(w); err != nil {
					return fmt.Errorf("saving wallet: %w", err)
				}
			}

			// Print startup banner
			cyan := color.New(color.FgCyan, color.Bold)
			dim := color.New(color.Faint)
			yellow := color.New(color.FgYellow)
			publicHTTPURL := fmt.Sprintf("http://localhost:%d", port)
			if baseURL != "" {
				publicHTTPURL = baseURL
			} else if docker {
				publicHTTPURL = fmt.Sprintf("http://host.docker.internal:%d", port)
			}
			httpsURL := w.IssuerURL

			cyan.Printf("EUDI Dev Wallet %s\n", Version)
			dim.Println("───────────────────────────────────────")
			fmt.Printf("  Server:      http://localhost:%d\n", port)
			if publicHTTPURL != fmt.Sprintf("http://localhost:%d", port) {
				dim.Printf("               %s\n", publicHTTPURL)
			}
			fmt.Printf("  HTTPS:       %s\n", httpsURL)
			fmt.Printf("  Authorize:   %s/authorize\n", publicHTTPURL)
			dim.Printf("               %s/authorize\n", httpsURL)
			fmt.Printf("  Trust List:  %s/api/trustlist\n", publicHTTPURL)
			dim.Printf("               %s/api/trustlist\n", httpsURL)
			fmt.Printf("  Trust Lists: %s/api/trustlists\n", publicHTTPURL)
			dim.Printf("               %s/api/trustlists\n", httpsURL)
			fmt.Printf("  Metadata:    %s/.well-known/jwt-vc-issuer\n", httpsURL)
			fmt.Printf("  Credentials: %d loaded\n", len(w.GetCredentials()))
			fmt.Printf("  Storage:     %s\n", store.Dir)
			fmt.Printf("  Validation:  %s\n", w.ValidationMode)
			if w.AutoAccept {
				fmt.Printf("  Mode:        auto-accept\n")
			} else {
				fmt.Printf("  Mode:        interactive (consent UI)\n")
			}
			fmt.Printf("  Transcript:  %s\n", w.SessionTranscript)
			if w.PreferredFormat != "" {
				fmt.Printf("  Preferred:   %s\n", w.PreferredFormat)
			}
			if w.BaseURL != "" {
				fmt.Printf("  Status List: %s/api/statuslist\n", publicHTTPURL)
				dim.Printf("               %s/api/statuslist\n", httpsURL)
			}
			if w.RequireEncryptedRequest {
				fmt.Printf("  Encrypted:   request object encryption required\n")
			}
			if w.RequireHAIP {
				fmt.Printf("  HAIP:        enforced (x509_hash, direct_post.jwt, DCQL, JAR, ES256)\n")
			}

			// Register URL scheme handlers if requested
			if register && !noRegister {
				serveArgs, err := serializeWalletServeArgs(cmd)
				if err != nil {
					return fmt.Errorf("serializing wallet serve flags for registration: %w", err)
				}
				if err := wallet.RegisterURLSchemes(wallet.RegisterOptions{
					ListenerPort: port,
					AutoAccept:   w.AutoAccept,
					ServeArgs:    serveArgs,
				}); err != nil {
					yellow.Printf("  Register:    skipped (%s)\n", err)
				} else if wallet.SupportsURLSchemeRegistration() {
					fmt.Printf("  Register:    URL scheme handlers registered\n")
				} else {
					yellow.Printf("  Register:    not supported on this platform; use 'wallet accept <uri>' for copied links\n")
				}
			}

			dim.Println("───────────────────────────────────────")
			fmt.Println()

			if len(w.GetCredentials()) > 0 {
				for _, c := range w.GetCredentials() {
					fmt.Printf("  [%s] %s (%d claims)\n", c.Format, credLabel(c), len(c.Claims))
				}
				fmt.Println()
			}

			srv := wallet.NewServer(w, port, func() {
				if err := store.Save(w); err != nil {
					fmt.Fprintf(os.Stderr, "warning: saving wallet: %v\n", err)
				}
			})
			srv.SetStore(store)
			// Embed the credential decoder UI so stored credentials can be
			// inspected from the wallet UI.
			srv.Mount("/decoder", web.NewMux(""))
			if err := configureIssuerTLSCertificate(srv, store, w.IssuerURL); err != nil {
				return err
			}

			// Always enable request logging
			srv.SetLogger(func(format string, args ...any) {
				timestamp := time.Now().Format("15:04:05")
				dim.Printf("[%s] ", timestamp)
				fmt.Printf(format+"\n", args...)
			})

			// Open browser UI for incoming interactive presentation and issuance flows.
			if !w.AutoAccept {
				srv.SetOnUIRequest(func() {
					url := fmt.Sprintf("http://localhost:%d/?focus=overview", port)
					fmt.Printf("  Opening wallet UI: %s\n", url)
					openBrowser(url)
				})
			}

			if register && !noRegister {
				fmt.Println("Listening for URL scheme dispatches...")
				fmt.Println()
			}

			// Record this instance so `wallet instances` can discover it and
			// `wallet kill` and POST /api/shutdown can stop it.
			pid := os.Getpid()
			if err := remote.RegisterInstance(remote.Instance{
				PID:       pid,
				Port:      port,
				URL:       fmt.Sprintf("http://localhost:%d", port),
				WalletDir: store.Dir,
				StartedAt: time.Now(),
			}); err != nil {
				fmt.Fprintf(os.Stderr, "warning: registering wallet instance: %v\n", err)
			}
			defer remote.UnregisterInstance(pid)
			srv.ShutdownFunc = func() {
				remote.UnregisterInstance(pid)
				os.Exit(0)
			}

			return srv.ListenAndServe()
		},
	}

	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Wallet server port")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "Headless mode: auto-accept presentations and credential offers")
	cmd.Flags().StringSliceVar(&credFiles, "credential", nil, "Import credential from file (repeatable)")
	cmd.Flags().BoolVar(&pid, "pid", false, "Auto-generate default EUDI PID credentials (SD-JWT + mDoc)")
	cmd.Flags().StringVar(&keyPath, "key", "", "Holder private key file (PEM/JWK); uses stored key or auto-generates")
	cmd.Flags().StringVar(&issuerKey, "issuer-key", "", "Issuer key for generated credentials (PEM/JWK)")
	cmd.Flags().StringVar(&sessionTranscript, "session-transcript", "oid4vp", "mDoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	cmd.Flags().BoolVar(&register, "register", false, "Register OS URL scheme handlers (openid4vp://, haip-vp://, openid-credential-offer://, haip-vci://)")
	cmd.Flags().BoolVar(&noRegister, "no-register", false, "Skip URL scheme registration (overrides --register)")
	cmd.Flags().BoolVar(&statusList, "status-list", false, "Embed status list references in generated credentials")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Base URL for the wallet's HTTP endpoints; its host is also reused for HTTPS wallet endpoints")
	cmd.Flags().BoolVar(&docker, "docker", false, "Use host.docker.internal instead of localhost for both HTTP and HTTPS wallet endpoint URLs")
	cmd.Flags().StringVar(&preferredFormat, "preferred-format", "", "Preferred credential format when multiple match: 'dc+sd-jwt', 'mso_mdoc', or 'jwt_vc_json'")
	cmd.Flags().BoolVar(&requireEncryptedRequest, "require-encrypted-request", false, "Require verifiers to encrypt request objects (sends encryption key in wallet_metadata)")
	cmd.Flags().BoolVar(&haip, "haip", false, "Enforce HAIP 1.0 compliance (x509_hash, direct_post.jwt, DCQL, JAR, ES256)")
	cmd.Flags().StringVar(&vciClientID, "vci-client-id", "", "Client ID the wallet should use for OID4VCI authorization-code flows")
	cmd.Flags().StringVar(&vciRedirectURI, "vci-redirect-uri", "", "Redirect URI the wallet should use for OID4VCI authorization-code flows")
	return cmd
}

func serializeWalletServeArgs(cmd *cobra.Command) ([]string, error) {
	args := []string{}
	var err error
	appendFlag := func(flags *pflag.FlagSet, flag *pflag.Flag) {
		if err != nil {
			return
		}
		if flag.Name == "register" || flag.Name == "no-register" {
			return
		}
		switch flag.Value.Type() {
		case "bool":
			args = append(args, "--"+flag.Name)
		case "stringSlice", "stringArray":
			values, getErr := flags.GetStringSlice(flag.Name)
			if getErr != nil {
				err = getErr
				return
			}
			for _, value := range values {
				args = append(args, "--"+flag.Name, value)
			}
		default:
			args = append(args, "--"+flag.Name, flag.Value.String())
		}
	}

	visitChangedPersistentFlags(cmd, func(flag *pflag.Flag) {
		if flag.Name != "wallet-dir" && flag.Name != "mode" {
			return
		}
		args = append(args, "--"+flag.Name, flag.Value.String())
	})
	cmd.Flags().Visit(func(flag *pflag.Flag) {
		appendFlag(cmd.Flags(), flag)
	})
	if err != nil {
		return nil, err
	}
	return args, nil
}
