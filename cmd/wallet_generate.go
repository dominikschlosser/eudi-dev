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

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

func walletGeneratePIDCmd() *cobra.Command {
	var (
		claimsFlag string
		keyPath    string
		vctFlag    string
		statusList bool
		baseURL    string
		docker     bool
	)

	cmd := &cobra.Command{
		Use:   "generate-pid",
		Short: "Generate default EUDI PID credentials (SD-JWT + mDoc) (deprecated)",
		Long:  "Deprecated: generate-pid will be removed in a future release. Issue from the pre-defined german-pid-sdjwt and german-pid-mdoc credential templates instead. If PID credentials already exist, they are replaced. Use --claims to override specific claim values.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printGeneratePIDDeprecation(cmd, claimsFlag, vctFlag)
			if c, err := remoteClientIfConfigured(); err != nil {
				return err
			} else if c != nil {
				overrides, err := parseClaimsOverrides(claimsFlag)
				if err != nil {
					return err
				}
				vct := ""
				if cmd.Flags().Changed("vct") {
					vct = vctFlag
				}
				return remoteGeneratePID(c, overrides, vct)
			}
			w, store, err := loadWallet()
			if err != nil {
				return err
			}

			if keyPath != "" {
				issuerKey, err := loadWalletECKey(keyPath, "issuer")
				if err != nil {
					return err
				}
				w.IssuerKey = issuerKey
			}

			walletPort := defaultWalletCommandPort()
			effectiveBaseURL := baseURL
			if statusList {
				if effectiveBaseURL == "" {
					if docker {
						effectiveBaseURL = fmt.Sprintf("http://host.docker.internal:%d", walletPort)
					} else {
						effectiveBaseURL = fmt.Sprintf("http://localhost:%d", walletPort)
					}
				}
				w.BaseURL = effectiveBaseURL
			}
			if port := walletPortFromBaseURL(effectiveBaseURL); port > 0 {
				walletPort = port
			}
			if effectiveBaseURL != "" {
				issuerURL, err := deriveWalletIssuerURL(walletPort, effectiveBaseURL, docker)
				if err != nil {
					return err
				}
				w.IssuerURL = issuerURL
			} else if docker {
				w.IssuerURL = wallet.LocalIssuerURL(walletPort+1, true)
			} else if w.IssuerURL == "" {
				w.IssuerURL = wallet.LocalIssuerURL(walletPort+1, false)
			}

			overrides, err := parseClaimsOverrides(claimsFlag)
			if err != nil {
				return err
			}

			// Only pass an explicit --vct so the template's VCT (which a
			// user override of german-pid-sdjwt may change) applies otherwise.
			vct := ""
			if cmd.Flags().Changed("vct") {
				vct = vctFlag
			}
			if err := w.GenerateDefaultCredentials(overrides, vct); err != nil {
				return fmt.Errorf("generating PID credentials: %w", err)
			}

			if err := store.Save(w); err != nil {
				return fmt.Errorf("saving wallet: %w", err)
			}

			fmt.Println("Generated default EUDI PID credentials (SD-JWT + mDoc)")
			return nil
		},
	}

	cmd.Flags().StringVar(&claimsFlag, "claims", "", "Claim overrides as JSON (e.g. '{\"given_name\":\"Max\"}')")
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to PEM-encoded EC private key for signing (default: auto-generated)")
	cmd.Flags().StringVar(&vctFlag, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type for SD-JWT PID")
	cmd.Flags().BoolVar(&statusList, "status-list", true, "Embed status list references in generated credentials")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Base URL for status list endpoint (default: http://localhost:8085)")
	cmd.Flags().BoolVar(&docker, "docker", false, "Use host.docker.internal instead of localhost for --base-url")
	return cmd
}

// printGeneratePIDDeprecation warns that generate-pid is deprecated and
// prints the equivalent template-based issue commands, carrying over the
// claim and VCT flags the user passed.
func printGeneratePIDDeprecation(cmd *cobra.Command, claimsFlag, vctFlag string) {
	sdEquiv := "oid4vc-dev issue sdjwt --wallet --template german-pid-sdjwt"
	mdocEquiv := "oid4vc-dev issue mdoc --wallet --template german-pid-mdoc"
	if claimsFlag != "" {
		sdEquiv += " --claims '" + claimsFlag + "'"
		mdocEquiv += " --claims '" + claimsFlag + "'"
	}
	if cmd.Flags().Changed("vct") {
		sdEquiv += " --vct " + vctFlag
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "Warning: `wallet generate-pid` is deprecated and will be removed in a future release.")
	fmt.Fprintln(cmd.ErrOrStderr(), "Issue from the pre-defined credential templates instead:")
	fmt.Fprintln(cmd.ErrOrStderr(), "  "+sdEquiv)
	fmt.Fprintln(cmd.ErrOrStderr(), "  "+mdocEquiv)
}
