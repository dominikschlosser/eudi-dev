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
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

func walletRegistrarCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registrar",
		Short: "Register relying parties and issue their certificates",
		Long: `The wallet's registrar registers relying parties (TS05 v1.5) and issues their
access certificates (ETSI TS 119 411-8) and registration certificates (ETSI TS
119 475). The content of both certificates comes from the registration.`,
	}
	cmd.AddCommand(walletRegistrarRegisterCmd(), walletRegistrarListCmd(), walletAccessCertCmd(), walletRegistrationCertCmd(), walletRegistrarStatusCmd(true), walletRegistrarStatusCmd(false))
	return cmd
}

func walletRegistrarRegisterCmd() *cobra.Command {
	var (
		rp                                  wallet.WalletRelyingParty
		identifier, supportURI, serviceID   string
		legalName, purpose, privacy, dcqlIn string
	)
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a relying party, optionally with an intended use",
		Long: `Registers a relying party with the wallet's registrar. The registrar assigns an
identifier when --identifier is empty. --purpose and --dcql add an intended use
with the credentials and claims of a DCQL query.`,
		Example: `  eudi wallet registrar register --name "Example Shop"
  eudi wallet registrar register --name "Example Shop" --purpose "Age check" --dcql query.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if identifier != "" {
				rp.Identifier = []wallet.Identifier{{Identifier: identifier}}
			}
			if legalName != "" {
				rp.LegalPerson.LegalName = []string{legalName}
			}
			service := wallet.WalletRelyingPartyService{ServiceIdentifier: serviceID}
			if supportURI != "" {
				service.SupportURI = []string{supportURI}
			}
			if purpose != "" || dcqlIn != "" {
				use, err := intendedUseFromFlags(purpose, privacy, dcqlIn)
				if err != nil {
					return err
				}
				service.IntendedUses = []wallet.IntendedUse{use}
			}
			rp.Services = []wallet.WalletRelyingPartyService{service}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			stored, err := svc.RegisterRelyingParty(rp)
			if err != nil {
				return err
			}
			printResult(stored, func() {
				fmt.Printf("Registered %s as %s\n", stored.TradeName, stored.Identifier[0].Identifier)
				for _, use := range stored.Services[0].IntendedUses {
					fmt.Printf("Intended use: %s\n", use.IntendedUseIdentifier)
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&rp.TradeName, "name", "", "Trade name of the relying party (required)")
	cmd.Flags().StringVar(&identifier, "identifier", "", "organizationIdentifier, such as LEIXG-5299000ABCDEF12345 (default: assigned)")
	cmd.Flags().StringVar(&legalName, "legal-name", "", "Legal name (default --name)")
	cmd.Flags().StringVar(&rp.Country, "country", "", "Country code (default the identifier's country)")
	cmd.Flags().StringVar(&supportURI, "support-uri", "", "Support contact URL (default a placeholder page on the wallet)")
	cmd.Flags().StringVar(&serviceID, "service-id", "", "Service identifier (the organizational unit in access certificates)")
	cmd.Flags().StringVar(&purpose, "purpose", "", "Purpose of the intended use (shown in the consent dialog)")
	cmd.Flags().StringVar(&dcqlIn, "dcql", "", "DCQL query with the credentials and claims to register for the intended use (file, JSON or '-' for stdin)")
	cmd.Flags().StringVar(&privacy, "privacy-policy", "", "Privacy policy URL of the intended use (default a placeholder page on the wallet)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagFilename("dcql", "json")
	return cmd
}

func intendedUseFromFlags(purpose, privacy, dcqlInput string) (wallet.IntendedUse, error) {
	use := wallet.IntendedUse{}
	if purpose != "" {
		use.Purpose = []wallet.MultiLangString{{Lang: "en", Content: purpose}}
	}
	if privacy != "" {
		use.PrivacyPolicy = []wallet.Policy{{PolicyURI: privacy}}
	}
	if dcqlInput == "" {
		return use, fmt.Errorf("an intended use needs --dcql with the credentials and claims to register")
	}
	raw, err := format.ReadInput(dcqlInput)
	if err != nil {
		return use, fmt.Errorf("reading the DCQL query: %w", err)
	}
	var query struct {
		Credentials []wallet.RegisteredCredential `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(raw), &query); err != nil {
		return use, fmt.Errorf("parsing the DCQL query: %w", err)
	}
	use.Credentials = query.Credentials
	return use, nil
}

func walletRegistrarListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the wallet's provider registration and the registered relying parties",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			records, err := svc.RegistrarRecords()
			if err != nil {
				return err
			}
			printResult(records, func() {
				tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "IDENTIFIER\tNAME\tSERVICES\tINTENDED USES")
				for _, rp := range records {
					uses := 0
					for _, service := range rp.Services {
						uses += len(service.IntendedUses)
					}
					fmt.Fprintf(tw, "%s\t%s\t%d\t%d\n", rp.Identifier[0].Identifier, rp.TradeName, len(rp.Services), uses)
				}
				_ = tw.Flush()
			})
			return nil
		},
	}
}

func walletAccessCertCmd() *cobra.Command {
	var (
		req     wallet.AccessCertificateRequest
		csrPath string
	)
	cmd := &cobra.Command{
		Use:   "access-cert",
		Short: "Issue an access certificate for a CSR of a registered relying party",
		Long: `Signs an access certificate (ETSI TS 119 411-8) for the key of a certificate
signing request. The relying party keeps its private key. The public key comes
from the CSR and the subject from the registration, so the CSR subject can stay
empty.

It prints the PEM certificate. The client identifiers for it (x509_hash, and
x509_san_dns for every --dns name) go to stderr, or into the JSON output
with --json.`,
		Example: `  openssl ecparam -name prime256v1 -genkey -noout -out verifier.key
  openssl req -new -key verifier.key -subj "/" -out verifier.csr
  eudi wallet registrar access-cert --identifier NTRNL-1A2B3C4D5E6F7A8B --csr verifier.csr > verifier.pem`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pemData, err := format.ReadInput(csrPath)
			if err != nil {
				return fmt.Errorf("reading the CSR: %w", err)
			}
			req.CSR = pemData
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			result, err := svc.AccessCertificate(req)
			if err != nil {
				return err
			}
			printResult(result, func() {
				for _, clientID := range result.ClientIDs {
					fmt.Fprintf(os.Stderr, "client_id: %s\n", clientID)
				}
				_, _ = fmt.Fprint(cmd.OutOrStdout(), result.Certificate)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&req.Identifier, "identifier", "", "Identifier of the registered relying party (required)")
	cmd.Flags().StringVar(&req.ServiceIdentifier, "service-id", "", "Service of the relying party (default the first service)")
	cmd.Flags().StringVar(&csrPath, "csr", "", "PEM certificate signing request (file or '-' for stdin, required)")
	cmd.Flags().StringSliceVar(&req.DNSNames, "dns", nil, "DNS name for the x509_san_dns client identifier (repeatable)")
	cmd.Flags().StringVar(&req.Validity, "validity", "", "Validity as a Go duration, at most 8760h (default 8760h)")
	_ = cmd.MarkFlagRequired("identifier")
	_ = cmd.MarkFlagRequired("csr")
	_ = cmd.MarkFlagFilename("csr", "csr", "pem")
	return cmd
}

func walletRegistrationCertCmd() *cobra.Command {
	var req wallet.RegistrationCertificateRequest
	var output string
	cmd := &cobra.Command{
		Use:   "registration-cert",
		Short: "Issue a registration certificate for a registered intended use",
		Long: `Signs a registration certificate (ETSI TS 119 475, typ rc-wrp+jwt) for an
intended use of a registered relying party and prints it inside a verifier_info
value (OpenID4VP 1.0 §5.1). A verifier puts that value in its requests,
and the wallet shows the registered purpose. With --arf the wallet also checks
that a request asks only for registered credentials and claims (ARF RPRC_21).

An intended use has one valid certificate at a time. Issuing a new one revokes
the previous one.

Without --intended-use it certifies the relying party's only intended use.
--print certificate prints the bare registration certificate instead, and
--json prints both.`,
		Example: `  eudi wallet registrar registration-cert --identifier NTRNL-1A2B3C4D5E6F7A8B
  eudi wallet registrar registration-cert --identifier NTRNL-1A2B3C4D5E6F7A8B --print certificate | eudi decode
  eudi wallet registrar registration-cert --identifier NTRNL-1A2B3C4D5E6F7A8B --intended-use 3f2a9c1e7b6d4a50 --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if output != "verifier-info" && output != "certificate" {
				return fmt.Errorf("--print takes verifier-info or certificate, not %q", output)
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if req.IntendedUseIdentifier == "" {
				if req.IntendedUseIdentifier, err = onlyIntendedUse(svc, req.Identifier, req.ServiceIdentifier); err != nil {
					return err
				}
			}
			result, err := svc.RegistrationCertificate(req)
			if err != nil {
				return err
			}
			printResult(result, func() {
				if output == "certificate" {
					fmt.Fprintln(cmd.OutOrStdout(), result.RegistrationCertificate)
					return
				}
				fmt.Fprintln(cmd.OutOrStdout(), result.VerifierInfo)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&req.Identifier, "identifier", "", "Identifier of the registered relying party (required)")
	cmd.Flags().StringVar(&req.ServiceIdentifier, "service-id", "", "Service of the relying party (default any)")
	cmd.Flags().StringVar(&req.IntendedUseIdentifier, "intended-use", "", "Intended use to certify (default the only one)")
	cmd.Flags().StringVar(&req.Validity, "validity", "", "Validity as a Go duration, at most 8760h (default 4320h)")
	cmd.Flags().StringVar(&output, "print", "verifier-info", "What to print: verifier-info (the request parameter) or certificate (the bare JWT)")
	_ = cmd.RegisterFlagCompletionFunc("print", staticCompletion("verifier-info", "certificate"))
	_ = cmd.MarkFlagRequired("identifier")
	return cmd
}

func onlyIntendedUse(svc walletService, identifier, serviceIdentifier string) (string, error) {
	records, err := svc.RegistrarRecords()
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(records, func(rp wallet.WalletRelyingParty) bool {
		return slices.ContainsFunc(rp.Identifier, func(id wallet.Identifier) bool { return id.Identifier == strings.TrimSpace(identifier) })
	})
	if i < 0 {
		return "", fmt.Errorf("relying party %s is not registered", identifier)
	}
	var uses []string
	for _, service := range records[i].Services {
		if serviceIdentifier != "" && service.ServiceIdentifier != serviceIdentifier {
			continue
		}
		for _, use := range service.IntendedUses {
			uses = append(uses, use.IntendedUseIdentifier)
		}
	}
	if len(uses) != 1 {
		return "", fmt.Errorf("relying party %s has %d intended uses, so pass --intended-use (%s)", identifier, len(uses), strings.Join(uses, ", "))
	}
	return uses[0], nil
}

// walletRegistrarStatusCmd revokes or activates registration certificates.
func walletRegistrarStatusCmd(revoke bool) *cobra.Command {
	var identifier, intendedUse string
	use, verb, done := "activate", "Activate", "Activated"
	if revoke {
		use, verb, done = "revoke", "Revoke", "Revoked"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: verb + " the registration certificates of a relying party",
		Long: verb + ` the registration certificates issued for an intended use, or for every
intended use of the relying party without --intended-use. The change shows in
the registrar's status list, and the registration itself is kept.

Certificates the registrar revoked itself stay revoked. That happens when a
newer certificate replaces one, or when an update changes or removes its
intended use.`,
		Example: "  eudi wallet registrar " + use + " --identifier NTRNL-1A2B3C4D5E6F7A8B\n  eudi wallet registrar " + use + " --identifier NTRNL-1A2B3C4D5E6F7A8B --intended-use 3f2a9c1e7b6d4a50",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			changed, err := svc.SetRegistrationCertificatesRevoked(identifier, intendedUse, revoke)
			if err != nil {
				return err
			}
			printResult(map[string]int{"changed": changed}, func() {
				fmt.Printf("%s %d registration certificate(s)\n", done, changed)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&identifier, "identifier", "", "Identifier of the registered relying party (required)")
	cmd.Flags().StringVar(&intendedUse, "intended-use", "", "Only change the certificates of this intended use (default all)")
	_ = cmd.MarkFlagRequired("identifier")
	return cmd
}
