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
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

func walletCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "List, add and remove attestation types in the catalogue of attestations",
		Long: `The wallet keeps a catalogue of attestations (EC TS11 v1.0). Each entry describes
an attestation type: its formats and the schema of each, its rulebook, its level
of security and the trusted list of its issuers.

Every predefined credential template is in the catalogue. To add a user
template, tick "Add the template to the attestation catalogue" when you save
it. You can also add other attestation types. When you register a
verifier or an issuer in the web UI, the type fields suggest these types.

Without a subcommand, or with list, it lists the catalogue.`,
		Args: cobra.NoArgs,
		RunE: listCatalog,
	}
	cmd.AddCommand(walletCatalogAddCmd(), walletCatalogRemoveCmd(), listSubcommand(cmd))
	return cmd
}

func listCatalog(cmd *cobra.Command, args []string) error {
	svc, err := managedWallet()
	if err != nil {
		return err
	}
	entries, err := svc.CatalogAttestations()
	if err != nil {
		return err
	}
	printResult(entries, func() {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tTYPES\tLEVEL OF SECURITY")
		for _, e := range entries {
			types := make([]string, 0, len(e.Credentials))
			for _, c := range e.Credentials {
				types = append(types, c.Format+":"+c.Type)
			}
			name := e.Name
			if e.Template {
				name += " (template)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Schema.ID, name, strings.Join(types, " "), e.Schema.AttestationLoS)
		}
		_ = tw.Flush()
	})
	return nil
}

func walletCatalogAddCmd() *cobra.Command {
	var (
		entry                    wallet.CatalogAttestation
		types, claims            []string
		los, trustedList         string
		bindingType, rulebookURI string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add an attestation type to the catalogue",
		Long: `Adds an attestation type. The catalogue assigns its id and serves a schema for
each format: SD-JWT VC Type Metadata for dc+sd-jwt, and the doctype with its
namespaces for mso_mdoc.

--type takes format:type, once per format. --claim takes format:claim. For
SD-JWT, separate path segments with dots. An mdoc claim is an element of
the doctype's namespace, or namespace:element.`,
		Example: `  eudi wallet catalog add --name "University diploma" --type dc+sd-jwt:urn:example:diploma:1 --claim dc+sd-jwt:degree
  eudi wallet catalog add --name "University diploma" --type mso_mdoc:org.example.diploma.1 --claim mso_mdoc:degree --los moderate --trusted-list https://example.com/lote`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, value := range types {
				format, typ, ok := strings.Cut(value, ":")
				if !ok || strings.TrimSpace(typ) == "" {
					return fmt.Errorf("--type %q is not format:type, such as dc+sd-jwt:urn:example:diploma:1", value)
				}
				entry.Credentials = append(entry.Credentials, wallet.CatalogCredential{Format: format, Type: strings.TrimSpace(typ)})
			}
			for _, value := range claims {
				format, claim, ok := strings.Cut(value, ":")
				i := -1
				for j, c := range entry.Credentials {
					if c.Format == format {
						i = j
					}
				}
				if !ok || claim == "" || i < 0 {
					return fmt.Errorf("--claim %q is not format:claim for a format of --type", value)
				}
				entry.Credentials[i].Claims = append(entry.Credentials[i].Claims, catalogClaimPath(format, entry.Credentials[i].Type, claim))
			}
			if los != "" {
				entry.Schema.AttestationLoS = "iso_18045_" + los
			}
			entry.Schema.BindingType = bindingType
			entry.Schema.RulebookURI = rulebookURI
			if trustedList != "" {
				isLOTE := true
				entry.Schema.TrustedAuthorities = []wallet.TrustAuthority{{FrameworkType: "etsi_tl", Value: trustedList, IsLOTE: &isLOTE}}
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			added, err := svc.AddCatalogAttestation(entry)
			if err != nil {
				return err
			}
			printResult(added, func() {
				fmt.Printf("Added %s as %s\n", added.Name, added.Schema.ID)
				for _, uri := range added.Schema.SchemaURIs {
					fmt.Printf("Schema %s: %s\n", uri.FormatIdentifier, uri.URI)
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&entry.Name, "name", "", "Name of the attestation type (required)")
	cmd.Flags().StringArrayVar(&types, "type", nil, "Format and type, such as dc+sd-jwt:urn:example:diploma:1 or mso_mdoc:org.example.diploma.1 (repeatable, required)")
	cmd.Flags().StringArrayVar(&claims, "claim", nil, "Format and claim, such as dc+sd-jwt:address.locality or mso_mdoc:degree (repeatable)")
	cmd.Flags().StringVar(&los, "los", "", "Level of security: basic, enhanced-basic, moderate or high (default basic)")
	cmd.Flags().StringVar(&bindingType, "binding", "", "How the attestation is bound to its holder: key (a key in the wallet), claim (linked to another credential, such as a PID), biometric or none (default key)")
	cmd.Flags().StringVar(&rulebookURI, "rulebook", "", "URL of the rulebook (default a placeholder page on the wallet)")
	cmd.Flags().StringVar(&trustedList, "trusted-list", "", "URL of the trusted list of its issuers (ETSI TS 119 602)")
	_ = cmd.RegisterFlagCompletionFunc("los", staticCompletion("basic", "enhanced-basic", "moderate", "high"))
	_ = cmd.RegisterFlagCompletionFunc("binding", staticCompletion("key", "claim", "biometric", "none"))
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("type")
	return cmd
}

// catalogClaimPath turns a claim flag into a claim path. An mdoc claim
// without a namespace is in the doctype's namespace.
func catalogClaimPath(format, typ, claim string) []any {
	if format == "mso_mdoc" {
		if at := strings.LastIndex(claim, ":"); at > 0 {
			return []any{claim[:at], claim[at+1:]}
		}
		return []any{typ, claim}
	}
	path := []any{}
	for _, segment := range strings.Split(claim, ".") {
		path = append(path, segment)
	}
	return path
}

func walletCatalogRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm <id>",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove an attestation type you added",
		Long:    "Removes an attestation type you added, including one added with a template. The entries of the predefined templates can't be removed.",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if err := svc.DeleteCatalogAttestation(args[0]); err != nil {
				return err
			}
			printResult(map[string]string{"removed": args[0]}, func() {
				fmt.Printf("Removed %s\n", args[0])
			})
			return nil
		},
	}
}
