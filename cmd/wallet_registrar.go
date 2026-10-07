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
	"maps"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

func walletRegistrarCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registrar",
		Short: "Register relying parties and issue their certificates",
		Long: `The wallet's registrar registers relying parties (TS05 v1.5) and issues their
access certificates (ETSI TS 119 411-8) and registration certificates (ETSI TS
119 475). The content of both certificates comes from the registration.

A verifier registers intended uses and gets a registration certificate for each.
An issuer registers as an attestation provider and lists its attestation types.
It gets one registration certificate for its service.`,
	}
	cmd.AddCommand(walletPartiesCmd("verifiers"), walletPartiesCmd("issuers"), walletAccessCertCmd(), walletRegistrationCertCmd(), walletRegistrarStatusCmd(true), walletRegistrarStatusCmd(false))
	return cmd
}

// partyFlags hold the registration fields that verifiers and issuers share.
type partyFlags struct {
	rp                                registrar.WalletRelyingParty
	identifier, legalName, supportURI string
	serviceID                         string
}

func (f *partyFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.rp.TradeName, "name", "", "Trade name (required)")
	cmd.Flags().StringVar(&f.identifier, "identifier", "", "organizationIdentifier, such as LEIXG-5299000ABCDEF12345 (default: assigned)")
	cmd.Flags().StringVar(&f.legalName, "legal-name", "", "Legal name (default --name)")
	cmd.Flags().StringVar(&f.rp.Country, "country", "", "Country code (default the identifier's country)")
	cmd.Flags().StringVar(&f.supportURI, "support-uri", "", "Support contact URL (default a placeholder page on the wallet)")
	cmd.Flags().StringVar(&f.serviceID, "service-id", "", "Service identifier (the organizational unit in access certificates)")
	_ = cmd.MarkFlagRequired("name")
}

func (f *partyFlags) register(service registrar.WalletRelyingPartyService) (registrar.WalletRelyingParty, error) {
	rp := f.rp
	if f.identifier != "" {
		rp.Identifier = []registrar.Identifier{{Identifier: f.identifier}}
	}
	if f.legalName != "" {
		rp.LegalPerson.LegalName = []string{f.legalName}
	}
	service.ServiceIdentifier = f.serviceID
	service.SupportURI = f.supportURI
	rp.Services = []registrar.WalletRelyingPartyService{service}
	svc, err := managedWallet()
	if err != nil {
		return registrar.WalletRelyingParty{}, err
	}
	return svc.RegisterRelyingParty(rp)
}

func walletPartiesCmd(role string) *cobra.Command {
	isIssuer := role == "issuers"
	short, add := "List, add and remove registered verifiers", walletVerifiersAddCmd()
	if isIssuer {
		short, add = "List, add and remove registered issuers", walletIssuersAddCmd()
	}
	cmd := &cobra.Command{
		Use:   role,
		Short: short,
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
			parties := slices.DeleteFunc(records, func(rp registrar.WalletRelyingParty) bool { return !hasRole(rp, role) })
			printResult(parties, func() {
				tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				if isIssuer {
					fmt.Fprintln(tw, "IDENTIFIER\tNAME\tATTESTATIONS")
				} else {
					fmt.Fprintln(tw, "IDENTIFIER\tNAME\tINTENDED USES")
				}
				for _, rp := range parties {
					var items []string
					for _, service := range rp.Services {
						if isIssuer {
							for _, a := range service.ProvidesAttestations {
								items = append(items, a.Format+":"+a.Type)
							}
							continue
						}
						for _, use := range service.IntendedUses {
							items = append(items, use.IntendedUseIdentifier)
						}
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\n", rp.Identifier[0].Identifier, rp.TradeName, strings.Join(items, " "))
				}
				_ = tw.Flush()
			})
			return nil
		},
	}
	cmd.AddCommand(add, walletPartyRemoveCmd(role), listSubcommand(cmd))
	return cmd
}

// hasRole reports whether a registration is one of the verifiers or issuers.
// A service provider counts as a verifier even before it has intended uses.
func hasRole(rp registrar.WalletRelyingParty, role string) bool {
	return slices.ContainsFunc(rp.Services, func(s registrar.WalletRelyingPartyService) bool {
		if role == "issuers" {
			return len(s.ProvidesAttestations) > 0
		}
		return len(s.IntendedUses) > 0 || slices.Contains(s.Entitlements, registrar.ServiceProviderEntitlement)
	})
}

// listSubcommand runs the parent's listing as "list", like wallet list and
// templates list.
func listSubcommand(parent *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: parent.Short,
		Args:  cobra.NoArgs,
		RunE:  parent.RunE,
	}
}

func walletPartyRemoveCmd(role string) *cobra.Command {
	singular := strings.TrimSuffix(role, "s")
	return &cobra.Command{
		Use:     "rm <identifier>",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove a registered " + singular + " and revoke its registration certificates",
		Long: "Removes the registration of a " + singular + ` and revokes all its registration
certificates. A relying party that is a verifier and an issuer is removed in
both roles.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			records, err := svc.RegistrarRecords()
			if err != nil {
				return err
			}
			i := slices.IndexFunc(records, func(rp registrar.WalletRelyingParty) bool {
				return slices.ContainsFunc(rp.Identifier, func(id registrar.Identifier) bool { return id.Identifier == args[0] })
			})
			if i < 0 || !hasRole(records[i], role) {
				return fmt.Errorf("%s is not a registered %s", args[0], singular)
			}
			if err := svc.DeleteRelyingParty(args[0]); err != nil {
				return err
			}
			printResult(map[string]string{"removed": args[0]}, func() {
				fmt.Printf("Removed %s\n", args[0])
			})
			return nil
		},
	}
}

func walletVerifiersAddCmd() *cobra.Command {
	var party partyFlags
	var purpose, privacy, dcqlIn string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Register a verifier with an intended use",
		Long: `Registers a verifier with the wallet's registrar. The registrar assigns an
identifier when --identifier is empty.

The intended use lists the credentials and claims of a DCQL query. Requests
with that query then pass the over-asking check of --arf (ARF RPRC_21).
Run registration-cert to get its registration certificate.`,
		Example: `  eudi wallet registrar verifiers add --name "Example Shop" --purpose "Age check" --dcql query.json`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			use, err := intendedUseFromFlags(purpose, privacy, dcqlIn)
			if err != nil {
				return err
			}
			stored, err := party.register(registrar.WalletRelyingPartyService{IntendedUses: []registrar.IntendedUse{use}})
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
	party.add(cmd)
	cmd.Flags().StringVar(&purpose, "purpose", "", "Purpose of the intended use (shown in the consent dialog)")
	cmd.Flags().StringVar(&dcqlIn, "dcql", "", "DCQL query with the credentials and claims to register (file, JSON or '-' for stdin, required)")
	cmd.Flags().StringVar(&privacy, "privacy-policy", "", "Privacy policy URL of the intended use (default a placeholder page on the wallet)")
	_ = cmd.MarkFlagRequired("dcql")
	_ = cmd.MarkFlagFilename("dcql", "json")
	return cmd
}

func walletIssuersAddCmd() *cobra.Command {
	var party partyFlags
	var entitlement string
	var attestations []string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Register an issuer and its attestation types",
		Long: `Registers an issuer as an attestation provider with the wallet's registrar. The
registrar assigns an identifier when --identifier is empty.

--entitlement names the kind of provider (ETSI TS 119 475 Annex A.2) and
each --attestation adds one attestation type (ARF RPRC_15). Run
registration-cert to get the registration certificate. It comes inside an
issuer_info value for your issuer metadata.`,
		Example: `  eudi wallet registrar issuers add --name "Example University" --attestation dc+sd-jwt:urn:example:diploma:1
  eudi wallet registrar issuers add --name "Example PID Provider" --entitlement pid --attestation dc+sd-jwt:urn:eudi:pid:1 --attestation mso_mdoc:eu.europa.ec.eudi.pid.1`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			uri, ok := entitlementNames[entitlement]
			if !ok {
				return fmt.Errorf("--entitlement takes pid, qeaa, pub-eaa or eaa, not %q", entitlement)
			}
			provided, err := providedAttestations(attestations)
			if err != nil {
				return err
			}
			stored, err := party.register(registrar.WalletRelyingPartyService{Entitlements: []string{uri}, ProvidesAttestations: provided})
			if err != nil {
				return err
			}
			printResult(stored, func() {
				fmt.Printf("Registered %s as %s\n", stored.TradeName, stored.Identifier[0].Identifier)
				for _, attestation := range stored.Services[0].ProvidesAttestations {
					fmt.Printf("Attestation: %s %s\n", attestation.Format, attestation.Type)
				}
			})
			return nil
		},
	}
	party.add(cmd)
	cmd.Flags().StringVar(&entitlement, "entitlement", "eaa", "Kind of provider: pid, qeaa, pub-eaa or eaa (non-qualified)")
	cmd.Flags().StringArrayVar(&attestations, "attestation", nil, "Attestation type as format:type, such as dc+sd-jwt:urn:eudi:pid:1 or mso_mdoc:eu.europa.ec.eudi.pid.1 (repeatable, required)")
	_ = cmd.RegisterFlagCompletionFunc("entitlement", staticCompletion(slices.Sorted(maps.Keys(entitlementNames))...))
	_ = cmd.MarkFlagRequired("attestation")
	return cmd
}

// entitlementNames are the provider entitlements of ETSI TS 119 475 V1.2.1
// Annex A.2 that --entitlement takes.
var entitlementNames = map[string]string{
	"pid":     registrar.PIDProviderEntitlement,
	"qeaa":    registrar.QEAAProviderEntitlement,
	"pub-eaa": registrar.PubEAAProviderEntitlement,
	"eaa":     registrar.NonQEAAProviderEntitlement,
}

// providedAttestations parses format:type values. The type of an SD-JWT VC is
// its vct and the type of an mdoc its doctype.
func providedAttestations(values []string) ([]registrar.ProvidedAttestation, error) {
	attestations := make([]registrar.ProvidedAttestation, 0, len(values))
	for _, value := range values {
		format, typ, ok := strings.Cut(strings.TrimSpace(value), ":")
		typ = strings.TrimSpace(typ)
		if !ok || typ == "" {
			return nil, fmt.Errorf("--attestation %q is not format:type, such as dc+sd-jwt:urn:eudi:pid:1", value)
		}
		if format != "dc+sd-jwt" && format != "mso_mdoc" {
			return nil, fmt.Errorf("--attestation %q has format %q, not dc+sd-jwt or mso_mdoc", value, format)
		}
		attestations = append(attestations, registrar.ProvidedAttestation{Format: format, Type: typ})
	}
	return attestations, nil
}

func intendedUseFromFlags(purpose, privacy, dcqlInput string) (registrar.IntendedUse, error) {
	use := registrar.IntendedUse{}
	if purpose != "" {
		use.Purpose = []registrar.MultiLangString{{Lang: "en", Content: purpose}}
	}
	if privacy != "" {
		use.PrivacyPolicy = []registrar.Policy{{PolicyURI: privacy}}
	}
	if dcqlInput == "" {
		return use, fmt.Errorf("an intended use needs --dcql with the credentials and claims to register")
	}
	raw, err := format.ReadInput(dcqlInput)
	if err != nil {
		return use, fmt.Errorf("reading the DCQL query: %w", err)
	}
	var query struct {
		Credentials []registrar.RegisteredCredential `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(raw), &query); err != nil {
		return use, fmt.Errorf("parsing the DCQL query: %w", err)
	}
	use.Credentials = query.Credentials
	return use, nil
}

func walletAccessCertCmd() *cobra.Command {
	var (
		req     registrar.AccessCertificateRequest
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
	var req registrar.RegistrationCertificateRequest
	var output string
	var provider bool
	cmd := &cobra.Command{
		Use:   "registration-cert",
		Short: "Issue a registration certificate for an intended use or an issuer service",
		Long: `Signs a registration certificate (ETSI TS 119 475, typ rc-wrp+jwt).

For a verifier it certifies an intended use and prints the certificate inside a
verifier_info value (OpenID4VP 1.0 §5.1). A verifier puts that value in its
requests, and the wallet shows the registered purpose. With --arf the wallet
also checks that a request asks only for registered credentials and claims
(ARF RPRC_21).

For an issuer it certifies the attestation provider service with the attestation
types (ARF RPRC_13) and prints an issuer_info value (ETSI TS 119 472-3
§4.2.3). An issuer puts that value in its Credential Issuer Metadata. With --arf
the wallet checks the value before requesting a credential.

An intended use or a service has one valid certificate at a time. Issuing a new
one revokes the previous one.

Without --intended-use it certifies the relying party's only intended use, or
its only provider service. --provider certifies the provider service of
--service-id. --print certificate prints the bare registration certificate
instead, and --json prints both.`,
		Example: `  eudi wallet registrar registration-cert --identifier NTRNL-1A2B3C4D5E6F7A8B
  eudi wallet registrar registration-cert --identifier NTRNL-1A2B3C4D5E6F7A8B --print certificate | eudi decode
  eudi wallet registrar registration-cert --identifier NTRNL-1A2B3C4D5E6F7A8B --intended-use 3f2a9c1e7b6d4a50 --json
  eudi wallet registrar registration-cert --identifier NTRNL-1A2B3C4D5E6F7A8B --service-id diplomas --provider`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if output != "info" && output != "certificate" {
				return fmt.Errorf("--print takes info or certificate, not %q", output)
			}
			if provider && req.IntendedUseIdentifier != "" {
				return fmt.Errorf("--provider certifies a service, so it takes no --intended-use")
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if req.IntendedUseIdentifier == "" && !provider {
				if req.IntendedUseIdentifier, err = onlyCertificateTarget(svc, req.Identifier, req.ServiceIdentifier); err != nil {
					return err
				}
			}
			result, err := svc.RegistrationCertificate(req)
			if err != nil {
				return err
			}
			printResult(result, func() {
				switch {
				case output == "certificate":
					fmt.Fprintln(cmd.OutOrStdout(), result.RegistrationCertificate)
				case result.IssuerInfo != "":
					fmt.Fprintln(cmd.OutOrStdout(), result.IssuerInfo)
				default:
					fmt.Fprintln(cmd.OutOrStdout(), result.VerifierInfo)
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&req.Identifier, "identifier", "", "Identifier of the registered relying party (required)")
	cmd.Flags().StringVar(&req.ServiceIdentifier, "service-id", "", "Service of the relying party (default the service of the intended use)")
	cmd.Flags().StringVar(&req.IntendedUseIdentifier, "intended-use", "", "Intended use to certify (default the only one)")
	cmd.Flags().BoolVar(&provider, "provider", false, "Certify the attestation provider service instead of an intended use")
	cmd.Flags().StringVar(&req.Validity, "validity", "", "Validity as a Go duration, at most 8760h (default 4320h)")
	cmd.Flags().StringVar(&output, "print", "info", "What to print: info (verifier_info or issuer_info) or certificate (the bare JWT)")
	_ = cmd.RegisterFlagCompletionFunc("print", staticCompletion("info", "certificate"))
	_ = cmd.MarkFlagRequired("identifier")
	return cmd
}

// onlyCertificateTarget returns the only intended use of the relying party, or
// an empty string when its only certificate target is a provider service.
func onlyCertificateTarget(svc walletService, identifier, serviceIdentifier string) (string, error) {
	records, err := svc.RegistrarRecords()
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(records, func(rp registrar.WalletRelyingParty) bool {
		return slices.ContainsFunc(rp.Identifier, func(id registrar.Identifier) bool { return id.Identifier == strings.TrimSpace(identifier) })
	})
	if i < 0 {
		return "", fmt.Errorf("relying party %s is not registered", identifier)
	}
	var uses, providers []string
	for _, service := range records[i].Services {
		if serviceIdentifier != "" && service.ServiceIdentifier != serviceIdentifier {
			continue
		}
		for _, use := range service.IntendedUses {
			uses = append(uses, use.IntendedUseIdentifier)
		}
		if len(service.ProvidesAttestations) > 0 {
			name := service.ServiceIdentifier
			if name == "" {
				name = "(no service identifier)"
			}
			providers = append(providers, name)
		}
	}
	switch {
	case len(uses) == 1 && len(providers) == 0:
		return uses[0], nil
	case len(uses) == 0 && len(providers) == 1:
		return "", nil
	case len(providers) == 0:
		return "", fmt.Errorf("relying party %s has %d intended uses, so pass --intended-use (%s)", identifier, len(uses), strings.Join(uses, ", "))
	default:
		return "", fmt.Errorf("relying party %s has intended uses (%s) and provider services (%s), so pass --intended-use, or --service-id with --provider", identifier, strings.Join(uses, ", "), strings.Join(providers, ", "))
	}
}

// walletRegistrarStatusCmd revokes or activates registration certificates.
func walletRegistrarStatusCmd(revoke bool) *cobra.Command {
	var identifier string
	var scope registrar.RegistrationScope
	use, verb, done := "activate", "Activate", "Activated"
	if revoke {
		use, verb, done = "revoke", "Revoke", "Revoked"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: verb + " the registration certificates of a relying party",
		Long: verb + ` the registration certificates issued for an intended use with
--intended-use, for a service with --service-id, or for the whole relying party.
A service's certificates are its provider certificate and those of its intended
uses. The change shows in the registrar's status list, and the registration
itself is kept.

Certificates the registrar revoked itself stay revoked. That happens when a
newer certificate replaces one, or when an update changes or removes what it
certifies.`,
		Example: "  eudi wallet registrar " + use + " --identifier NTRNL-1A2B3C4D5E6F7A8B\n  eudi wallet registrar " + use + " --identifier NTRNL-1A2B3C4D5E6F7A8B --intended-use 3f2a9c1e7b6d4a50\n  eudi wallet registrar " + use + " --identifier NTRNL-1A2B3C4D5E6F7A8B --service-id diplomas",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			changed, err := svc.SetRegistrationCertificatesRevoked(identifier, scope, revoke)
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
	cmd.Flags().StringVar(&scope.IntendedUseIdentifier, "intended-use", "", "Only change the certificates of this intended use (default all)")
	cmd.Flags().StringVar(&scope.ServiceIdentifier, "service-id", "", "Only change the certificates of this service (default all)")
	_ = cmd.MarkFlagRequired("identifier")
	return cmd
}
