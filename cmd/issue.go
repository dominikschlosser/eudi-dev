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
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

var (
	issueClaims                string
	issueTemplate              string
	issueAlwaysDisclosed       []string
	issueSaveTemplate          string
	issueKeyPath               string
	issueIssuer                string
	issueVCT                   string
	issueExpires               string
	issueNBF                   string
	issueDocType               string
	issueNamespace             string
	issuePID                   bool
	issueOmit                  []string
	issueToWallet              bool
	issueStatusListURI         string
	issueStatusListIdx         int
	issueTrustProfile          string
	issueEntitlements          []string
	issueTrustListType         string
	issueStatusDetermination   string
	issueSchemeCommunityRule   string
	issueSchemeTerritory       string
	issueTrustEntityName       string
	issueIssuanceServiceType   string
	issueRevocationServiceType string
	issueIssuanceServiceName   string
	issueRevocationServiceName string
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Generate test SD-JWT, JWT, or mDOC credentials",
	Long:  "Generate test credentials for development and testing. Produces valid, signed credentials using ephemeral keys by default.",
}

var issueSDJWTCmd = &cobra.Command{
	Use:   "sdjwt",
	Short: "Generate a test SD-JWT credential",
	Long:  "Generate a signed SD-JWT credential with selectively disclosable claims. Uses an ephemeral P-256 key by default.",
	RunE:  runIssueSDJWT,
}

var issueJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Generate a test JWT VC credential",
	Long:  "Generate a signed JWT VC credential with claims directly in the payload (no selective disclosure). Uses an ephemeral P-256 key by default.",
	RunE:  runIssueJWT,
}

var issueMDOCCmd = &cobra.Command{
	Use:   "mdoc",
	Short: "Generate a test mDOC credential",
	Long:  "Generate a signed mDOC (IssuerSigned) credential. Uses an ephemeral P-256 key by default.",
	RunE:  runIssueMDOC,
}

func init() {
	rootCmd.AddCommand(issueCmd)
	issueCmd.PersistentFlags().StringVar(&walletDir, "wallet-dir", "", "Wallet storage directory (default ~/.eudi-dev/wallet/, legacy ~/.oid4vc-dev/wallet/ keeps working)")
	issueCmd.PersistentFlags().StringVar(&templatesDir, "templates-dir", "", "Credential template directory (default <wallet-dir>/templates/)")
	issueCmd.PersistentFlags().StringVar(&remoteFlag, "remote", "", "With --wallet: issue on a remote wallet server at this URL (\"local\" forces the local store)")
	issueCmd.AddCommand(issueSDJWTCmd)
	issueCmd.AddCommand(issueJWTCmd)
	issueCmd.AddCommand(issueMDOCCmd)

	// SD-JWT flags
	issueSDJWTCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueSDJWTCmd.Flags().StringVar(&issueTemplate, "template", "", "Credential template name or file (see `templates list`); --claims overrides individual claims")
	issueSDJWTCmd.Flags().StringSliceVar(&issueAlwaysDisclosed, "always-disclosed", nil, "Claims to embed plainly instead of selectively disclosable (dotted paths for nested claims, e.g. address.country)")
	issueSDJWTCmd.Flags().StringVar(&issueSaveTemplate, "save-template", "", "Save the issued claims and settings as a credential template with this name")
	issueSDJWTCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK); ephemeral P-256 if omitted")
	issueSDJWTCmd.Flags().StringVar(&issueIssuer, "iss", "https://issuer.example", "Issuer URL")
	issueSDJWTCmd.Flags().StringVar(&issueVCT, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type")
	issueSDJWTCmd.Flags().StringVar(&issueExpires, "exp", "720h", "Expiration duration (e.g. 720h, 24h)")
	issueSDJWTCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueSDJWTCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueSDJWTCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Comma-separated claim names to omit from --pid (e.g. place_of_birth,sex)")
	issueSDJWTCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueSDJWTCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueSDJWTCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")
	addIssueTrustMetadataFlags(issueSDJWTCmd)

	// JWT flags
	issueJWTCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueJWTCmd.Flags().StringVar(&issueTemplate, "template", "", "Credential template name or file (see `templates list`); --claims overrides individual claims")
	issueJWTCmd.Flags().StringVar(&issueSaveTemplate, "save-template", "", "Save the issued claims and settings as a credential template with this name")
	issueJWTCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK); ephemeral P-256 if omitted")
	issueJWTCmd.Flags().StringVar(&issueIssuer, "iss", "https://issuer.example", "Issuer URL")
	issueJWTCmd.Flags().StringVar(&issueVCT, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type")
	issueJWTCmd.Flags().StringVar(&issueExpires, "exp", "720h", "Expiration duration (e.g. 720h, 24h)")
	issueJWTCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueJWTCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueJWTCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Comma-separated claim names to omit from --pid (e.g. place_of_birth,sex)")
	issueJWTCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueJWTCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueJWTCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")
	addIssueTrustMetadataFlags(issueJWTCmd)

	// mDOC flags
	issueMDOCCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueMDOCCmd.Flags().StringVar(&issueTemplate, "template", "", "Credential template name or file (see `templates list`); --claims overrides individual claims")
	issueMDOCCmd.Flags().StringVar(&issueSaveTemplate, "save-template", "", "Save the issued claims and settings as a credential template with this name")
	issueMDOCCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK); ephemeral P-256 if omitted")
	issueMDOCCmd.Flags().StringVar(&issueDocType, "doc-type", "eu.europa.ec.eudi.pid.1", "Document type")
	issueMDOCCmd.Flags().StringVar(&issueNamespace, "namespace", "eu.europa.ec.eudi.pid.1", "Namespace")
	issueMDOCCmd.Flags().StringVar(&issueExpires, "exp", "720h", "Expiration duration (e.g. 720h, 24h)")
	issueMDOCCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueMDOCCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueMDOCCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Comma-separated claim names to omit from --pid (e.g. birth_place,sex)")
	issueMDOCCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueMDOCCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueMDOCCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")
	addIssueTrustMetadataFlags(issueMDOCCmd)

	// Shell completion for knowable values
	for _, c := range []*cobra.Command{issueSDJWTCmd, issueJWTCmd, issueMDOCCmd} {
		_ = c.RegisterFlagCompletionFunc("template", completeTemplateNames)
		_ = c.RegisterFlagCompletionFunc("trust-profile", staticCompletion("auto", "pid", "local"))
	}
	_ = issueCmd.RegisterFlagCompletionFunc("remote", completeRemoteFlag)
	_ = issueCmd.MarkPersistentFlagDirname("wallet-dir")
	_ = issueCmd.MarkPersistentFlagDirname("templates-dir")
}

func runIssueSDJWT(cmd *cobra.Command, args []string) error {
	if issueToWallet {
		return runIssueSDJWTToWallet(cmd)
	}

	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	tpl, err := resolveIssueTemplate(cmd, "sdjwt")
	if err != nil {
		return err
	}
	claims, err := resolveIssueClaimsForFormat("sdjwt", tpl)
	if err != nil {
		return err
	}
	alwaysDisclosed, err := resolveIssueAlwaysDisclosed("sdjwt", tpl)
	if err != nil {
		return err
	}

	expDuration, err := time.ParseDuration(issueExpires)
	if err != nil {
		return fmt.Errorf("invalid --exp duration: %w", err)
	}

	nbf, err := parseNBF(issueNBF)
	if err != nil {
		return err
	}

	cfg := mock.SDJWTConfig{
		Issuer:          issueIssuer,
		VCT:             issueVCT,
		ExpiresIn:       expDuration,
		NotBefore:       nbf,
		Claims:          claims,
		Key:             key,
		StatusListURI:   issueStatusListURI,
		StatusListIdx:   issueStatusListIdx,
		AlwaysDisclosed: alwaysDisclosed,
	}

	result, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		return fmt.Errorf("generating SD-JWT: %w", err)
	}

	fmt.Println(result)

	if err := saveIssueTemplate("sdjwt", claims, alwaysDisclosed); err != nil {
		return err
	}
	if issueToWallet {
		return importToWallet(result)
	}
	return nil
}

func runIssueJWT(cmd *cobra.Command, args []string) error {
	if issueToWallet {
		return runIssueJWTToWallet(cmd)
	}

	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	tpl, err := resolveIssueTemplate(cmd, "jwt")
	if err != nil {
		return err
	}
	claims, err := resolveIssueClaimsForFormat("jwt", tpl)
	if err != nil {
		return err
	}

	expDuration, err := time.ParseDuration(issueExpires)
	if err != nil {
		return fmt.Errorf("invalid --exp duration: %w", err)
	}

	nbf, err := parseNBF(issueNBF)
	if err != nil {
		return err
	}

	cfg := mock.JWTConfig{
		Issuer:        issueIssuer,
		VCT:           issueVCT,
		ExpiresIn:     expDuration,
		NotBefore:     nbf,
		Claims:        claims,
		Key:           key,
		StatusListURI: issueStatusListURI,
		StatusListIdx: issueStatusListIdx,
	}

	result, err := mock.GenerateJWT(cfg)
	if err != nil {
		return fmt.Errorf("generating JWT: %w", err)
	}

	fmt.Println(result)

	if err := saveIssueTemplate("jwt", claims, nil); err != nil {
		return err
	}
	if issueToWallet {
		return importToWallet(result)
	}
	return nil
}

func runIssueMDOC(cmd *cobra.Command, args []string) error {
	if issueToWallet {
		return runIssueMDOCToWallet(cmd)
	}

	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	tpl, err := resolveIssueTemplate(cmd, "mdoc")
	if err != nil {
		return err
	}
	claims, err := resolveIssueClaimsForFormat("mdoc", tpl)
	if err != nil {
		return err
	}
	if _, err := resolveIssueAlwaysDisclosed("mdoc", tpl); err != nil {
		return err
	}

	expDuration, err := time.ParseDuration(issueExpires)
	if err != nil {
		return fmt.Errorf("invalid --exp duration: %w", err)
	}

	nbf, err := parseNBF(issueNBF)
	if err != nil {
		return err
	}

	cfg := mock.MDOCConfig{
		DocType:       issueDocType,
		Namespace:     issueNamespace,
		Claims:        claims,
		Key:           key,
		ExpiresIn:     expDuration,
		ValidFrom:     nbf,
		StatusListURI: issueStatusListURI,
		StatusListIdx: issueStatusListIdx,
	}

	result, err := mock.GenerateMDOC(cfg)
	if err != nil {
		return fmt.Errorf("generating mDOC: %w", err)
	}

	fmt.Println(result)

	if err := saveIssueTemplate("mdoc", claims, nil); err != nil {
		return err
	}
	if issueToWallet {
		return importToWallet(result)
	}
	return nil
}

func loadOrGenerateIssueKey() (*ecdsa.PrivateKey, error) {
	if issueKeyPath != "" {
		privKey, err := keys.LoadPrivateKey(issueKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading key: %w", err)
		}
		ecKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("--key must be an EC private key (P-256)")
		}
		return ecKey, nil
	}

	key, err := mock.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Ephemeral signing key (public JWK):")
	fmt.Fprintln(os.Stderr, mock.PublicKeyJWK(&key.PublicKey))
	return key, nil
}

func loadWalletForIssue(cmd *cobra.Command) (*wallet.Wallet, *wallet.WalletStore, error) {
	store := wallet.NewWalletStore(walletDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		return nil, nil, fmt.Errorf("loading wallet: %w", err)
	}
	if templatesDir != "" {
		w.TemplatesDir = templatesDir
	}

	if issueKeyPath != "" {
		issuerKey, err := loadWalletECKey(issueKeyPath, "issuer")
		if err != nil {
			return nil, nil, err
		}
		w.IssuerKey = issuerKey
		if len(w.CertChain) < 2 || w.CAKey == nil {
			return nil, nil, fmt.Errorf("wallet has no CA certificate chain")
		}
		if err := w.SetCertificateAuthority(w.CAKey, w.CertChain[len(w.CertChain)-1]); err != nil {
			return nil, nil, fmt.Errorf("rebuilding wallet issuer certificate chain: %w", err)
		}
	}

	if cmd.Flags().Changed("iss") {
		w.IssuerURL = strings.TrimRight(strings.TrimSpace(issueIssuer), "/")
	} else if strings.TrimSpace(w.IssuerURL) == "" || (registeredWalletListenerPort() > 0 && isLocalhostIssuerURL(w.IssuerURL)) {
		w.IssuerURL = wallet.LocalIssuerURL(defaultWalletCommandPort()+1, false)
	}

	return w, store, nil
}

func runIssueSDJWTToWallet(cmd *cobra.Command) error {
	return runIssueToWallet(cmd, "sdjwt")
}

func runIssueJWTToWallet(cmd *cobra.Command) error {
	return runIssueToWallet(cmd, "jwt")
}

func runIssueMDOCToWallet(cmd *cobra.Command) error {
	return runIssueToWallet(cmd, "mdoc")
}

func runIssueToWallet(cmd *cobra.Command, format string) error {
	req, err := issueAPIRequestFromFlags(cmd, format)
	if err != nil {
		return err
	}
	svc, err := managedWalletWithLoader(func() (*wallet.Wallet, *wallet.WalletStore, error) {
		return loadWalletForIssue(cmd)
	})
	if err != nil {
		return err
	}
	result, err := svc.Issue(req)
	if err != nil {
		return err
	}
	fmt.Println(docString(result, "raw"))
	if path := docString(result, "template_path"); path != "" {
		printTemplateSaved("Saved", issueSaveTemplate, path)
	}
	label := docString(result, "vct")
	if label == "" {
		label = docString(result, "doctype")
	}
	fmt.Fprintf(os.Stderr, "Imported %s credential (%s) into wallet\n", docString(result, "format"), label)
	return nil
}

// resolveIssueTemplate loads the credential template selected by --template,
// or the pre-defined german-pid template when --pid is set without --claims. It
// applies the template's VCT, doc type, namespace, and expiry to flags the
// user did not set explicitly.
func resolveIssueTemplate(cmd *cobra.Command, format string) (*credtemplate.Template, error) {
	var name string
	switch {
	case issueTemplate != "":
		name = issueTemplate
	case issuePID && issueClaims == "":
		if format == "mdoc" {
			name = "german-pid-mdoc"
		} else {
			name = "german-pid-sdjwt"
		}
	default:
		return nil, nil
	}

	tpl, err := credtemplate.Load(name, resolveTemplatesDir())
	if err != nil {
		return nil, err
	}
	if tpl.Format != "" {
		tplFormat, err := credtemplate.NormalizeFormat(tpl.Format)
		if err != nil {
			return nil, err
		}
		if tplFormat != "" && tplFormat != format {
			return nil, fmt.Errorf("template %q is for format %s, not %s", tpl.Name, tplFormat, format)
		}
	}

	flags := cmd.Flags()
	if tpl.VCT != "" && flags.Lookup("vct") != nil && !flags.Changed("vct") {
		issueVCT = tpl.VCT
	}
	if tpl.DocType != "" && flags.Lookup("doc-type") != nil && !flags.Changed("doc-type") {
		issueDocType = tpl.DocType
	}
	if tpl.Namespace != "" && flags.Lookup("namespace") != nil && !flags.Changed("namespace") {
		issueNamespace = tpl.Namespace
	}
	if tpl.Exp != "" && !flags.Changed("exp") {
		issueExpires = tpl.Exp
	}
	return tpl, nil
}

// resolveIssueAlwaysDisclosed combines the template's always-disclosed list
// with --always-disclosed. Ignored for jwt (all claims are plain there) and
// rejected for mdoc (every element is selectively disclosable).
func resolveIssueAlwaysDisclosed(format string, tpl *credtemplate.Template) ([]string, error) {
	var merged []string
	seen := make(map[string]bool)
	var lists [][]string
	if tpl != nil {
		lists = append(lists, tpl.AlwaysDisclosed)
	}
	lists = append(lists, issueAlwaysDisclosed)
	for _, list := range lists {
		for _, path := range list {
			path = strings.TrimSpace(path)
			if path == "" || seen[path] {
				continue
			}
			seen[path] = true
			merged = append(merged, path)
		}
	}
	switch format {
	case "mdoc":
		if len(merged) > 0 {
			return nil, fmt.Errorf("always-disclosed claims are not supported for mdoc: every mdoc element is selectively disclosable")
		}
		return nil, nil
	case "jwt":
		return nil, nil
	default:
		return merged, nil
	}
}

// saveIssueTemplate persists the resolved issuance parameters as a user
// template, mirroring the wallet's save-as-template behavior for the
// standalone issue commands.
func saveIssueTemplate(format string, claims map[string]any, alwaysDisclosed []string) error {
	if issueSaveTemplate == "" {
		return nil
	}
	tpl := credtemplate.Template{
		Name:            issueSaveTemplate,
		Format:          format,
		Exp:             issueExpires,
		Claims:          claims,
		AlwaysDisclosed: alwaysDisclosed,
	}
	if format == "mdoc" {
		tpl.DocType = issueDocType
		tpl.Namespace = issueNamespace
	} else {
		tpl.VCT = issueVCT
	}
	path, err := credtemplate.Save(resolveTemplatesDir(), tpl)
	if err != nil {
		return fmt.Errorf("saving template: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Saved template %q to %s\n", issueSaveTemplate, path)
	return nil
}

// issueAPIRequestFromFlags maps the issue flags onto the POST /api/issue
// request body, the issuance contract shared by both walletService backends.
// Templates resolve on the managed wallet against its template directory, so
// only the template name and the explicit overrides travel.
func issueAPIRequestFromFlags(cmd *cobra.Command, format string) (map[string]any, error) {
	req := map[string]any{"format": format}
	if issueTemplate != "" {
		req["template"] = issueTemplate
	}
	if issuePID {
		req["pid"] = true
	}
	if issueClaims != "" {
		var data []byte
		if strings.HasPrefix(issueClaims, "@") {
			var err error
			data, err = os.ReadFile(issueClaims[1:])
			if err != nil {
				return nil, fmt.Errorf("reading claims file: %w", err)
			}
		} else {
			data = []byte(issueClaims)
		}
		var claims map[string]any
		if err := json.Unmarshal(data, &claims); err != nil {
			return nil, fmt.Errorf("parsing claims JSON: %w", err)
		}
		req["claims"] = claims
	}
	if len(issueOmit) > 0 {
		req["omit"] = issueOmit
	}
	if len(issueAlwaysDisclosed) > 0 {
		req["always_disclosed"] = issueAlwaysDisclosed
	}
	if issueSaveTemplate != "" {
		req["save_as_template"] = issueSaveTemplate
	}
	flags := cmd.Flags()
	if flags.Changed("vct") {
		req["vct"] = issueVCT
	}
	if flags.Lookup("doc-type") != nil && flags.Changed("doc-type") {
		req["doctype"] = issueDocType
	}
	if flags.Lookup("namespace") != nil && flags.Changed("namespace") {
		req["namespace"] = issueNamespace
	}
	if flags.Changed("exp") {
		req["exp"] = issueExpires
	}
	if issueNBF != "" {
		req["nbf"] = issueNBF
	}
	if flags.Changed("status-list-uri") {
		req["status_list_uri"] = issueStatusListURI
	}
	if flags.Changed("status-list-idx") {
		req["status_list_idx"] = issueStatusListIdx
	}
	if issueTrustProfile != "" && issueTrustProfile != "auto" {
		req["trust_profile"] = issueTrustProfile
	}
	// The registration metadata flags (--entitlement, --trust-list-type, ...)
	// travel in the "trust" object. The server sets Format/VCT/DocType and
	// applies the trust profile, so an empty spec here is equivalent to sending
	// none.
	req["trust"] = issueTrustSpecFromFlags()
	return req, nil
}

func resolveIssueClaimsForFormat(format string, tpl *credtemplate.Template) (map[string]any, error) {
	var overrides map[string]any
	if issueClaims != "" {
		var data []byte
		if strings.HasPrefix(issueClaims, "@") {
			var err error
			data, err = os.ReadFile(issueClaims[1:])
			if err != nil {
				return nil, fmt.Errorf("reading claims file: %w", err)
			}
		} else {
			data = []byte(issueClaims)
		}
		if err := json.Unmarshal(data, &overrides); err != nil {
			return nil, fmt.Errorf("parsing claims JSON: %w", err)
		}
	}

	if tpl != nil {
		return omitClaims(credtemplate.MergeClaims(tpl.Claims, overrides), issueOmit), nil
	}
	if overrides != nil {
		return omitClaims(overrides, issueOmit), nil
	}
	return omitClaims(mock.DefaultClaims, issueOmit), nil
}

func addIssueTrustMetadataFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&issueTrustProfile, "trust-profile", "auto", "Trust-list profile for --wallet registration metadata: auto, pid, or local")
	cmd.Flags().StringSliceVar(&issueEntitlements, "entitlement", nil, "Registrar entitlement URI to persist with the issued credential (repeatable)")
	cmd.Flags().StringVar(&issueTrustListType, "trust-list-type", "", "Trust-list LoTE type to persist with the issued credential")
	cmd.Flags().StringVar(&issueStatusDetermination, "status-determination-approach", "", "Trust-list status determination approach URI to persist with the issued credential")
	cmd.Flags().StringVar(&issueSchemeCommunityRule, "scheme-community-rule", "", "Trust-list scheme community rule URI to persist with the issued credential")
	cmd.Flags().StringVar(&issueSchemeTerritory, "scheme-territory", "", "Trust-list scheme territory to persist with the issued credential")
	cmd.Flags().StringVar(&issueTrustEntityName, "trust-entity-name", "", "Trust-list entity name to persist with the issued credential")
	cmd.Flags().StringVar(&issueIssuanceServiceType, "issuance-service-type", "", "Trust-list issuance service type identifier to persist with the issued credential")
	cmd.Flags().StringVar(&issueRevocationServiceType, "revocation-service-type", "", "Trust-list revocation service type identifier to persist with the issued credential")
	cmd.Flags().StringVar(&issueIssuanceServiceName, "issuance-service-name", "", "Trust-list issuance service name to persist with the issued credential")
	cmd.Flags().StringVar(&issueRevocationServiceName, "revocation-service-name", "", "Trust-list revocation service name to persist with the issued credential")
}

func issueTrustSpecFromFlags() wallet.IssuedAttestationSpec {
	return wallet.IssuedAttestationSpec{
		Entitlements:                append([]string(nil), issueEntitlements...),
		TrustListType:               issueTrustListType,
		StatusDeterminationApproach: issueStatusDetermination,
		SchemeTypeCommunityRules:    issueSchemeCommunityRule,
		SchemeTerritory:             issueSchemeTerritory,
		EntityName:                  issueTrustEntityName,
		IssuanceServiceType:         issueIssuanceServiceType,
		RevocationServiceType:       issueRevocationServiceType,
		IssuanceServiceName:         issueIssuanceServiceName,
		RevocationServiceName:       issueRevocationServiceName,
	}
}

func buildIssueAttestationSpecForType(format, vct, docType string) (wallet.IssuedAttestationSpec, error) {
	spec := issueTrustSpecFromFlags()
	spec.Format = format
	spec.VCT = vct
	spec.DocType = docType
	return wallet.NormalizeIssuedAttestationSpec(spec, issueTrustProfile)
}

func buildIssueAttestationSpec(imported *wallet.StoredCredential) (wallet.IssuedAttestationSpec, error) {
	return buildIssueAttestationSpecForType(imported.Format, imported.VCT, imported.DocType)
}

func importToWallet(raw string) error {
	store := wallet.NewWalletStore(walletDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		return fmt.Errorf("loading wallet: %w", err)
	}

	imported, err := w.ImportCredential(raw)
	if err != nil {
		return fmt.Errorf("importing to wallet: %w", err)
	}
	spec, err := buildIssueAttestationSpec(imported)
	if err != nil {
		return fmt.Errorf("building issued-attestation metadata: %w", err)
	}
	if err := w.RegisterIssuedAttestation(spec); err != nil {
		return fmt.Errorf("registering issued-attestation metadata: %w", err)
	}

	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}

	label := imported.VCT
	if label == "" {
		label = imported.DocType
	}
	fmt.Fprintf(os.Stderr, "Imported %s credential (%s) into wallet\n", imported.Format, label)
	return nil
}

func parseNBF(val string) (*time.Time, error) {
	if val == "" {
		return nil, nil
	}
	// Try as duration first (e.g. "-1h")
	if d, err := time.ParseDuration(val); err == nil {
		t := time.Now().Add(d)
		return &t, nil
	}
	// Try as RFC3339
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return nil, fmt.Errorf("invalid --nbf value %q: expected RFC3339 (e.g. 2025-01-15T00:00:00Z) or duration (e.g. -1h)", val)
	}
	return &t, nil
}

func omitClaims(claims map[string]any, omit []string) map[string]any {
	if len(omit) == 0 {
		return claims
	}
	exclude := make(map[string]bool, len(omit))
	for _, name := range omit {
		exclude[strings.TrimSpace(name)] = true
	}
	result := make(map[string]any, len(claims))
	for k, v := range claims {
		if !exclude[k] {
			result[k] = v
		}
	}
	return result
}
