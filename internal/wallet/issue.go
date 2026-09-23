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

package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v2/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v2/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v2/internal/mock"
)

const DefaultIssueExpiry = 720 * time.Hour

const DefaultMDOCDocType = "eu.europa.ec.eudi.pid.1"

// IssueOptions describes a credential to issue with the wallet's issuer key
// and import into the wallet. It is shared by the `issue ... --wallet` CLI
// commands and the wallet server's POST /api/issue endpoint.
type IssueOptions struct {
	// Format is "sdjwt", "jwt", or "mdoc" (the stored format identifiers
	// "dc+sd-jwt", "jwt_vc_json", and "mso_mdoc" are accepted as aliases).
	// When empty, the template's format is used.
	Format string
	// Template is a credential template name or file path. Template claims
	// become the base claim set, with Claims merged on top. Template VCT,
	// doc type, namespace, and expiry apply when the matching option is
	// unset. Templates are resolved against the wallet's template directory.
	Template string
	// Claims are the credential claims. When nil and no template is given,
	// PID selects the full EUDI PID Rulebook claim set (the pre-defined PID
	// templates of the type VCT names), otherwise a small default claim set
	// is used.
	Claims map[string]any
	PID    bool
	// AlwaysDisclosed lists claims (dotted paths for nested claims) that are
	// embedded plainly in an SD-JWT payload instead of becoming selective
	// disclosures. Combined with the template's always_disclosed list.
	// Rejected for mdoc (every element is selectively disclosable there).
	AlwaysDisclosed []string
	// SaveTemplate saves the resolved issuance parameters as a user template
	// with this name after successful issuance.
	SaveTemplate string
	// Omit removes top-level claims by name from the resolved claim set.
	Omit []string
	// VCT applies to sdjwt/jwt and defaults to mock.DefaultPIDVCT.
	VCT string
	// DocType and Namespace apply to mdoc. DocType defaults to
	// DefaultMDOCDocType, Namespace defaults to DocType. Namespace is the
	// default namespace for claims. A claim key of the form
	// "namespace:element" places that element in its own namespace instead
	// (the same convention used when displaying imported mdoc claims).
	DocType   string
	Namespace string
	// ExpiresIn defaults to DefaultIssueExpiry when zero.
	ExpiresIn time.Duration
	NotBefore *time.Time
	// StatusListURI and StatusListIdx control the embedded status reference.
	// A nil URI means "use the wallet's own status list when configured". An
	// explicit empty URI disables the status reference. A nil index means
	// "next free index" when the wallet's own status list is used.
	StatusListURI *string
	StatusListIdx *int
	// TrustProfile is the trust-list profile hint: "", "auto", "pid", or "local".
	TrustProfile string
	// Trust carries optional trust/registration metadata to persist with the
	// issued credential type. Format, VCT, and DocType are overwritten with
	// the resolved values.
	Trust IssuedAttestationSpec
	// Display follows OpenID4VCI §12.2.4. Cache data or HTTPS images with address
	// checks. Nil supplies no explicit display metadata.
	Display *IssueDisplay
	// Issue copies with distinct holder keys for batch rotation (EUDI ARF method C).
	// Values below two issue one credential. JWT VC batches are unsupported because
	// they lack holder binding.
	BatchSize int
	// Use this template's display when a form supplies claims separately. Explicit
	// Display fields override it. Empty falls back to Template.
	DisplayTemplate string
	// SigningKey and SigningCertChain replace the wallet's issuer key and
	// certificate chain for this issuance. Set together, and the leaf must
	// certify the key. Trust and registration metadata are not applied, the
	// type registers like an imported foreign credential.
	SigningKey       *ecdsa.PrivateKey
	SigningCertChain []*x509.Certificate
	// Unbound issues the credential without a holder key. An SD-JWT VC then
	// names no cnf, a bearer credential (cnf is optional, SD-JWT VC §3.2.2.2).
	// An mdoc names no MSO deviceKey, which ISO 18013-5 §9.1.2.4 makes
	// mandatory, so an unbound mdoc is a malformed document for testing
	// verifier rejection.
	Unbound bool
}

// ParseSigningOverride reads a signing override: a PEM or JWK private key and
// a PEM certificate chain, leaf first. Both must be given and the leaf must
// certify the key.
func ParseSigningOverride(keyData, certData string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	keyData, certData = strings.TrimSpace(keyData), strings.TrimSpace(certData)
	if keyData == "" && certData == "" {
		return nil, nil, nil
	}
	if keyData == "" || certData == "" {
		return nil, nil, fmt.Errorf("signing key and signing certificate must be given together")
	}
	parsed, err := keys.ParsePrivateKey([]byte(keyData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing signing key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("the signing key must be an EC private key")
	}
	chain, err := keys.ParseCertificatesPEM([]byte(certData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing signing certificate: %w", err)
	}
	leafPub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafPub.Equal(&key.PublicKey) {
		return nil, nil, fmt.Errorf("the leaf certificate does not certify the signing key")
	}
	return key, chain, nil
}

// judgeSigningChainAnchor holds a signing-override chain that carries its
// self-signed root to the validation mode: strict refuses the issuance, debug
// warns and embeds the chain as given (for testing verifier rejection). A JWT
// VC is exempt: RFC 7515 lets x5c carry the full chain including the root.
func (w *Wallet) judgeSigningChainAnchor(format string, chain []*x509.Certificate) error {
	if format == "jwt" || len(mock.WithoutSelfSignedTrustAnchor(chain)) == len(chain) {
		return nil
	}
	finding := "HAIP 1.0 §6.1.1: the signing certificate chain includes its self-signed root, which MUST NOT be included in the credential's x5c"
	if format == "mdoc" {
		finding = "ISO 18013-5: the signing certificate chain includes its self-signed root, which does not belong in the x5chain header"
	}
	if w.Mode() == ValidationModeStrict {
		return fmt.Errorf("%s", finding)
	}
	w.AddWarning("management", finding+". It is embedded as given.", nil)
	return nil
}

type IssueDisplay struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
	Logo            string `json:"logo"`
	LogoAltText     string `json:"logo_alt_text"`
	BackgroundImage string `json:"background_image"`
}

type IssueResult struct {
	Raw        string
	Credential *StoredCredential
	// StatusIdx is the status list index embedded in the credential. It is
	// only meaningful when StatusRegistered is true.
	StatusIdx int
	// StatusRegistered reports whether the credential was registered on the
	// wallet's own status list.
	StatusRegistered bool
	TemplatePath     string
}

// IssueCredential requires the caller to save the wallet to persist the credential, status
// and type registration.
func (w *Wallet) IssueCredential(opts IssueOptions) (*IssueResult, error) {
	tpl, pidTemplate, err := w.resolveIssueTemplate(opts)
	if err != nil {
		return nil, err
	}

	formatInput := opts.Format
	if strings.TrimSpace(formatInput) == "" && tpl != nil {
		formatInput = tpl.Format
	}
	format, err := normalizeIssueFormat(formatInput)
	if err != nil {
		return nil, err
	}
	// A template the caller named has to match the format they asked for. A
	// PID template picked from opts.PID is a claim set, so a jwt request uses
	// the SD-JWT PID template's claims.
	if tpl != nil && tpl.Format != "" && !pidTemplate {
		tplFormat, err := credtemplate.NormalizeFormat(tpl.Format)
		if err != nil {
			return nil, err
		}
		if tplFormat != "" && tplFormat != format {
			return nil, fmt.Errorf("template %q is for format %s, not %s", tpl.Name, tplFormat, format)
		}
	}

	claims := opts.Claims
	if tpl != nil {
		claims = credtemplate.MergeClaims(tpl.Claims, opts.Claims)
	} else if claims == nil {
		claims = mock.DefaultClaims
	}
	claims = omitIssueClaims(claims, opts.Omit)

	alwaysDisclosed := opts.AlwaysDisclosed
	if tpl != nil {
		alwaysDisclosed = mergeAlwaysDisclosed(tpl.AlwaysDisclosed, opts.AlwaysDisclosed)
	}
	if format == "mdoc" && len(alwaysDisclosed) > 0 {
		return nil, fmt.Errorf("always-disclosed claims are not supported for mdoc: every mdoc element is selectively disclosable")
	}

	expiresIn := opts.ExpiresIn
	if expiresIn == 0 && tpl != nil && tpl.Exp != "" {
		expiresIn, err = time.ParseDuration(tpl.Exp)
		if err != nil {
			return nil, fmt.Errorf("template %q: invalid exp duration: %w", tpl.Name, err)
		}
	}
	if expiresIn == 0 {
		expiresIn = DefaultIssueExpiry
	}

	vct := strings.TrimSpace(opts.VCT)
	if vct == "" && tpl != nil {
		vct = strings.TrimSpace(tpl.VCT)
	}
	if vct == "" {
		vct = mock.DefaultPIDVCT
	}
	docType := strings.TrimSpace(opts.DocType)
	if docType == "" && tpl != nil {
		docType = strings.TrimSpace(tpl.DocType)
	}
	if docType == "" {
		docType = DefaultMDOCDocType
	}
	namespace := strings.TrimSpace(opts.Namespace)
	if namespace == "" && tpl != nil {
		namespace = strings.TrimSpace(tpl.Namespace)
	}
	if namespace == "" {
		namespace = docType
	}

	statusURI, statusIdx, registerStatus, err := w.resolveIssueStatus(opts.StatusListURI, opts.StatusListIdx)
	if err != nil {
		return nil, err
	}

	spec := opts.Trust
	switch format {
	case "sdjwt":
		spec.Format, spec.VCT, spec.DocType = "dc+sd-jwt", vct, ""
	case "jwt":
		spec.Format, spec.VCT, spec.DocType = "jwt_vc_json", vct, ""
	case "mdoc":
		spec.Format, spec.VCT, spec.DocType = "mso_mdoc", "", docType
	}
	spec, err = NormalizeIssuedAttestationSpec(spec, opts.TrustProfile)
	if err != nil {
		return nil, err
	}
	signingKey := w.IssuerKey
	var certChain []*x509.Certificate
	if opts.SigningKey != nil {
		signingKey = opts.SigningKey
		certChain = opts.SigningCertChain
		if err := w.judgeSigningChainAnchor(format, certChain); err != nil {
			return nil, err
		}
	} else {
		certChain, err = w.SigningCertChainForIssuedCredential(spec, claims)
		if err != nil {
			return nil, err
		}
	}

	issuer := strings.TrimRight(strings.TrimSpace(w.IssuerURL), "/")
	if issuer == "" {
		issuer = "https://issuer.example"
	}

	var holderPub *ecdsa.PublicKey
	if !opts.Unbound && w.HolderKey != nil {
		holderPub = &w.HolderKey.PublicKey
	}

	if opts.BatchSize >= 2 {
		if format == "jwt" {
			return nil, fmt.Errorf("batch issuance needs holder binding, which jwt_vc_json does not carry")
		}
		if opts.Unbound {
			return nil, fmt.Errorf("an unbound credential cannot be issued as a batch (a batch needs a distinct holder key per copy)")
		}
	}

	signCopy := func(holderPub *ecdsa.PublicKey, statusIdx int) (string, error) {
		// An override chain is embedded as given, so a chain carrying its
		// root can be issued to test verifier rejection.
		keepAnchor := opts.SigningKey != nil
		switch format {
		case "sdjwt":
			return mock.GenerateSDJWT(mock.SDJWTConfig{
				Issuer: issuer, VCT: vct, ExpiresIn: expiresIn, NotBefore: opts.NotBefore,
				Claims: claims, Key: signingKey, HolderKey: holderPub,
				StatusListURI: statusURI, StatusListIdx: statusIdx, CertChain: certChain,
				AlwaysDisclosed: alwaysDisclosed, KeepTrustAnchor: keepAnchor,
			})
		case "jwt":
			return mock.GenerateJWT(mock.JWTConfig{
				Issuer: issuer, VCT: vct, ExpiresIn: expiresIn, NotBefore: opts.NotBefore,
				Claims: claims, Key: signingKey,
				StatusListURI: statusURI, StatusListIdx: statusIdx, CertChain: certChain,
			})
		case "mdoc":
			return mock.GenerateMDOC(mock.MDOCConfig{
				DocType: docType, NamespaceClaims: splitClaimsByNamespace(claims, namespace),
				Key: signingKey, HolderKey: holderPub, ExpiresIn: expiresIn, ValidFrom: opts.NotBefore,
				StatusListURI: statusURI, StatusListIdx: statusIdx, CertChain: certChain,
				KeepTrustAnchor: keepAnchor,
			})
		}
		return "", fmt.Errorf("unsupported format %q", format)
	}

	// Override display fields individually so setting a name or color preserves the
	// template's artwork.
	displaySource := tpl
	if opts.DisplayTemplate != "" {
		dt, err := credtemplate.Load(opts.DisplayTemplate, w.Templates)
		if err != nil {
			return nil, fmt.Errorf("loading the display template %q: %w", opts.DisplayTemplate, err)
		}
		displaySource = dt
	}
	var issuedDisplay *CredentialDisplay
	if displaySource != nil {
		issuedDisplay = w.templateDisplay(displaySource.Display)
	}
	if opts.Display != nil {
		issuedDisplay = mergeCredentialDisplay(issuedDisplay, w.issuedDisplay(*opts.Display))
	}
	applyIssuedDisplay := func(cred *StoredCredential) {
		if issuedDisplay != nil {
			w.rememberDisplay(cred, issuedDisplay)
		}
	}

	// A fixed index cannot be shared across a batch (a shared index would link
	// two presentations), so a batch draws even its first copy from the
	// counter. The fully automatic case (no status URI and no index) already
	// drew a unique counter index.
	if opts.BatchSize >= 2 && registerStatus && (opts.StatusListIdx != nil || opts.StatusListURI != nil) {
		if statusIdx, err = w.NextStatusIndex(); err != nil {
			return nil, err
		}
	}

	raw, err := signCopy(holderPub, statusIdx)
	if err != nil {
		return nil, fmt.Errorf("generating credential: %w", err)
	}
	imported, err := w.ImportCredential(raw)
	if err != nil {
		return nil, fmt.Errorf("importing to wallet: %w", err)
	}
	applyIssuedDisplay(imported)
	if registerStatus {
		w.RegisterStatusEntry(imported.ID, statusIdx)
	}

	// Use a separate holder key and status index for each batch copy so presentations
	// can rotate without sharing identifiers.
	if opts.BatchSize >= 2 {
		group := newCredentialID()
		w.setBatchFields(imported.ID, group, "")
		imported.BatchGroup = group
		for i := 1; i < opts.BatchSize; i++ {
			copyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("generating batch copy key: %w", err)
			}
			copyIdx := statusIdx
			if registerStatus {
				if copyIdx, err = w.NextStatusIndex(); err != nil {
					return nil, err
				}
			}
			copyRaw, err := signCopy(&copyKey.PublicKey, copyIdx)
			if err != nil {
				return nil, fmt.Errorf("generating batch copy: %w", err)
			}
			pem, err := encodeECPrivateKeyPEM(copyKey)
			if err != nil {
				return nil, err
			}
			copyCred, err := w.importBatchCopy(copyRaw, group, pem)
			if err != nil {
				return nil, fmt.Errorf("importing batch copy: %w", err)
			}
			applyIssuedDisplay(copyCred)
			if registerStatus {
				w.RegisterStatusEntry(copyCred.ID, copyIdx)
			}
		}
	}

	// The request's trust metadata describes the wallet CA, not a foreign
	// chain, so an override keeps the plain registration the import made.
	if opts.SigningKey == nil {
		if err := w.RegisterIssuedAttestation(spec); err != nil {
			return nil, fmt.Errorf("registering issued-attestation metadata: %w", err)
		}
	}

	result := &IssueResult{
		Raw:              raw,
		Credential:       imported,
		StatusIdx:        statusIdx,
		StatusRegistered: registerStatus,
	}

	if name := strings.TrimSpace(opts.SaveTemplate); name != "" {
		saved := credtemplate.Template{
			Name:            name,
			Format:          format,
			Exp:             formatIssueExpiry(expiresIn),
			Claims:          claims,
			AlwaysDisclosed: alwaysDisclosed,
		}
		switch format {
		case "mdoc":
			saved.DocType = docType
			saved.Namespace = namespace
		default:
			saved.VCT = vct
		}
		path, err := credtemplate.Save(w.Templates, saved)
		if err != nil {
			return nil, fmt.Errorf("saving template: %w", err)
		}
		result.TemplatePath = path
	}

	return result, nil
}

// Select an explicit template or the PID template for the requested type. pidTemplate
// distinguishes an inferred claim set from a named template, which must match the
// format.
func (w *Wallet) resolveIssueTemplate(opts IssueOptions) (tpl *credtemplate.Template, pidTemplate bool, err error) {
	if name := strings.TrimSpace(opts.Template); name != "" {
		tpl, err = credtemplate.Load(name, w.Templates)
		return tpl, false, err
	}
	if opts.PID && opts.Claims == nil {
		sdName, mdocName, _ := credtemplate.PIDTemplateNames(opts.VCT)
		name := sdName
		if format, _ := normalizeIssueFormat(opts.Format); format == "mdoc" {
			name = mdocName
		}
		tpl, err = credtemplate.Load(name, w.Templates)
		return tpl, true, err
	}
	return nil, false, nil
}

func mergeAlwaysDisclosed(base, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	var out []string
	for _, list := range [][]string{base, extra} {
		for _, path := range list {
			path = strings.TrimSpace(path)
			if path == "" || seen[path] {
				continue
			}
			seen[path] = true
			out = append(out, path)
		}
	}
	return out
}

func formatIssueExpiry(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	}
	return d.String()
}

func normalizeIssueFormat(format string) (string, error) {
	switch strings.TrimSpace(format) {
	case "sdjwt", "sd-jwt", "dc+sd-jwt":
		return "sdjwt", nil
	case "jwt", "jwt_vc_json":
		return "jwt", nil
	case "mdoc", "mso_mdoc":
		return "mdoc", nil
	default:
		return "", fmt.Errorf("unsupported credential format %q: expected sdjwt, jwt, or mdoc", format)
	}
}

// resolveIssueStatus mirrors the status-flag semantics of the issue commands:
// an explicit URI wins (and registers on the wallet's own status list only if
// it matches), an explicit index alone requires the wallet status list, and
// with neither the wallet status list is used when configured.
func (w *Wallet) resolveIssueStatus(uri *string, idx *int) (string, int, bool, error) {
	switch {
	case uri != nil:
		statusURI := strings.TrimSpace(*uri)
		if statusURI == "" {
			return "", 0, false, nil
		}
		statusIdx := 0
		if idx != nil {
			statusIdx = *idx
		}
		return statusURI, statusIdx, statusURI == w.StatusListURL(), nil
	case idx != nil:
		statusURI := strings.TrimSpace(w.StatusListURL())
		if statusURI == "" {
			return "", 0, false, fmt.Errorf("wallet status list is not configured")
		}
		return statusURI, *idx, true, nil
	default:
		statusURI := strings.TrimSpace(w.StatusListURL())
		if statusURI == "" {
			return "", 0, false, nil
		}
		idx, err := w.NextStatusIndex()
		if err != nil {
			return "", 0, false, err
		}
		return statusURI, idx, true, nil
	}
}

func splitClaimsByNamespace(claims map[string]any, defaultNamespace string) map[string]map[string]any {
	return mock.SplitClaimsByNamespace(claims, defaultNamespace)
}

func omitIssueClaims(claims map[string]any, omit []string) map[string]any {
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
