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
	"fmt"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// DefaultIssueExpiry is the credential lifetime used when no expiry is given.
const DefaultIssueExpiry = 720 * time.Hour

// DefaultMDOCDocType is the doc type / namespace used for mdoc issuance when
// none is given.
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
	// Display sets the credential's §12.2.4 appearance (name, description,
	// colors, logo and background image). Image fields take a data URI or an
	// https URI, which is fetched through the policed client and cached. Nil
	// leaves the credential without display metadata.
	Display *IssueDisplay
	// BatchSize mints this many distinct-key copies of the credential, tied
	// into one batch so the wallet presents an unused copy each time (EUDI ARF
	// method C). 0 or 1 issues a single credential. Needs holder binding, so it
	// is rejected for jwt_vc_json.
	BatchSize int
	// DisplayTemplate names the template whose display the credential wears,
	// used when a form flattened a template's claims into explicit values but
	// its embedded logo and background image could not travel in a form field.
	// The named template's display is the base; an explicit Display is laid over
	// it. Empty falls back to the Template (if any) for the display.
	DisplayTemplate string
}

// IssueDisplay is the appearance an operator sets for a self-issued credential.
type IssueDisplay struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
	Logo            string `json:"logo"`
	BackgroundImage string `json:"background_image"`
}

// IssueResult is the outcome of IssueCredential.
type IssueResult struct {
	// Raw is the encoded credential as printed by the issue commands.
	Raw string
	// Credential is the stored credential imported into the wallet.
	Credential *StoredCredential
	// StatusIdx is the status list index embedded in the credential. It is
	// only meaningful when StatusRegistered is true.
	StatusIdx int
	// StatusRegistered reports whether the credential was registered on the
	// wallet's own status list.
	StatusRegistered bool
	// TemplatePath is the file the issuance parameters were saved to when
	// SaveTemplate was set.
	TemplatePath string
}

// IssueCredential issues a credential with the wallet's issuer key and
// certificate chain, imports it into the wallet, and registers status and
// issued-attestation metadata. The caller is responsible for persisting the
// wallet afterwards.
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
	// A template the caller named has to match the format they asked for. One
	// PID picked for them is a claim set rather than a choice of format: the
	// SD-JWT PID template is what a jwt request with PID is asking for too,
	// since a JWT VC carries the same claims plainly.
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
	certChain, err := w.SigningCertChainForIssuedAttestation(spec)
	if err != nil {
		return nil, err
	}

	issuer := strings.TrimRight(strings.TrimSpace(w.IssuerURL), "/")
	if issuer == "" {
		issuer = "https://issuer.example"
	}

	var holderPub *ecdsa.PublicKey
	if w.HolderKey != nil {
		holderPub = &w.HolderKey.PublicKey
	}

	if opts.BatchSize >= 2 && format == "jwt" {
		return nil, fmt.Errorf("batch issuance needs holder binding, which jwt_vc_json does not carry")
	}

	// signCopy mints one credential, holder-bound to holderPub and carrying the
	// given status index.
	signCopy := func(holderPub *ecdsa.PublicKey, statusIdx int) (string, error) {
		switch format {
		case "sdjwt":
			return mock.GenerateSDJWT(mock.SDJWTConfig{
				Issuer: issuer, VCT: vct, ExpiresIn: expiresIn, NotBefore: opts.NotBefore,
				Claims: claims, Key: w.IssuerKey, HolderKey: holderPub,
				StatusListURI: statusURI, StatusListIdx: statusIdx, CertChain: certChain,
				AlwaysDisclosed: alwaysDisclosed,
			})
		case "jwt":
			return mock.GenerateJWT(mock.JWTConfig{
				Issuer: issuer, VCT: vct, ExpiresIn: expiresIn, NotBefore: opts.NotBefore,
				Claims: claims, Key: w.IssuerKey,
				StatusListURI: statusURI, StatusListIdx: statusIdx, CertChain: certChain,
			})
		case "mdoc":
			return mock.GenerateMDOC(mock.MDOCConfig{
				DocType: docType, NamespaceClaims: splitClaimsByNamespace(claims, namespace),
				Key: w.IssuerKey, HolderKey: holderPub, ExpiresIn: expiresIn, ValidFrom: opts.NotBefore,
				StatusListURI: statusURI, StatusListIdx: statusIdx, CertChain: certChain,
			})
		}
		return "", fmt.Errorf("unsupported format %q", format)
	}

	// The credential's appearance is a template's, with any explicit fields laid
	// over it, so choosing a template keeps its art (name, logo, background
	// image) even when the operator also sets a name or a color, and even when a
	// form flattened the template's claims and named it only for the display.
	displaySource := tpl
	if opts.DisplayTemplate != "" {
		dt, err := credtemplate.Load(opts.DisplayTemplate, w.TemplatesDir)
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

	// An explicit index cannot be shared across a batch (a shared index would
	// link two presentations), so a batch draws even its first copy from the
	// counter, the way the extra copies do. The auto case already drew a unique
	// index, so it is left as is.
	if opts.BatchSize >= 2 && registerStatus && opts.StatusListIdx != nil {
		statusIdx = w.nextStatusIndex()
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

	// A batch mints the extra copies, each on its own key and (when the wallet
	// governs the status) its own status index, tied to the primary so the
	// wallet presents an unused copy each time.
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
				copyIdx = w.nextStatusIndex()
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

	if err := w.RegisterIssuedAttestation(spec); err != nil {
		return nil, fmt.Errorf("registering issued-attestation metadata: %w", err)
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
		path, err := credtemplate.Save(w.TemplatesDir, saved)
		if err != nil {
			return nil, fmt.Errorf("saving template: %w", err)
		}
		result.TemplatePath = path
	}

	return result, nil
}

// resolveIssueTemplate loads the template referenced by opts: an explicit
// Template name or path, or the pre-defined PID template matching the format
// and the requested PID type when PID is set without explicit claims.
//
// resolveIssueTemplate reports pidTemplate for a template it picked itself
// from opts.PID, which the caller asked for by claim set rather than by name.
func (w *Wallet) resolveIssueTemplate(opts IssueOptions) (tpl *credtemplate.Template, pidTemplate bool, err error) {
	if name := strings.TrimSpace(opts.Template); name != "" {
		tpl, err = credtemplate.Load(name, w.TemplatesDir)
		return tpl, false, err
	}
	if opts.PID && opts.Claims == nil {
		sdName, mdocName, _ := credtemplate.PIDTemplateNames(opts.VCT)
		name := sdName
		if format, _ := normalizeIssueFormat(opts.Format); format == "mdoc" {
			name = mdocName
		}
		tpl, err = credtemplate.Load(name, w.TemplatesDir)
		return tpl, true, err
	}
	return nil, false, nil
}

// mergeAlwaysDisclosed combines two always-disclosed lists without duplicates.
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

// formatIssueExpiry renders a duration as a compact Go duration string
// (e.g. "720h" instead of "720h0m0s").
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
		return statusURI, w.NextStatusIndex(), true, nil
	}
}

// splitClaimsByNamespace groups mdoc claims by namespace. Keys of the form
// "namespace:element" go into that namespace, all other keys go into the
// default namespace.
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
