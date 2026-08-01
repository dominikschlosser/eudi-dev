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
	"fmt"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
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
	Format string
	// Claims are the credential claims. When nil, PID selects the full EUDI
	// PID Rulebook claim set, otherwise a small default claim set is used.
	Claims map[string]any
	PID    bool
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
	// A nil URI means "use the wallet's own status list when configured"; an
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
}

// IssueResult is the outcome of IssueCredential.
type IssueResult struct {
	// Raw is the encoded credential as printed by the issue commands.
	Raw string
	// Credential is the stored credential imported into the wallet.
	Credential *StoredCredential
	// StatusIdx is the status list index embedded in the credential; it is
	// only meaningful when StatusRegistered is true.
	StatusIdx int
	// StatusRegistered reports whether the credential was registered on the
	// wallet's own status list.
	StatusRegistered bool
}

// IssueCredential issues a credential with the wallet's issuer key and
// certificate chain, imports it into the wallet, and registers status and
// issued-attestation metadata. The caller is responsible for persisting the
// wallet afterwards.
func (w *Wallet) IssueCredential(opts IssueOptions) (*IssueResult, error) {
	format, err := normalizeIssueFormat(opts.Format)
	if err != nil {
		return nil, err
	}

	claims := opts.Claims
	if claims == nil {
		switch {
		case opts.PID && format == "mdoc":
			claims = mock.MDOCPIDClaims
		case opts.PID:
			claims = mock.SDJWTPIDClaims
		default:
			claims = mock.DefaultClaims
		}
	}
	claims = omitIssueClaims(claims, opts.Omit)

	expiresIn := opts.ExpiresIn
	if expiresIn == 0 {
		expiresIn = DefaultIssueExpiry
	}

	vct := strings.TrimSpace(opts.VCT)
	if vct == "" {
		vct = mock.DefaultPIDVCT
	}
	docType := strings.TrimSpace(opts.DocType)
	if docType == "" {
		docType = DefaultMDOCDocType
	}
	namespace := strings.TrimSpace(opts.Namespace)
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

	var raw string
	switch format {
	case "sdjwt":
		raw, err = mock.GenerateSDJWT(mock.SDJWTConfig{
			Issuer:        issuer,
			VCT:           vct,
			ExpiresIn:     expiresIn,
			NotBefore:     opts.NotBefore,
			Claims:        claims,
			Key:           w.IssuerKey,
			HolderKey:     holderPub,
			StatusListURI: statusURI,
			StatusListIdx: statusIdx,
			CertChain:     certChain,
		})
		if err != nil {
			return nil, fmt.Errorf("generating SD-JWT: %w", err)
		}
	case "jwt":
		raw, err = mock.GenerateJWT(mock.JWTConfig{
			Issuer:        issuer,
			VCT:           vct,
			ExpiresIn:     expiresIn,
			NotBefore:     opts.NotBefore,
			Claims:        claims,
			Key:           w.IssuerKey,
			StatusListURI: statusURI,
			StatusListIdx: statusIdx,
			CertChain:     certChain,
		})
		if err != nil {
			return nil, fmt.Errorf("generating JWT: %w", err)
		}
	case "mdoc":
		raw, err = mock.GenerateMDOC(mock.MDOCConfig{
			DocType:         docType,
			NamespaceClaims: splitClaimsByNamespace(claims, namespace),
			Key:             w.IssuerKey,
			HolderKey:       holderPub,
			ExpiresIn:       expiresIn,
			ValidFrom:       opts.NotBefore,
			StatusListURI:   statusURI,
			StatusListIdx:   statusIdx,
			CertChain:       certChain,
		})
		if err != nil {
			return nil, fmt.Errorf("generating mDOC: %w", err)
		}
	}

	imported, err := w.ImportCredential(raw)
	if err != nil {
		return nil, fmt.Errorf("importing to wallet: %w", err)
	}
	if registerStatus {
		w.RegisterStatusEntry(imported.ID, statusIdx)
	}
	if err := w.RegisterIssuedAttestation(spec); err != nil {
		return nil, fmt.Errorf("registering issued-attestation metadata: %w", err)
	}

	return &IssueResult{
		Raw:              raw,
		Credential:       imported,
		StatusIdx:        statusIdx,
		StatusRegistered: registerStatus,
	}, nil
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
	out := make(map[string]map[string]any)
	for key, value := range claims {
		ns, name := defaultNamespace, key
		if i := strings.Index(key, ":"); i > 0 {
			ns, name = key[:i], key[i+1:]
		}
		if out[ns] == nil {
			out[ns] = make(map[string]any)
		}
		out[ns][name] = value
	}
	if len(out) == 0 {
		out[defaultNamespace] = map[string]any{}
	}
	return out
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
