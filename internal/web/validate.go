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

package web

import (
	"crypto"
	"fmt"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/output"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/statuslist"
	"github.com/dominikschlosser/eudi-dev/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/internal/validate"
)

// ValidateOpts holds the options for credential validation.
type ValidateOpts struct {
	Key          string
	TrustListURL string
	TrustListRaw string
	CheckStatus  bool
}

// Validate decodes a credential and runs validation checks.
// It returns the same structure as Decode, plus a "validation" object.
func Validate(input string, opts ValidateOpts) (map[string]any, error) {
	detected := detectCredentialFormat(input)

	var checks []CheckResult

	switch detected {
	case format.FormatSDJWT:
		token, err := sdjwt.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("parsing SD-JWT: %w", err)
		}
		result := output.BuildSDJWTJSON(token)

		// Expiry check
		checks = append(checks, checkSDJWTExpiry(token))

		// Integrity check
		checks = append(checks, CheckSDJWTIntegrity(token))

		// Signature check
		checks = append(checks, checkSDJWTSignature(token, opts))

		// Status check
		checks = append(checks, checkSDJWTStatus(token, opts))

		result["validation"] = map[string]any{
			"checks": checks,
		}
		return result, nil

	case format.FormatJWT:
		token, err := sdjwt.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("parsing JWT: %w", err)
		}
		result := output.BuildJWTJSON(token)

		// Expiry check
		checks = append(checks, checkSDJWTExpiry(token))

		// Integrity — not applicable for plain JWT
		checks = append(checks, CheckResult{
			Name:   "integrity",
			Status: "skipped",
			Detail: "Not applicable for plain JWT",
		})

		// Signature check
		checks = append(checks, checkSDJWTSignature(token, opts))

		// Status check — not applicable for plain JWT
		checks = append(checks, CheckResult{
			Name:   "status",
			Status: "skipped",
			Detail: "Not applicable for plain JWT",
		})

		result["validation"] = map[string]any{
			"checks": checks,
		}
		return result, nil

	case format.FormatMDOC:
		doc, err := mdoc.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("parsing mDOC: %w", err)
		}
		result := output.BuildMDOCJSON(doc)

		// Expiry check
		checks = append(checks, checkMDOCExpiry(doc))

		// Integrity check
		checks = append(checks, CheckMDOCIntegrity(doc))

		// Signature check
		checks = append(checks, checkMDOCSignature(doc, opts))

		// Status check
		checks = append(checks, checkMDOCStatus(doc, opts))

		result["validation"] = map[string]any{
			"checks": checks,
		}
		return result, nil

	default:
		return nil, fmt.Errorf("unable to auto-detect credential format (not JWT, SD-JWT, or mDOC)")
	}
}

func checkSDJWTExpiry(token *sdjwt.Token) CheckResult {
	now := time.Now()

	if nbf, ok := token.Payload["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		if now.Before(nbfTime) {
			return CheckResult{
				Name:   "expiry",
				Status: "fail",
				Detail: fmt.Sprintf("not yet valid (valid from %s)", nbfTime.Format(time.RFC3339)),
			}
		}
	}

	exp, ok := token.Payload["exp"].(float64)
	if !ok {
		return CheckResult{
			Name:   "expiry",
			Status: "skipped",
			Detail: "No exp claim present",
		}
	}

	expTime := time.Unix(int64(exp), 0)
	if now.After(expTime) {
		return CheckResult{
			Name:   "expiry",
			Status: "fail",
			Detail: fmt.Sprintf("expired %s", relativeTimeGo(expTime)),
		}
	}

	return CheckResult{
		Name:   "expiry",
		Status: "pass",
		Detail: fmt.Sprintf("expires %s", relativeTimeGo(expTime)),
	}
}

func checkMDOCExpiry(doc *mdoc.Document) CheckResult {
	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil || doc.IssuerAuth.MSO.ValidityInfo == nil {
		return CheckResult{
			Name:   "expiry",
			Status: "skipped",
			Detail: "No validity info in MSO",
		}
	}

	vi := doc.IssuerAuth.MSO.ValidityInfo
	now := time.Now()

	if vi.ValidFrom != nil && now.Before(*vi.ValidFrom) {
		return CheckResult{
			Name:   "expiry",
			Status: "fail",
			Detail: fmt.Sprintf("not yet valid (valid from %s)", vi.ValidFrom.Format(time.RFC3339)),
		}
	}

	if vi.ValidUntil == nil {
		return CheckResult{
			Name:   "expiry",
			Status: "skipped",
			Detail: "No validUntil in MSO",
		}
	}

	if now.After(*vi.ValidUntil) {
		return CheckResult{
			Name:   "expiry",
			Status: "fail",
			Detail: fmt.Sprintf("expired %s", relativeTimeGo(*vi.ValidUntil)),
		}
	}

	return CheckResult{
		Name:   "expiry",
		Status: "pass",
		Detail: fmt.Sprintf("expires %s", relativeTimeGo(*vi.ValidUntil)),
	}
}

func checkSDJWTSignature(token *sdjwt.Token, opts ValidateOpts) CheckResult {
	pubKeys, tlCerts, err := resolveKeys(opts)
	if err != nil {
		return CheckResult{
			Name:   "signature",
			Status: "fail",
			Detail: err.Error(),
		}
	}

	// Without explicit keys, credentials issued by the local wallet validate
	// against its CA with a full chain.
	if len(pubKeys) == 0 && len(tlCerts) == 0 {
		if anchors := localWalletTrustAnchors(); len(anchors) > 0 {
			if caKey, err := validate.ExtractAndValidateX5C(token.Header, anchors); err == nil && caKey != nil {
				result := sdjwt.Verify(token, caKey)
				if result.SignatureValid {
					return CheckResult{
						Name:   "signature",
						Status: "pass",
						Detail: fmt.Sprintf("Valid (%s, via local wallet CA, chain verified)", result.Algorithm),
					}
				}
			}
		}
	}

	result, source, err := validate.VerifyJWTSignature(token, pubKeys, tlCerts)
	if err != nil {
		if len(pubKeys) == 0 && len(tlCerts) == 0 {
			if localResult, localSource := verifyWithLocalWalletIssuerKey(token); localResult != nil {
				result = localResult
				source = localSource
				err = nil
			}
		}
		if err != nil && len(pubKeys) == 0 && len(tlCerts) == 0 && validate.CanResolveJWTIssuerMetadata(token) {
			return CheckResult{
				Name:   "signature",
				Status: "skipped",
				Detail: fmt.Sprintf("Issuer metadata lookup failed: %v", err),
			}
		}
		if err != nil {
			return CheckResult{
				Name:   "signature",
				Status: "fail",
				Detail: err.Error(),
			}
		}
	}
	if result == nil {
		if len(pubKeys) == 0 && len(tlCerts) == 0 {
			if localResult, localSource := verifyWithLocalWalletIssuerKey(token); localResult != nil {
				result = localResult
				source = localSource
			}
		}
	}
	if result == nil {
		detail := "No key provided"
		if validate.CanResolveJWTIssuerMetadata(token) {
			detail = "Issuer metadata verification unavailable"
		}
		return CheckResult{
			Name:   "signature",
			Status: "skipped",
			Detail: detail,
		}
	}
	if result.SignatureValid {
		if source != "" {
			return CheckResult{
				Name:   "signature",
				Status: "pass",
				Detail: fmt.Sprintf("Valid (%s, via %s)", result.Algorithm, source),
			}
		}
		return CheckResult{
			Name:   "signature",
			Status: "pass",
			Detail: fmt.Sprintf("Valid (%s)", result.Algorithm),
		}
	}
	detail := "Signature verification failed"
	if source != "" {
		detail = fmt.Sprintf("Signature verification failed via %s", source)
	}
	return CheckResult{
		Name:   "signature",
		Status: "fail",
		Detail: detail,
	}
}

func checkMDOCSignature(doc *mdoc.Document, opts ValidateOpts) CheckResult {
	pubKeys, tlCerts, err := resolveKeys(opts)
	if err != nil {
		return CheckResult{
			Name:   "signature",
			Status: "fail",
			Detail: err.Error(),
		}
	}

	if len(pubKeys) == 0 && len(tlCerts) == 0 {
		// Credentials issued by the local wallet validate against its CA
		// with a full chain.
		if anchors := localWalletTrustAnchors(); len(anchors) > 0 {
			if caKey, err := validate.ExtractAndValidateMDOCX5Chain(doc, anchors); err == nil && caKey != nil {
				result := mdoc.Verify(doc, caKey)
				if result.SignatureValid {
					return CheckResult{
						Name:   "signature",
						Status: "pass",
						Detail: fmt.Sprintf("Valid (%s, via local wallet CA, chain verified)", result.Algorithm),
					}
				}
			}
		}
		// Offline check against the embedded x5chain leaf certificate.
		if leafKey, err := validate.ExtractMDOCX5ChainLeafKey(doc); err == nil && leafKey != nil {
			result := mdoc.Verify(doc, leafKey)
			if result.SignatureValid {
				return CheckResult{
					Name:   "signature",
					Status: "pass",
					Detail: fmt.Sprintf("Valid (%s, via %s)", result.Algorithm, validate.SourceX5CLeaf),
				}
			}
			return CheckResult{
				Name:   "signature",
				Status: "fail",
				Detail: "Signature invalid (embedded x5chain leaf key)",
			}
		}
		return CheckResult{
			Name:   "signature",
			Status: "skipped",
			Detail: "No key provided",
		}
	}

	// Try x5chain validation first
	if len(tlCerts) > 0 {
		if x5cKey, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts); err == nil && x5cKey != nil {
			result := mdoc.Verify(doc, x5cKey)
			if result.SignatureValid {
				return CheckResult{
					Name:   "signature",
					Status: "pass",
					Detail: fmt.Sprintf("Valid (%s, chain verified)", result.Algorithm),
				}
			}
			return CheckResult{
				Name:   "signature",
				Status: "fail",
				Detail: "Signature invalid (chain-derived key)",
			}
		}
	}

	for _, key := range pubKeys {
		result := mdoc.Verify(doc, key)
		if result.SignatureValid {
			return CheckResult{
				Name:   "signature",
				Status: "pass",
				Detail: fmt.Sprintf("Valid (%s)", result.Algorithm),
			}
		}
	}

	return CheckResult{
		Name:   "signature",
		Status: "fail",
		Detail: "Signature verification failed",
	}
}

func checkSDJWTStatus(token *sdjwt.Token, opts ValidateOpts) CheckResult {
	if !opts.CheckStatus {
		return CheckResult{
			Name:   "status",
			Status: "skipped",
			Detail: "Not requested",
		}
	}

	ref := statuslist.ExtractStatusRef(token.ResolvedClaims)
	_, tlCerts, err := resolveKeys(opts)
	if err != nil {
		return CheckResult{
			Name:   "status",
			Status: "fail",
			Detail: err.Error(),
		}
	}
	return checkStatusRef(ref, tlCerts)
}

func checkMDOCStatus(doc *mdoc.Document, opts ValidateOpts) CheckResult {
	if !opts.CheckStatus {
		return CheckResult{
			Name:   "status",
			Status: "skipped",
			Detail: "Not requested",
		}
	}

	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil || doc.IssuerAuth.MSO.Status == nil {
		return CheckResult{
			Name:   "status",
			Status: "skipped",
			Detail: "No status reference in credential",
		}
	}

	// ExtractStatusRef expects {"status": {"status_list": ...}} but MSO.Status
	// is already the inner status object. Wrap it so the lookup works.
	ref := statuslist.ExtractStatusRef(map[string]any{"status": doc.IssuerAuth.MSO.Status})
	_, tlCerts, err := resolveKeys(opts)
	if err != nil {
		return CheckResult{
			Name:   "status",
			Status: "fail",
			Detail: err.Error(),
		}
	}
	return checkStatusRef(ref, tlCerts)
}

func checkStatusRef(ref *statuslist.StatusRef, tlCerts []trustlist.CertInfo) CheckResult {
	if ref == nil {
		return CheckResult{
			Name:   "status",
			Status: "skipped",
			Detail: "No status list reference in credential",
		}
	}

	checkOpts := statuslist.CheckOptions{}
	for _, ci := range tlCerts {
		if len(ci.Raw) > 0 {
			checkOpts.TrustListCerts = append(checkOpts.TrustListCerts, statuslist.TrustCert{Raw: ci.Raw})
		}
	}

	result, err := statuslist.CheckWithOptions(ref, checkOpts)
	if err != nil {
		return CheckResult{
			Name:   "status",
			Status: "fail",
			Detail: fmt.Sprintf("Status check error: %v", err),
		}
	}

	signatureDetail := ""
	if result.SignatureValid != nil {
		if *result.SignatureValid {
			signatureDetail = fmt.Sprintf(", signature: %s", result.SignatureInfo)
		} else {
			signatureDetail = fmt.Sprintf(", signature invalid: %s", result.SignatureInfo)
		}
	}
	if result.SignatureValid != nil && !*result.SignatureValid {
		return CheckResult{
			Name:   "status",
			Status: "fail",
			Detail: fmt.Sprintf("Status list signature invalid (index %d, status=%d%s)", result.Index, result.Status, signatureDetail),
		}
	}

	if result.IsValid {
		return CheckResult{
			Name:   "status",
			Status: "pass",
			Detail: fmt.Sprintf("Valid (index %d, status=%d%s)", result.Index, result.Status, signatureDetail),
		}
	}

	return CheckResult{
		Name:   "status",
		Status: "fail",
		Detail: fmt.Sprintf("Revoked (index %d, status=%d%s)", result.Index, result.Status, signatureDetail),
	}
}

func resolveKeys(opts ValidateOpts) ([]crypto.PublicKey, []trustlist.CertInfo, error) {
	var pubKeys []crypto.PublicKey
	var tlCerts []trustlist.CertInfo

	if opts.Key != "" {
		key, err := keys.ParsePublicKey([]byte(opts.Key))
		if err != nil {
			return nil, nil, fmt.Errorf("parsing key: %w", err)
		}
		pubKeys = append(pubKeys, key)
	}

	if opts.TrustListRaw != "" {
		tl, err := trustlist.Parse(opts.TrustListRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing trust list: %w", err)
		}
		tlCerts = trustlist.ExtractPublicKeys(tl)
		for _, ci := range tlCerts {
			pubKeys = append(pubKeys, ci.PublicKey)
		}
	}

	if opts.TrustListURL != "" {
		tlRaw, err := format.ReadInput(opts.TrustListURL)
		if err != nil {
			return nil, nil, fmt.Errorf("fetching trust list: %w", err)
		}
		tl, err := trustlist.Parse(tlRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing trust list: %w", err)
		}
		certs := trustlist.ExtractPublicKeys(tl)
		tlCerts = append(tlCerts, certs...)
		for _, ci := range certs {
			pubKeys = append(pubKeys, ci.PublicKey)
		}
	}

	return pubKeys, tlCerts, nil
}

func relativeTimeGo(t time.Time) string {
	diff := time.Until(t)
	future := diff > 0
	if diff < 0 {
		diff = -diff
	}

	days := int(diff.Hours() / 24)
	hours := int(diff.Hours())
	minutes := int(diff.Minutes())
	months := days / 30

	var str string
	if months >= 2 {
		str = fmt.Sprintf("%d months", months)
	} else if months == 1 {
		str = "1 month"
	} else if days >= 2 {
		str = fmt.Sprintf("%d days", days)
	} else if days == 1 {
		str = "1 day"
	} else if hours >= 2 {
		str = fmt.Sprintf("%d hours", hours)
	} else if hours == 1 {
		str = "1 hour"
	} else if minutes >= 2 {
		str = fmt.Sprintf("%d minutes", minutes)
	} else {
		str = "1 minute"
	}

	if future {
		return "in " + str
	}
	return str + " ago"
}
