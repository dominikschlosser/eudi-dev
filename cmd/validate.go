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
	"crypto"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/output"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/statuslist"
	"github.com/dominikschlosser/eudi-dev/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/internal/validate"
)

var (
	keyFile        string
	trustListFile  string
	statusListFlag bool
	allowExpired   bool
)

var validateCmd = &cobra.Command{
	Use:   "validate [input]",
	Short: "Validate a credential (signature, expiry, revocation)",
	Long: `Decode and validate a credential. Unlike 'decode' (which only parses and displays),
'validate' actively checks correctness:

  - Signature verification (requires --key or --trust-list)
  - Expiry check (use --allow-expired to skip)
  - Revocation status via status list when the credential contains a status reference

If neither --key nor --trust-list is provided, signature verification is skipped
and only expiry/status checks are performed. This is useful for quick revocation
checks without needing the issuer's key.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runValidate,
}

func init() {
	validateCmd.Flags().StringVar(&keyFile, "key", "", "Public key file (PEM or JWK)")
	validateCmd.Flags().StringVar(&trustListFile, "trust-list", "", "ETSI trust list JWT (file path or URL)")
	validateCmd.Flags().BoolVar(&statusListFlag, "status-list", true, "Check revocation via status list when the credential contains a status reference")
	validateCmd.Flags().BoolVar(&allowExpired, "allow-expired", false, "Don't fail on expired credentials")
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	input := ""
	if len(args) > 0 {
		input = args[0]
	}

	raw, err := format.ReadInput(input)
	if err != nil {
		return err
	}

	opts := output.Options{
		JSON:    jsonOutput,
		NoColor: noColor,
		Verbose: verbose,
	}

	// Load public key(s)
	var pubKeys []crypto.PublicKey

	if keyFile != "" {
		key, err := keys.LoadPublicKey(keyFile)
		if err != nil {
			return fmt.Errorf("loading key: %w", err)
		}
		pubKeys = append(pubKeys, key)
	}

	var tlCerts []trustlist.CertInfo
	if trustListFile != "" {
		tlRaw, err := format.ReadInput(trustListFile)
		if err != nil {
			return fmt.Errorf("reading trust list: %w", err)
		}
		tl, err := trustlist.Parse(tlRaw)
		if err != nil {
			return fmt.Errorf("parsing trust list: %w", err)
		}
		tlCerts = trustlist.ExtractPublicKeys(tl)
		for _, ci := range tlCerts {
			pubKeys = append(pubKeys, ci.PublicKey)
		}
	}

	detected := format.Detect(raw)

	switch detected {
	case format.FormatSDJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		output.PrintSDJWT(token, opts)

		if bestResult, source, err := validate.VerifyJWTSignature(token, pubKeys, tlCerts); bestResult != nil {
			output.PrintVerifyResultSDJWT(bestResult, opts)
			printLeafSourceNote(source, opts)

			if !bestResult.SignatureValid {
				return fmt.Errorf("signature verification failed")
			}
			if bestResult.Expired && !allowExpired {
				return fmt.Errorf("credential expired")
			}
		} else if err != nil {
			return err
		} else {
			if !opts.JSON {
				fmt.Println("\n  Signature verification skipped (no --key/--trust-list and issuer metadata resolution unavailable)")
			}
			// Still check expiry from parsed claims
			if exp, ok := token.ResolvedClaims["exp"]; ok {
				if expFloat, ok := exp.(float64); ok {
					if time.Unix(int64(expFloat), 0).Before(time.Now()) {
						if !opts.JSON {
							fmt.Println("  ✗ Credential expired")
						}
						if !allowExpired {
							return fmt.Errorf("credential expired")
						}
					}
				}
			}
		}

		// Status list check
		if statusListFlag {
			if err := checkStatus(token.ResolvedClaims, tlCerts, opts); err != nil {
				return err
			}
		}

	case format.FormatJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing JWT: %w", err)
		}
		output.PrintJWT(token, opts)

		if bestResult, source, err := validate.VerifyJWTSignature(token, pubKeys, tlCerts); bestResult != nil {
			output.PrintVerifyResultSDJWT(bestResult, opts)
			printLeafSourceNote(source, opts)

			if !bestResult.SignatureValid {
				return fmt.Errorf("signature verification failed")
			}
			if bestResult.Expired && !allowExpired {
				return fmt.Errorf("credential expired")
			}
		} else if err != nil {
			return err
		} else {
			if !opts.JSON {
				fmt.Println("\n  Signature verification skipped (no --key/--trust-list and issuer metadata resolution unavailable)")
			}
			if exp, ok := token.ResolvedClaims["exp"]; ok {
				if expFloat, ok := exp.(float64); ok {
					if time.Unix(int64(expFloat), 0).Before(time.Now()) {
						if !opts.JSON {
							fmt.Println("  ✗ Credential expired")
						}
						if !allowExpired {
							return fmt.Errorf("credential expired")
						}
					}
				}
			}
		}

		if statusListFlag {
			if err := checkStatus(token.ResolvedClaims, tlCerts, opts); err != nil {
				return err
			}
		}

	case format.FormatMDOC:
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing mDOC: %w", err)
		}
		output.PrintMDOC(doc, opts)

		leafKey, _ := validate.ExtractMDOCX5ChainLeafKey(doc)
		if len(pubKeys) > 0 {
			x5cKey, _ := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
			bestResult := verifyWithBestKey(pubKeys, x5cKey, func(key crypto.PublicKey) (*mdoc.VerifyResult, bool) {
				r := mdoc.Verify(doc, key)
				return r, r.SignatureValid
			})
			output.PrintVerifyResultMDOC(bestResult, opts)

			if !bestResult.SignatureValid {
				return fmt.Errorf("signature verification failed")
			}
			if bestResult.Expired && !allowExpired {
				return fmt.Errorf("credential expired")
			}
		} else if leafKey != nil {
			// Offline check against the embedded x5chain leaf certificate.
			result := mdoc.Verify(doc, leafKey)
			output.PrintVerifyResultMDOC(result, opts)
			printLeafSourceNote(validate.SourceX5CLeaf, opts)

			if !result.SignatureValid {
				return fmt.Errorf("signature verification failed")
			}
			if result.Expired && !allowExpired {
				return fmt.Errorf("credential expired")
			}
		} else {
			if !opts.JSON {
				fmt.Println("\n  Signature verification skipped (no --key or --trust-list provided)")
			}
			// Check expiry from MSO
			if doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil && doc.IssuerAuth.MSO.ValidityInfo != nil {
				if doc.IssuerAuth.MSO.ValidityInfo.ValidUntil != nil && doc.IssuerAuth.MSO.ValidityInfo.ValidUntil.Before(time.Now()) {
					if !opts.JSON {
						fmt.Println("  ✗ Credential expired")
					}
					if !allowExpired {
						return fmt.Errorf("credential expired")
					}
				}
			}
		}

		// Status list check for mDOC — wrap in "status" key since ExtractStatusRef
		// expects {"status": {"status_list": ...}} but MSO.Status is the inner map.
		if statusListFlag && doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil && doc.IssuerAuth.MSO.Status != nil {
			if err := checkStatus(map[string]any{"status": doc.IssuerAuth.MSO.Status}, tlCerts, opts); err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("unable to auto-detect credential format")
	}

	return nil
}

// printLeafSourceNote explains a leaf-only verification so a green result is
// not mistaken for a trust statement.
func printLeafSourceNote(source string, opts output.Options) {
	if source == validate.SourceX5CLeaf && !opts.JSON {
		fmt.Println("  Note: verified with the credential's embedded certificate (chain not validated). Pass --trust-list to also validate trust.")
	}
}

// verifyWithBestKey tries verifying with x5cKey first (if available), then
// falls back to iterating through pubKeys. Returns the best result found.
func verifyWithBestKey[T any](pubKeys []crypto.PublicKey, x5cKey crypto.PublicKey, verify func(crypto.PublicKey) (T, bool)) T {
	if x5cKey != nil {
		result, _ := verify(x5cKey)
		return result
	}
	var best T
	for _, key := range pubKeys {
		result, valid := verify(key)
		best = result
		if valid {
			break
		}
	}
	return best
}

func checkStatus(claims map[string]any, tlCerts []trustlist.CertInfo, opts output.Options) error {
	ref := statuslist.ExtractStatusRef(claims)
	if ref == nil {
		return nil
	}

	// Build check options with trust list certs for signature validation
	checkOpts := statuslist.CheckOptions{}
	for _, ci := range tlCerts {
		if len(ci.Raw) > 0 {
			checkOpts.TrustListCerts = append(checkOpts.TrustListCerts, statuslist.TrustCert{Raw: ci.Raw})
		}
	}

	result, err := statuslist.CheckWithOptions(ref, checkOpts)
	if err != nil {
		return fmt.Errorf("status check: %w", err)
	}
	if opts.JSON {
		output.PrintJSON(result)
	} else {
		if result.IsValid {
			fmt.Printf("\n  ✓ Status: valid (index %d, status=%d)\n", result.Index, result.Status)
		} else {
			fmt.Printf("\n  ✗ Status: revoked (index %d, status=%d)\n", result.Index, result.Status)
		}
		if result.SignatureValid != nil {
			if *result.SignatureValid {
				fmt.Printf("  ✓ Status list signature: %s\n", result.SignatureInfo)
			} else {
				fmt.Printf("  ✗ Status list signature: %s\n", result.SignatureInfo)
			}
		}
	}
	if !result.IsValid {
		return fmt.Errorf("credential revoked")
	}
	if result.SignatureValid != nil && !*result.SignatureValid {
		return fmt.Errorf("status list signature invalid")
	}
	return nil
}
