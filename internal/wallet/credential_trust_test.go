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

import "testing"

// credentialByFormat returns the wallet's stored credential of the given
// format, failing the test when none is present.
func credentialByFormat(t *testing.T, w *Wallet, format string) StoredCredential {
	t.Helper()
	for _, c := range w.GetCredentials() {
		if c.Format == format {
			return c
		}
	}
	t.Fatalf("wallet holds no %s credential", format)
	return StoredCredential{}
}

// An SD-JWT the wallet issued to its own holder key reports its issuer by the
// iss claim, a signature that is self-consistent against the embedded x5c leaf,
// a binding to this wallet, and the number of selective-disclosure entries.
func TestCredentialSummarySDJWTTrustFields(t *testing.T) {
	w := generateTestWalletWithPID(t)
	cred := credentialByFormat(t, w, "dc+sd-jwt")
	summary := w.CredentialSummaryWithStatus(cred)

	if _, ok := summary["issued_at"].(string); !ok {
		t.Errorf("issued_at missing or not a string: %v", summary["issued_at"])
	}

	issuer, ok := summary["issuer"].(map[string]any)
	if !ok {
		t.Fatalf("issuer missing or not an object: %v", summary["issuer"])
	}
	if issuer["kind"] != "iss" {
		t.Errorf("issuer kind = %v, want iss", issuer["kind"])
	}
	if value, _ := issuer["value"].(string); value == "" {
		t.Errorf("issuer value is empty: %v", issuer["value"])
	}

	signature, ok := summary["signature"].(map[string]any)
	if !ok {
		t.Fatalf("signature missing or not an object: %v", summary["signature"])
	}
	if alg, _ := signature["algorithm"].(string); alg == "" {
		t.Errorf("signature algorithm is empty: %v", signature["algorithm"])
	}
	if signature["self_consistent"] != true {
		t.Errorf("signature self_consistent = %v, want true", signature["self_consistent"])
	}

	if summary["holder_binding"] != holderBindingThisWallet {
		t.Errorf("holder_binding = %v, want %s", summary["holder_binding"], holderBindingThisWallet)
	}
}

// An mdoc names its issuer by the document signer leaf certificate and reports
// the algorithm that signed it.
func TestCredentialSummaryMDocTrustFields(t *testing.T) {
	w := generateTestWalletWithPID(t)
	cred := credentialByFormat(t, w, "mso_mdoc")
	summary := w.CredentialSummaryWithStatus(cred)

	issuer, ok := summary["issuer"].(map[string]any)
	if !ok {
		t.Fatalf("issuer missing or not an object: %v", summary["issuer"])
	}
	if issuer["kind"] != "cert" {
		t.Errorf("issuer kind = %v, want cert", issuer["kind"])
	}
	if value, _ := issuer["value"].(string); value == "" {
		t.Errorf("issuer value is empty: %v", issuer["value"])
	}

	signature, ok := summary["signature"].(map[string]any)
	if !ok {
		t.Fatalf("signature missing or not an object: %v", summary["signature"])
	}
	if alg, _ := signature["algorithm"].(string); alg == "" {
		t.Errorf("signature algorithm is empty: %v", signature["algorithm"])
	}
}

// A credential the issuer bound to no holder key reports a holder binding of
// none: there is no key for the wallet to be missing.
func TestCredentialSummaryHolderBindingNone(t *testing.T) {
	w := generateTestWallet(t)
	imported, err := w.ImportCredential(sdJWTBoundTo(t, w, nil))
	if err != nil {
		t.Fatalf("importing: %v", err)
	}
	summary := w.CredentialSummaryWithStatus(*imported)
	if summary["holder_binding"] != holderBindingNone {
		t.Errorf("holder_binding = %v, want %s", summary["holder_binding"], holderBindingNone)
	}
}

// A credential bound to a key this wallet does not hold reports other_key: it
// can be decoded and shown, but the wallet cannot sign a presentation of it.
func TestCredentialSummaryHolderBindingOtherKey(t *testing.T) {
	w := generateTestWallet(t)
	imported, err := w.ImportCredential(sdJWTBoundTo(t, w, foreignHolderKey(t)))
	if err != nil {
		t.Fatalf("importing: %v", err)
	}
	summary := w.CredentialSummaryWithStatus(*imported)
	if summary["holder_binding"] != holderBindingOtherKey {
		t.Errorf("holder_binding = %v, want %s", summary["holder_binding"], holderBindingOtherKey)
	}
}
