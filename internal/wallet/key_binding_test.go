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
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

const keyBindingEvent = "credential_key_binding_not_held"

func sdJWTBoundTo(t *testing.T, w *Wallet, holder *ecdsa.PublicKey) string {
	t.Helper()
	cred, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test-issuer.example",
		VCT:       "TestBoundCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"given_name": "Test"},
		Key:       w.IssuerKey,
		HolderKey: holder,
	})
	if err != nil {
		t.Fatalf("generating SD-JWT: %v", err)
	}
	return cred
}

func mdocBoundTo(t *testing.T, w *Wallet, holder *ecdsa.PublicKey) string {
	t.Helper()
	cred, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    map[string]any{"family_name": "Doe"},
		Key:       w.IssuerKey,
		HolderKey: holder,
	})
	if err != nil {
		t.Fatalf("generating mdoc: %v", err)
	}
	return cred
}

func foreignHolderKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating a foreign holder key: %v", err)
	}
	return &key.PublicKey
}

// A credential bound to someone else's key can be stored and read, but the
// wallet cannot sign a KB-JWT (RFC 9901 §4.3) or a DeviceSigned (ISO 18013-5
// §9.1.3) for it, so the import says so instead of leaving the discovery to a
// verifier refusing the presentation.
func TestImportReportsACredentialBoundToAKeyTheWalletDoesNotHold(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  func(t *testing.T, w *Wallet, holder *ecdsa.PublicKey) string
	}{
		{"sd-jwt", sdJWTBoundTo},
		{"mdoc", mdocBoundTo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			imported, err := w.ImportCredential(tc.raw(t, w, foreignHolderKey(t)))
			if err != nil {
				t.Fatalf("importing: %v", err)
			}

			entry := findLogEntry(w.GetLog(), keyBindingEvent)
			if entry == nil {
				t.Fatal("importing a credential bound to another key logged no warning")
			}
			if entry.Severity != severityWarning {
				t.Errorf("the entry has severity %q, want %q", entry.Severity, severityWarning)
			}
			if got := entry.Details["credential_id"]; got != imported.ID {
				t.Errorf("the warning names credential %v, want %s", got, imported.ID)
			}
			if entry.Details["binding_key"] == entry.Details["wallet_key"] {
				t.Error("the warning reports the same key as bound and held")
			}

			summary := w.CredentialSummaryWithStatus(*imported)
			if summary["key_binding_not_held"] != true {
				t.Error("the credential summary does not mark the key binding as not held")
			}
		})
	}
}

// The ordinary case stays quiet: an issuance binds the credential to the
// wallet's own holder key, and a warning on every one of those would train the
// reader to ignore it.
func TestImportStaysQuietForACredentialBoundToTheWalletKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  func(t *testing.T, w *Wallet, holder *ecdsa.PublicKey) string
	}{
		{"sd-jwt", sdJWTBoundTo},
		{"mdoc", mdocBoundTo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			imported, err := w.ImportCredential(tc.raw(t, w, &w.HolderKey.PublicKey))
			if err != nil {
				t.Fatalf("importing: %v", err)
			}
			if entry := findLogEntry(w.GetLog(), keyBindingEvent); entry != nil {
				t.Fatalf("a credential bound to the wallet's own key was reported: %s", entry.Detail)
			}
			if _, marked := w.CredentialSummaryWithStatus(*imported)["key_binding_not_held"]; marked {
				t.Error("a credential bound to the wallet's own key is marked in the summary")
			}
		})
	}
}

// A credential without holder binding is presented without a KB-JWT at all,
// so there is no key for the wallet to be missing.
func TestImportStaysQuietForACredentialWithoutHolderBinding(t *testing.T) {
	w := generateTestWallet(t)
	imported, err := w.ImportCredential(sdJWTBoundTo(t, w, nil))
	if err != nil {
		t.Fatalf("importing: %v", err)
	}
	if entry := findLogEntry(w.GetLog(), keyBindingEvent); entry != nil {
		t.Fatalf("a credential without holder binding was reported: %s", entry.Detail)
	}
	if _, marked := w.CredentialSummaryWithStatus(*imported)["key_binding_not_held"]; marked {
		t.Error("a credential without holder binding is marked in the summary")
	}
}

// A cnf naming a key the wallet cannot even compare is still a credential
// bound elsewhere: the holder key is a P-256 key, so nothing else can be it.
func TestHolderBindingOfAnUnreadableConfirmationKey(t *testing.T) {
	for name, jwk := range map[string]confirmationJWK{
		"another curve":  {Kty: "EC", Crv: "P-384", X: "AAAA", Y: "AAAA"},
		"another kty":    {Kty: "OKP", Crv: "Ed25519", X: "AAAA"},
		"no coordinates": {Kty: "EC", Crv: "P-256"},
	} {
		t.Run(name, func(t *testing.T) {
			if key := jwk.publicKey(); key != nil {
				t.Errorf("read a holder key out of %+v", jwk)
			}
		})
	}
}

// A DID names a key nothing in this toolkit resolves, and the EUDI ecosystem
// uses none: HAIP 1.0 §6.1.1 puts the issuer's signing certificate in x5c. A
// credential arriving with one is kept, so the wallet says at that moment that
// its issuer signature will never be checked.
func TestImportReportsAnIssuerKeyNamedByADID(t *testing.T) {
	w := generateTestWallet(t)
	const did = "did:key:z6MkuR4XP7DmHiEzKK46ypK2RyZ3XgqQCz1DHw7XtMg3CEuf"
	imported, err := w.ImportCredential(sdJWTSignedByDID(t, did))
	if err != nil {
		t.Fatalf("importing: %v", err)
	}

	entry := findLogEntry(w.GetLog(), "credential_issuer_key_is_a_did")
	if entry == nil {
		t.Fatal("importing a credential whose issuer key is a DID logged no warning")
	}
	if entry.Severity != severityWarning {
		t.Errorf("the entry has severity %q, want %q", entry.Severity, severityWarning)
	}
	if got := entry.Details["issuer_key_did"]; got != did {
		t.Errorf("the warning names %v as the issuer key, want %s", got, did)
	}
	if got := CredentialSummary(*imported)["issuer_key_did"]; got != did {
		t.Errorf("the credential summary names %v as the issuer key, want %s", got, did)
	}
}

// An issuer resolvable the way the profile expects is not a finding, so the
// warning keeps meaning something.
func TestImportStaysQuietForAnIssuerKeyNotNamedByADID(t *testing.T) {
	w := generateTestWallet(t)
	imported, err := w.ImportCredential(sdJWTBoundTo(t, w, &w.HolderKey.PublicKey))
	if err != nil {
		t.Fatalf("importing: %v", err)
	}
	if entry := findLogEntry(w.GetLog(), "credential_issuer_key_is_a_did"); entry != nil {
		t.Fatalf("an ordinary issuer was reported as a DID: %s", entry.Detail)
	}
	if _, named := CredentialSummary(*imported)["issuer_key_did"]; named {
		t.Error("an ordinary issuer is named as a DID in the summary")
	}
}

// sdJWTSignedByDID builds a credential whose header and iss name a DID, the
// shape an issuer outside the EUDI ecosystem produces. The signature is not
// checked on import, and no key here could check this one.
func sdJWTSignedByDID(t *testing.T, did string) string {
	t.Helper()
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("encoding: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := encode(map[string]any{"alg": "EdDSA", "typ": "dc+sd-jwt", "kid": did})
	payload := encode(map[string]any{
		"iss": did,
		"vct": "urn:test:did-issued:1",
		"iat": time.Now().Unix(),
	})
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("not a signature")) + "~"
}

// Presenting a credential the wallet cannot sign key binding for is reported
// before the response goes out. Debug mode still sends it, because the
// verifier's refusal is what a run against that verifier is here to show, and
// strict mode stops while the nonce is unspent.
func TestPresentingACredentialWithAnUnheldKeyBindingIsReported(t *testing.T) {
	present := func(t *testing.T, w *Wallet) (VPTokenResult, error) {
		t.Helper()
		imported, err := w.ImportCredential(sdJWTBoundTo(t, w, foreignHolderKey(t)))
		if err != nil {
			t.Fatalf("importing: %v", err)
		}
		return w.CreateVPToken(
			CredentialMatch{CredentialID: imported.ID, SelectedKeys: []string{"given_name"}},
			PresentationParams{Nonce: "n", ClientID: "x509_hash:abc"},
		)
	}

	t.Run("debug sends it and says so", func(t *testing.T) {
		w := generateTestWallet(t)
		result, err := present(t, w)
		if err != nil {
			t.Fatalf("debug mode refused the presentation: %v", err)
		}
		if result.Token == "" {
			t.Error("debug mode produced no presentation")
		}
		entry := findLogEntry(w.GetLog(), "key_binding_cannot_be_signed")
		if entry == nil {
			t.Fatal("presenting a credential bound to another key logged no warning")
		}
		if entry.Action != "presentation" {
			t.Errorf("the entry belongs to %q, want the presentation flow", entry.Action)
		}
		if entry.Severity != severityWarning {
			t.Errorf("the entry has severity %q, want %q", entry.Severity, severityWarning)
		}
	})

	t.Run("strict stops before the nonce is spent", func(t *testing.T) {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeStrict
		if _, err := present(t, w); err == nil {
			t.Fatal("strict mode signed a key binding it cannot sign")
		}
		entry := findLogEntry(w.GetLog(), "key_binding_cannot_be_signed")
		if entry == nil {
			t.Fatal("the refusal was not logged")
		}
		if entry.Success {
			t.Error("the entry is marked successful")
		}
	})
}

// A credential bound to the wallet's own key presents without a word, so the
// warning keeps meaning something.
func TestPresentingAHeldCredentialIsNotReported(t *testing.T) {
	w := generateTestWallet(t)
	imported, err := w.ImportCredential(sdJWTBoundTo(t, w, &w.HolderKey.PublicKey))
	if err != nil {
		t.Fatalf("importing: %v", err)
	}
	if _, err := w.CreateVPToken(
		CredentialMatch{CredentialID: imported.ID, SelectedKeys: []string{"given_name"}},
		PresentationParams{Nonce: "n", ClientID: "x509_hash:abc"},
	); err != nil {
		t.Fatalf("presenting: %v", err)
	}
	if entry := findLogEntry(w.GetLog(), "key_binding_cannot_be_signed"); entry != nil {
		t.Fatalf("a credential bound to the wallet's own key was reported: %s", entry.Detail)
	}
}

// The primary copy of a batch the issuer bound to a proof key other than the
// holder key is imported with that key, so it is presentable and importing it
// stays quiet: a warning here would be a false alarm the wallet contradicts the
// moment it signs the key binding with the recorded key.
func TestImportStaysQuietForABatchPrimaryBoundToAProofKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  func(t *testing.T, w *Wallet, holder *ecdsa.PublicKey) string
	}{
		{"sd-jwt", sdJWTBoundTo},
		{"mdoc", mdocBoundTo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			ephemeral, err := mock.GenerateKey()
			if err != nil {
				t.Fatalf("generating an ephemeral proof key: %v", err)
			}
			keys := []*ecdsa.PrivateKey{w.HolderKey, ephemeral}
			imported, err := w.importPrimaryCredential(tc.raw(t, w, &ephemeral.PublicKey), keys)
			if err != nil {
				t.Fatalf("importing: %v", err)
			}
			if entry := findLogEntry(w.GetLog(), keyBindingEvent); entry != nil {
				t.Fatalf("the batch primary was falsely reported as unpresentable: %s", entry.Detail)
			}
			signer, err := w.batchSigningKey(*imported)
			if err != nil {
				t.Fatalf("resolving the signing key: %v", err)
			}
			if !signer.PublicKey.Equal(&ephemeral.PublicKey) {
				t.Fatal("the primary must sign its key binding with the proof key it is bound to")
			}
		})
	}
}
