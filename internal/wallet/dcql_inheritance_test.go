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
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// sdjwtVCTQuery is a DCQL query for one SD-JWT credential of the given type.
func sdjwtVCTQuery(vct string) map[string]any {
	return map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{vct}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
			},
		},
	}
}

// A wallet holding only the German PID answers a request for the
// country-independent one: the German type extends it, so a credential of the
// German type is a credential of both.
func TestEvaluateDCQL_ExtendingTypeAnswersForTheTypeItExtends(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateDefaultCredentials(nil, mock.GermanPIDVCT); err != nil {
		t.Fatalf("generating the German PID: %v", err)
	}
	logs := captureTestLogs(t)

	matches := w.EvaluateDCQL(sdjwtVCTQuery(mock.DefaultPIDVCT))
	if len(matches) != 1 {
		t.Fatalf("expected the German PID to answer, got %d matches", len(matches))
	}
	if matches[0].VCT != mock.GermanPIDVCT {
		t.Errorf("matched vct = %q, want %q", matches[0].VCT, mock.GermanPIDVCT)
	}
	if !strings.Contains(logs.String(), "an extending type answers for the type it extends") {
		t.Error("the log does not say why a credential of another type matched")
	}
}

// Inheritance runs one way only. A verifier asking for the German PID wants
// the German attributes, and the country-independent PID has not got them.
func TestEvaluateDCQL_ExtendedTypeDoesNotAnswerForTheExtendingOne(t *testing.T) {
	w := generateTestWalletWithPID(t)

	if matches := w.EvaluateDCQL(sdjwtVCTQuery(mock.GermanPIDVCT)); len(matches) != 0 {
		t.Fatalf("the country-independent PID answered a request for the German type: %d matches", len(matches))
	}
}

// A wallet holding both answers with one of them, because the query asks for
// a single credential.
func TestEvaluateDCQL_BothPIDTypesHeld(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("generating the baseline: %v", err)
	}

	matches := w.EvaluateDCQL(sdjwtVCTQuery(mock.DefaultPIDVCT))
	if len(matches) != 1 {
		t.Fatalf("expected exactly one credential to be presented, got %d", len(matches))
	}

	// Asking for the German type reaches only the German credential.
	german := w.EvaluateDCQL(sdjwtVCTQuery(mock.GermanPIDVCT))
	if len(german) != 1 {
		t.Fatalf("expected the German PID to answer its own type, got %d matches", len(german))
	}
	if german[0].VCT != mock.GermanPIDVCT {
		t.Errorf("matched vct = %q, want %q", german[0].VCT, mock.GermanPIDVCT)
	}
}

// A credential of a type this tool knows nothing about still answers for the
// types its aka_vcts claim names (draft-ietf-oauth-sd-jwt-vc-18 §2.2.2.2),
// which is how an issuer states inheritance without retrievable Type Metadata.
func TestEvaluateDCQL_AkaVCTsFromAnUnknownType(t *testing.T) {
	w := generateTestWallet(t)
	w.Credentials = append(w.Credentials, StoredCredential{
		ID:     "regional-pid",
		Format: "dc+sd-jwt",
		VCT:    "urn:example:pid:xx:1",
		Claims: map[string]any{
			"given_name":          "ERIKA",
			credtype.AkaVCTsClaim: []any{mock.DefaultPIDVCT},
		},
	})

	matches := w.EvaluateDCQL(sdjwtVCTQuery(mock.DefaultPIDVCT))
	if len(matches) != 1 {
		t.Fatalf("expected the aka_vcts credential to answer, got %d matches", len(matches))
	}
	if matches[0].CredentialID != "regional-pid" {
		t.Errorf("matched credential = %q, want regional-pid", matches[0].CredentialID)
	}
}

// The mdoc PIDs share a doctype, because ISO/IEC 18013-5 has no inheritance
// between document types: a doctype request reaches both, and the German
// elements are addressable in their own namespace.
func TestEvaluateDCQL_MDocPIDsShareTheirDoctype(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("generating the baseline: %v", err)
	}

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "mso_mdoc",
				"meta":   map[string]any{"doctype_value": mock.PIDNamespace},
				"claims": []any{
					map[string]any{"path": []any{credtype.GermanPIDNamespace, "birth_name"}},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 1 {
		t.Fatalf("expected the German mdoc PID to answer, got %d matches", len(matches))
	}
	if len(matches[0].Claims) == 0 {
		t.Error("the national element was not selected for disclosure")
	}
}
