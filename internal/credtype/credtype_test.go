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

package credtype

import (
	"reflect"
	"testing"
)

func TestAnswers(t *testing.T) {
	tests := []struct {
		name      string
		vct       string
		aka       []string
		requested string
		want      bool
	}{
		{"same type", PIDVCT, nil, PIDVCT, true},
		{
			// A verifier asking for the country-independent PID is answered by
			// the German one.
			"extending type answers for the type it extends",
			GermanPIDVCT, nil, PIDVCT, true,
		},
		{
			"aka_vcts alone is enough",
			"urn:example:pid:xx:1", []string{PIDVCT}, PIDVCT, true,
		},
		{
			// Inheritance runs one way. A verifier asking for the German PID
			// wants the German attributes, which the general type has not got.
			"the extended type does not answer for the extending one",
			PIDVCT, nil, GermanPIDVCT, false,
		},
		{"unrelated type", "urn:example:ticket:1", nil, PIDVCT, false},
		{"no requested type", GermanPIDVCT, nil, "", false},
		{"no credential type", "", []string{PIDVCT}, PIDVCT, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Answers(tt.vct, tt.aka, tt.requested); got != tt.want {
				t.Errorf("Answers(%q, %v, %q) = %t, want %t", tt.vct, tt.aka, tt.requested, got, tt.want)
			}
		})
	}
}

func TestChain(t *testing.T) {
	tests := []struct {
		name string
		vct  string
		aka  []string
		want []string
	}{
		{"own type first", GermanPIDVCT, nil, []string{GermanPIDVCT, PIDVCT}},
		{"no inheritance", "urn:example:ticket:1", nil, []string{"urn:example:ticket:1"}},
		{"empty type", "", []string{PIDVCT}, nil},
		{
			// A credential naming its parent explicitly must not have it
			// listed twice.
			"aka_vcts repeating a known parent",
			GermanPIDVCT, []string{PIDVCT}, []string{GermanPIDVCT, PIDVCT},
		},
		{
			// The chain continues through what aka_vcts reached, so a type
			// naming only its immediate parent still answers for that
			// parent's parent.
			"inheritance continues through aka_vcts",
			"urn:example:pid:de:regional:1", []string{GermanPIDVCT},
			[]string{"urn:example:pid:de:regional:1", GermanPIDVCT, PIDVCT},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Chain(tt.vct, tt.aka); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Chain(%q, %v) = %v, want %v", tt.vct, tt.aka, got, tt.want)
			}
		})
	}
}

func TestAkaVCTs(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		want   []string
	}{
		{"absent", map[string]any{"vct": GermanPIDVCT}, nil},
		{
			"list of types",
			map[string]any{AkaVCTsClaim: []any{PIDVCT, "urn:example:other:1"}},
			[]string{PIDVCT, "urn:example:other:1"},
		},
		// A malformed aka_vcts claim is ignored.
		{"not a list", map[string]any{AkaVCTsClaim: PIDVCT}, nil},
		{"non-string entries", map[string]any{AkaVCTsClaim: []any{42, PIDVCT, ""}}, []string{PIDVCT}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AkaVCTs(tt.claims)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AkaVCTs(%v) = %v, want %v", tt.claims, got, tt.want)
			}
		})
	}
}

// PID_14 makes every domestic PID type an extension of the
// country-independent one, so this holds for countries nothing here has heard
// of. Inheritance says what a credential is, not who may issue it: nothing
// here may grow into a trust decision (draft-ietf-oauth-sd-jwt-vc-19 §7.7).
func TestExtends(t *testing.T) {
	tests := []struct {
		vct    string
		parent string
	}{
		{GermanPIDVCT, PIDVCT},
		// A country this tool has no entry for.
		{"urn:eudi:pid:fr:1", PIDVCT},
		{"urn:eudi:pid:es:2", PIDVCT},
		// A region code, which PID_06 allows for the mdoc namespace and
		// PID_14 leaves open for the type.
		{"urn:eudi:pid:de-by:1", PIDVCT},
		// Not domestic: the country-independent type itself, and whatever a
		// later rulebook numbers.
		{PIDVCT, ""},
		{"urn:eudi:pid:2", ""},
		// Outside the PID namespace nothing is implied. Such a type states
		// its own relationships in aka_vcts.
		{"urn:eudi:mdl:1", ""},
		{"https://credentials.example.com/membership", ""},
		{"", ""},
	}
	for _, tt := range tests {
		parent, ok := Extends(tt.vct)
		if tt.parent == "" {
			if ok {
				t.Errorf("Extends(%q) = %q, true, want no parent", tt.vct, parent)
			}
			continue
		}
		if !ok || parent != tt.parent {
			t.Errorf("Extends(%q) = %q, %t, want %q, true", tt.vct, parent, ok, tt.parent)
		}
	}
}

// A national PID from any country answers a request for the type it extends
// (PID_14).
func TestAnswers_AnyDomesticPIDType(t *testing.T) {
	for _, vct := range []string{GermanPIDVCT, "urn:eudi:pid:fr:1", "urn:eudi:pid:nl:1"} {
		if !Answers(vct, nil, PIDVCT) {
			t.Errorf("%q does not answer a request for %q", vct, PIDVCT)
		}
		if Answers(PIDVCT, nil, vct) {
			t.Errorf("%q answered a request for %q, but inheritance runs one way", PIDVCT, vct)
		}
	}
	// Two domestic types are siblings, not relatives.
	if Answers(GermanPIDVCT, nil, "urn:eudi:pid:fr:1") {
		t.Error("the German PID answered a request for the French one")
	}
}
