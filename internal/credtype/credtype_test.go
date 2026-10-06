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
			"extending type answers for the type it extends",
			"urn:eudi:pid:de:1", nil, PIDVCT, true,
		},
		{
			"aka_vcts alone is enough",
			"urn:example:pid:xx:1", []string{PIDVCT}, PIDVCT, true,
		},
		{
			// Inheritance runs one way. A request for the German PID needs
			// German attributes, and the general type lacks them.
			"the extended type does not answer for the extending one",
			PIDVCT, nil, "urn:eudi:pid:de:1", false,
		},
		{"unrelated type", "urn:example:ticket:1", nil, PIDVCT, false},
		{"no requested type", "urn:eudi:pid:de:1", nil, "", false},
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
		{"own type first", "urn:eudi:pid:de:1", nil, []string{"urn:eudi:pid:de:1", PIDVCT}},
		{"no inheritance", "urn:example:ticket:1", nil, []string{"urn:example:ticket:1"}},
		{"empty type", "", []string{PIDVCT}, nil},
		{
			"aka_vcts repeating a known parent",
			"urn:eudi:pid:de:1", []string{PIDVCT}, []string{"urn:eudi:pid:de:1", PIDVCT},
		},
		{
			// A type that lists only its immediate parent in aka_vcts also
			// answers for that parent's parent.
			"inheritance continues through aka_vcts",
			"urn:example:pid:de:regional:1", []string{"urn:eudi:pid:de:1"},
			[]string{"urn:example:pid:de:regional:1", "urn:eudi:pid:de:1", PIDVCT},
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
		{"absent", map[string]any{"vct": "urn:eudi:pid:de:1"}, nil},
		{
			"list of types",
			map[string]any{AkaVCTsClaim: []any{PIDVCT, "urn:example:other:1"}},
			[]string{PIDVCT, "urn:example:other:1"},
		},
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
// country-independent one. This holds for any country code. Inheritance is
// never a trust decision (draft-ietf-oauth-sd-jwt-vc-19 §7.7).
func TestExtends(t *testing.T) {
	tests := []struct {
		vct    string
		parent string
	}{
		{"urn:eudi:pid:de:1", PIDVCT},
		{"urn:eudi:pid:fr:1", PIDVCT},
		{"urn:eudi:pid:es:2", PIDVCT},
		// PID_06 allows a region code in the mdoc namespace. PID_14
		// allows it in the type.
		{"urn:eudi:pid:de-by:1", PIDVCT},
		{PIDVCT, ""},
		{"urn:eudi:pid:2", ""},
		// A type outside the PID namespace states its parents in aka_vcts.
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

func TestAnswers_AnyDomesticPIDType(t *testing.T) {
	for _, vct := range []string{"urn:eudi:pid:de:1", "urn:eudi:pid:fr:1", "urn:eudi:pid:nl:1"} {
		if !Answers(vct, nil, PIDVCT) {
			t.Errorf("%q does not answer a request for %q", vct, PIDVCT)
		}
		if Answers(PIDVCT, nil, vct) {
			t.Errorf("%q answered a request for %q, but inheritance runs one way", PIDVCT, vct)
		}
	}
	if Answers("urn:eudi:pid:de:1", nil, "urn:eudi:pid:fr:1") {
		t.Error("the German PID answered a request for the French one")
	}
}
