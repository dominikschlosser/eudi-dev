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
	"reflect"
	"testing"
)

// A DCQL claim path is written as a selector string, and getting the parse
// wrong means either disclosing a claim nobody asked for or reporting a
// credential as not matching when it does.
func TestParseSDJWTSelector(t *testing.T) {
	tests := []struct {
		selector string
		want     []any
		wantOK   bool
	}{
		{selector: "given_name", want: []any{"given_name"}, wantOK: true},
		{selector: "address.locality", want: []any{"address", "locality"}, wantOK: true},
		{selector: "a.b.c", want: []any{"a", "b", "c"}, wantOK: true},
		{selector: "degrees[0]", want: []any{"degrees", 0}, wantOK: true},
		{selector: "degrees[0].type", want: []any{"degrees", 0, "type"}, wantOK: true},
		// A wildcard is a nil segment, which is how "every element" is carried.
		{selector: "degrees[*]", want: []any{"degrees", nil}, wantOK: true},
		{selector: "degrees[*].type", want: []any{"degrees", nil, "type"}, wantOK: true},
		{selector: "a[0][1]", want: []any{"a", 0, 1}, wantOK: true},

		{selector: "", wantOK: false},
		{selector: ".", wantOK: false},
		{selector: ".leading", wantOK: false},
		{selector: "a[]", wantOK: false},
		{selector: "a[x]", wantOK: false},
		{selector: "a[0", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			got, ok := parseSDJWTSelector(tt.selector)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got %#v)", ok, tt.wantOK, got)
			}
			if tt.wantOK && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("path = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestClaimValueAtPath(t *testing.T) {
	value := map[string]any{
		"address": map[string]any{"locality": "Berlin", "postal_code": "10115"},
		"degrees": []any{
			map[string]any{"type": "BA", "year": float64(2019)},
			map[string]any{"type": "MA"},
		},
		"nicknames": []any{"Ada", "Addy"},
	}

	tests := []struct {
		name   string
		path   []any
		want   any
		wantOK bool
	}{
		{name: "an empty path is the value itself", path: nil, want: value, wantOK: true},
		{name: "a nested object", path: []any{"address", "locality"}, want: "Berlin", wantOK: true},
		{name: "an array element", path: []any{"degrees", 0, "type"}, want: "BA", wantOK: true},
		{name: "a whole array under a wildcard", path: []any{"nicknames", nil}, want: []any{"Ada", "Addy"}, wantOK: true},
		{name: "a wildcard collecting a member", path: []any{"degrees", nil, "type"}, want: []any{"BA", "MA"}, wantOK: true},

		{name: "a key that is not there", path: []any{"address", "country"}, wantOK: false},
		{name: "descending into a scalar", path: []any{"address", "locality", "deeper"}, wantOK: false},
		{name: "an index past the end", path: []any{"degrees", 9}, wantOK: false},
		{name: "a negative index", path: []any{"degrees", -1}, wantOK: false},
		{name: "an index into an object", path: []any{"address", 0}, wantOK: false},
		{name: "a wildcard over an object", path: []any{"address", nil}, wantOK: false},
		{name: "a segment of an unusable type", path: []any{1.5}, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := claimValueAtPath(value, tt.path)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got %#v)", ok, tt.wantOK, got)
			}
			if tt.wantOK && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("value = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// A wildcard that matches nothing must report no match rather than an empty
// list, or a credential without the claim would look like it has it.
func TestClaimValueAtPathWildcardWithNoMatches(t *testing.T) {
	value := map[string]any{"degrees": []any{map[string]any{"other": 1}}}

	if got, ok := claimValueAtPath(value, []any{"degrees", nil, "type"}); ok {
		t.Errorf("value = %#v, ok = %v, want no match", got, ok)
	}
}

func TestClaimValueBySelector(t *testing.T) {
	sdjwt := StoredCredential{
		Format: "dc+sd-jwt",
		Claims: map[string]any{
			"given_name": "Ada",
			"address":    map[string]any{"locality": "Berlin"},
		},
	}
	// An mdoc selector names the element directly: the namespace split has
	// already happened by the time claims are stored.
	mdocCred := StoredCredential{
		Format: "mso_mdoc",
		Claims: map[string]any{"given_name": "Ada"},
	}

	tests := []struct {
		name     string
		cred     StoredCredential
		selector string
		want     any
		wantOK   bool
	}{
		{name: "a top level claim", cred: sdjwt, selector: "given_name", want: "Ada", wantOK: true},
		{name: "a nested claim", cred: sdjwt, selector: "address.locality", want: "Berlin", wantOK: true},
		{name: "a claim that is absent", cred: sdjwt, selector: "family_name", wantOK: false},
		{name: "an unparseable selector", cred: sdjwt, selector: "", wantOK: false},
		{name: "a selector that starts with an index", cred: sdjwt, selector: "[0]", wantOK: false},
		{name: "an mdoc element", cred: mdocCred, selector: "given_name", want: "Ada", wantOK: true},
		{name: "an mdoc element that is absent", cred: mdocCred, selector: "family_name", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := claimValueBySelector(tt.cred, tt.selector)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got %#v)", ok, tt.wantOK, got)
			}
			if tt.wantOK && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("value = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// The path is written back into log lines and the consent dialog, so every
// segment type has to render.
func TestClaimPathString(t *testing.T) {
	tests := []struct {
		name string
		path []any
		want string
	}{
		{name: "empty", path: nil, want: "<empty>"},
		{name: "one name", path: []any{"given_name"}, want: "given_name"},
		{name: "nested names", path: []any{"address", "locality"}, want: "address.locality"},
		{name: "an index", path: []any{"degrees", float64(0)}, want: "degrees[0]"},
		{name: "a wildcard", path: []any{"degrees", nil}, want: "degrees[*]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claimPathString(tt.path); got != tt.want {
				t.Errorf("claimPathString(%#v) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
