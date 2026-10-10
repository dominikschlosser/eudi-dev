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

package registrar

import (
	"slices"
	"strings"
)

// CredentialTypes reads the types of a DCQL meta object. SD-JWT VC uses
// vct_values. mdoc uses doctype_value.
func CredentialTypes(meta any) []string {
	m, ok := meta.(map[string]any)
	if !ok {
		return nil
	}
	var types []string
	switch values := m["vct_values"].(type) {
	case []string:
		types = append(types, values...)
	case []any:
		for _, v := range values {
			if s, ok := v.(string); ok {
				types = append(types, s)
			}
		}
	}
	if s, ok := m["doctype_value"].(string); ok && s != "" {
		types = append(types, s)
	}
	return types
}

func dedupeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}
