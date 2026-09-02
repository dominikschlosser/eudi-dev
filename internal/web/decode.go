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
	"fmt"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

// Decode detects the credential format and returns a JSON-serializable map.
func Decode(input string) (map[string]any, error) {
	detected := detectCredentialFormat(input)

	switch detected {
	case format.FormatSDJWT:
		return Validate(input, ValidateOpts{})

	case format.FormatJWT:
		return Validate(input, ValidateOpts{})

	case format.FormatMDOC:
		return Validate(input, ValidateOpts{})

	default:
		return nil, fmt.Errorf("unable to auto-detect credential format (not JWT, SD-JWT, or mDOC)")
	}
}

// detectCredentialFormat coerces an OID4 result from format.Detect back to a
// credential format when the input is structurally a JWT or SD-JWT: a
// credential JWT may carry OID4-like fields such as client_id.
func detectCredentialFormat(input string) format.CredentialFormat {
	detected := format.Detect(input)

	if detected == format.FormatOID4VCI || detected == format.FormatOID4VP {
		trimmed := strings.TrimSpace(input)
		if strings.Contains(trimmed, "~") {
			return format.FormatSDJWT
		}
		parts := strings.Split(trimmed, ".")
		if len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 {
			return format.FormatJWT
		}
	}

	return detected
}
