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
	"fmt"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/internal/oid4vc"
)

// ValidateHAIPCompliance checks an authorization request against HAIP 1.0 requirements.
// Returns a list of violation messages. Empty list means compliant.
//
// HAIP requires:
//   - response_mode MUST be an encrypted mode: direct_post.jwt or dc_api.jwt
//   - client_id MUST use an allowed HAIP scheme
//   - Signed Request Objects (JAR) MUST be used except for web-origin Browser API requests
//   - DCQL query MUST be used (not presentation_definition)
//   - Request Object alg MUST be ES256 when a Request Object is present
func ValidateHAIPCompliance(params *AuthorizationRequestParams, reqObj *oid4vc.RequestObjectJWT) []string {
	var violations []string
	if params == nil {
		return []string{"HAIP: authorization request is missing"}
	}
	var payload map[string]any
	if reqObj != nil {
		payload = reqObj.Payload
	}
	if payload == nil && params != nil {
		payload = params.RequestPayload
	}

	// Encrypted response modes are required.
	if params.ResponseMode != "direct_post.jwt" && params.ResponseMode != "dc_api.jwt" {
		violations = append(violations, fmt.Sprintf(
			"HAIP: response_mode MUST be 'direct_post.jwt' or 'dc_api.jwt', got %q", params.ResponseMode))
	}

	// Current HAIP wallet profiles use x509-bound or web-origin client identifiers.
	if !strings.HasPrefix(params.ClientID, "x509_hash:") &&
		!strings.HasPrefix(params.ClientID, "x509_san_dns:") &&
		!strings.HasPrefix(params.ClientID, "web-origin:") {
		violations = append(violations, fmt.Sprintf(
			"HAIP: client_id MUST use 'x509_hash:', 'x509_san_dns:', or 'web-origin:' scheme, got %q", params.ClientID))
	}

	// Browser API web-origin requests may be unsigned; other HAIP requests require JAR.
	requiresJAR := !(params.ResponseMode == "dc_api.jwt" && strings.HasPrefix(params.ClientID, "web-origin:"))
	if requiresJAR && (reqObj == nil || reqObj.Header == nil) {
		violations = append(violations, "HAIP: signed Request Object (JAR) MUST be used")
	}

	// §5.2.4: DCQL query MUST be used
	if params.DCQLQuery == nil {
		violations = append(violations, "HAIP: DCQL query MUST be used (not presentation_definition)")
	}

	// §7: ES256 MUST be supported; request object alg MUST be ES256
	if reqObj != nil && reqObj.Header != nil {
		alg := jsonutil.GetString(reqObj.Header, "alg")
		if alg != "" && alg != "ES256" {
			violations = append(violations, fmt.Sprintf(
				"HAIP: Request Object algorithm MUST be ES256, got %q", alg))
		}
	}

	if params.ResponseMode == "dc_api.jwt" && params.RequestOrigin != "" {
		unsignedWebOrigin := reqObj == nil && strings.HasPrefix(params.ClientID, "web-origin:")
		if (!unsignedWebOrigin || expectedOriginsProvided(payload)) &&
			!originAllowedByExpectedOrigins(payload, params.RequestOrigin) {
			violations = append(violations, fmt.Sprintf(
				"HAIP: expected_origins MUST include caller origin %q", params.RequestOrigin))
		}
	}

	return violations
}

func expectedOriginsProvided(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	_, ok := payload["expected_origins"]
	return ok
}

func originAllowedByExpectedOrigins(payload map[string]any, origin string) bool {
	if payload == nil {
		return false
	}
	values := jsonutil.GetArray(payload, "expected_origins")
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if text, ok := value.(string); ok && text == origin {
			return true
		}
	}
	return false
}
