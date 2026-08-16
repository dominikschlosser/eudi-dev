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

package statuslist

import (
	"strconv"
	"strings"
)

// NegotiateMediaType picks the Status List Token representation for an HTTP
// Accept header. Section 8.1 uses "Content negotiation as defined in
// [RFC9110]" over application/statuslist+jwt and application/statuslist+cwt. A
// client asking for neither, or for both equally, gets the JWT form.
func NegotiateMediaType(accept string) string {
	jwtQ := acceptQuality(accept, MediaTypeJWT)
	cwtQ := acceptQuality(accept, MediaTypeCWT)
	if cwtQ > jwtQ {
		return MediaTypeCWT
	}
	return MediaTypeJWT
}

// acceptQuality returns the q-value an Accept header assigns to a media type,
// taking the most specific match. A header that mentions nothing matching
// scores 0.
func acceptQuality(accept, mediaType string) float64 {
	if strings.TrimSpace(accept) == "" {
		return 0
	}
	slash := strings.Index(mediaType, "/")
	typeWildcard := mediaType[:slash] + "/*"

	best := 0.0
	bestRank := -1
	for _, entry := range strings.Split(accept, ",") {
		parts := strings.Split(entry, ";")
		name := strings.ToLower(strings.TrimSpace(parts[0]))

		rank := -1
		switch name {
		case mediaType:
			rank = 2
		case typeWildcard:
			rank = 1
		case "*/*":
			rank = 0
		}
		if rank < bestRank {
			continue
		}

		q := 1.0
		for _, param := range parts[1:] {
			key, value, found := strings.Cut(param, "=")
			if !found || strings.ToLower(strings.TrimSpace(key)) != "q" {
				continue
			}
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
				q = parsed
			}
		}
		best, bestRank = q, rank
	}
	if bestRank < 0 {
		return 0
	}
	return best
}
