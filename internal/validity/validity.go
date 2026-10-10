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

// Package validity compares the time claims of credentials and status lists
// with the current time.
package validity

import (
	"fmt"
	"time"
)

// ClockSkew is the tolerance for every time comparison. RFC 7519 §4.1.4:
// "Implementers MAY provide for some small leeway, usually no more than a few
// minutes, to account for clock skew."
const ClockSkew = time.Minute

// Expired reports whether now is past notAfter (exp, validUntil). A missing
// time never expires.
func Expired(notAfter *time.Time, now time.Time) bool {
	return notAfter != nil && now.After(notAfter.Add(ClockSkew))
}

// NotYet reports whether now is before notBefore (nbf, validFrom, iat). A
// missing time is always reached.
func NotYet(notBefore *time.Time, now time.Time) bool {
	return notBefore != nil && now.Add(ClockSkew).Before(*notBefore)
}

// Relative describes t relative to now, such as "in 3 days" or "2 hours ago".
func Relative(t, now time.Time) string {
	d := t.Sub(now)
	if d < 0 {
		return formatDuration(-d) + " ago"
	}
	return "in " + formatDuration(d)
}

func formatDuration(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d >= 60*day:
		return fmt.Sprintf("%d months", int(d/(30*day)))
	case d >= 30*day:
		return "1 month"
	case d >= 2*day:
		return fmt.Sprintf("%d days", int(d/day))
	case d >= day:
		return "1 day"
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	case d >= time.Hour:
		return "1 hour"
	case d >= 2*time.Minute:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	default:
		return "1 minute"
	}
}
