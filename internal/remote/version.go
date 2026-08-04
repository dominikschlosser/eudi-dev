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

package remote

import (
	"strconv"
	"strings"
)

// Version is a release version reduced to what a compatibility check needs.
// Pre-release and build metadata are parsed away: a 1.19.0-rc.1 instance
// speaks the API of 1.19.0 as far as the CLI is concerned.
type Version struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion reads a semantic version as reported by /api/version or built
// into the CLI. It reports false for anything without a numeric major and
// minor, which covers the development build ("dev") and an instance too old
// to report a version at all.
func ParseVersion(raw string) (Version, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "v")
	// Cut pre-release and build metadata: 1.19.0-rc.1+abc -> 1.19.0.
	if i := strings.IndexAny(raw, "-+"); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" {
		return Version{}, false
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return Version{}, false
	}
	numbers := make([]int, 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return Version{}, false
		}
		numbers[i] = n
	}
	return Version{Major: numbers[0], Minor: numbers[1], Patch: numbers[2]}, true
}

// String renders the version the way it is reported.
func (v Version) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// Compatibility says whether a CLI can manage an instance.
type Compatibility int

const (
	// CompatibilityUnknown means one of the two sides does not report a
	// comparable version (a development build, or an instance predating
	// version reporting). Nothing can be concluded, so nothing is claimed.
	CompatibilityUnknown Compatibility = iota
	// Compatible means both sides run the same major release.
	Compatible
	// Incompatible means the major releases differ.
	Incompatible
)

// CheckCompatibility compares the CLI's release with an instance's the way
// semantic versioning defines it: the major release is what carries breaking
// changes, so anything within one major release can manage anything else in
// it. Minor and patch differences are compatible.
func CheckCompatibility(cli, instance string) Compatibility {
	cliVersion, cliOK := ParseVersion(cli)
	instanceVersion, instanceOK := ParseVersion(instance)
	if !cliOK || !instanceOK {
		return CompatibilityUnknown
	}
	if cliVersion.Major != instanceVersion.Major {
		return Incompatible
	}
	return Compatible
}
