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

// Package config provides shared default constants used across the CLI and internal packages.
package config

import (
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultWalletPort is the default port for the wallet HTTP server.
	DefaultWalletPort = 8085

	// DefaultServePort is the default port for the decode/validate web UI.
	DefaultServePort = 8080

	// DefaultProxyPort is the default port for the debugging reverse proxy.
	DefaultProxyPort = 9090

	// DefaultProxyDashboardPort is the default port for the proxy's dashboard,
	// which serves the recorded traffic to the browser and to `proxy logs`.
	DefaultProxyDashboardPort = 9091

	// ConsentTimeout is how long the wallet waits for interactive consent before timing out.
	ConsentTimeout = 5 * time.Minute

	// AuthorizationCallbackWait is how long an authorization code flow waits
	// for the user to finish signing in at the issuer. The CLI follows the
	// offer for the same span, so it stops looking when the flow it is
	// watching has already given up.
	AuthorizationCallbackWait = 5 * time.Minute

	// SlowRequestTimeout covers the requests that legitimately outlast a normal
	// round trip: an authorization code flow waits for the user to sign in at
	// the issuer, and a consent approval waits for the flow behind it. It
	// bounds the wallet server's response write, the remote CLI client, and
	// the consent approval wait.
	SlowRequestTimeout = 2 * time.Minute
)

// BaseDir returns the tool's state directory. Resolution order: the
// EUDI_DEV_HOME environment variable, the legacy OID4VC_DEV_HOME variable,
// an existing legacy ~/.oid4vc-dev directory (so existing setups keep
// working after the rename), and ~/.eudi-dev otherwise.
func BaseDir() string {
	if custom := os.Getenv("EUDI_DEV_HOME"); custom != "" {
		return custom
	}
	if custom := os.Getenv("OID4VC_DEV_HOME"); custom != "" {
		return custom
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	newDir := filepath.Join(home, ".eudi-dev")
	legacyDir := filepath.Join(home, ".oid4vc-dev")
	if _, err := os.Stat(newDir); err == nil {
		return newDir
	}
	if _, err := os.Stat(legacyDir); err == nil {
		return legacyDir
	}
	return newDir
}
