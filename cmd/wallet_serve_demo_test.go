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

package cmd

import (
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

// Demo mode is the EUDI profile, but only demo mode: a plain `wallet serve`
// must keep its permissive defaults, which is what every existing user and
// the OIDF conformance wrapper rely on. The flags stay overridable so a
// self-hosted demo can opt out.
func TestDemoModeImpliesEUDIProfile(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantMode       wallet.ValidationMode
		wantHAIP       bool
		wantVCIVersion wallet.VCIVersion
	}{
		{
			name:           "plain serve keeps the permissive defaults",
			args:           []string{"--port", "0"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       false,
			wantVCIVersion: wallet.VCIVersion10,
		},
		{
			name:           "demo implies HAIP in debug and the 1.1 feature level",
			args:           []string{"--port", "0", "--demo"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       true,
			wantVCIVersion: wallet.VCIVersion11,
		},
		{
			name:           "explicit mode wins over the demo default",
			args:           []string{"--port", "0", "--demo", "--mode", "strict"},
			wantMode:       wallet.ValidationModeStrict,
			wantHAIP:       true,
			wantVCIVersion: wallet.VCIVersion11,
		},
		{
			name:           "explicit haip=false wins over the demo default",
			args:           []string{"--port", "0", "--demo", "--haip=false"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       false,
			wantVCIVersion: wallet.VCIVersion11,
		},
		{
			name:           "explicit vci-version wins over the demo default",
			args:           []string{"--port", "0", "--demo", "--vci-version", "1.0"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       true,
			wantVCIVersion: wallet.VCIVersion10,
		},
		{
			name:           "haip without demo is still available on its own",
			args:           []string{"--port", "0", "--haip"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       true,
			wantVCIVersion: wallet.VCIVersion10,
		},
		{
			name:           "the 1.1 feature level is available without demo",
			args:           []string{"--port", "0", "--vci-version", "1.1"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       false,
			wantVCIVersion: wallet.VCIVersion11,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := resolveServeProfile(t, tc.args)
			if w.ValidationMode != tc.wantMode {
				t.Errorf("validation mode = %q, want %q", w.ValidationMode, tc.wantMode)
			}
			if w.RequireHAIP != tc.wantHAIP {
				t.Errorf("RequireHAIP = %v, want %v", w.RequireHAIP, tc.wantHAIP)
			}
			if got := w.VCIFeatureVersion(); got != tc.wantVCIVersion {
				t.Errorf("VCIVersion = %q, want %q", got, tc.wantVCIVersion)
			}
		})
	}
}

// TestServeRejectsAnUnknownVCIVersion keeps the failure at flag-resolution
// time, where the operator sees it, rather than at the first issuance.
func TestServeRejectsAnUnknownVCIVersion(t *testing.T) {
	cmd, opts := walletServeCmdWithOptions()
	if err := cmd.ParseFlags([]string{"--port", "0", "--vci-version", "1.2"}); err != nil {
		t.Fatalf("parsing flags: %v", err)
	}
	w := newTestServeWallet(t)
	if err := applyVCIVersion(w, opts.VCIVersion); err == nil {
		t.Fatal("applyVCIVersion accepted an unknown version")
	}
}

// resolveServeProfile applies the serve flags the way RunE does, through the
// same helpers, without starting a server. Restating that resolution here
// instead would test the copy: an earlier version of this test did, and went
// on asserting a demo default the command had stopped applying.
func resolveServeProfile(t *testing.T, args []string) *wallet.Wallet {
	w, _ := resolveServeProfileWithOptions(t, args)
	return w
}

func resolveServeProfileWithOptions(t *testing.T, args []string) (*wallet.Wallet, *walletServeOptions) {
	t.Helper()

	cmd, opts := walletServeCmdWithOptions()
	// --mode is a persistent flag on the parent command.
	cmd.Flags().StringVar(&walletValidationMode, "mode", string(wallet.ValidationModeDebug), "")
	t.Cleanup(func() { walletValidationMode = string(wallet.ValidationModeDebug) })

	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}

	w := newTestServeWallet(t)
	if err := applyValidationMode(w, walletValidationMode); err != nil {
		t.Fatalf("applying validation mode: %v", err)
	}
	if opts.Demo {
		applyDemoProfileDefaults(cmd, opts, w)
	}
	if err := applyVCIVersion(w, opts.VCIVersion); err != nil {
		t.Fatalf("applying vci version: %v", err)
	}
	if opts.HAIP {
		w.RequireHAIP = true
	}
	return w, opts
}

// The demo baseline is a default like the others: an explicit --pid=false
// starts the demo without seeding one.
func TestDemoModePIDBaselineIsOverridable(t *testing.T) {
	_, withDefault := resolveServeProfileWithOptions(t, []string{"--port", "0", "--demo"})
	if !withDefault.PID {
		t.Error("demo did not imply the PID baseline")
	}
	_, disabled := resolveServeProfileWithOptions(t, []string{"--port", "0", "--demo", "--pid=false"})
	if disabled.PID {
		t.Error("explicit --pid=false did not win over the demo default")
	}
	_, plain := resolveServeProfileWithOptions(t, []string{"--port", "0"})
	if plain.PID {
		t.Error("plain serve seeded a PID baseline nobody asked for")
	}
}

func newTestServeWallet(t *testing.T) *wallet.Wallet {
	t.Helper()

	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	return wallet.New(holderKey, issuerKey, false)
}
