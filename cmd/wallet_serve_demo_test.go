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
		name       string
		args       []string
		wantMode   wallet.ValidationMode
		wantHAIP   bool
		wantDemoOn bool
	}{
		{
			name:     "plain serve keeps the permissive defaults",
			args:     []string{"--port", "0"},
			wantMode: wallet.ValidationModeDebug,
			wantHAIP: false,
		},
		{
			name:       "demo implies strict and HAIP",
			args:       []string{"--port", "0", "--demo"},
			wantMode:   wallet.ValidationModeStrict,
			wantHAIP:   true,
			wantDemoOn: true,
		},
		{
			name:       "explicit mode wins over the demo default",
			args:       []string{"--port", "0", "--demo", "--mode", "debug"},
			wantMode:   wallet.ValidationModeDebug,
			wantHAIP:   true,
			wantDemoOn: true,
		},
		{
			name:       "explicit haip=false wins over the demo default",
			args:       []string{"--port", "0", "--demo", "--haip=false"},
			wantMode:   wallet.ValidationModeStrict,
			wantHAIP:   false,
			wantDemoOn: true,
		},
		{
			name:     "haip without demo is still available on its own",
			args:     []string{"--port", "0", "--haip"},
			wantMode: wallet.ValidationModeDebug,
			wantHAIP: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mode, haip := resolveServeProfile(t, tc.args)
			if mode != tc.wantMode {
				t.Errorf("validation mode = %q, want %q", mode, tc.wantMode)
			}
			if haip != tc.wantHAIP {
				t.Errorf("RequireHAIP = %v, want %v", haip, tc.wantHAIP)
			}
		})
	}
}

// resolveServeProfile applies the serve flags the way RunE does, without
// starting a server.
func resolveServeProfile(t *testing.T, args []string) (wallet.ValidationMode, bool) {
	t.Helper()

	cmd := walletServeCmd()
	// --mode is a persistent flag on the parent command.
	cmd.Flags().StringVar(&walletValidationMode, "mode", string(wallet.ValidationModeDebug), "")
	t.Cleanup(func() { walletValidationMode = string(wallet.ValidationModeDebug) })

	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}

	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	w := wallet.New(holderKey, issuerKey, false)
	if err := applyValidationMode(w, walletValidationMode); err != nil {
		t.Fatalf("applying validation mode: %v", err)
	}

	demo, err := cmd.Flags().GetBool("demo")
	if err != nil {
		t.Fatalf("reading --demo: %v", err)
	}
	haip, err := cmd.Flags().GetBool("haip")
	if err != nil {
		t.Fatalf("reading --haip: %v", err)
	}

	if demo {
		if !cmd.Flags().Changed("mode") {
			w.ValidationMode = wallet.ValidationModeStrict
		}
		if !cmd.Flags().Changed("haip") {
			haip = true
		}
	}
	if haip {
		w.RequireHAIP = true
	}
	return w.ValidationMode, w.RequireHAIP
}
