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
	"crypto"
	"slices"
	"testing"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/oid4vc-dev/internal/config"
	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

func TestTypeLabel(t *testing.T) {
	tests := []struct {
		name    string
		vct     string
		docType string
		format  string
		want    string
	}{
		{"vct preferred", "urn:eu.europa.ec:pid", "org.iso.mdl", "dc+sd-jwt", "urn:eu.europa.ec:pid"},
		{"docType fallback", "", "org.iso.mdl", "mso_mdoc", "org.iso.mdl"},
		{"format fallback", "", "", "dc+sd-jwt", "dc+sd-jwt"},
		{"all empty", "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := typeLabel(tt.vct, tt.docType, tt.format)
			if got != tt.want {
				t.Errorf("typeLabel(%q, %q, %q) = %q, want %q", tt.vct, tt.docType, tt.format, got, tt.want)
			}
		})
	}
}

func TestCredLabel(t *testing.T) {
	tests := []struct {
		name string
		cred wallet.StoredCredential
		want string
	}{
		{"with VCT", wallet.StoredCredential{VCT: "urn:pid", DocType: "org.iso.mdl", Format: "dc+sd-jwt"}, "urn:pid"},
		{"with DocType only", wallet.StoredCredential{DocType: "org.iso.mdl", Format: "mso_mdoc"}, "org.iso.mdl"},
		{"format only", wallet.StoredCredential{Format: "dc+sd-jwt"}, "dc+sd-jwt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := credLabel(tt.cred)
			if got != tt.want {
				t.Errorf("credLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"ab", 1, "a..."},
	}

	for _, tt := range tests {
		got := format.Truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}

func TestParseClaimsOverrides(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		result, err := parseClaimsOverrides("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid JSON", func(t *testing.T) {
		result, err := parseClaimsOverrides(`{"given_name":"Max","age":30}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result["given_name"] != "Max" {
			t.Errorf("expected given_name=Max, got %v", result["given_name"])
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := parseClaimsOverrides("{invalid")
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestApplySessionTranscriptMode(t *testing.T) {
	tests := []struct {
		mode    string
		want    wallet.SessionTranscriptMode
		wantErr bool
	}{
		{"oid4vp", wallet.SessionTranscriptOID4VP, false},
		{"", wallet.SessionTranscriptOID4VP, false},
		{"iso", wallet.SessionTranscriptISO, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run("mode="+tt.mode, func(t *testing.T) {
			w := &wallet.Wallet{}
			err := applySessionTranscriptMode(w, tt.mode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("applySessionTranscriptMode(%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
			if !tt.wantErr && w.SessionTranscript != tt.want {
				t.Errorf("got transcript mode %q, want %q", w.SessionTranscript, tt.want)
			}
		})
	}
}

func TestApplyValidationMode(t *testing.T) {
	tests := []struct {
		mode    string
		want    wallet.ValidationMode
		wantErr bool
	}{
		{"debug", wallet.ValidationModeDebug, false},
		{"", wallet.ValidationModeDebug, false},
		{"strict", wallet.ValidationModeStrict, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run("mode="+tt.mode, func(t *testing.T) {
			w := &wallet.Wallet{}
			err := applyValidationMode(w, tt.mode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("applyValidationMode(%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
			if !tt.wantErr && w.ValidationMode != tt.want {
				t.Errorf("got validation mode %q, want %q", w.ValidationMode, tt.want)
			}
		})
	}
}

func TestSetLocalPresentationIssuerURL(t *testing.T) {
	w := &wallet.Wallet{IssuerURL: "https://localhost:8086"}

	setLocalPresentationIssuerURL(w, 31127)

	if got, want := w.IssuerURL, "https://localhost:31128"; got != want {
		t.Fatalf("setLocalPresentationIssuerURL() = %q, want %q", got, want)
	}
}

func TestEffectivePresentationPort(t *testing.T) {
	if got, want := effectivePresentationPort(0), config.DefaultWalletPort; got != want {
		t.Fatalf("effectivePresentationPort(0) = %d, want %d", got, want)
	}
	if got, want := effectivePresentationPort(31127), 31127; got != want {
		t.Fatalf("effectivePresentationPort(31127) = %d, want %d", got, want)
	}
}

func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://example.com", true},
		{"http://example.com", true},
		{"HTTP://EXAMPLE.COM", true},
		{"HTTPS://EXAMPLE.COM", true},
		{"openid4vp://authorize", false},
		{"eyJhbGci...", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isHTTPURL(tt.input)
		if got != tt.want {
			t.Errorf("isHTTPURL(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestVerifyWithBestKey(t *testing.T) {
	type result struct {
		valid bool
		keyID string
	}

	// Mock keys as simple int pointers for testing
	key1 := new(int)
	*key1 = 1
	key2 := new(int)
	*key2 = 2

	t.Run("x5cKey takes priority", func(t *testing.T) {
		called := false
		r := verifyWithBestKey(
			[]crypto.PublicKey{key1},
			key2, // x5cKey
			func(key crypto.PublicKey) (result, bool) {
				called = true
				if key == key2 {
					return result{valid: true, keyID: "x5c"}, true
				}
				return result{valid: false, keyID: "fallback"}, false
			},
		)
		if !called {
			t.Error("verify function was not called")
		}
		if r.keyID != "x5c" {
			t.Errorf("expected x5c key used, got %s", r.keyID)
		}
	})

	t.Run("falls back to pubKeys when no x5cKey", func(t *testing.T) {
		callCount := 0
		r := verifyWithBestKey(
			[]crypto.PublicKey{key1, key2},
			nil, // no x5cKey
			func(key crypto.PublicKey) (result, bool) {
				callCount++
				if key == key2 {
					return result{valid: true, keyID: "key2"}, true
				}
				return result{valid: false, keyID: "key1"}, false
			},
		)
		if r.keyID != "key2" {
			t.Errorf("expected key2 to be selected, got %s", r.keyID)
		}
		if callCount != 2 {
			t.Errorf("expected 2 calls, got %d", callCount)
		}
	})

	t.Run("stops on first valid key", func(t *testing.T) {
		callCount := 0
		r := verifyWithBestKey(
			[]crypto.PublicKey{key1, key2},
			nil,
			func(key crypto.PublicKey) (result, bool) {
				callCount++
				return result{valid: true, keyID: "first"}, true
			},
		)
		if callCount != 1 {
			t.Errorf("expected 1 call (early exit), got %d", callCount)
		}
		if !r.valid {
			t.Error("expected valid result")
		}
	})

	t.Run("returns last result when none valid", func(t *testing.T) {
		r := verifyWithBestKey(
			[]crypto.PublicKey{key1, key2},
			nil,
			func(key crypto.PublicKey) (result, bool) {
				if key == key2 {
					return result{valid: false, keyID: "last"}, false
				}
				return result{valid: false, keyID: "first"}, false
			},
		)
		if r.keyID != "last" {
			t.Errorf("expected last result, got %s", r.keyID)
		}
	})
}

func TestWalletRegisterOptions(t *testing.T) {
	args := []string{
		"--port", "9123",
		"--auto-accept",
		"--haip",
		"--vci-client-id", "wallet-client",
		"--credential", "cred1.json",
	}

	opts, err := walletRegisterOptions(args)
	if err != nil {
		t.Fatalf("walletRegisterOptions() error = %v", err)
	}
	if opts.ListenerPort != 9123 {
		t.Fatalf("ListenerPort = %d, want 9123", opts.ListenerPort)
	}
	if !opts.AutoAccept {
		t.Fatal("AutoAccept = false, want true")
	}
	if !slices.Equal(opts.ServeArgs, args) {
		t.Fatalf("ServeArgs = %#v, want %#v", opts.ServeArgs, args)
	}
}

func TestWalletRegisterOptions_Defaults(t *testing.T) {
	opts, err := walletRegisterOptions(nil)
	if err != nil {
		t.Fatalf("walletRegisterOptions() error = %v", err)
	}
	if opts.ListenerPort != config.DefaultWalletPort {
		t.Fatalf("ListenerPort = %d, want %d", opts.ListenerPort, config.DefaultWalletPort)
	}
	if opts.AutoAccept {
		t.Fatal("AutoAccept = true, want false")
	}
	if len(opts.ServeArgs) != 0 {
		t.Fatalf("ServeArgs = %#v, want empty", opts.ServeArgs)
	}
}

func TestWalletRegisterInheritedServeArgs(t *testing.T) {
	parent := &cobra.Command{Use: "wallet"}
	parent.PersistentFlags().String("wallet-dir", "", "")
	parent.PersistentFlags().String("mode", "debug", "")
	cmd := &cobra.Command{Use: "register"}
	parent.AddCommand(cmd)
	if err := parent.PersistentFlags().Set("wallet-dir", "/tmp/isolated-wallet"); err != nil {
		t.Fatalf("set wallet-dir: %v", err)
	}
	if err := parent.PersistentFlags().Set("mode", "strict"); err != nil {
		t.Fatalf("set mode: %v", err)
	}

	got := walletRegisterInheritedServeArgs(cmd)
	if !argPairPresent(got, "--wallet-dir", "/tmp/isolated-wallet") {
		t.Fatalf("walletRegisterInheritedServeArgs() missing wallet-dir: %#v", got)
	}
	if !argPairPresent(got, "--mode", "strict") {
		t.Fatalf("walletRegisterInheritedServeArgs() missing mode: %#v", got)
	}
}

func TestSerializeWalletServeArgs(t *testing.T) {
	parent := &cobra.Command{Use: "wallet"}
	parent.PersistentFlags().String("wallet-dir", "", "")
	cmd := &cobra.Command{Use: "serve"}
	parent.AddCommand(cmd)
	flags := cmd.Flags()
	flags.Int("port", config.DefaultWalletPort, "")
	flags.Bool("auto-accept", false, "")
	flags.String("base-url", "", "")
	flags.StringSlice("credential", nil, "")
	flags.Bool("register", false, "")
	flags.Bool("no-register", false, "")
	if err := flags.Set("port", "9123"); err != nil {
		t.Fatalf("set port: %v", err)
	}
	if err := flags.Set("auto-accept", "true"); err != nil {
		t.Fatalf("set auto-accept: %v", err)
	}
	if err := flags.Set("base-url", "http://localhost:9123"); err != nil {
		t.Fatalf("set base-url: %v", err)
	}
	if err := flags.Set("credential", "first.json"); err != nil {
		t.Fatalf("set credential 1: %v", err)
	}
	if err := flags.Set("credential", "second.json"); err != nil {
		t.Fatalf("set credential 2: %v", err)
	}
	if err := flags.Set("register", "true"); err != nil {
		t.Fatalf("set register: %v", err)
	}
	if err := parent.PersistentFlags().Set("wallet-dir", "/tmp/isolated-wallet"); err != nil {
		t.Fatalf("set wallet-dir: %v", err)
	}

	got, err := serializeWalletServeArgs(cmd)
	if err != nil {
		t.Fatalf("serializeWalletServeArgs() error = %v", err)
	}

	want := []string{
		"--wallet-dir", "/tmp/isolated-wallet",
		"--auto-accept",
		"--base-url", "http://localhost:9123",
		"--credential", "first.json",
		"--credential", "second.json",
		"--port", "9123",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("serializeWalletServeArgs() = %#v, want %#v", got, want)
	}
}

func TestSerializeWalletServeArgs_BoolFalseOmitted(t *testing.T) {
	cmd := &cobra.Command{Use: "serve"}
	flags := cmd.Flags()
	flags.Bool("auto-accept", false, "")
	flags.Bool("register", false, "")
	flags.Bool("no-register", false, "")

	got, err := serializeWalletServeArgs(cmd)
	if err != nil {
		t.Fatalf("serializeWalletServeArgs() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("serializeWalletServeArgs() = %#v, want empty", got)
	}
}

func argPairPresent(args []string, flag string, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
