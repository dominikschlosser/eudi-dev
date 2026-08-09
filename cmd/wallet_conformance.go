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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/internal/config"
)

// conformancePref is the override the CLI sends to a remote wallet it cannot
// reconfigure. Absent fields inherit the target wallet's own setting.
type conformancePref struct {
	Mode      string `json:"mode,omitempty"`
	HAIP      *bool  `json:"haip,omitempty"`
	Encrypted *bool  `json:"encrypted,omitempty"`
}

func conformancePrefPath() string {
	return filepath.Join(config.BaseDir(), "conformance.json")
}

func loadConformancePref() conformancePref {
	var p conformancePref
	data, err := os.ReadFile(conformancePrefPath())
	if err != nil {
		return p
	}
	_ = json.Unmarshal(data, &p)
	return p
}

func saveConformancePref(p conformancePref) error {
	if p.Mode == "" && p.HAIP == nil && p.Encrypted == nil {
		if err := os.Remove(conformancePrefPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.BaseDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(conformancePrefPath(), data, 0o600)
}

// headers renders the preference as the X-Eudi-Dev-* headers the wallet reads.
// Returns nil when nothing is set, so an unset preference sends no headers and
// the target wallet keeps its own settings.
func (p conformancePref) headers() map[string]string {
	h := map[string]string{}
	if p.Mode != "" {
		h["X-Eudi-Dev-Mode"] = p.Mode
	}
	if p.HAIP != nil {
		h["X-Eudi-Dev-HAIP"] = strconv.FormatBool(*p.HAIP)
	}
	if p.Encrypted != nil {
		h["X-Eudi-Dev-Encrypted"] = strconv.FormatBool(*p.Encrypted)
	}
	if len(h) == 0 {
		return nil
	}
	return h
}

func printConformancePref(cmd *cobra.Command, p conformancePref) {
	out := cmd.OutOrStdout()
	if p.Mode == "" && p.HAIP == nil && p.Encrypted == nil {
		fmt.Fprintln(out, "No CLI conformance override set; remote wallets use their own settings.")
		return
	}
	fmt.Fprintln(out, "CLI conformance override (sent to remote wallets):")
	if p.Mode != "" {
		fmt.Fprintf(out, "  mode:      %s\n", p.Mode)
	}
	if p.HAIP != nil {
		fmt.Fprintf(out, "  haip:      %t\n", *p.HAIP)
	}
	if p.Encrypted != nil {
		fmt.Fprintf(out, "  encrypted: %t\n", *p.Encrypted)
	}
}

func walletConformanceCmd() *cobra.Command {
	var mode string
	var haip, encrypted, reset bool

	cmd := &cobra.Command{
		Use:   "conformance",
		Short: "Set the conformance override the CLI sends to a remote wallet",
		Long: "Sets a validation-strictness override the CLI attaches (as X-Eudi-Dev-* headers) to every request it makes to a remote wallet, for example after `wallet instances use <url>`. A remote wallet's own settings cannot be changed from here, so it honors this override per request instead.\n\n" +
			"This does not affect a local wallet: change a local wallet's settings in its web UI (the conformance panel), which every local flow already honors.\n\n" +
			"With no flags it prints the current override.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if reset {
				if err := saveConformancePref(conformancePref{}); err != nil {
					return fmt.Errorf("clearing conformance override: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Cleared the CLI conformance override.")
				return nil
			}

			p := loadConformancePref()
			flags := cmd.Flags()
			if flags.Changed("mode") {
				switch mode {
				case "strict", "debug":
					p.Mode = mode
				default:
					return fmt.Errorf("invalid --mode %q (must be strict or debug)", mode)
				}
			}
			if flags.Changed("haip") {
				v := haip
				p.HAIP = &v
			}
			if flags.Changed("encrypted") {
				v := encrypted
				p.Encrypted = &v
			}
			if flags.Changed("mode") || flags.Changed("haip") || flags.Changed("encrypted") {
				if err := saveConformancePref(p); err != nil {
					return fmt.Errorf("saving conformance override: %w", err)
				}
			}
			printConformancePref(cmd, loadConformancePref())
			return nil
		},
	}
	cmd.Flags().StringVar(&mode, "mode", "", "Validation mode to request from remote wallets: strict or debug")
	cmd.Flags().BoolVar(&haip, "haip", false, "Request HAIP 1.0 enforcement from remote wallets")
	cmd.Flags().BoolVar(&encrypted, "encrypted", false, "Request encrypted request objects from remote wallets")
	cmd.Flags().BoolVar(&reset, "reset", false, "Clear the CLI conformance override")
	_ = cmd.RegisterFlagCompletionFunc("mode", staticCompletion("strict", "debug"))
	return cmd
}
