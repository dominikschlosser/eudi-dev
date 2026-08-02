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
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/internal/remote"
)

// remoteFlag is the one-off remote override (--remote <url>, or --remote
// local to force the local store despite a persisted remote).
var remoteFlag string

// activeRemoteURL resolves the remote wallet target: the --remote flag wins,
// then the target persisted by `wallet use`. Empty means local management.
func activeRemoteURL() (string, error) {
	if strings.TrimSpace(remoteFlag) != "" {
		if strings.EqualFold(strings.TrimSpace(remoteFlag), "local") {
			return "", nil
		}
		return remote.NormalizeURL(remoteFlag)
	}
	return remote.Active(), nil
}

// remoteClientIfConfigured returns a client for the active remote wallet, or
// nil when the CLI manages the local store. It prints the target to stderr
// so remote operations are never silent.
func remoteClientIfConfigured() (*remote.Client, error) {
	url, err := activeRemoteURL()
	if err != nil {
		return nil, err
	}
	if url == "" {
		return nil, nil
	}
	fmt.Fprintf(os.Stderr, "Managing remote wallet %s\n", url)
	return remote.NewClient(url), nil
}

func instancesUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "use [url|local]",
		ValidArgsFunction: completeUseTargets,
		Short:             "Switch wallet management to a remote instance (or back to local)",
		Long: "Selects which wallet the management commands operate on. With a URL the CLI manages that " +
			"running eudi-dev wallet server over its REST API. With \"local\" it manages the local wallet store again. " +
			"Without arguments it prints the current target.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				active := remote.Active()
				if active == "" {
					fmt.Println("local")
					return nil
				}
				fmt.Println(active)
				if _, ok := healthSummary(active); !ok {
					fmt.Fprintln(os.Stderr, "Warning: the remote wallet is not reachable")
				}
				return nil
			}

			target := args[0]
			if strings.EqualFold(target, "local") {
				if err := remote.ClearActive(); err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "Managing the local wallet store again")
				return nil
			}

			normalized, err := remote.NormalizeURL(target)
			if err != nil {
				return err
			}
			version, ok := healthSummary(normalized)
			if !ok {
				return fmt.Errorf("no eudi-dev wallet reachable at %s (is it running?)", normalized)
			}
			if _, err := remote.SetActive(normalized); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Managing remote wallet %s %s\n", normalized, version)
			return nil
		},
	}
}

// healthSummary probes a wallet URL and returns a short description.
func healthSummary(url string) (string, bool) {
	client := remote.NewClient(url)
	version, err := client.Version()
	if err != nil {
		return "", false
	}
	summary := ""
	if pid, ok := version["pid"].(float64); ok {
		summary = fmt.Sprintf("(pid %d)", int(pid))
	}
	return summary, true
}

func walletInstancesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "instances",
		Short: "Manage running eudi-dev wallet instances on this system",
		Long: "Finds, stops, and selects running wallet servers. Without a subcommand it lists them " +
			"(same as `wallet instances list`).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstancesList()
		},
	}
	cmd.AddCommand(instancesListCmd())
	cmd.AddCommand(instancesUseCmd())
	cmd.AddCommand(instancesKillCmd())
	return cmd
}

func instancesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List running wallet instances",
		Long: "Scans the instance registry and the local process list for running wallet servers and checks " +
			"that they respond. Use `wallet instances use <url>` to manage one of them and " +
			"`wallet instances kill <target>` to stop one.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstancesList()
		},
	}
}

func runInstancesList() error {
	instances := remote.Discover(time.Second)
	active := remote.Active()

	if jsonOutput {
		data, err := json.MarshalIndent(instances, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	if len(instances) == 0 {
		fmt.Println("No running wallet instances found.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "URL\tPID\tWALLET DIR\tSOURCE\tACTIVE")
	for _, inst := range instances {
		activeMark := ""
		if active != "" && active == strings.TrimRight(inst.URL, "/") {
			activeMark = "*"
		}
		dir := inst.WalletDir
		if dir == "" {
			dir = "-"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", inst.URL, inst.PID, dir, inst.Source, activeMark)
	}
	return tw.Flush()
}

func instancesKillCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:               "kill [pid|port|url]",
		ValidArgsFunction: completeInstanceTargets,
		Short:             "Stop a running eudi-dev wallet instance",
		Long: "Stops a running wallet server found by `wallet instances list`. The target is a pid, a port, or a URL. " +
			"The instance is asked to exit via its shutdown endpoint. When it does not respond, a local process " +
			"gets a SIGTERM instead.",
		Args: func(cmd *cobra.Command, args []string) error {
			if all {
				if len(args) != 0 {
					return fmt.Errorf("--all does not take a target")
				}
				return nil
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			instances := remote.Discover(time.Second)

			var targets []remote.DiscoveredInstance
			if all {
				targets = instances
			} else {
				target, err := matchInstance(instances, args[0])
				if err != nil {
					return err
				}
				targets = []remote.DiscoveredInstance{target}
			}
			if len(targets) == 0 {
				fmt.Println("No running wallet instances found.")
				return nil
			}

			active := remote.Active()
			for _, inst := range targets {
				if err := stopInstance(inst); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to stop %s (pid %d): %v\n", inst.URL, inst.PID, err)
					continue
				}
				fmt.Printf("Stopped %s (pid %d)\n", inst.URL, inst.PID)
				if active != "" && active == strings.TrimRight(inst.URL, "/") {
					fmt.Fprintln(os.Stderr, "Note: this was the active remote wallet. Run `wallet instances use local` or pick another instance.")
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Stop all running wallet instances")
	return cmd
}

// matchInstance resolves a kill target (pid, port, or URL) against the
// discovered instances.
func matchInstance(instances []remote.DiscoveredInstance, target string) (remote.DiscoveredInstance, error) {
	target = strings.TrimSpace(target)
	normalizedURL := ""
	if strings.Contains(target, "://") || strings.Contains(target, ":") && strings.Contains(target, ".") || strings.HasPrefix(target, "localhost") {
		if u, err := remote.NormalizeURL(target); err == nil {
			normalizedURL = u
		}
	}
	number, numErr := strconv.Atoi(target)

	for _, inst := range instances {
		if normalizedURL != "" && strings.TrimRight(inst.URL, "/") == normalizedURL {
			return inst, nil
		}
		if numErr == nil && (inst.PID == number || inst.Port == number) {
			return inst, nil
		}
	}
	return remote.DiscoveredInstance{}, fmt.Errorf("no running wallet instance matches %q (run `wallet instances list`)", target)
}

// stopInstance asks the instance to shut down via its API and falls back to
// SIGTERM for local processes.
func stopInstance(inst remote.DiscoveredInstance) error {
	client := remote.NewClient(inst.URL)
	if err := client.Shutdown(); err == nil {
		remote.UnregisterInstance(inst.PID)
		return nil
	}
	if inst.PID <= 0 {
		return fmt.Errorf("shutdown request failed and no pid is known")
	}
	proc, err := os.FindProcess(inst.PID)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("sending SIGTERM: %w", err)
	}
	remote.UnregisterInstance(inst.PID)
	return nil
}

func walletInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show the configuration of the managed wallet (local or remote)",
		Long: "Prints the introspection document of the wallet the CLI currently manages. For a remote wallet " +
			"this is the instance's /api/config endpoint (pid, port, directories, URLs, and runtime behavior). " +
			"For the local store it shows the equivalent local view.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if c, err := remoteClientIfConfigured(); err != nil {
				return err
			} else if c != nil {
				cfg, err := c.ServerConfig()
				if err != nil {
					return err
				}
				cfg["remote_url"] = c.BaseURL
				data, err := json.MarshalIndent(cfg, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(data))
				return nil
			}

			w, store, err := loadWallet()
			if err != nil {
				return err
			}
			templates := w.TemplatesDir
			if templates == "" {
				templates = store.Dir + "/templates"
			}
			info := map[string]any{
				"remote_url":       "",
				"wallet_dir":       store.Dir,
				"templates_dir":    templates,
				"base_url":         w.BaseURL,
				"issuer_url":       w.IssuerURL,
				"status_list_url":  w.StatusListURL(),
				"preferred_format": w.PreferredFormat,
				"validation_mode":  string(w.ValidationMode),
				"credential_count": len(w.GetCredentials()),
			}
			data, err := json.MarshalIndent(info, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		},
	}
}
