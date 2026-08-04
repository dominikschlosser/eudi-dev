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

// remoteClientIfConfigured returns a client for the wallet the CLI should
// manage over HTTP, or nil when the CLI manages the local store directly.
// The target is resolved in order: the --remote flag, the target persisted
// by `wallet instances use`, then a running local instance that serves the
// same wallet directory. The last rule keeps a single writer per wallet
// directory (a running server and a CLI writing the same files diverge,
// because the server holds its state in memory). `--remote local` or an
// explicit --templates-dir forces direct local store access.
func remoteClientIfConfigured() (*remote.Client, error) {
	url, err := activeRemoteURL()
	if err != nil {
		return nil, err
	}
	if url != "" {
		return remote.NewClient(url), nil
	}
	if strings.EqualFold(strings.TrimSpace(remoteFlag), "local") || templatesDir != "" {
		return nil, nil
	}
	if inst := remote.InstanceForWalletDir(loadStore().Dir, 500*time.Millisecond); inst != nil {
		fmt.Fprintf(os.Stderr, "Routing through the running wallet instance %s (pid %d, same wallet directory). Use --remote local for direct file access.\n", inst.URL, inst.PID)
		return remote.NewClient(inst.URL), nil
	}
	return nil, nil
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
			"that they respond. The active remote target set by `wallet instances use <url>` is listed too " +
			"when it responds, even when it runs elsewhere (for example in a Docker container). " +
			"Use `wallet instances use <url>` to manage one of them and " +
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

	// Discover includes a responding active remote, so a missing one is down.
	if active != "" {
		listed := false
		for _, inst := range instances {
			if strings.TrimRight(inst.URL, "/") == active {
				listed = true
				break
			}
		}
		if !listed {
			fmt.Fprintf(os.Stderr, "Active remote wallet %s is not responding.\n", active)
		}
	}

	managed := managedInstanceURL(instances)

	if jsonOutput {
		type listedInstance struct {
			remote.DiscoveredInstance
			Active bool `json:"active"`
		}
		listed := make([]listedInstance, len(instances))
		for i, inst := range instances {
			listed[i] = listedInstance{
				DiscoveredInstance: inst,
				Active:             managed != "" && managed == strings.TrimRight(inst.URL, "/"),
			}
		}
		data, err := json.MarshalIndent(listed, "", "  ")
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
		if managed != "" && managed == strings.TrimRight(inst.URL, "/") {
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

// managedInstanceURL resolves which of the discovered instances the
// management commands currently target, mirroring the routing rules of
// remoteClientIfConfigured: the --remote flag or the persisted remote target
// first, then the auto-routed instance that serves the local wallet
// directory. Empty means the CLI manages the local store directly.
func managedInstanceURL(instances []remote.DiscoveredInstance) string {
	if url, err := activeRemoteURL(); err == nil && url != "" {
		return url
	}
	if strings.EqualFold(strings.TrimSpace(remoteFlag), "local") || templatesDir != "" {
		return ""
	}
	localDir := loadStore().Dir
	for _, inst := range instances {
		if inst.WalletDir != "" && remote.SamePath(inst.WalletDir, localDir) {
			return strings.TrimRight(inst.URL, "/")
		}
	}
	return ""
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
	if inst.Source == "active" {
		// The pid of an active remote belongs to another system (for example
		// a container), so a signal from here would hit the wrong process.
		return fmt.Errorf("shutdown request failed and the instance is not a local process")
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

// warnServingConfigDivergence compares a running instance's introspection
// document with the local wallet file when both describe the same wallet
// directory. A running server keeps the serving config it read at startup,
// so after the file changed the two disagree until the server restarts.
func warnServingConfigDivergence(cfg map[string]any) {
	instanceDir, _ := cfg["wallet_dir"].(string)
	if instanceDir == "" {
		return
	}
	store := loadStore()
	if !remote.SamePath(instanceDir, store.Dir) {
		return
	}
	w, err := store.LoadOrCreate()
	if err != nil {
		return
	}
	instanceIssuer, _ := cfg["issuer_url"].(string)
	instanceBase, _ := cfg["base_url"].(string)
	var diffs []string
	if strings.TrimSpace(w.IssuerURL) != strings.TrimSpace(instanceIssuer) {
		diffs = append(diffs, fmt.Sprintf("issuer_url (instance %q, file %q)", instanceIssuer, w.IssuerURL))
	}
	if strings.TrimSpace(w.BaseURL) != strings.TrimSpace(instanceBase) {
		diffs = append(diffs, fmt.Sprintf("base_url (instance %q, file %q)", instanceBase, w.BaseURL))
	}
	if len(diffs) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "Warning: the running instance and wallet.json disagree on %s. Restart `%s wallet serve` to apply the file.\n",
		strings.Join(diffs, " and "), binaryName())
}

func walletInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "info",
		Aliases: []string{"config"},
		Short:   "Show the configuration of the managed wallet (local or remote)",
		Long: "Prints the introspection document of the wallet the CLI currently manages. For a remote wallet " +
			"this is the instance's /api/config endpoint (pid, port, directories, URLs, and runtime behavior). " +
			"For the local store it shows the equivalent local view.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			cfg, err := svc.Config()
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			if svc.URL() != "" {
				warnServingConfigDivergence(cfg)
			}
			return nil
		},
	}
}
