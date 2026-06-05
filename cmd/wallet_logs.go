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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

type walletLogPrintOptions struct {
	Verbose bool
	JSON    bool
}

func walletLogsCmd() *cobra.Command {
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show wallet interaction logs",
		Long:  "Show persisted interactions received by the wallet and sent from the wallet. By default each log entry is printed on one line.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOutput && follow {
				return fmt.Errorf("--json cannot be combined with --follow")
			}
			store := loadStore()
			w, err := store.LoadOrCreate()
			if err != nil {
				return fmt.Errorf("loading wallet: %w", err)
			}

			out := cmd.OutOrStdout()
			entries := w.GetLog()
			if err := printWalletLogs(out, entries, walletLogPrintOptions{Verbose: verbose, JSON: jsonOutput}); err != nil {
				return err
			}
			if !follow {
				return nil
			}
			return followWalletLogs(cmd.Context(), out, store, len(entries), walletLogPrintOptions{Verbose: verbose})
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow wallet logs and print new entries as they are persisted")
	cmd.AddCommand(walletLogsCleanCmd())
	return cmd
}

func walletLogsCleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clean",
		Short: "Remove old wallet logs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			store := loadStore()
			if err := store.ClearLog(); err != nil {
				return fmt.Errorf("cleaning wallet logs: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Cleared wallet logs.")
			return nil
		},
	}
}

func printWalletLogs(w io.Writer, entries []wallet.LogEntry, opts walletLogPrintOptions) error {
	if opts.JSON {
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling wallet logs: %w", err)
		}
		_, err = fmt.Fprintln(w, string(data))
		return err
	}
	for _, entry := range entries {
		printWalletLogEntry(w, entry, opts.Verbose)
	}
	return nil
}

func printWalletLogEntry(w io.Writer, entry wallet.LogEntry, verbose bool) {
	status := "✓"
	if !entry.Success {
		status = "✗"
	}
	timestamp := entry.Time.Local().Format("2006-01-02 15:04:05")
	detail := oneLine(entry.Detail)
	fmt.Fprintf(w, "%s %s %s %s\n", timestamp, status, entry.Action, detail)
	if !verbose || len(entry.Details) == 0 {
		return
	}
	fmt.Fprintln(w, "  details:")
	for _, key := range sortedWalletLogDetailKeys(entry.Details) {
		printWalletLogDetail(w, key, entry.Details[key], 2)
	}
}

func printWalletLogDetail(w io.Writer, key string, value any, depth int) {
	prefix := strings.Repeat("  ", depth)
	switch typed := value.(type) {
	case map[string]any:
		fmt.Fprintf(w, "%s┌ %s:\n", prefix, key)
		for _, nestedKey := range sortedWalletLogDetailKeys(typed) {
			printWalletLogDetail(w, nestedKey, typed[nestedKey], depth+1)
		}
	default:
		fmt.Fprintf(w, "%s┌ %s: %s\n", prefix, key, walletLogValueString(value, prefix+"  "))
	}
}

func walletLogValueString(value any, prefix string) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		data, err := json.MarshalIndent(value, prefix, "  ")
		if err != nil {
			return fmt.Sprintf("%v", value)
		}
		return string(data)
	}
}

func sortedWalletLogDetailKeys(details map[string]any) []string {
	keys := make([]string, 0, len(details))
	for key := range details {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func followWalletLogs(ctx context.Context, out io.Writer, store *wallet.WalletStore, seen int, opts walletLogPrintOptions) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w, err := store.LoadOrCreate()
			if err != nil {
				return fmt.Errorf("loading wallet: %w", err)
			}
			entries := w.GetLog()
			if seen > len(entries) {
				seen = 0
			}
			if seen < len(entries) {
				if err := printWalletLogs(out, entries[seen:], opts); err != nil {
					return err
				}
				seen = len(entries)
			}
		}
	}
}

func walletLogEntriesAfter(entries []wallet.LogEntry, after time.Time) []wallet.LogEntry {
	if after.IsZero() {
		return entries
	}
	for i, entry := range entries {
		if entry.Time.After(after) {
			return entries[i:]
		}
	}
	return nil
}
