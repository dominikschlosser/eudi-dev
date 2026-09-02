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
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/proxy"
)

// proxyLogsReconnectDelay is how long the follow waits before reattaching to
// a stream that ended. A variable so tests do not have to wait for it.
var proxyLogsReconnectDelay = 2 * time.Second

func proxyLogsCmd() *cobra.Command {
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs [dashboard-url]",
		Short: "Print the traffic a running proxy recorded",
		Long: fmt.Sprintf(`Prints the traffic of a proxy that is already running, read from its
dashboard, in the same form the proxy prints it itself. Use it for a proxy in
a container, in the background, or on another machine.

The argument is the dashboard URL, not the proxy port. Without one it reads a
proxy on this machine (http://localhost:%d).

A proxy started without --all-traffic never recorded non-OID4VP/VCI requests,
so they cannot be read back here either.

Examples:
  eudi proxy logs
  eudi proxy logs http://localhost:9091 --follow
  eudi proxy logs https://proxy.internal.example --follow`, config.DefaultProxyDashboardPort),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOutput && follow {
				return fmt.Errorf("--json cannot be combined with --follow")
			}

			target := fmt.Sprintf("http://localhost:%d", config.DefaultProxyDashboardPort)
			if len(args) == 1 {
				target = args[0]
			}
			client, err := proxy.NewDashboardClient(target)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			// Subscribed before the recorded traffic is read, so an entry
			// arriving between the two is printed once rather than missed.
			var stream *proxy.EntryStream
			if follow {
				if stream, err = client.Stream(ctx); err != nil {
					return err
				}
				defer func() { _ = stream.Close() }()
			}

			entries, err := client.Entries(ctx)
			if err != nil {
				return err
			}
			if jsonOutput {
				return printProxyEntriesJSON(cmd.OutOrStdout(), entries)
			}

			var lastID int64
			for _, entry := range entries {
				proxy.PrintEntryWithDecodeBase(entry, client.BaseURL)
				lastID = entry.ID
			}
			if !follow {
				if len(entries) == 0 {
					fmt.Fprintf(cmd.ErrOrStderr(), "The proxy at %s has recorded no traffic yet.\n", client.BaseURL)
				}
				return nil
			}
			return followProxyEntries(ctx, client, stream, cmd.ErrOrStderr(), lastID)
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Keep running and print traffic as the proxy records it")
	return cmd
}

func printProxyEntriesJSON(out io.Writer, entries []*proxy.TrafficEntry) error {
	if entries == nil {
		entries = []*proxy.TrafficEntry{}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(entries)
}

// followProxyEntries prints entries as the proxy records them, reattaching
// whenever the stream ends, until the follow is interrupted.
func followProxyEntries(ctx context.Context, client *proxy.DashboardClient, stream *proxy.EntryStream, out io.Writer, lastID int64) error {
	for {
		for {
			entry, err := stream.Next()
			if err != nil {
				break
			}
			// The recorded traffic printed above may already contain what
			// the stream delivers first, since the subscription predates it.
			if entry.ID <= lastID {
				continue
			}
			proxy.PrintEntryWithDecodeBase(entry, client.BaseURL)
			lastID = entry.ID
		}
		_ = stream.Close()

		fmt.Fprintf(out, "Lost the stream from %s, reattaching...\n", client.BaseURL)
		next, err := reattachToProxy(ctx, client, out)
		if err != nil {
			return nil
		}
		stream = next

		// The gap is filled from the entry list rather than the stream,
		// which only carries what arrives from now on.
		lastID = printMissedEntries(ctx, client, out, lastID)
	}
}

// reattachToProxy keeps opening the stream until it succeeds or the follow is
// interrupted, so a proxy that is down for a while is waited out.
func reattachToProxy(ctx context.Context, client *proxy.DashboardClient, out io.Writer) (*proxy.EntryStream, error) {
	reported := false
	for {
		if err := sleepContext(ctx, proxyLogsReconnectDelay); err != nil {
			return nil, err
		}
		stream, err := client.Stream(ctx)
		if err == nil {
			fmt.Fprintf(out, "Reattached to %s\n", client.BaseURL)
			return stream, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !reported {
			// Reported once, so a proxy that stays down does not fill the
			// terminal with the same line.
			fmt.Fprintf(out, "Still waiting for %s: %v\n", client.BaseURL, err)
			reported = true
		}
	}
}

// printMissedEntries prints what the proxy recorded while the stream was
// down, and returns the id to continue from.
func printMissedEntries(ctx context.Context, client *proxy.DashboardClient, out io.Writer, lastID int64) int64 {
	entries, err := client.Entries(ctx)
	if err != nil {
		fmt.Fprintf(out, "Could not read what %s recorded while the stream was down: %v\n", client.BaseURL, err)
		return lastID
	}
	// What the proxy holds now decides what counts as already seen. A proxy
	// that restarted numbers its entries from the beginning again, so an
	// empty or lower-numbered record is new traffic rather than old.
	if len(entries) == 0 {
		return 0
	}
	highest := entries[len(entries)-1].ID
	if highest < lastID {
		fmt.Fprintf(out, "%s restarted, its traffic is numbered from the beginning again\n", client.BaseURL)
		lastID = 0
	}
	for _, entry := range entries {
		if entry.ID <= lastID {
			continue
		}
		proxy.PrintEntryWithDecodeBase(entry, client.BaseURL)
		lastID = entry.ID
	}
	return lastID
}

// sleepContext waits for d, or returns the context's error when it ends
// first.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return errors.New("interrupted")
	}
}
