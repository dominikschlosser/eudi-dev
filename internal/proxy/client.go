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

// Reading a running proxy from outside it, through the two dashboard
// endpoints the dashboard page itself uses: the recorded traffic and the
// stream of what arrives.

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// entriesTimeout bounds a one-shot read of the recorded traffic. The stream
// deliberately has no deadline, but a dashboard that accepts a connection and
// then says nothing must not hang the command.
var entriesTimeout = 30 * time.Second

// DashboardClient reads traffic from a running proxy's dashboard.
type DashboardClient struct {
	// BaseURL is the dashboard origin, without a trailing slash.
	BaseURL string
	// HTTPClient sends the requests. A nil client uses a default one with
	// no timeout, because following a stream has no deadline.
	HTTPClient *http.Client
}

// NewDashboardClient returns a client for the dashboard at rawURL. A bare
// host or host:port is read as http, so `eudi proxy logs localhost:9091`
// works.
func NewDashboardClient(rawURL string) (*DashboardClient, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, fmt.Errorf("no dashboard URL")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid dashboard URL %q: %w", rawURL, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("dashboard URL %q names no host", rawURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("dashboard URL %q must be http or https", rawURL)
	}
	base := parsed.Scheme + "://" + parsed.Host + strings.TrimRight(parsed.Path, "/")
	return &DashboardClient{BaseURL: base}, nil
}

func (c *DashboardClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *DashboardClient) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching the proxy dashboard at %s: %w", c.BaseURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("proxy dashboard at %s answered %s for %s", c.BaseURL, resp.Status, path)
	}
	return resp, nil
}

// Entries returns the traffic the proxy has recorded so far, oldest first.
func (c *DashboardClient) Entries(ctx context.Context) ([]*TrafficEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, entriesTimeout)
	defer cancel()

	resp, err := c.get(ctx, "/api/entries")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []*TrafficEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("reading the recorded traffic: %w", err)
	}
	return entries, nil
}

// EntryStream delivers the entries a proxy records from now on.
type EntryStream struct {
	body   io.ReadCloser
	reader *bufio.Reader
}

// Stream subscribes to the dashboard's event stream. The subscription is in
// place when this returns, so entries recorded from here on are delivered
// even while the caller is still reading the list of earlier ones.
func (c *DashboardClient) Stream(ctx context.Context) (*EntryStream, error) {
	resp, err := c.get(ctx, "/api/stream")
	if err != nil {
		return nil, err
	}
	return &EntryStream{body: resp.Body, reader: bufio.NewReader(resp.Body)}, nil
}

// Next returns the next entry, blocking until one arrives. It returns
// io.EOF when the proxy closed the stream.
func (s *EntryStream) Next() (*TrafficEntry, error) {
	var data []string
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			// The blank line ends an event. An event carrying no data is a
			// keepalive comment and nothing to report.
			if len(data) == 0 {
				continue
			}
			// Data fields of one event are joined with newlines, as the
			// event stream format defines them.
			payload := strings.Join(data, "\n")
			data = nil
			var entry *TrafficEntry
			if err := json.Unmarshal([]byte(payload), &entry); err != nil || entry == nil {
				// A malformed event, or a null one, is not worth ending the
				// stream over: the next is likely fine.
				continue
			}
			return entry, nil
		case strings.HasPrefix(line, ":"):
			// Comment, which is what the keepalive is.
			continue
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
}

// Close ends the subscription.
func (s *EntryStream) Close() error {
	return s.body.Close()
}
