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

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleHAR(t *testing.T) {
	store := NewStore(100)
	store.Add(&TrafficEntry{
		Timestamp:       time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
		Method:          "GET",
		URL:             "http://example.com/test",
		RequestHeaders:  http.Header{"Accept": {"*/*"}},
		StatusCode:      200,
		ResponseHeaders: http.Header{"Content-Type": {"text/plain"}},
		ResponseBody:    "hello",
		DurationMS:      10,
	})

	d := NewDashboard(store, 0)

	req := httptest.NewRequest("GET", "/api/har", nil)
	w := httptest.NewRecorder()
	d.handleHAR(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != `attachment; filename="eudi-dev.har"` {
		t.Errorf("unexpected Content-Disposition: %s", cd)
	}

	var har map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&har); err != nil {
		t.Fatalf("failed to decode HAR JSON: %v", err)
	}

	log, ok := har["log"].(map[string]any)
	if !ok {
		t.Fatal("expected log object in HAR")
	}
	entries, ok := log["entries"].([]any)
	if !ok {
		t.Fatal("expected entries array in HAR log")
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 HAR entry, got %d", len(entries))
	}
}

func TestHandleHAREmpty(t *testing.T) {
	store := NewStore(100)
	d := NewDashboard(store, 0)

	req := httptest.NewRequest("GET", "/api/har", nil)
	w := httptest.NewRecorder()
	d.handleHAR(w, req)

	var har map[string]any
	json.NewDecoder(w.Result().Body).Decode(&har)
	log := har["log"].(map[string]any)
	entries := log["entries"].([]any)
	if len(entries) != 0 {
		t.Errorf("expected 0 HAR entries for empty store, got %d", len(entries))
	}
}

func TestHandleEntries(t *testing.T) {
	store := NewStore(100)
	store.Add(&TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/test",
		StatusCode: 200,
	})

	d := NewDashboard(store, 0)

	req := httptest.NewRequest("GET", "/api/entries", nil)
	w := httptest.NewRecorder()
	d.handleEntries(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var entries []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("failed to decode entries JSON: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestHandleEntriesEmpty(t *testing.T) {
	store := NewStore(100)
	d := NewDashboard(store, 0)

	req := httptest.NewRequest("GET", "/api/entries", nil)
	w := httptest.NewRecorder()
	d.handleEntries(w, req)

	var entries []map[string]any
	json.NewDecoder(w.Result().Body).Decode(&entries)
	// json.Decode on `null` returns nil for slices
	if len(entries) != 0 {
		t.Errorf("expected empty entries, got %d", len(entries))
	}
}

func TestHandleEntriesMultiple(t *testing.T) {
	store := NewStore(100)
	for i := 0; i < 5; i++ {
		store.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/", StatusCode: 200})
	}

	d := NewDashboard(store, 0)
	req := httptest.NewRequest("GET", "/api/entries", nil)
	w := httptest.NewRecorder()
	d.handleEntries(w, req)

	var entries []map[string]any
	json.NewDecoder(w.Result().Body).Decode(&entries)
	if len(entries) != 5 {
		t.Errorf("expected 5 entries, got %d", len(entries))
	}
}

func TestHandleStream(t *testing.T) {
	store := NewStore(100)
	d := NewDashboard(store, 0)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/stream", d.handleStream)
	srv := httptest.NewServer(mux)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %s", ct)
	}

	// Wait for the SSE handler to subscribe before adding the entry.
	// Without this, store.Add can fire before Subscribe() runs in the handler,
	// causing the notification to be dropped and the test to time out.
	deadline := time.Now().Add(2 * time.Second)
	for store.SubscriberCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if store.SubscriberCount() == 0 {
		t.Fatal("SSE handler did not subscribe in time")
	}

	// Add an entry — it should arrive over SSE
	store.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/test", StatusCode: 200})

	scanner := bufio.NewScanner(resp.Body)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			jsonData := strings.TrimPrefix(line, "data: ")
			var entry map[string]any
			if err := json.Unmarshal([]byte(jsonData), &entry); err != nil {
				t.Errorf("failed to parse SSE JSON: %v", err)
			}
			if entry["method"] != "GET" {
				t.Errorf("expected method GET, got %v", entry["method"])
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("no SSE data line found")
	}

	// Close response body first, then server — avoids hanging on unsub drain
	resp.Body.Close()
	srv.Close()
}

func TestHandleHARContainsFlowID(t *testing.T) {
	store := NewStore(100)
	e := &TrafficEntry{
		Timestamp:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=test&response_type=vp_token&state=s1",
		StatusCode: 200,
		Class:      ClassVPAuthRequest,
		ClassLabel: "VP Auth Request",
	}
	Classify(e)
	store.Add(e)

	// The entry in the store should have a FlowID
	entries := store.Entries()
	if entries[0].FlowID == "" {
		t.Error("expected FlowID to be set")
	}
}
