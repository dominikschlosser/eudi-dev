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

package wallet

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Issuer metadata is read from somebody else's server at the start of every
// flow. One slow or failed answer is not evidence that the issuer cannot be
// talked to, and giving up on it ends the flow reporting what the metadata did
// not contain rather than that it was never read.
func TestMetadataFetchRetriesATransientFailure(t *testing.T) {
	previous := metadataRetryDelay
	metadataRetryDelay = time.Millisecond
	t.Cleanup(func() { metadataRetryDelay = previous })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			// The shape of a server that is briefly unable to answer.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"ok"}`))
	}))
	defer srv.Close()

	resp, err := fetchMetadataDocument(func() (*http.Request, error) {
		return http.NewRequest("GET", srv.URL, nil)
	})
	if err != nil {
		t.Fatalf("fetchMetadataDocument: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("server was called %d times, want 2 (one failure then the retry)", got)
	}
}

// A 404 is the server saying it publishes nothing at that location, which is
// an answer rather than a moment to wait out. Retrying it would multiply every
// well-known probe that is expected to miss.
func TestMetadataFetchDoesNotRetryANotFound(t *testing.T) {
	previous := metadataRetryDelay
	metadataRetryDelay = time.Millisecond
	t.Cleanup(func() { metadataRetryDelay = previous })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	resp, err := fetchMetadataDocument(func() (*http.Request, error) {
		return http.NewRequest("GET", srv.URL, nil)
	})
	if err != nil {
		t.Fatalf("fetchMetadataDocument: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server was called %d times, want 1", got)
	}
}

// A server that never answers is reported once the attempts are used up,
// naming the read rather than what the document did not contain.
func TestMetadataFetchGivesUpAfterTheAttempts(t *testing.T) {
	previous := metadataRetryDelay
	metadataRetryDelay = time.Millisecond
	t.Cleanup(func() { metadataRetryDelay = previous })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	if _, err := fetchMetadataDocument(func() (*http.Request, error) {
		return http.NewRequest("GET", srv.URL, nil)
	}); err == nil {
		t.Fatal("expected an error once the attempts were used up")
	}
	if got := calls.Load(); got != int32(metadataFetchAttempts) {
		t.Errorf("server was called %d times, want %d", got, metadataFetchAttempts)
	}
}
