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
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestStoreAddAndEntries(t *testing.T) {
	s := NewStore(10)

	s.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/1"})
	s.Add(&TrafficEntry{Method: "POST", URL: "http://example.com/2"})

	entries := s.Entries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ID != 1 || entries[1].ID != 2 {
		t.Errorf("unexpected IDs: %d, %d", entries[0].ID, entries[1].ID)
	}
}

func TestStoreEviction(t *testing.T) {
	s := NewStore(3)

	for i := 0; i < 5; i++ {
		s.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/"})
	}

	entries := s.Entries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries after eviction, got %d", len(entries))
	}
	// Oldest should be ID 3 (IDs 1,2 evicted)
	if entries[0].ID != 3 {
		t.Errorf("expected oldest entry ID 3, got %d", entries[0].ID)
	}
}

func TestStoreFlowsMapBounded(t *testing.T) {
	s := NewStore(10)
	for i := 0; i < 500; i++ {
		e := &TrafficEntry{
			Method:     "GET",
			URL:        fmt.Sprintf("http://example.com/authorize?client_id=test&response_type=vp_token&state=state-%d", i),
			Class:      ClassVPAuthRequest,
			ClassLabel: "VP Auth Request",
		}
		Classify(e)
		s.Add(e)
	}
	// Each entry contributes one correlation key, and the buffer holds 10, so
	// the flows map must not accumulate all 500 keys.
	if got := len(s.flows); got > s.maxSize*3 {
		t.Fatalf("flows map grew to %d for a %d-entry buffer, eviction is not pruning it", got, s.maxSize)
	}
}

func TestStoreFlowCorrelation(t *testing.T) {
	s := NewStore(100)

	// Add VP Auth Request with state
	e1 := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=test&response_type=vp_token&state=state123",
		Class:      ClassVPAuthRequest,
		ClassLabel: "VP Auth Request",
	}
	Classify(e1) // to set Decoded for correlation
	s.Add(e1)

	if e1.FlowID == "" {
		t.Fatal("expected FlowID to be set on first entry")
	}

	// Add VP Auth Response with same state
	e2 := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "state=state123&vp_token=eyJ...",
		Class:       ClassVPAuthResponse,
		ClassLabel:  "VP Auth Response",
	}
	Classify(e2)
	s.Add(e2)

	if e2.FlowID != e1.FlowID {
		t.Errorf("expected same flow ID, got %q and %q", e1.FlowID, e2.FlowID)
	}

	// Verify FlowEntries
	flowEntries := s.FlowEntries(e1.FlowID)
	if len(flowEntries) != 2 {
		t.Fatalf("expected 2 flow entries, got %d", len(flowEntries))
	}
}

func TestStoreFlowEntriesEmpty(t *testing.T) {
	s := NewStore(100)
	entries := s.FlowEntries("nonexistent")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nonexistent flow, got %d", len(entries))
	}
}

func TestStoreFlowCorrelationVCITokenToCredentialByAccessToken(t *testing.T) {
	s := NewStore(100)

	tokenEntry := &TrafficEntry{
		Method:      "POST",
		URL:         "http://issuer.example/token",
		RequestBody: "grant_type=authorization_code&code=issued-code",
		Class:       ClassVCITokenRequest,
		ClassLabel:  "VCI Token Request",
		Decoded: map[string]any{
			"code": "issued-code",
			"response": map[string]any{
				"access_token": "token-123",
				"authorization_details": []any{
					map[string]any{
						"credential_configuration_id": "membership-credential",
						"credential_identifiers":      []any{"membership-credential_0000"},
					},
				},
			},
		},
	}
	s.Add(tokenEntry)

	credentialEntry := &TrafficEntry{
		Method:         "POST",
		URL:            "http://issuer.example/credential",
		RequestHeaders: http.Header{"Authorization": {"DPoP token-123"}},
		Class:          ClassVCICredentialRequest,
		ClassLabel:     "VCI Credential Request",
		Decoded: map[string]any{
			"request": map[string]any{
				"credential_identifier": "membership-credential_0000",
			},
		},
	}
	s.Add(credentialEntry)

	if tokenEntry.FlowID == "" || credentialEntry.FlowID == "" {
		t.Fatal("expected both entries to have a flow ID")
	}
	if credentialEntry.FlowID != tokenEntry.FlowID {
		t.Fatalf("expected token and credential requests to share a flow, got %q and %q", tokenEntry.FlowID, credentialEntry.FlowID)
	}
}

func TestStoreFlowCorrelationVPRequestURIToAuthResponse(t *testing.T) {
	s := NewStore(100)

	authRequest := &TrafficEntry{
		Method:     "GET",
		URL:        "http://wallet.example/authorize?client_id=verifier&response_type=vp_token&request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F123",
		Class:      ClassVPAuthRequest,
		ClassLabel: "VP Auth Request",
	}
	Classify(authRequest)
	s.Add(authRequest)

	requestObject := &TrafficEntry{
		Method:       "GET",
		URL:          "https://verifier.example/request/123",
		ResponseBody: "header.payload.sig",
		Class:        ClassVPRequestObject,
		ClassLabel:   "VP Request Object",
		Decoded: map[string]any{
			"payload": map[string]any{
				"state": "req-123",
			},
		},
	}
	s.Add(requestObject)

	authResponse := &TrafficEntry{
		Method:      "POST",
		URL:         "https://verifier.example/response",
		RequestBody: "state=req-123&vp_token=eyJ...",
		Class:       ClassVPAuthResponse,
		ClassLabel:  "VP Auth Response",
	}
	Classify(authResponse)
	s.Add(authResponse)

	if authRequest.FlowID == "" || requestObject.FlowID == "" || authResponse.FlowID == "" {
		t.Fatal("expected all VP entries to have a flow ID")
	}
	if authRequest.FlowID != requestObject.FlowID || requestObject.FlowID != authResponse.FlowID {
		t.Fatalf("expected request_uri-based VP flow to stay grouped, got %q, %q, %q", authRequest.FlowID, requestObject.FlowID, authResponse.FlowID)
	}
}

func TestStoreNoFlowIDForUnknown(t *testing.T) {
	s := NewStore(100)
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
	}
	s.Add(e)

	if e.FlowID != "" {
		t.Errorf("expected empty FlowID for unknown class, got %q", e.FlowID)
	}
}

func TestStoreSubscribe(t *testing.T) {
	s := NewStore(100)
	ch, unsub := s.Subscribe()

	go func() {
		s.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/"})
	}()

	select {
	case entry := <-ch:
		if entry.Method != "GET" {
			t.Errorf("expected GET, got %s", entry.Method)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for subscriber notification")
	}

	go unsub()
}
