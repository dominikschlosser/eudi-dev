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
	"bytes"
	"compress/zlib"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/statuslist"
)

// readPublishedStatus decodes a status list JWT and returns the declared bits
// together with the value packed at idx.
func readPublishedStatus(t *testing.T, token string, idx int) (int, int) {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %d segments", len(parts))
	}
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}
	sl, ok := payload["status_list"].(map[string]any)
	if !ok {
		t.Fatal("no status_list in the published token")
	}
	bitsFloat, ok := sl["bits"].(float64)
	if !ok {
		t.Fatalf("bits is not a number: %v", sl["bits"])
	}
	bits := int(bitsFloat)

	compressed, err := format.DecodeBase64URL(sl["lst"].(string))
	if err != nil {
		t.Fatalf("decoding lst: %v", err)
	}
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("zlib reader: %v", err)
	}
	defer r.Close()
	bitstring, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decompressing: %v", err)
	}

	bitPos := idx * bits
	if bitPos/8 >= len(bitstring) {
		t.Fatalf("index %d is past the published list of %d bytes", idx, len(bitstring))
	}
	mask := (1 << bits) - 1
	return bits, (int(bitstring[bitPos/8]) >> (bitPos % 8)) & mask
}

// A one-bit list can only say VALID or INVALID, so a credential the wallet
// marks SUSPENDED needs a wider list for an external verifier to read the
// status this wallet's own API reports. Section 7 requires the Status Issuer
// to pick a width that can carry the statuses it uses.
func TestBuildStatusList_WidensForTheStatusValuesInUse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		wantBits int
	}{
		{"valid only", 0, 1},
		{"revoked", 1, 1},
		{"suspended", 2, 2},
		{"application specific", 0x0D, 4},
		{"the widest registered value", 200, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.StatusListCounter = 4
			w.RegisterStatusEntry("cred", 2)
			if _, ok := w.SetCredentialStatus("cred", tc.status); !ok {
				t.Fatalf("SetCredentialStatus(%d) was refused", tc.status)
			}

			bits, bitstring := w.BuildStatusList()
			if bits != tc.wantBits {
				t.Fatalf("bits = %d, want %d for status %d", bits, tc.wantBits, tc.status)
			}
			bitPos := 2 * bits
			mask := (1 << bits) - 1
			got := (int(bitstring[bitPos/8]) >> (bitPos % 8)) & mask
			if got != tc.status {
				t.Errorf("the published entry reads %d, want the stored %d", got, tc.status)
			}
		})
	}
}

// The status the wallet's own API reports and the status an external verifier
// reads out of the published list have to be the same number.
func TestHandleStatusList_PublishesTheStoredStatusValue(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://localhost:8086"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	cred := w.GetCredentials()[0]
	entry, ok := w.SetCredentialStatus(cred.ID, 2) // SUSPENDED
	if !ok {
		t.Fatal("SetCredentialStatus(2) was refused")
	}

	resp := serverRequest(t, srv, "GET", "/api/statuslist", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	bits, published := readPublishedStatus(t, resp.Body.String(), entry.Index)
	if bits != 2 {
		t.Errorf("published bits = %d, want 2 so SUSPENDED fits", bits)
	}
	if published != 2 {
		t.Errorf("the published status is %d, the wallet stores %d", published, entry.Status)
	}
	if statuslist.StatusName(published) != "SUSPENDED" {
		t.Errorf("published status names %q, want SUSPENDED", statuslist.StatusName(published))
	}
}

// Section 7: "Status Types MUST have a numeric value between 0 and 255 for
// their representation in the Status List."
func TestSetCredentialStatus_RefusesValuesOutsideTheStatusTypeRange(t *testing.T) {
	w := generateTestWallet(t)
	w.StatusListCounter = 1
	w.RegisterStatusEntry("cred", 0)

	for _, status := range []int{-1, 256, 1 << 20} {
		if _, ok := w.SetCredentialStatus("cred", status); ok {
			t.Errorf("status %d was stored", status)
		}
	}
	for _, status := range []int{0, 1, 2, 255} {
		if _, ok := w.SetCredentialStatus("cred", status); !ok {
			t.Errorf("status %d was refused", status)
		}
	}
}

// Section 8.4: "If the Server does not support the additional query parameter,
// it SHOULD return a status code of 501 (Not Implemented)". Serving the
// current list for a historical request hands the client a token for a moment
// it did not ask about.
func TestHandleStatusList_TimeQueryParameterIsNotImplemented(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	srv := NewServer(w, 0, nil)

	resp := serverRequest(t, srv, "GET", "/api/statuslist?time=1686925000", "")
	if resp.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.Code)
	}
}

// Section 8.1: "The HTTP endpoint SHOULD support the use of Cross-Origin
// Resource Sharing (CORS) [CORS] ... to enable Browser-based clients to
// access it".
func TestHandleStatusList_AllowsCrossOriginReads(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	srv := NewServer(w, 0, nil)

	resp := serverRequest(t, srv, "GET", "/api/statuslist", "")
	if got := resp.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}
}

// Section 8.1 content negotiation: a client that asks for the CWT form gets a
// tagged COSE_Sign1 under the CWT media type, and everything else keeps
// getting the JWT form.
func TestHandleStatusList_ServesCWTWhenAsked(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://localhost:8086"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	req := httptest.NewRequest("GET", "/api/statuslist", nil)
	req.Header.Set("Accept", statuslist.MediaTypeCWT)
	resp := httptest.NewRecorder()
	srv.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.Code)
	}
	if got := resp.Header().Get("Content-Type"); got != statuslist.MediaTypeCWT {
		t.Fatalf("Content-Type = %q, want %q", got, statuslist.MediaTypeCWT)
	}
	body := resp.Body.Bytes()
	if len(body) == 0 || body[0] != 0xd2 {
		t.Fatalf("the body must be a tagged COSE_Sign1 (tag 18), got % x", body[:min(len(body), 4)])
	}

	// The default is still the JWT form.
	jwtResp := serverRequest(t, srv, "GET", "/api/statuslist", "")
	if got := jwtResp.Header().Get("Content-Type"); got != statuslist.MediaTypeJWT {
		t.Errorf("Content-Type = %q, want %q", got, statuslist.MediaTypeJWT)
	}
}
