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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tinyPNGDataURI = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC"

// A display image is stored as a content-addressed file beside wallet.json, with
// only a reference left in the file, so the store the wallet reparses on every
// request stays small. The image is still served, and an older wallet that
// embedded the image as a data URI keeps working.
func TestDisplayImagesStoredAsAssetsBesideWallet(t *testing.T) {
	srv := newTestServer(t, true)
	store := NewWalletStore(t.TempDir())
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("initializing store: %v", err)
	}
	srv.SetStore(store)

	body := `{"format":"sdjwt","vct":"urn:example:asset","display":{"name":"Badge","logo":"` + tinyPNGDataURI + `"}}`
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", body)
	if resp.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", resp.Code, resp.Body.String())
	}
	id, _ := decodeJSON(t, resp)["id"].(string)

	// A freshly issued credential still holds the image in memory as a data URI,
	// and the endpoint serves it before any save (an old wallet works the same).
	if before := serverRequest(t, srv, http.MethodGet, "/api/credentials/"+id+"/display/logo", ""); before.Code != http.StatusOK || before.Body.Len() == 0 {
		t.Fatalf("embedded image not served before save: %d len=%d", before.Code, before.Body.Len())
	}

	// Persisting moves the image into the assets directory.
	if err := store.Save(srv.wallet); err != nil {
		t.Fatalf("save: %v", err)
	}
	walletJSON, err := os.ReadFile(filepath.Join(store.Dir, "wallet.json"))
	if err != nil {
		t.Fatalf("reading wallet.json: %v", err)
	}
	if strings.Contains(string(walletJSON), "data:image/") {
		t.Error("wallet.json still embeds the display image after save")
	}
	if !strings.Contains(string(walletJSON), "asset:") {
		t.Error("wallet.json does not reference the image as an asset")
	}
	if entries, _ := os.ReadDir(store.assetsDir()); len(entries) == 0 {
		t.Error("no asset file was written beside wallet.json")
	}

	// A reload yields the reference in memory, and the endpoint serves the asset.
	reloaded, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	var stored *StoredCredential
	for i := range reloaded.Credentials {
		if reloaded.Credentials[i].ID == id {
			stored = &reloaded.Credentials[i]
		}
	}
	if stored == nil || stored.Display == nil || !strings.HasPrefix(stored.Display.LogoURI, "asset:") {
		t.Fatalf("reloaded display is not an asset reference: %+v", stored)
	}

	srv2 := NewServer(reloaded, 0, func() {})
	srv2.SetStore(store)
	img := serverRequest(t, srv2, http.MethodGet, "/api/credentials/"+id+"/display/logo", "")
	if img.Code != http.StatusOK || img.Body.Len() == 0 {
		t.Fatalf("asset not served after reload: %d len=%d", img.Code, img.Body.Len())
	}
	if ct := img.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
}

// storeDisplayAsset is content-addressed: the same image writes one file and
// yields the same reference however many credentials carry it.
func TestStoreDisplayAssetDedupes(t *testing.T) {
	store := NewWalletStore(t.TempDir())
	refA, okA := store.storeDisplayAsset(tinyPNGDataURI)
	refB, okB := store.storeDisplayAsset(tinyPNGDataURI)
	if !okA || !okB || refA != refB {
		t.Fatalf("expected one shared reference, got %q and %q", refA, refB)
	}
	entries, _ := os.ReadDir(store.assetsDir())
	if len(entries) != 1 {
		t.Fatalf("expected a single asset file, got %d", len(entries))
	}
	// A non data URI is passed through unchanged and writes nothing.
	if ref, converted := store.storeDisplayAsset("https://issuer.example/logo.svg"); converted || ref != "https://issuer.example/logo.svg" {
		t.Fatalf("an external URL should pass through unchanged, got %q converted=%v", ref, converted)
	}
}
