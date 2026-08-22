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
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/internal/format"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
)

// tinyPNG is a 1x1 transparent PNG, small enough to embed and valid enough
// for a content-type check.
var tinyPNG, _ = base64.StdEncoding.DecodeString(
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")

// cardArtPNG builds an opaque image the shape of real card art: smooth color
// bands with a light dither, which PNG stores far over the cache cap while a
// card-size JPEG comes out small.
func cardArtPNG(t *testing.T) []byte {
	t.Helper()
	const width, height = 1700, 1080
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	state := uint32(1)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			offset := img.PixOffset(x, y)
			for c := 0; c < 3; c++ {
				state = state*1664525 + 1013904223
				dither := int(state>>16)%9 - 4
				band := 128 + 90*math.Sin((float64(x)+0.7*float64(y))/24+float64(c))
				img.Pix[offset+c] = uint8(min(255, max(0, int(band)+dither)))
			}
			img.Pix[offset+3] = 255
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encoding test art: %v", err)
	}
	if buf.Len() <= maxDisplayImageBytes {
		t.Fatalf("test art must exceed the cache cap, got %d bytes", buf.Len())
	}
	return buf.Bytes()
}

// pixelBombPNG builds an all-white image whose dimensions exceed the pixel
// cap while its bytes stay well within the download cap, the shape of a
// decompression bomb: cheap to serve, ruinous to decode. The dimension guard
// rejects it on its declared size before the pixels are ever allocated.
func pixelBombPNG(t *testing.T) []byte {
	t.Helper()
	side := 8192 // 67 megapixels, past the 32-megapixel cap
	img := image.NewRGBA(image.Rect(0, 0, side, side))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encoding bomb: %v", err)
	}
	if buf.Len() > maxDisplayImageFetchBytes {
		t.Fatalf("bomb must fit the download cap to reach the dimension guard, got %d bytes", buf.Len())
	}
	return buf.Bytes()
}

// displayIssuer serves an issuer whose test-config carries the given
// credential_metadata display array (§12.2.4), plus image endpoints the
// display entries can point at.
func displayIssuer(t *testing.T, w *Wallet, display []map[string]any) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format":                "dc+sd-jwt",
						"vct":                   "urn:test:credential",
						"proof_types_supported": map[string]any{"jwt": map[string]any{"proof_signing_alg_values_supported": []any{"ES256"}}},
						"credential_metadata":   map[string]any{"display": display},
					},
				},
			})

		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			json.NewEncoder(rw).Encode(map[string]any{
				"issuer":         serverURL,
				"token_endpoint": serverURL + "/token",
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-c-nonce",
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			io.Copy(io.Discard, r.Body)
			json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})

		case strings.HasSuffix(r.URL.Path, "/logo.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(tinyPNG)

		case strings.HasSuffix(r.URL.Path, "/background.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(tinyPNG)

		case strings.HasSuffix(r.URL.Path, "/huge.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(bytes.Repeat([]byte{0x42}, maxDisplayImageBytes+1))

		case strings.HasSuffix(r.URL.Path, "/art.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(cardArtPNG(t))

		case strings.HasSuffix(r.URL.Path, "/bomb.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(pixelBombPNG(t))

		case strings.HasSuffix(r.URL.Path, "/page.html"):
			rw.Header().Set("Content-Type", "text/html")
			rw.Write([]byte("<html>not an image</html>"))

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	serverURL = srv.URL
	// The display entries are written before the server URL exists, so image
	// URIs use the SERVER placeholder and get the real host here.
	for _, entry := range display {
		for _, key := range []string{"logo", "background_image"} {
			if obj, ok := entry[key].(map[string]any); ok {
				if uri, ok := obj["uri"].(string); ok {
					obj["uri"] = strings.Replace(uri, "SERVER", serverURL, 1)
				}
			}
		}
	}

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			preAuthorizedCodeGrant: map[string]any{"pre-authorized_code": "test-pre-auth-code"},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
}

// issueWithDisplay runs the offer and returns the credential as the store
// keeps it, which is where the display lands.
func issueWithDisplay(t *testing.T, w *Wallet, display []map[string]any) *StoredCredential {
	t.Helper()
	srv, offerURI := displayIssuer(t, w, display)
	t.Cleanup(srv.Close)

	oldClient := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = oldClient })

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	for _, c := range w.GetCredentials() {
		if c.ID == result.CredentialID {
			return &c
		}
	}
	t.Fatalf("credential %s not in the store", result.CredentialID)
	return nil
}

// TestProcessCredentialOffer_CredentialDisplay covers the §12.2.4 display
// properties of the offered configuration: the wallet persists them with the
// credential and caches the referenced images, so the card can carry the
// issuer's appearance without asking the issuer again.
func TestProcessCredentialOffer_CredentialDisplay(t *testing.T) {
	t.Run("name, colors and images are stored with the credential", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"description":      "A styled test credential",
			"locale":           "en-US",
			"background_color": "#1a2b3c",
			"text_color":       "#ffffff",
			"logo":             map[string]any{"uri": "SERVER/logo.png", "alt_text": "Test issuer logo"},
			"background_image": map[string]any{"uri": "SERVER/background.png"},
		}})

		d := imported.Display
		if d == nil {
			t.Fatal("expected the credential to carry the display metadata")
		}
		if d.Name != "Test Badge" || d.Description != "A styled test credential" {
			t.Errorf("name/description = %q/%q", d.Name, d.Description)
		}
		if d.BackgroundColor != "#1a2b3c" || d.TextColor != "#ffffff" {
			t.Errorf("colors = %q/%q", d.BackgroundColor, d.TextColor)
		}
		if !strings.HasPrefix(d.LogoURI, "data:image/png;base64,") {
			t.Errorf("logo not cached as a data URI: %.60q", d.LogoURI)
		}
		if d.LogoAltText != "Test issuer logo" {
			t.Errorf("logo alt text = %q", d.LogoAltText)
		}
		if !strings.HasPrefix(d.BackgroundURI, "data:image/png;base64,") {
			t.Errorf("background image not cached as a data URI: %.60q", d.BackgroundURI)
		}
	})

	t.Run("an invalid color is dropped and warned about, the rest survives", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"background_color": "red;background:url(https://evil.example)",
			"text_color":       "#ffffff",
		}})

		d := imported.Display
		if d == nil || d.Name != "Test Badge" {
			t.Fatal("expected the display name to survive an invalid color")
		}
		if d.BackgroundColor != "" {
			t.Errorf("invalid background_color kept: %q", d.BackgroundColor)
		}
		if d.TextColor != "#ffffff" {
			t.Errorf("valid text_color dropped: %q", d.TextColor)
		}
		warning := findLogEntry(w.GetLog(), "credential_display_invalid")
		if warning == nil {
			t.Fatal("expected a credential_display_invalid entry")
		}
		if warning.Severity != severityWarning {
			t.Errorf("severity = %q, want %q", warning.Severity, severityWarning)
		}
		if !strings.Contains(warning.Detail, "background_color") {
			t.Errorf("detail does not name the field: %s", warning.Detail)
		}
	})

	t.Run("an image beyond the cap is rejected with a warning", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name": "Test Badge",
			"logo": map[string]any{"uri": "SERVER/huge.png"},
		}})

		if imported.Display == nil {
			t.Fatal("expected the display name to survive a rejected image")
		}
		if imported.Display.LogoURI != "" {
			t.Errorf("oversized logo should not be cached: %.60q", imported.Display.LogoURI)
		}
		if findLogEntry(w.GetLog(), "credential_display_image_rejected") == nil {
			t.Error("expected a credential_display_image_rejected entry")
		}
	})

	t.Run("a non-image answer is rejected with a warning", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name": "Test Badge",
			"logo": map[string]any{"uri": "SERVER/page.html"},
		}})

		if imported.Display == nil {
			t.Fatal("expected the display name to survive a rejected image")
		}
		if imported.Display.LogoURI != "" {
			t.Errorf("non-image logo should not be cached: %.60q", imported.Display.LogoURI)
		}
		if findLogEntry(w.GetLog(), "credential_display_image_rejected") == nil {
			t.Error("expected a credential_display_image_rejected entry")
		}
	})

	t.Run("card art beyond the cap is downscaled and cached", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"background_image": map[string]any{"uri": "SERVER/art.png"},
		}})

		d := imported.Display
		if d == nil || !strings.HasPrefix(d.BackgroundURI, "data:image/jpeg;base64,") {
			t.Fatalf("expected downscaled JPEG card art, got %.40q", d.BackgroundURI)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(d.BackgroundURI, "data:image/jpeg;base64,"))
		if err != nil {
			t.Fatalf("decoding cached art: %v", err)
		}
		if len(raw) > maxDisplayImageBytes {
			t.Errorf("cached art is %d bytes, over the %d cap", len(raw), maxDisplayImageBytes)
		}
		if entry := findLogEntry(w.GetLog(), "credential_display_image_rejected"); entry != nil {
			t.Errorf("downscalable art was rejected: %s", entry.Detail)
		}
	})

	t.Run("a pixel-bomb image is rejected before it is decoded whole", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"background_image": map[string]any{"uri": "SERVER/bomb.png"},
		}})

		if imported.Display == nil {
			t.Fatal("expected the display name to survive a rejected image")
		}
		if imported.Display.BackgroundURI != "" {
			t.Errorf("pixel bomb should not be cached: %.40q", imported.Display.BackgroundURI)
		}
		warning := findLogEntry(w.GetLog(), "credential_display_image_rejected")
		if warning == nil {
			t.Fatal("expected a credential_display_image_rejected entry")
		}
		if !strings.Contains(warning.Detail, "megapixel") {
			t.Errorf("detail does not name the dimension cap: %s", warning.Detail)
		}
	})

	t.Run("a data URI image is kept as it is", func(t *testing.T) {
		w := generateTestWallet(t)
		dataURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(tinyPNG)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name": "Test Badge",
			"logo": map[string]any{"uri": dataURI},
		}})

		if imported.Display == nil || imported.Display.LogoURI != dataURI {
			t.Errorf("data URI logo should be stored unchanged")
		}
	})

	t.Run("a low-contrast color pair is warned about and kept", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"background_color": "#888888",
			"text_color":       "#777777",
		}})

		// The pair is kept and the warning is logged: the card face paints the
		// declared colors, so a low-contrast pair renders as declared.
		d := imported.Display
		if d == nil || d.BackgroundColor != "#888888" || d.TextColor != "#777777" {
			t.Fatalf("expected the pair to be kept, got %+v", d)
		}
		warning := findLogEntry(w.GetLog(), "credential_display_low_contrast")
		if warning == nil {
			t.Fatal("expected a credential_display_low_contrast entry")
		}
		if !strings.Contains(warning.Detail, "3:1") {
			t.Errorf("detail does not name the threshold: %s", warning.Detail)
		}
	})

	t.Run("the summary carries the display for the UI", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"background_color": "#1a2b3c",
			"text_color":       "#ffffff",
		}})
		summary := CredentialSummary(*imported)
		d, ok := summary["display"].(*CredentialDisplay)
		if !ok || d.Name != "Test Badge" {
			t.Errorf("summary display = %#v", summary["display"])
		}
	})

	t.Run("a configuration without display stores none", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, nil)
		if imported.Display != nil {
			t.Errorf("expected no display, got %+v", imported.Display)
		}
	})
}

// TestGenerateDefaultCredentials_Display gives the wallet's own generated
// PID credentials the eudi-dev appearance, so the demo baseline looks like
// what an issuer-styled credential looks like.
func TestGenerateDefaultCredentials_Display(t *testing.T) {
	w := generateTestWallet(t)
	// Both baseline PID types, so the German one can be told from the
	// country-independent one.
	for _, vct := range []string{mock.DefaultPIDVCT, mock.GermanPIDVCT} {
		if err := w.GenerateDefaultCredentials(nil, vct); err != nil {
			t.Fatalf("GenerateDefaultCredentials(%s): %v", vct, err)
		}
	}
	creds := w.GetCredentials()
	if len(creds) == 0 {
		t.Fatal("expected generated credentials")
	}
	for _, c := range creds {
		if c.Display == nil {
			t.Errorf("credential %s (%s) has no display", c.ID, c.Format)
			continue
		}
		if c.Display.Name == "" {
			t.Errorf("credential %s has no display name", c.ID)
		}
		if !strings.HasPrefix(c.Display.LogoURI, "data:image/svg+xml") {
			t.Errorf("credential %s does not carry the eudi-dev logo: %.40q", c.ID, c.Display.LogoURI)
		}
	}

	// The German PID is told apart from the country-independent one: its own
	// name and a background image the country-independent PID does not carry.
	var german, independent *StoredCredential
	for i := range creds {
		switch creds[i].VCT {
		case mock.GermanPIDVCT:
			german = &creds[i]
		case mock.DefaultPIDVCT:
			independent = &creds[i]
		}
	}
	if german == nil || independent == nil {
		t.Fatalf("expected both PID types, got german=%v independent=%v", german != nil, independent != nil)
	}
	if german.Display.Name == independent.Display.Name {
		t.Errorf("the two PID types share the display name %q", german.Display.Name)
	}
	if !strings.HasPrefix(german.Display.BackgroundURI, "data:image/") {
		t.Errorf("the German PID carries no distinguishing background image: %.40q", german.Display.BackgroundURI)
	}
	if independent.Display.BackgroundURI != "" {
		t.Errorf("the country-independent PID should not carry a background image: %.40q", independent.Display.BackgroundURI)
	}
}

// TestCacheDisplayImage_BlocksInternalAddress covers the shared-demo case: the
// image URI comes from the offer's issuer metadata, which a visitor controls,
// so a display fetch must be held to the same policy as every other issuance
// fetch and refused when it names an internal address (ADR-0004).
func TestCacheDisplayImage_BlocksInternalAddress(t *testing.T) {
	w := generateTestWallet(t)

	// The real policed path runs only for the default client, so the test
	// override is dropped for the duration.
	oldClient := httpClient
	httpClient = defaultHTTPClient
	defer func() { httpClient = oldClient }()

	format.SetFetchPolicy(format.BlockPrivateAddresses)
	defer format.SetFetchPolicy(nil)

	// A loopback address stands in for any internal target (cloud metadata,
	// a service on the demo host). The port is closed, so a fetch that was
	// not blocked would fail with a connection error rather than silently
	// pass, but the policy refuses it at dial time first.
	got := w.cacheDisplayImage("http://127.0.0.1:9/internal.png", "logo")
	if got != "" {
		t.Errorf("a display image at an internal address was fetched: %.40q", got)
	}
	entry := findLogEntry(w.GetLog(), "credential_display_image_rejected")
	if entry == nil {
		t.Fatal("expected a credential_display_image_rejected entry")
	}
	if !strings.Contains(entry.Detail, "internal address") {
		t.Errorf("rejection does not name the policy block: %s", entry.Detail)
	}
}
