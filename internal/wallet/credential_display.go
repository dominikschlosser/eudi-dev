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
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/image/draw"
)

// CredentialDisplay is the appearance a §12.2.4 display entry declares for a
// credential, kept with the credential so the card renders it without asking
// the issuer again. The image fields hold data URIs: a remote image is
// fetched once at issuance and embedded, so rendering a card never calls the
// issuer (an issuer serving its logo per view would otherwise see every time
// the wallet opens).
type CredentialDisplay struct {
	Name            string `json:"name,omitempty"`
	Description     string `json:"description,omitempty"`
	Locale          string `json:"locale,omitempty"`
	LogoURI         string `json:"logo_uri,omitempty"`
	LogoAltText     string `json:"logo_alt_text,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
	BackgroundURI   string `json:"background_uri,omitempty"`
}

// maxDisplayImageBytes caps a cached display image. The image lives in
// wallet.json, which every save rewrites whole, so a card background stays
// small or stays out.
const maxDisplayImageBytes = 256 << 10

// maxDisplayImageFetchBytes caps what is downloaded for a display image.
// Real card art runs to a few megabytes, and anything over the cache cap is
// downscaled to card size before it is stored.
const maxDisplayImageFetchBytes = 4 << 20

// displayImageMaxSide is the longest side a cached display image keeps. A
// card never renders wider, so more pixels only bloat the store.
const displayImageMaxSide = 1024

// maxDisplayImagePixels bounds what is decoded into memory. A few-megabyte
// image can carry enormous dimensions (a decompression bomb), and decoding
// allocates four bytes per pixel, so the dimensions are checked before the
// decode. 32 megapixels is far past any card art and caps the decode at
// ~128MB, which matters on a shared demo fetching attacker-named URIs.
const maxDisplayImagePixels = 32 << 20

// cssColorValue matches what §12.2.4 allows for the two color fields:
// "numerical color values defined in CSS Color Module Level 3", which are the
// hex forms and the rgb()/rgba()/hsl()/hsla() functions, plus the named
// colors. Only a value of this shape reaches a style sheet.
var cssColorValue = regexp.MustCompile(`^(#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}|[a-zA-Z]{3,30}|(?:rgb|rgba|hsl|hsla)\([0-9,.%\s]{1,40}\))$`)

// resolveCredentialDisplay reads the display §12.2.4 declares for the issued
// configuration, with the images cached. The first entry is the one used,
// the same rule the consent dialog follows. Everything here is cosmetic, so
// a finding is a warning in every mode and never fails the issuance.
func (w *Wallet) resolveCredentialDisplay(metadata map[string]any, configID string) *CredentialDisplay {
	configs, _ := metadata["credential_configurations_supported"].(map[string]any)
	config, _ := configs[configID].(map[string]any)
	credentialMetadata, _ := config["credential_metadata"].(map[string]any)
	entry, ok := firstDisplayEntry(credentialMetadata["display"])
	if !ok {
		return nil
	}
	d := &CredentialDisplay{}
	d.Name, _ = entry["name"].(string)
	d.Description, _ = entry["description"].(string)
	d.Locale, _ = entry["locale"].(string)
	d.BackgroundColor = w.displayColor(entry, "background_color")
	d.TextColor = w.displayColor(entry, "text_color")
	if logo, ok := entry["logo"].(map[string]any); ok {
		uri, _ := logo["uri"].(string)
		d.LogoURI = w.cacheDisplayImage(uri, "logo")
		if d.LogoURI != "" {
			d.LogoAltText, _ = logo["alt_text"].(string)
		}
	}
	if background, ok := entry["background_image"].(map[string]any); ok {
		uri, _ := background["uri"].(string)
		d.BackgroundURI = w.cacheDisplayImage(uri, "background_image")
	}
	w.checkDisplayContrast(d)
	if *d == (CredentialDisplay{}) {
		return nil
	}
	return d
}

// checkDisplayContrast rates the declared color pair. The card face paints the
// declared background and text colors, so a low-contrast pair renders a name
// that is hard to read, and the finding warns about it. A color the parser
// cannot rate (a named color, an hsl() function) is left to the issuer's
// judgement.
func (w *Wallet) checkDisplayContrast(d *CredentialDisplay) {
	if d.BackgroundColor == "" || d.TextColor == "" {
		return
	}
	background, okBackground := parseCSSColor(d.BackgroundColor)
	text, okText := parseCSSColor(d.TextColor)
	if !okBackground || !okText {
		return
	}
	ratio := contrastRatio(background, text)
	if ratio >= 3 {
		return
	}
	w.addProtocolWarning("issuance", "credential_display_low_contrast",
		fmt.Sprintf("The credential display colors %s on %s have a contrast ratio of %.1f:1, below the 3:1 a readable card needs.",
			d.TextColor, d.BackgroundColor, ratio),
		map[string]any{
			"background_color": d.BackgroundColor,
			"text_color":       d.TextColor,
			"contrast_ratio":   ratio,
		})
}

// parseCSSColor reads the hex and rgb()/rgba() forms into RGB channels.
func parseCSSColor(value string) ([3]float64, bool) {
	var rgb [3]float64
	value = strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(value, "#") && len(value) == 4:
		for i := 0; i < 3; i++ {
			n, err := strconv.ParseUint(strings.Repeat(value[i+1:i+2], 2), 16, 8)
			if err != nil {
				return rgb, false
			}
			rgb[i] = float64(n)
		}
		return rgb, true
	case strings.HasPrefix(value, "#") && len(value) == 7:
		for i := 0; i < 3; i++ {
			n, err := strconv.ParseUint(value[1+2*i:3+2*i], 16, 8)
			if err != nil {
				return rgb, false
			}
			rgb[i] = float64(n)
		}
		return rgb, true
	case strings.HasPrefix(value, "rgb(") || strings.HasPrefix(value, "rgba("):
		inner := value[strings.Index(value, "(")+1 : len(value)-1]
		parts := strings.Split(inner, ",")
		if len(parts) < 3 {
			return rgb, false
		}
		for i := 0; i < 3; i++ {
			part := strings.TrimSpace(parts[i])
			percent := strings.HasSuffix(part, "%")
			n, err := strconv.ParseFloat(strings.TrimSuffix(part, "%"), 64)
			if err != nil {
				return rgb, false
			}
			if percent {
				n = n * 255 / 100
			}
			rgb[i] = n
		}
		return rgb, true
	}
	return rgb, false
}

// contrastRatio is the WCAG 2 contrast ratio of two colors.
func contrastRatio(a, b [3]float64) float64 {
	la, lb := relativeLuminance(a), relativeLuminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func relativeLuminance(rgb [3]float64) float64 {
	var channels [3]float64
	for i, c := range rgb {
		c /= 255
		if c <= 0.04045 {
			c /= 12.92
		} else {
			c = math.Pow((c+0.055)/1.055, 2.4)
		}
		channels[i] = c
	}
	return 0.2126*channels[0] + 0.7152*channels[1] + 0.0722*channels[2]
}

// displayColor reads one color field against the §12.2.4 value space.
func (w *Wallet) displayColor(entry map[string]any, field string) string {
	value, _ := entry[field].(string)
	if value == "" {
		return ""
	}
	if cssColorValue.MatchString(value) {
		return value
	}
	w.addProtocolWarning("issuance", "credential_display_invalid",
		fmt.Sprintf("The credential display %s is %q, which is not a CSS Color Module Level 3 color (§12.2.4). It is ignored.", field, value),
		map[string]any{"field": field, "value": value})
	return ""
}

// cacheDisplayImage turns a display image URI into the data URI the card
// renders. §12.2.4 names both schemes: a data: URI is read in place, an
// https: URI is fetched once through the policed client. An image over the
// cache cap is downscaled to card size before it is stored, so real card art
// (a multi-megabyte PNG) still ends up on the card.
func (w *Wallet) cacheDisplayImage(uri, field string) string {
	if uri == "" {
		return ""
	}
	if strings.HasPrefix(uri, "data:") {
		body, mediaType, ok := decodeImageDataURI(uri)
		if !ok {
			w.rejectDisplayImage(field, uri, "a data URI must carry a base64 image")
			return ""
		}
		return w.encodeDisplayImage(body, mediaType, field, uri)
	}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		w.rejectDisplayImage(field, uri, err.Error())
		return ""
	}
	// Through the policed client, like every other issuance fetch: the URI
	// comes from the offer's issuer metadata, which on a shared demo is
	// attacker-controlled, so it must not reach an internal address
	// (ADR-0004).
	resp, err := doIssuanceRequest(req)
	if err != nil {
		w.rejectDisplayImage(field, uri, err.Error())
		return ""
	}
	defer resp.Body.Close()
	contentType := resp.Header.Get("Content-Type")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(contentType, "image/") {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("HTTP %d with content type %q, the card needs an image", resp.StatusCode, contentType))
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDisplayImageFetchBytes+1))
	if err != nil {
		w.rejectDisplayImage(field, uri, err.Error())
		return ""
	}
	if len(body) > maxDisplayImageFetchBytes {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("larger than the %dMB download cap", maxDisplayImageFetchBytes>>20))
		return ""
	}
	mediaType, _, _ := strings.Cut(contentType, ";")
	return w.encodeDisplayImage(body, strings.TrimSpace(mediaType), field, uri)
}

// encodeDisplayImage produces the cached data URI: the bytes as served when
// they fit the cap, a card-size re-encoding when they are larger. Every image
// is dimension-checked first, since a small file can carry enormous
// dimensions (a decompression bomb) that would bloat the store and every
// viewer's browser even when the bytes fit the cap.
func (w *Wallet) encodeDisplayImage(body []byte, mediaType, field, uri string) string {
	config, _, err := image.DecodeConfig(bytes.NewReader(body))
	if err != nil {
		w.rejectDisplayImage(field, uri, "not a raster image the wallet can read")
		return ""
	}
	if config.Width <= 0 || config.Height <= 0 || config.Width*config.Height > maxDisplayImagePixels {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("%dx%d pixels, past the %d-megapixel cap", config.Width, config.Height, maxDisplayImagePixels>>20))
		return ""
	}
	if len(body) <= maxDisplayImageBytes {
		return "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(body)
	}
	shrunk, shrunkType, ok := shrinkDisplayImage(body)
	if !ok {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("larger than the %dKB cap and not a raster image the wallet can shrink", maxDisplayImageBytes>>10))
		return ""
	}
	if len(shrunk) > maxDisplayImageBytes {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("still larger than the %dKB cap at card size", maxDisplayImageBytes>>10))
		return ""
	}
	return "data:" + shrunkType + ";base64," + base64.StdEncoding.EncodeToString(shrunk)
}

// decodeImageDataURI reads the base64 form of an image data URI.
func decodeImageDataURI(uri string) ([]byte, string, bool) {
	rest, ok := strings.CutPrefix(uri, "data:")
	if !ok {
		return nil, "", false
	}
	meta, payload, ok := strings.Cut(rest, ",")
	if !ok || !strings.HasPrefix(meta, "image/") || !strings.HasSuffix(meta, ";base64") {
		return nil, "", false
	}
	body, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, "", false
	}
	return body, strings.TrimSuffix(meta, ";base64"), true
}

// shrinkDisplayImage resamples a raster image to card size. JPEG keeps the
// result small, so it is the output for an opaque image, and PNG keeps the
// transparency of one that has it.
func shrinkDisplayImage(body []byte) ([]byte, string, bool) {
	src, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, "", false
	}
	bounds := src.Bounds()
	side := max(bounds.Dx(), bounds.Dy())
	scale := 1.0
	if side > displayImageMaxSide {
		scale = float64(displayImageMaxSide) / float64(side)
	}
	dst := image.NewRGBA(image.Rect(0, 0, max(1, int(float64(bounds.Dx())*scale)), max(1, int(float64(bounds.Dy())*scale))))
	draw.BiLinear.Scale(dst, dst.Bounds(), src, bounds, draw.Src, nil)

	var out bytes.Buffer
	if dst.Opaque() {
		if err := jpeg.Encode(&out, dst, &jpeg.Options{Quality: 80}); err != nil {
			return nil, "", false
		}
		return out.Bytes(), "image/jpeg", true
	}
	if err := png.Encode(&out, dst); err != nil {
		return nil, "", false
	}
	return out.Bytes(), "image/png", true
}

func (w *Wallet) rejectDisplayImage(field, uri, reason string) {
	w.addProtocolWarning("issuance", "credential_display_image_rejected",
		fmt.Sprintf("The credential display %s image was not kept: %s.", field, reason),
		map[string]any{"field": field, "uri": uri, "reason": reason})
}

// rememberDisplay attaches a display to a credential: to the store's entry
// and to the caller's copy. Import hands back a copy, and the server restores
// that copy into a store that was reloaded mid-flow, so a display only the
// store entry carries would be lost right there.
func (w *Wallet) rememberDisplay(cred *StoredCredential, d *CredentialDisplay) {
	if w == nil || cred == nil || d == nil {
		return
	}
	cred.Display = d
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == cred.ID {
			w.Credentials[i].Display = d
			return
		}
	}
}
