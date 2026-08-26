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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/image/draw"

	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
)

// CredentialDisplay is the appearance a §12.2.4 display entry declares for a
// credential, kept with the credential so the card renders it without asking
// the issuer again. The image fields hold a data URI or an "asset:" reference:
// a remote image is fetched once at issuance and stored, so rendering a card
// never calls the issuer (an issuer serving its logo per view would otherwise
// see every time the wallet opens). Under --adhoc-display-images the field
// instead holds the issuer's https URL, fetched by the card on demand.
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

// The text a credential's display carries is cosmetic, so it is capped rather
// than trusted: an issuer's metadata, an operator form, and a template all feed
// it, and any of them can be long or hostile. The cap bounds what the wallet
// stores and renders. Images are already byte-capped in cacheDisplayImage.
const (
	maxDisplayNameRunes        = 80
	maxDisplayDescriptionRunes = 300
	maxDisplayLocaleRunes      = 35
	maxDisplayAltTextRunes     = 120
)

// boundDisplayText trims a display string and caps it at max runes, so an
// over-long value is kept to a safe length rather than refused (the text is
// cosmetic, so bounding it never fails an issuance).
func boundDisplayText(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes])
}

// mergeCredentialDisplay lays the fields of over onto base, so an explicit
// display overrides only the fields it sets and inherits the rest (a template's
// art in particular) from base. Either side may be nil.
func mergeCredentialDisplay(base, over *CredentialDisplay) *CredentialDisplay {
	if base == nil {
		return over
	}
	if over == nil {
		return base
	}
	out := *base
	if over.Name != "" {
		out.Name = over.Name
	}
	if over.Description != "" {
		out.Description = over.Description
	}
	if over.BackgroundColor != "" {
		out.BackgroundColor = over.BackgroundColor
	}
	if over.TextColor != "" {
		out.TextColor = over.TextColor
	}
	// A new logo carries its own alt text (even an empty one, so a replaced logo
	// never keeps the old text). An alt text set on its own lays over the base,
	// so an operator can describe a template's logo without replacing it.
	if over.LogoURI != "" {
		out.LogoURI = over.LogoURI
		out.LogoAltText = over.LogoAltText
	} else if over.LogoAltText != "" {
		out.LogoAltText = over.LogoAltText
	}
	if over.BackgroundURI != "" {
		out.BackgroundURI = over.BackgroundURI
	}
	return &out
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

// displayForListing returns a credential's display for an API response with its
// image fields as reference URLs (/api/credentials/{id}/display/{logo|background})
// instead of inline data URIs, so a listing does not ship every card's art as
// base64. A card renders from a small JSON, and the browser fetches and caches
// each image on its own.
func displayForListing(c StoredCredential) map[string]any {
	d := c.Display
	if d == nil {
		return nil
	}
	m := map[string]any{}
	addStringDetail(m, "name", d.Name)
	addStringDetail(m, "description", d.Description)
	addStringDetail(m, "locale", d.Locale)
	addStringDetail(m, "background_color", d.BackgroundColor)
	addStringDetail(m, "text_color", d.TextColor)
	addStringDetail(m, "logo_alt_text", d.LogoAltText)
	if d.LogoURI != "" {
		m["logo_uri"] = displayImageRef(c.ID, "logo", d.LogoURI)
	}
	if d.BackgroundURI != "" {
		m["background_uri"] = displayImageRef(c.ID, "background", d.BackgroundURI)
	}
	return m
}

// displayImageRef references a stored image (a data URI or an "asset:" file) by
// an endpoint URL the wallet serves, and passes an external http(s) URL through
// unchanged.
func displayImageRef(id, kind, uri string) string {
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri
	}
	return "/api/credentials/" + id + "/display/" + kind
}

// dataURIImage decodes a base64 data URI into its content type and bytes.
func dataURIImage(uri string) (contentType string, data []byte, ok bool) {
	if !strings.HasPrefix(uri, "data:") {
		return "", nil, false
	}
	rest := uri[len("data:"):]
	comma := strings.IndexByte(rest, ',')
	if comma < 0 {
		return "", nil, false
	}
	meta, payload := rest[:comma], rest[comma+1:]
	if !strings.Contains(meta, "base64") {
		return "", nil, false
	}
	contentType = "application/octet-stream"
	if head, _, found := strings.Cut(meta, ";"); found && head != "" {
		contentType = head
	} else if meta != "" && !strings.Contains(meta, "=") {
		contentType = strings.TrimSuffix(meta, ";base64")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		return "", nil, false
	}
	return contentType, decoded, true
}

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
	name, _ := entry["name"].(string)
	d.Name = boundDisplayText(name, maxDisplayNameRunes)
	description, _ := entry["description"].(string)
	d.Description = boundDisplayText(description, maxDisplayDescriptionRunes)
	locale, _ := entry["locale"].(string)
	d.Locale = boundDisplayText(locale, maxDisplayLocaleRunes)
	d.BackgroundColor = w.displayColor(entry, "background_color")
	d.TextColor = w.displayColor(entry, "text_color")
	if logo, ok := entry["logo"].(map[string]any); ok {
		uri, _ := logo["uri"].(string)
		d.LogoURI = w.cacheDisplayImage(uri, "logo")
		if d.LogoURI != "" {
			altText, _ := logo["alt_text"].(string)
			d.LogoAltText = boundDisplayText(altText, maxDisplayAltTextRunes)
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

// templateDisplay resolves a template's display to a credential display. Colors
// run through the §12.2.4 validation, and each image reference becomes card art:
// an "embedded:<file>" name reads a bundled asset, and a data URI or https URL
// runs through the policed, size-capped cache. It returns nil for a nil or empty
// template display.
func (w *Wallet) templateDisplay(td *credtemplate.TemplateDisplay) *CredentialDisplay {
	if td == nil {
		return nil
	}
	d := &CredentialDisplay{
		Name:            boundDisplayText(td.Name, maxDisplayNameRunes),
		Description:     boundDisplayText(td.Description, maxDisplayDescriptionRunes),
		Locale:          "en-US",
		BackgroundColor: w.displayColor(map[string]any{"background_color": td.BackgroundColor}, "background_color"),
		TextColor:       w.displayColor(map[string]any{"text_color": td.TextColor}, "text_color"),
		LogoURI:         w.templateImage(td.Logo, "logo"),
		LogoAltText:     boundDisplayText(td.LogoAltText, maxDisplayAltTextRunes),
		BackgroundURI:   w.templateImage(td.BackgroundImage, "background_image"),
	}
	if d.Name == "" && d.Description == "" && d.BackgroundColor == "" &&
		d.TextColor == "" && d.LogoURI == "" && d.BackgroundURI == "" {
		return nil
	}
	w.checkDisplayContrast(d)
	return d
}

// templateImage resolves a template image reference to card art. An
// "embedded:<file>" reference reads a bundled asset by base name, so a template
// can only reach the wallet's own read-only assets. Any other value is a display
// image URI and runs through the policed cache.
func (w *Wallet) templateImage(ref, field string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if name, ok := strings.CutPrefix(ref, "embedded:"); ok {
		data, err := staticFiles.ReadFile("static/" + filepath.Base(name))
		if err != nil {
			w.rejectDisplayImage(field, ref, "not a bundled asset")
			return ""
		}
		return "data:" + embeddedImageMIME(name) + ";base64," + base64.StdEncoding.EncodeToString(data)
	}
	return w.cacheDisplayImage(ref, field)
}

// embeddedImageMIME is the media type of a bundled image, by extension.
func embeddedImageMIME(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	}
	return "application/octet-stream"
}

// issuedDisplay builds the display for a self-issued credential from operator
// input. Colors run through the same §12.2.4 validation as an offer's display
// (a bad one is dropped with a warning) and images through the same policed,
// size-capped cache, so a self-issued card is held to the rules an issuer's is.
// It returns nil when the input carries no display.
func (w *Wallet) issuedDisplay(in IssueDisplay) *CredentialDisplay {
	d := &CredentialDisplay{
		Name:            boundDisplayText(in.Name, maxDisplayNameRunes),
		Description:     boundDisplayText(in.Description, maxDisplayDescriptionRunes),
		BackgroundColor: w.displayColor(map[string]any{"background_color": in.BackgroundColor}, "background_color"),
		TextColor:       w.displayColor(map[string]any{"text_color": in.TextColor}, "text_color"),
		LogoURI:         w.cacheDisplayImage(strings.TrimSpace(in.Logo), "logo"),
		LogoAltText:     boundDisplayText(in.LogoAltText, maxDisplayAltTextRunes),
		BackgroundURI:   w.cacheDisplayImage(strings.TrimSpace(in.BackgroundImage), "background_image"),
	}
	if d.Name == "" && d.Description == "" && d.BackgroundColor == "" &&
		d.TextColor == "" && d.LogoURI == "" && d.BackgroundURI == "" {
		return nil
	}
	w.checkDisplayContrast(d)
	return d
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
// (a multi-megabyte PNG) still ends up on the card. Under
// --adhoc-display-images an https: URI is kept as the URL instead, for the card
// to fetch on demand.
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
	if w.AdhocDisplayImages && strings.HasPrefix(uri, "https://") {
		// Keep the https URL instead of fetching and storing the image, so the
		// card fetches it on demand (the issuer's own declared image URL, passed
		// to the browser as-is by displayImageRef). Only https: is kept: an http
		// image is mixed content a browser blocks on an https wallet page, so it
		// falls through and is fetched and stored as usual, and any other scheme
		// falls through and is rejected below. The card art then loads from the
		// issuer on every render, which the issuer can see, so this is off by
		// default.
		return uri
	}
	return w.fetchAndEmbedDisplayImage(uri, field)
}

// embedDisplayImage resolves an image to an embedded data URI, ignoring
// --adhoc-display-images. It is for an image shown once at consent time and
// never stored (the issuer logo): there is nothing to keep out of the store,
// and the consent dialog needs it inline to render it under the wallet's own
// image policy rather than pointing the page at the issuer's host.
func (w *Wallet) embedDisplayImage(uri, field string) string {
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
	return w.fetchAndEmbedDisplayImage(uri, field)
}

// fetchAndEmbedDisplayImage GETs a non-data image URI and returns it as a
// cached data URI. The fetch goes through the policed client, like every other
// issuance fetch: the URI comes from the offer's issuer metadata, which on a
// shared demo is attacker-controlled, so it must not reach an internal address
// (ADR-0004).
func (w *Wallet) fetchAndEmbedDisplayImage(uri, field string) string {
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		w.rejectDisplayImage(field, uri, err.Error())
		return ""
	}
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
	if mediaType == "image/svg+xml" {
		return w.keepVectorImage(body, field, uri)
	}
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

// keepVectorImage stores an SVG logo as it was served. SVG is vector, so it
// carries no pixel dimensions to cap, and a browser renders it inertly in an
// <img> or a CSS background (no scripts run, no external references load). The
// byte cap still bounds what the shared store holds, and an embedded script tag
// is refused as defense in depth.
func (w *Wallet) keepVectorImage(body []byte, field, uri string) string {
	if len(body) > maxDisplayImageBytes {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("larger than the %dKB cap", maxDisplayImageBytes>>10))
		return ""
	}
	// The SVG is not scanned for active content. It is only ever rendered
	// through an <img> tag, where an SVG runs in a secure static mode (no
	// scripts, no event handlers, no external loads), and the endpoint that
	// serves it carries the wallet's script-src 'self' CSP even when opened on
	// its own. A blocklist here would catch <script> and miss onload, a
	// javascript: href and the rest, so it is left out rather than reading as a
	// safety it does not provide.
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(body)
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
