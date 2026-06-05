package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"net/url"
	"strings"
	"testing"
)

func TestQRCodeDataURLUsesLargeImage(t *testing.T) {
	offer := `{"credential_issuer":"http://localhost:8080/realms/wallet-app-demo","credential_configuration_ids":["membership-credential"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"` + strings.Repeat("a", 900) + `"}}}`
	content := "openid-credential-offer://?credential_offer=" + url.QueryEscape(offer)

	dataURL, err := qrCodeDataURL(content)
	if err != nil {
		t.Fatalf("qrCodeDataURL() error = %v", err)
	}

	prefix := "data:image/png;base64,"
	encoded := strings.TrimPrefix(string(dataURL), prefix)
	if encoded == string(dataURL) {
		t.Fatalf("QR code data URL missing prefix %q", prefix)
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding QR PNG data URL: %v", err)
	}

	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decoding QR PNG: %v", err)
	}
	bounds := img.Bounds()
	if bounds.Dx() < 640 || bounds.Dy() < 640 {
		t.Fatalf("QR PNG size = %dx%d, want at least 640x640", bounds.Dx(), bounds.Dy())
	}
}

func TestQRCodeCSSDisplaysLargeImage(t *testing.T) {
	raw, err := uiFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("reading app.css: %v", err)
	}

	css := string(raw)
	if !strings.Contains(css, "grid-template-columns: minmax(320px, 460px) minmax(0, 1fr);") {
		t.Fatalf("offer grid should leave enough space for the larger QR")
	}
	if !strings.Contains(css, "width: min(420px, 100%);") {
		t.Fatalf("QR code CSS should display the image at a scan-friendly size")
	}
}
