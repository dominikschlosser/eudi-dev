package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"net/http"
	"net/http/httptest"
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

func TestCreateOfferURIUsesHAIPScheme(t *testing.T) {
	var issuerBase string
	kc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/create-credential-offer"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": issuerBase + "/realms/wallet-app-demo",
				"nonce":  "credential-offer/abc",
			})
		case r.URL.Path == "/realms/wallet-app-demo/credential-offer/abc":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"credential_issuer": issuerBase + "/realms/wallet-app-demo",
				"credential_configuration_ids": []string{
					"membership-credential",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer kc.Close()
	issuerBase = kc.URL

	s := newServer(config{
		KeycloakBaseURL:        kc.URL,
		KeycloakRealm:          "wallet-app-demo",
		OID4VCICredentialScope: "membership-credential",
	})

	got, err := s.createOfferURI("access-token")
	if err != nil {
		t.Fatalf("createOfferURI() error = %v", err)
	}
	if !strings.HasPrefix(got, "haip-vci://?credential_offer=") {
		t.Fatalf("createOfferURI() = %q, want haip-vci scheme", got)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse offer URI: %v", err)
	}
	var offer map[string]any
	if err := json.Unmarshal([]byte(parsed.Query().Get("credential_offer")), &offer); err != nil {
		t.Fatalf("decode credential_offer: %v", err)
	}
	if offer["credential_issuer"] != kc.URL+"/realms/wallet-app-demo" {
		t.Fatalf("credential_issuer = %v, want public keycloak URL", offer["credential_issuer"])
	}
}
