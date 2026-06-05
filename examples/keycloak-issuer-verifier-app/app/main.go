package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

//go:embed templates/*.html static/*
var uiFS embed.FS

const credentialOfferQRCodeSize = 640

type config struct {
	AppHost                string
	AppPort                string
	AppBaseURL             string
	WalletUIURL            string
	KeycloakBaseURL        string
	KeycloakCACert         string
	KeycloakRealm          string
	OID4VCICredentialScope string
	AppClientID            string
	AppRedirectURI         string
	KeycloakTrustListPath  string
}

type authSession struct {
	Verifier  string
	Mode      string
	CreatedAt time.Time
}

type appSession struct {
	CreatedAt         time.Time
	LoginMethod       string
	IDToken           string
	AccessToken       string
	RefreshToken      string
	IDTokenClaims     map[string]any
	AccessTokenClaims map[string]any
}

type homePageData struct {
	Title             string
	SignedIn          bool
	WalletUIURL       string
	LoginMethod       string
	IDTokenClaims     string
	AccessTokenClaims string
}

type issuePageData struct {
	Title         string
	WalletUIURL   string
	OfferHref     template.URL
	OfferURI      string
	OfferPayload  string
	QRCodeDataURL template.URL
	AcceptCommand string
	HasOffer      bool
}

type messagePageData struct {
	Title   string
	Heading string
	Message string
}

type loginFailedPageData struct {
	Title       string
	Error       string
	Description string
}

type server struct {
	cfg          config
	authMu       sync.Mutex
	authSessions map[string]authSession
	appMu        sync.Mutex
	appSessions  map[string]appSession
	static       http.Handler
}

func loadConfig() config {
	appHost := getenvDefault("APP_HOST", "127.0.0.1")
	appPort := getenvDefault("APP_PORT", "8090")
	appBaseURL := getenvDefault("APP_BASE_URL", fmt.Sprintf("http://%s:%s", appHost, appPort))
	return config{
		AppHost:                appHost,
		AppPort:                appPort,
		AppBaseURL:             appBaseURL,
		WalletUIURL:            getenvDefault("WALLET_UI_URL", "http://localhost:8085/"),
		KeycloakBaseURL:        getenvDefault("KEYCLOAK_BASE_URL", "http://localhost:8080"),
		KeycloakCACert:         os.Getenv("KEYCLOAK_CA_CERT"),
		KeycloakRealm:          getenvDefault("KEYCLOAK_REALM", "wallet-app-demo"),
		OID4VCICredentialScope: getenvDefault("OID4VCI_CREDENTIAL_SCOPE", "membership-credential"),
		AppClientID:            getenvDefault("APP_CLIENT_ID", "wallet-app"),
		AppRedirectURI:         getenvDefault("APP_REDIRECT_URI", appBaseURL+"/callback"),
		KeycloakTrustListPath:  os.Getenv("KEYCLOAK_TRUST_LIST_PATH"),
	}
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func newServer(cfg config) *server {
	staticFS, err := fs.Sub(uiFS, "static")
	if err != nil {
		panic(err)
	}
	return &server{
		cfg:          cfg,
		authSessions: map[string]authSession{},
		appSessions:  map[string]appSession{},
		static:       http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))),
	}
}

func (s *server) httpClient() (*http.Client, error) {
	transport := &http.Transport{}
	if s.cfg.KeycloakCACert != "" {
		caBytes, err := os.ReadFile(s.cfg.KeycloakCACert)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if ok := pool.AppendCertsFromPEM(caBytes); !ok {
			return nil, fmt.Errorf("failed to load CA certificate %s", s.cfg.KeycloakCACert)
		}
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: transport}, nil
}

func (s *server) keycloakRealmURL() string {
	return s.cfg.KeycloakBaseURL + "/realms/" + s.cfg.KeycloakRealm
}

func (s *server) jsonRequest(method, rawURL string, body any, headers map[string]string) (map[string]any, error) {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, rawURL, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	client, err := s.httpClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s failed (%d): %s", method, rawURL, resp.StatusCode, string(respBody))
	}
	if len(respBody) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *server) formRequest(rawURL string, values url.Values) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client, err := s.httpClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s failed (%d): %s", rawURL, resp.StatusCode, string(respBody))
	}
	if len(respBody) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func randomToken(size int) string {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func pkcePair() (string, string) {
	verifier := randomToken(48)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func decodeJWTPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return map[string]any{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func prettyJSON(value any) string {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func wrapCredentialOfferJSON(rawOfferJSON string, walletScheme string) (string, error) {
	rawOfferJSON = strings.TrimSpace(rawOfferJSON)
	if rawOfferJSON == "" {
		return "", fmt.Errorf("credential offer JSON missing")
	}
	return walletScheme + "?credential_offer=" + url.QueryEscape(rawOfferJSON), nil
}

func walletOfferHref(raw string) (template.URL, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parsing wallet offer URI: %w", err)
	}
	switch parsed.Scheme {
	case "openid-credential-offer", "haip-vci":
		// #nosec G203 -- only validated wallet schemes generated by this example are allowed here.
		return template.URL(raw), nil
	default:
		return "", fmt.Errorf("unexpected wallet offer scheme: %s", parsed.Scheme)
	}
}

func credentialOfferPayload(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	inline := strings.TrimSpace(parsed.Query().Get("credential_offer"))
	if inline == "" {
		if target := strings.TrimSpace(parsed.Query().Get("credential_offer_uri")); target != "" {
			return target
		}
		return raw
	}
	var decoded any
	if err := json.Unmarshal([]byte(inline), &decoded); err != nil {
		return inline
	}
	return prettyJSON(decoded)
}

func qrCodeDataURL(content string) (template.URL, error) {
	matrix, err := qrcode.NewQRCodeWriter().Encode(content, gozxing.BarcodeFormat_QR_CODE, credentialOfferQRCodeSize, credentialOfferQRCodeSize, nil)
	if err != nil {
		return "", fmt.Errorf("encoding QR code: %w", err)
	}

	img := image.NewRGBA(image.Rect(0, 0, matrix.GetWidth(), matrix.GetHeight()))
	light := color.RGBA{R: 255, G: 255, B: 255, A: 255}
	dark := color.RGBA{R: 15, G: 23, B: 42, A: 255}
	for y := 0; y < matrix.GetHeight(); y++ {
		for x := 0; x < matrix.GetWidth(); x++ {
			if matrix.Get(x, y) {
				img.Set(x, y, dark)
				continue
			}
			img.Set(x, y, light)
		}
	}

	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		return "", fmt.Errorf("encoding QR PNG: %w", err)
	}

	// #nosec G203 -- this is a generated in-memory PNG data URL, not user input.
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBuf.Bytes())), nil
}

func rewriteOfferIssuer(rawIssuer, publicBase string) (string, error) {
	issuerURL, err := url.Parse(strings.TrimSpace(rawIssuer))
	if err != nil {
		return "", fmt.Errorf("parsing issuer URL: %w", err)
	}
	publicURL, err := url.Parse(strings.TrimSpace(publicBase))
	if err != nil {
		return "", fmt.Errorf("parsing public base URL: %w", err)
	}
	if issuerURL.Scheme == "" || issuerURL.Host == "" {
		return "", fmt.Errorf("issuer URL missing scheme or host")
	}
	issuerURL.Scheme = publicURL.Scheme
	issuerURL.Host = publicURL.Host
	return strings.TrimRight(issuerURL.String(), "/"), nil
}

func rewriteCredentialOfferForPublic(rawOffer map[string]any, publicBase string) (string, error) {
	cloned := make(map[string]any, len(rawOffer))
	for key, value := range rawOffer {
		cloned[key] = value
	}
	if issuer, _ := cloned["credential_issuer"].(string); strings.TrimSpace(issuer) != "" {
		publicIssuer, err := rewriteOfferIssuer(issuer, publicBase)
		if err != nil {
			return "", err
		}
		cloned["credential_issuer"] = publicIssuer
	}
	encoded, err := json.Marshal(cloned)
	if err != nil {
		return "", fmt.Errorf("encoding credential offer JSON: %w", err)
	}
	return string(encoded), nil
}

func (s *server) createOfferURI(accessToken string) (string, error) {
	offerURL := fmt.Sprintf(
		"%s/protocol/oid4vc/create-credential-offer?credential_configuration_id=%s&pre_authorized=true&type=uri",
		s.keycloakRealmURL(),
		url.QueryEscape(s.cfg.OID4VCICredentialScope),
	)
	offerData, err := s.jsonRequest(http.MethodGet, offerURL, nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	if err != nil {
		return "", err
	}
	issuer, _ := offerData["issuer"].(string)
	nonce, _ := offerData["nonce"].(string)
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(nonce) == "" {
		return "", fmt.Errorf("unexpected Keycloak credential offer response: expected JSON with issuer and nonce")
	}
	publicIssuer, err := rewriteOfferIssuer(issuer, s.cfg.KeycloakBaseURL)
	if err != nil {
		return "", err
	}
	publicOfferURI := publicIssuer + "/" + strings.TrimLeft(nonce, "/")
	offerPayload, err := s.jsonRequest(http.MethodGet, publicOfferURI, nil, nil)
	if err != nil {
		return "", fmt.Errorf("fetching credential offer JSON: %w", err)
	}
	inlineOffer, err := rewriteCredentialOfferForPublic(offerPayload, s.cfg.KeycloakBaseURL)
	if err != nil {
		return "", err
	}
	return wrapCredentialOfferJSON(inlineOffer, "openid-credential-offer://")
}

func (s *server) createLoginURL(mode string) (string, error) {
	if mode != "login" && mode != "password" && mode != "wallet" {
		return "", fmt.Errorf("unsupported login mode: %s", mode)
	}
	state := "s-" + randomToken(8)
	nonce := "n-" + randomToken(8)
	verifier, challenge := pkcePair()

	s.authMu.Lock()
	s.authSessions[state] = authSession{
		Verifier:  verifier,
		Mode:      mode,
		CreatedAt: time.Now(),
	}
	s.authMu.Unlock()

	values := url.Values{
		"client_id":             {s.cfg.AppClientID},
		"redirect_uri":          {s.cfg.AppRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if mode == "wallet" {
		values.Set("kc_idp_hint", "oid4vp")
		values.Set("prompt", "login")
	}
	return s.keycloakRealmURL() + "/protocol/openid-connect/auth?" + values.Encode(), nil
}

func (s *server) exchangeCode(code, state string) (map[string]any, error) {
	s.authMu.Lock()
	authSession, ok := s.authSessions[state]
	if ok {
		delete(s.authSessions, state)
	}
	s.authMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown or expired state: %s", state)
	}

	tokenData, err := s.formRequest(s.keycloakRealmURL()+"/protocol/openid-connect/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {s.cfg.AppClientID},
		"redirect_uri":  {s.cfg.AppRedirectURI},
		"code":          {code},
		"code_verifier": {authSession.Verifier},
	})
	if err != nil {
		return nil, err
	}
	return tokenData, nil
}

func (s *server) cleanupSessions() {
	cutoff := time.Now().Add(-1 * time.Hour)

	s.authMu.Lock()
	for key, value := range s.authSessions {
		if value.CreatedAt.Before(cutoff) {
			delete(s.authSessions, key)
		}
	}
	s.authMu.Unlock()

	s.appMu.Lock()
	for key, value := range s.appSessions {
		if value.CreatedAt.Before(cutoff) {
			delete(s.appSessions, key)
		}
	}
	s.appMu.Unlock()
}

func (s *server) currentAppSession(r *http.Request) (appSession, bool) {
	cookie, err := r.Cookie("demo_session")
	if err != nil {
		return appSession{}, false
	}
	s.appMu.Lock()
	session, ok := s.appSessions[cookie.Value]
	s.appMu.Unlock()
	return session, ok
}

func (s *server) renderTemplate(w http.ResponseWriter, status int, page string, data any) {
	tmpl, err := template.ParseFS(uiFS, "templates/base.html", "templates/"+page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

func (s *server) writeJSON(w http.ResponseWriter, status int, payload any) {
	body, _ := json.MarshalIndent(payload, "", "  ")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *server) writeError(w http.ResponseWriter, message string, status int) {
	s.renderTemplate(w, status, "error.html", messagePageData{
		Title:   "Error",
		Heading: "Request failed",
		Message: message,
	})
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.cleanupSessions()

	defer func() {
		if recovered := recover(); recovered != nil {
			s.writeError(w, fmt.Sprintf("%v", recovered), http.StatusInternalServerError)
		}
	}()

	if strings.HasPrefix(r.URL.Path, "/static/") {
		s.static.ServeHTTP(w, r)
		return
	}

	switch r.URL.Path {
	case "/":
		s.handleHome(w, r)
	case "/healthz":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	case "/api/login-url":
		s.handleAPILoginURL(w, r)
	case "/api/credential-offer":
		s.handleAPICredentialOffer(w, r)
	case "/keycloak-trustlist.jwt":
		s.handleTrustList(w, r)
	case "/login":
		s.redirectToLogin(w, r, "login")
	case "/login/password":
		s.redirectToLogin(w, r, "password")
	case "/login/wallet":
		s.redirectToLogin(w, r, "wallet")
	case "/issue":
		s.handleIssue(w, r)
	case "/logout":
		s.handleLogout(w, r)
	case "/callback":
		s.handleCallback(w, r)
	default:
		s.renderTemplate(w, http.StatusNotFound, "not_found.html", messagePageData{
			Title:   "Not Found",
			Heading: "Page not found",
			Message: "Return to the demo app and start again from there.",
		})
	}
}

func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	appSession, ok := s.currentAppSession(r)
	if !ok {
		s.renderTemplate(w, http.StatusOK, "home.html", homePageData{
			Title:       "Keycloak Wallet Demo",
			SignedIn:    false,
			WalletUIURL: s.cfg.WalletUIURL,
		})
		return
	}

	s.renderTemplate(w, http.StatusOK, "home.html", homePageData{
		Title:             "Keycloak Wallet Demo",
		SignedIn:          true,
		WalletUIURL:       s.cfg.WalletUIURL,
		LoginMethod:       appSession.LoginMethod,
		IDTokenClaims:     prettyJSON(appSession.IDTokenClaims),
		AccessTokenClaims: prettyJSON(appSession.AccessTokenClaims),
	})
}

func (s *server) handleAPILoginURL(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "login"
	}
	loginURL, err := s.createLoginURL(mode)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"login_url": loginURL, "mode": mode})
}

func (s *server) handleAPICredentialOffer(w http.ResponseWriter, r *http.Request) {
	appSession, ok := s.currentAppSession(r)
	if !ok {
		s.writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login_required"})
		return
	}
	offerURI, err := s.createOfferURI(appSession.AccessToken)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"offer_uri": offerURI})
}

func (s *server) handleTrustList(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.KeycloakTrustListPath) == "" {
		s.renderTemplate(w, http.StatusNotFound, "not_found.html", messagePageData{
			Title:   "Not Found",
			Heading: "Trust list not configured",
			Message: "Start the HTTP demo mode to serve the generated trust list from the app.",
		})
		return
	}
	raw, err := os.ReadFile(s.cfg.KeycloakTrustListPath)
	if err != nil {
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	_, _ = io.WriteString(w, strings.TrimSpace(string(raw)))
}

func (s *server) redirectToLogin(w http.ResponseWriter, r *http.Request, mode string) {
	loginURL, err := s.createLoginURL(mode)
	if err != nil {
		s.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (s *server) handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		s.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appSession, ok := s.currentAppSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		s.renderTemplate(w, http.StatusOK, "issue.html", issuePageData{
			Title:       "Create Membership Credential Offer",
			WalletUIURL: s.cfg.WalletUIURL,
			HasOffer:    false,
		})
		return
	}

	offerURI, err := s.createOfferURI(appSession.AccessToken)
	if err != nil {
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	offerHref, err := walletOfferHref(offerURI)
	if err != nil {
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	qrDataURL, err := qrCodeDataURL(offerURI)
	if err != nil {
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderTemplate(w, http.StatusOK, "issue.html", issuePageData{
		Title:         "Membership Credential Offer",
		WalletUIURL:   s.cfg.WalletUIURL,
		OfferHref:     offerHref,
		OfferURI:      offerURI,
		OfferPayload:  credentialOfferPayload(offerURI),
		QRCodeDataURL: qrDataURL,
		AcceptCommand: "oid4vc-dev wallet accept '" + offerURI + "'",
		HasOffer:      true,
	})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var session appSession
	var ok bool
	if cookie, err := r.Cookie("demo_session"); err == nil {
		s.appMu.Lock()
		session, ok = s.appSessions[cookie.Value]
		delete(s.appSessions, cookie.Value)
		s.appMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "demo_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	values := url.Values{
		"post_logout_redirect_uri": {s.cfg.AppBaseURL},
		"client_id":                {s.cfg.AppClientID},
	}
	if session.IDToken != "" {
		values.Set("id_token_hint", session.IDToken)
	}
	http.Redirect(w, r, s.keycloakRealmURL()+"/protocol/openid-connect/logout?"+values.Encode(), http.StatusFound)
}

func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if errValue := r.URL.Query().Get("error"); errValue != "" {
		s.renderTemplate(w, http.StatusBadRequest, "login_failed.html", loginFailedPageData{
			Title:       "Login Failed",
			Error:       errValue,
			Description: r.URL.Query().Get("error_description"),
		})
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		s.writeError(w, "missing code or state", http.StatusBadRequest)
		return
	}

	tokenData, err := s.exchangeCode(code, state)
	if err != nil {
		s.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	accessToken, _ := tokenData["access_token"].(string)
	refreshToken, _ := tokenData["refresh_token"].(string)
	idToken, _ := tokenData["id_token"].(string)
	accessClaims := decodeJWTPayload(accessToken)
	loginType, _ := accessClaims["login_type"].(string)
	if loginType == "" {
		loginType = "unknown"
	}

	sessionID := "app-" + randomToken(12)
	s.appMu.Lock()
	s.appSessions[sessionID] = appSession{
		CreatedAt:         time.Now(),
		LoginMethod:       loginType,
		IDToken:           idToken,
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		IDTokenClaims:     decodeJWTPayload(idToken),
		AccessTokenClaims: accessClaims,
	}
	s.appMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "demo_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func main() {
	cfg := loadConfig()
	srv := newServer(cfg)
	addr := cfg.AppHost + ":" + cfg.AppPort
	log.Printf("Serving demo app on %s", cfg.AppBaseURL)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatal(err)
	}
}
