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

// Command app is a small OpenID Connect relying party for the subject-binding
// demo. It sends the user to Keycloak's wallet login and shows the tokens that
// come back. The membership credential is issued by Keycloak during that login,
// so the app itself only signs the user in.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html static/*
var uiFS embed.FS

type config struct {
	AppHost         string
	AppPort         string
	AppBaseURL      string
	WalletUIURL     string
	KeycloakBaseURL string
	KeycloakCACert  string
	KeycloakRealm   string
	AppClientID     string
	AppRedirectURI  string
}

type authSession struct {
	Verifier  string
	CreatedAt time.Time
}

type appSession struct {
	CreatedAt         time.Time
	LoginMethod       string
	IDToken           string
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
		AppHost:         appHost,
		AppPort:         appPort,
		AppBaseURL:      appBaseURL,
		WalletUIURL:     getenvDefault("WALLET_UI_URL", "http://localhost:8087/"),
		KeycloakBaseURL: getenvDefault("KEYCLOAK_BASE_URL", "http://localhost:8080"),
		KeycloakCACert:  os.Getenv("KEYCLOAK_CA_CERT"),
		KeycloakRealm:   getenvDefault("KEYCLOAK_REALM", "wallet-app-demo"),
		AppClientID:     getenvDefault("APP_CLIENT_ID", "wallet-app"),
		AppRedirectURI:  getenvDefault("APP_REDIRECT_URI", appBaseURL+"/callback"),
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

// createLoginURL builds an authorization request that goes straight to the
// wallet identity provider. The user presents the PID, and on the first login
// signs in with a password so Keycloak can bind the account and issue the
// membership credential.
func (s *server) createLoginURL() (string, error) {
	state := "s-" + randomToken(8)
	nonce := "n-" + randomToken(8)
	verifier, challenge := pkcePair()

	s.authMu.Lock()
	s.authSessions[state] = authSession{
		Verifier:  verifier,
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
		"kc_idp_hint":           {"oid4vp"},
		"prompt":                {"login"},
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
	case "/login":
		s.redirectToLogin(w, r)
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

func (s *server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	loginURL, err := s.createLoginURL()
	if err != nil {
		s.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
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
	//nolint:gosec // G124: demo app served over plain http on localhost, so Secure cannot be set.
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
		IDTokenClaims:     decodeJWTPayload(idToken),
		AccessTokenClaims: accessClaims,
	}
	s.appMu.Unlock()

	//nolint:gosec // G124: demo app served over plain http on localhost, so Secure cannot be set.
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
