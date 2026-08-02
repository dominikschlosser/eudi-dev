package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

type jwksDocument struct {
	Keys []struct {
		Use string   `json:"use"`
		X5C []string `json:"x5c"`
	} `json:"keys"`
}

func getenvDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func fetchRealmSigningCert(baseURL, realm string) (*x509.Certificate, error) {
	jwksURL := strings.TrimRight(baseURL, "/") + "/realms/" + strings.TrimSpace(realm) + "/protocol/openid-connect/certs"
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: status %d", jwksURL, resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", jwksURL, err)
	}
	for _, key := range doc.Keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if len(key.X5C) == 0 || strings.TrimSpace(key.X5C[0]) == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(key.X5C[0])
		if err != nil {
			return nil, fmt.Errorf("decoding x5c from %s: %w", jwksURL, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c from %s: %w", jwksURL, err)
		}
		return cert, nil
	}
	return nil, fmt.Errorf("no signing certificate with x5c found at %s", jwksURL)
}

func main() {
	baseURL := getenvDefault("KEYCLOAK_BASE_URL", "http://localhost:8080")
	realm := getenvDefault("KEYCLOAK_REALM", "wallet-app-demo")
	outputPath := getenvDefault("KEYCLOAK_TRUST_LIST_PATH", "examples/keycloak-issuer-verifier-app/keycloak-trustlist.jwt")

	cert, err := fetchRealmSigningCert(baseURL, realm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating trust-list signing key: %v\n", err)
		os.Exit(1)
	}

	jwt, err := wallet.GenerateTrustListJWT(signingKey, cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating trust list JWT: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating output directory: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outputPath, []byte(jwt), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing trust list JWT: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated trust list:\n  %s\n", outputPath)
}
