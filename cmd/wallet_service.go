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

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/internal/keys"
	"github.com/dominikschlosser/eudi-dev/internal/remote"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

// walletService is the single surface the wallet management commands operate
// on. Both backends speak the wallet server's API document shapes, so every
// command formats its output exactly once and managing the local store and a
// running instance behave identically.
//
// Identity model: a wallet IS its store (the wallet directory); an instance
// is that store plus the URL it is exposed at. The same store can be reached
// both ways (for example a server started by the registry script serving the
// local wallet directory). The store has exactly one writer at a time, so
// managedWallet prefers the URL whenever a live server owns the store: an
// explicit target (--remote, `wallet instances use`) first, then a running
// instance discovered to serve the local wallet directory. Only when no
// server owns the store does the CLI write it directly.
type walletService interface {
	// URL is the managed instance's base URL, empty for the local store.
	URL() string
	Credentials() ([]map[string]any, error)
	Credential(id string) (map[string]any, error)
	ImportCredential(raw string) (map[string]any, error)
	RemoveCredential(id string) error
	RemoveAllCredentials() (int, error)
	Issue(req map[string]any) (map[string]any, error)
	Logs() ([]wallet.LogEntry, error)
	Templates() ([]credtemplate.Template, error)
	Template(name string) (*credtemplate.Template, error)
	// SaveTemplate returns the saved file path when the backend knows it
	// (the local store does, a remote instance does not).
	SaveTemplate(tpl credtemplate.Template) (string, error)
	DeleteTemplate(name string) error
	Certificate(kind, certFormat string, opts walletCertOptions) ([]byte, error)
	Config() (map[string]any, error)
}

// walletCertOptions carries the derivation inputs for the local TLS leaf
// certificate. A remote instance derives its own URLs, so the fields only
// apply to the local store.
type walletCertOptions struct {
	port    int
	baseURL string
	docker  bool
}

// managedWallet resolves the wallet the CLI manages: the remote client when
// a remote target is set or a running instance owns the wallet directory,
// otherwise the local store.
func managedWallet() (walletService, error) {
	return managedWalletWithLoader(loadWallet)
}

// managedWalletWithLoader is managedWallet with a custom local wallet loader
// for commands that apply flag overrides while loading.
func managedWalletWithLoader(load func() (*wallet.Wallet, *wallet.WalletStore, error)) (walletService, error) {
	c, err := remoteClientIfConfigured()
	if err != nil {
		return nil, err
	}
	if c != nil {
		return &remoteWallet{c: c}, nil
	}
	return &localWallet{load: load}, nil
}

// --- remote backend ---

type remoteWallet struct {
	c *remote.Client
}

func (r *remoteWallet) URL() string { return r.c.BaseURL }

func (r *remoteWallet) Credentials() ([]map[string]any, error) { return r.c.Credentials() }

func (r *remoteWallet) Credential(id string) (map[string]any, error) { return r.c.Credential(id) }

func (r *remoteWallet) ImportCredential(raw string) (map[string]any, error) {
	return r.c.ImportCredential(raw)
}

func (r *remoteWallet) RemoveCredential(id string) error { return r.c.RemoveCredential(id) }

func (r *remoteWallet) RemoveAllCredentials() (int, error) { return r.c.RemoveAllCredentials() }

func (r *remoteWallet) Issue(req map[string]any) (map[string]any, error) { return r.c.Issue(req) }

func (r *remoteWallet) Logs() ([]wallet.LogEntry, error) {
	data, err := r.c.Log()
	if err != nil {
		return nil, err
	}
	var entries []wallet.LogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decoding remote log: %w", err)
	}
	return entries, nil
}

func (r *remoteWallet) Templates() ([]credtemplate.Template, error) {
	docs, err := r.c.Templates()
	if err != nil {
		return nil, err
	}
	templates := make([]credtemplate.Template, 0, len(docs))
	for _, doc := range docs {
		tpl, err := decodeTemplateDoc(doc)
		if err != nil {
			return nil, err
		}
		templates = append(templates, *tpl)
	}
	return templates, nil
}

func (r *remoteWallet) Template(name string) (*credtemplate.Template, error) {
	doc, err := r.c.Template(name)
	if err != nil {
		return nil, err
	}
	return decodeTemplateDoc(doc)
}

func (r *remoteWallet) SaveTemplate(tpl credtemplate.Template) (string, error) {
	if _, err := r.c.PutTemplate(tpl.Name, tpl); err != nil {
		return "", err
	}
	return "", nil
}

func (r *remoteWallet) DeleteTemplate(name string) error { return r.c.DeleteTemplate(name) }

func (r *remoteWallet) Certificate(kind, certFormat string, _ walletCertOptions) ([]byte, error) {
	return r.c.Certificate(kind, certFormat)
}

func (r *remoteWallet) Config() (map[string]any, error) {
	cfg, err := r.c.ServerConfig()
	if err != nil {
		return nil, err
	}
	cfg["remote_url"] = r.c.BaseURL
	return cfg, nil
}

func decodeTemplateDoc(doc map[string]any) (*credtemplate.Template, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var tpl credtemplate.Template
	if err := json.Unmarshal(data, &tpl); err != nil {
		return nil, fmt.Errorf("decoding remote template: %w", err)
	}
	return &tpl, nil
}

// --- local backend ---

type localWallet struct {
	load func() (*wallet.Wallet, *wallet.WalletStore, error)
}

func (l *localWallet) URL() string { return "" }

func (l *localWallet) Credentials() ([]map[string]any, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	creds := w.GetCredentials()
	summaries := make([]map[string]any, len(creds))
	for i, c := range creds {
		summaries[i] = w.CredentialSummaryWithStatus(c)
	}
	return summaries, nil
}

func (l *localWallet) Credential(id string) (map[string]any, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	cred, ok := w.GetCredential(id)
	if !ok {
		return nil, fmt.Errorf("credential %s not found", id)
	}
	return w.CredentialSummaryWithStatus(cred), nil
}

func (l *localWallet) ImportCredential(raw string) (map[string]any, error) {
	w, store, err := l.load()
	if err != nil {
		return nil, err
	}
	imported, err := w.ImportCredential(raw)
	if err != nil {
		return nil, fmt.Errorf("importing credential: %w", err)
	}
	if err := store.Save(w); err != nil {
		return nil, fmt.Errorf("saving wallet: %w", err)
	}
	return w.CredentialSummaryWithStatus(*imported), nil
}

func (l *localWallet) RemoveCredential(id string) error {
	w, store, err := l.load()
	if err != nil {
		return err
	}
	if !w.RemoveCredential(id) {
		return fmt.Errorf("credential %s not found", id)
	}
	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}
	return nil
}

func (l *localWallet) RemoveAllCredentials() (int, error) {
	w, store, err := l.load()
	if err != nil {
		return 0, err
	}
	count := w.ClearCredentials()
	if err := store.Save(w); err != nil {
		return 0, fmt.Errorf("saving wallet: %w", err)
	}
	return count, nil
}

func (l *localWallet) Issue(req map[string]any) (map[string]any, error) {
	w, store, err := l.load()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var apiReq wallet.IssueAPIRequest
	if err := json.Unmarshal(data, &apiReq); err != nil {
		return nil, fmt.Errorf("building issue request: %w", err)
	}
	opts, err := apiReq.Options()
	if err != nil {
		return nil, err
	}
	summary, err := w.IssueSummary(opts)
	if err != nil {
		return nil, err
	}
	if err := store.Save(w); err != nil {
		return nil, fmt.Errorf("saving wallet: %w", err)
	}
	warnIssuedEndpointsOffline(store, w)
	return summary, nil
}

func (l *localWallet) Logs() ([]wallet.LogEntry, error) {
	w, _, err := l.load()
	if err != nil {
		return nil, err
	}
	return w.GetLog(), nil
}

func (l *localWallet) Templates() ([]credtemplate.Template, error) {
	return credtemplate.List(resolveTemplatesDir())
}

func (l *localWallet) Template(name string) (*credtemplate.Template, error) {
	return credtemplate.Load(name, resolveTemplatesDir())
}

func (l *localWallet) SaveTemplate(tpl credtemplate.Template) (string, error) {
	return credtemplate.Save(resolveTemplatesDir(), tpl)
}

func (l *localWallet) DeleteTemplate(name string) error {
	return credtemplate.Delete(resolveTemplatesDir(), name)
}

func (l *localWallet) Certificate(kind, certFormat string, opts walletCertOptions) ([]byte, error) {
	store := loadStore()
	var certPEM []byte
	switch kind {
	case "ca":
		var err error
		certPEM, err = store.LoadOrCreateSharedCACertificatePEM()
		if err != nil {
			return nil, fmt.Errorf("loading wallet CA certificate: %w", err)
		}
	case "tls":
		issuerURL, err := deriveWalletIssuerURL(opts.port, opts.baseURL, opts.docker)
		if err != nil {
			return nil, err
		}
		certPEM, err = store.LoadOrCreateIssuerTLSLeafCertificatePEMForURL(issuerURL)
		if err != nil {
			return nil, fmt.Errorf("loading wallet TLS certificate: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown certificate kind %q", kind)
	}
	if certFormat == "jwks" {
		return keys.CertificatePEMToJWKS(certPEM)
	}
	return certPEM, nil
}

func (l *localWallet) Config() (map[string]any, error) {
	w, store, err := l.load()
	if err != nil {
		return nil, err
	}
	templates := w.TemplatesDir
	if templates == "" {
		templates = store.Dir + "/templates"
	}
	return map[string]any{
		"remote_url":       "",
		"wallet_dir":       store.Dir,
		"templates_dir":    templates,
		"base_url":         w.BaseURL,
		"issuer_url":       w.IssuerURL,
		"status_list_url":  w.StatusListURL(),
		"preferred_format": w.PreferredFormat,
		"validation_mode":  string(w.ValidationMode),
		"credential_count": len(w.GetCredentials()),
	}, nil
}
