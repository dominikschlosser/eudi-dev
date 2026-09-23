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

// Package remote lets the CLI manage a running oid4vc-dev wallet server over
// its REST API instead of the local file store. It holds the REST client, the
// persisted active remote target, and discovery of wallet instances running
// on the local system.
package remote

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v2/internal/config"
	"github.com/dominikschlosser/eudi-dev/v2/internal/format"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
	// owner is the browser this client submits on behalf of, set when it
	// opened a wallet UI page for the flow it is about to start.
	owner string
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) do(method, path string, body any, out any) error {
	return c.doWithTimeout(0, method, path, body, out)
}

// doWithTimeout is do with a per-request deadline for calls that outlast a
// normal round trip, such as accepting an offer whose issuer defers the
// credential. A zero timeout keeps the client's own default.
func (c *Client) doWithTimeout(timeout time.Duration, method, path string, body any, out any) error {
	var reader io.Reader
	contentType := ""
	switch b := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(b)
	default:
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		reader = bytes.NewReader(data)
		contentType = "application/json"
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// Report the CLI version so the server can recognize older clients that need
	// compatibility handling.
	req.Header.Set(config.ClientHeader, "eudi-cli/"+version)
	if c.owner != "" {
		req.Header.Set(config.OwnerHeader, c.owner)
	}

	client := c.HTTP
	if timeout > 0 && client != nil && client.Timeout < timeout {
		withDeadline := *client
		withDeadline.Timeout = timeout
		client = &withDeadline
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s: %w", c.BaseURL+path, err)
	}
	defer resp.Body.Close()

	data, err := format.ReadRemoteBody(resp.Body, "wallet response")
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("remote wallet: %s (HTTP %d)", apiErr.Error, resp.StatusCode)
		}
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("remote wallet: %s (HTTP %d)", msg, resp.StatusCode)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if raw, ok := out.(*[]byte); ok {
		*raw = data
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

func (c *Client) Version() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/version", nil, &out)
	return out, err
}

func (c *Client) ServerConfig() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/config", nil, &out)
	return out, err
}

func (c *Client) Credentials() ([]map[string]any, error) {
	var out []map[string]any
	err := c.do(http.MethodGet, "/api/credentials", nil, &out)
	return out, err
}

func (c *Client) Credential(id string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/credentials/"+id, nil, &out)
	return out, err
}

func (c *Client) ImportCredential(raw string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPost, "/api/credentials", raw, &out)
	return out, err
}

func (c *Client) RefreshCredential(id string) (map[string]any, error) {
	var out map[string]any
	err := c.doWithTimeout(config.SlowRequestTimeout, http.MethodPost, "/api/credentials/"+id+"/refresh", nil, &out)
	return out, err
}

func (c *Client) RemoveCredential(id string) error {
	return c.do(http.MethodDelete, "/api/credentials/"+id, nil, nil)
}

func (c *Client) RemoveAllCredentials() (int, error) {
	var out struct {
		Deleted int `json:"deleted"`
	}
	err := c.do(http.MethodDelete, "/api/credentials", nil, &out)
	return out.Deleted, err
}

// Issue issues a credential with the remote wallet's issuer key. The request
// map uses the POST /api/issue field names.
func (c *Client) Issue(req map[string]any) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPost, "/api/issue", req, &out)
	return out, err
}

func (c *Client) GeneratePID(claims map[string]any, vct string) error {
	body := map[string]any{}
	if claims != nil {
		body["claims"] = claims
	}
	if vct != "" {
		body["vct"] = vct
	}
	return c.do(http.MethodPost, "/api/generate-pid", body, nil)
}

func (c *Client) Log() ([]byte, error) {
	var out []byte
	err := c.do(http.MethodGet, "/api/log", nil, &out)
	return out, err
}

func (c *Client) ClearLog() error {
	return c.do(http.MethodDelete, "/api/log", nil, nil)
}

func (c *Client) Templates() ([]map[string]any, error) {
	var out []map[string]any
	err := c.do(http.MethodGet, "/api/templates", nil, &out)
	return out, err
}

func (c *Client) Template(name string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/templates/"+name, nil, &out)
	return out, err
}

func (c *Client) PutTemplate(name string, doc any) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPut, "/api/templates/"+name, doc, &out)
	return out, err
}

func (c *Client) DeleteTemplate(name string) error {
	return c.do(http.MethodDelete, "/api/templates/"+name, nil, nil)
}

// Certificate exports the remote wallet's CA or TLS certificate. kind is
// "ca" or "tls", format is "pem" or "jwks".
func (c *Client) Certificate(kind, format string) ([]byte, error) {
	path := "/api/certificates/" + kind
	if format != "" && format != "pem" {
		path += "?format=" + format
	}
	var out []byte
	err := c.do(http.MethodGet, path, nil, &out)
	return out, err
}

// Allow time for consent and the protocol exchange that follows it.
const interactiveTimeout = config.ConsentTimeout + config.SlowRequestTimeout

// Present sends a presentation request URI to the remote wallet. With
// interactive set, the wallet shows its consent dialog and holds the response
// until the user decides, instead of auto-accepting the request.
func (c *Client) Present(uri string, interactive bool) (map[string]any, error) {
	var out map[string]any
	body := map[string]any{"uri": uri}
	timeout := time.Duration(0)
	if interactive {
		body["interactive"] = true
		timeout = interactiveTimeout
	}
	err := c.doWithTimeout(timeout, http.MethodPost, "/api/presentations", body, &out)
	return out, err
}

// AcceptOffer sends a credential offer URI to the remote wallet. An offer
// whose pre-authorized grant requires a transaction code needs txCode. An
// empty one is left out so the wallet keeps whatever it already holds. With
// interactive set, the wallet shows its consent dialog rather than importing
// the credential silently.
func (c *Client) AcceptOffer(uri, txCode string, interactive bool) (map[string]any, error) {
	var out map[string]any
	body := map[string]any{"uri": uri}
	if txCode != "" {
		body["tx_code"] = txCode
	}
	// Use the server's timeout for issuance requests that can outlast an ordinary API
	// call.
	timeout := config.SlowRequestTimeout
	if interactive {
		body["interactive"] = true
		timeout = interactiveTimeout
	}
	err := c.doWithTimeout(timeout, http.MethodPost, "/api/offers", body, &out)
	return out, err
}

// TrustList fetches an ETSI trust list JWT from the remote wallet. Without a
// selector this is the same default list as /api/trustlist.
func (c *Client) TrustList(id, vct, docType string) (string, error) {
	var out []byte
	if err := c.do(http.MethodGet, TrustListPath(id, vct, docType), nil, &out); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// TrustListPath maps a trust list selection to its endpoint. The CLI prints
// this path as well as fetching it, so the mapping lives in one place.
func TrustListPath(id, vct, docType string) string {
	if id != "" {
		return "/api/trustlists/" + url.PathEscape(id)
	}
	query := url.Values{}
	if vct != "" {
		query.Set("vct", vct)
	}
	if docType != "" {
		query.Set("doctype", docType)
	}
	if encoded := query.Encode(); encoded != "" {
		return "/api/trustlist?" + encoded
	}
	return "/api/trustlist"
}

func (c *Client) TrustLists() ([]map[string]any, error) {
	var out struct {
		TrustLists []map[string]any `json:"trust_lists"`
	}
	if err := c.do(http.MethodGet, "/api/trustlists", nil, &out); err != nil {
		return nil, err
	}
	return out.TrustLists, nil
}

// OfferStatus reports how an offer that paused for an interactive sign-in
// ended. The id comes from the offer_id of the authorization_required
// response.
func (c *Client) OfferStatus(id string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/offers/"+id, nil, &out)
	return out, err
}

func (c *Client) DeferredIssuances() ([]map[string]any, error) {
	var out []map[string]any
	err := c.do(http.MethodGet, "/api/deferred", nil, &out)
	return out, err
}

func (c *Client) CollectDeferred(id string) (map[string]any, error) {
	var out map[string]any
	err := c.doWithTimeout(config.SlowRequestTimeout, http.MethodPost, "/api/deferred/"+id+"/collect", nil, &out)
	return out, err
}

func (c *Client) AbandonDeferred(id string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodDelete, "/api/deferred/"+id, nil, &out)
	return out, err
}

// SetCredentialStatus revokes (1) or activates (0) a credential on the remote
// wallet's own status list.
func (c *Client) SetCredentialStatus(id string, status int) error {
	return c.do(http.MethodPost, "/api/credentials/"+id+"/status", map[string]any{"status": status}, nil)
}

func (c *Client) Shutdown() error {
	return c.do(http.MethodPost, "/api/shutdown", nil, nil)
}

// version is the release this binary was built as, set by the cmd package.
var version = "dev"

func SetVersion(v string) {
	if v = strings.TrimSpace(v); v != "" {
		version = v
	}
}

func NewOwnerToken() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (c *Client) ActsForAPage() bool {
	return c.owner != ""
}

func (c *Client) ActingFor(owner string) {
	c.owner = strings.TrimSpace(owner)
}
