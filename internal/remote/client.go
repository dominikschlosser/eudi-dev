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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/config"
)

// Client calls the management REST API of a running wallet server.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient creates a client for the wallet server at baseURL.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// do runs a request and decodes the JSON response into out (when out is not
// nil). Non-2xx responses become errors carrying the server's error message.
func (c *Client) do(method, path string, body any, out any) error {
	return c.doWithTimeout(0, method, path, body, out)
}

// doWithTimeout is do with a per-request deadline, for the calls that
// legitimately outlast a normal round trip. Accepting a credential offer is
// one: the issuer may defer the credential, and the wallet then polls for it.
// A zero timeout keeps the client's own default.
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

	data, err := io.ReadAll(resp.Body)
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

// Version returns the remote wallet's /api/version document (build id, pid).
func (c *Client) Version() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/version", nil, &out)
	return out, err
}

// ServerConfig returns the remote wallet's /api/config document.
func (c *Client) ServerConfig() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/config", nil, &out)
	return out, err
}

// Credentials lists the remote wallet's credentials.
func (c *Client) Credentials() ([]map[string]any, error) {
	var out []map[string]any
	err := c.do(http.MethodGet, "/api/credentials", nil, &out)
	return out, err
}

// Credential returns one credential by ID.
func (c *Client) Credential(id string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/credentials/"+id, nil, &out)
	return out, err
}

// ImportCredential imports a raw credential string.
func (c *Client) ImportCredential(raw string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPost, "/api/credentials", raw, &out)
	return out, err
}

// RemoveCredential deletes one credential by ID.
func (c *Client) RemoveCredential(id string) error {
	return c.do(http.MethodDelete, "/api/credentials/"+id, nil, nil)
}

// RemoveAllCredentials deletes all credentials and returns the count.
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

// GeneratePID regenerates the default PID credentials.
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

// Log returns the remote wallet's interaction log as raw JSON.
func (c *Client) Log() ([]byte, error) {
	var out []byte
	err := c.do(http.MethodGet, "/api/log", nil, &out)
	return out, err
}

// Templates lists all credential templates.
func (c *Client) Templates() ([]map[string]any, error) {
	var out []map[string]any
	err := c.do(http.MethodGet, "/api/templates", nil, &out)
	return out, err
}

// Template returns one template by name.
func (c *Client) Template(name string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/templates/"+name, nil, &out)
	return out, err
}

// PutTemplate creates or replaces a user template.
func (c *Client) PutTemplate(name string, doc any) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPut, "/api/templates/"+name, doc, &out)
	return out, err
}

// DeleteTemplate deletes a user template.
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

// Present sends a presentation request URI to the remote wallet.
func (c *Client) Present(uri string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPost, "/api/presentations", map[string]any{"uri": uri}, &out)
	return out, err
}

// AcceptOffer sends a credential offer URI to the remote wallet. An offer
// whose pre-authorized grant requires a transaction code needs txCode. An
// empty one is left out so the wallet keeps whatever it already holds.
func (c *Client) AcceptOffer(uri, txCode string) (map[string]any, error) {
	var out map[string]any
	body := map[string]any{"uri": uri}
	if txCode != "" {
		body["tx_code"] = txCode
	}
	// An issuer can defer the credential, and the wallet polls for it, so this
	// call waits as long as the wallet server is willing to.
	err := c.doWithTimeout(config.SlowRequestTimeout, http.MethodPost, "/api/offers", body, &out)
	return out, err
}

// OfferStatus reports how an offer that paused for an interactive sign-in
// ended. The id comes from the offer_id of the authorization_required
// response.
func (c *Client) OfferStatus(id string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/offers/"+id, nil, &out)
	return out, err
}

// DeferredIssuances lists the credentials the remote wallet is still
// collecting from their issuers.
func (c *Client) DeferredIssuances() ([]map[string]any, error) {
	var out []map[string]any
	err := c.do(http.MethodGet, "/api/deferred", nil, &out)
	return out, err
}

// CollectDeferred asks the remote wallet to make one deferred credential
// request now, rather than at the next scheduled attempt.
func (c *Client) CollectDeferred(id string) (map[string]any, error) {
	var out map[string]any
	err := c.doWithTimeout(config.SlowRequestTimeout, http.MethodPost, "/api/deferred/"+id+"/collect", nil, &out)
	return out, err
}

// AbandonDeferred stops the remote wallet collecting a deferred credential.
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

// Shutdown asks the remote wallet server to exit.
func (c *Client) Shutdown() error {
	return c.do(http.MethodPost, "/api/shutdown", nil, nil)
}
