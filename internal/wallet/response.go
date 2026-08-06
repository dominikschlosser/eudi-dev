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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/format"
)

// SubmitDirectPostObject submits an authorization response object via direct_post.
func SubmitDirectPostObject(responseURI string, payload map[string]any) (*DirectPostResult, error) {
	form := url.Values{}
	for key, value := range payload {
		switch key {
		case "vp_token":
			tokenJSON, err := json.Marshal(value)
			if err != nil {
				return nil, fmt.Errorf("marshaling vp_token: %w", err)
			}
			form.Set(key, string(tokenJSON))
		case "id_token", "state", "error", "error_description":
			if text, ok := value.(string); ok && text != "" {
				form.Set(key, text)
			}
		}
	}

	resp, err := format.HTTPClientForURL(responseURI).PostForm(responseURI, form)
	if err != nil {
		return nil, fmt.Errorf("posting to response_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := format.ReadRemoteBody(resp.Body, "verifier response")
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	result := &DirectPostResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}
	if err := applyVerifierResponse(result, resp.Header, body); err != nil {
		return nil, err
	}

	return result, nil
}

// SubmitDirectPost submits a VP token and optional id_token via direct_post to the response URI.
func SubmitDirectPost(responseURI, state string, vpToken any, idToken string) (*DirectPostResult, error) {
	return SubmitDirectPostObject(responseURI, buildPlainAuthorizationResponse(vpToken, idToken, state))
}

// SubmitDirectPostError submits an authorization error response via direct_post.
func SubmitDirectPostError(responseURI, state, errorCode, errorDescription string) (*DirectPostResult, error) {
	return SubmitDirectPostObject(responseURI, buildPlainAuthorizationErrorResponse(errorCode, errorDescription, state))
}

// DirectPostResult represents the result of a direct_post submission.
type DirectPostResult struct {
	StatusCode  int    `json:"status_code"`
	Body        string `json:"body"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// SubmitDirectPostJWT submits an encrypted JARM response via direct_post.jwt.
// The vp_token and state are inside the encrypted responseJWT payload.
// If cek is non-nil, it is included as X-Debug-JWE-CEK header for proxy debugging.
func SubmitDirectPostJWT(responseURI string, responseJWT string, cek []byte) (*DirectPostResult, error) {
	form := url.Values{}
	form.Set("response", responseJWT)

	req, err := http.NewRequest("POST", responseURI, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if len(cek) > 0 {
		cekB64 := base64.RawURLEncoding.EncodeToString(cek)
		req.Header.Set("X-Debug-JWE-CEK", cekB64)
		log.Printf("[VP] JWE content encryption key for proxy debugging: %s", cekB64)
	}

	resp, err := format.HTTPClientForURL(responseURI).Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting to response_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := format.ReadRemoteBody(resp.Body, "verifier response")
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	result := &DirectPostResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}
	if err := applyVerifierResponse(result, resp.Header, body); err != nil {
		return nil, err
	}

	return result, nil
}

// BuildFragmentRedirect constructs a redirect URL with vp_token, optional id_token, and state as
// fragment parameters per OID4VP 1.0 fragment response mode.
func BuildFragmentRedirect(redirectURI, state string, vpToken any, idToken string) (string, error) {
	fragment := url.Values{}
	if vpToken != nil {
		tokenJSON, err := json.Marshal(vpToken)
		if err != nil {
			return "", fmt.Errorf("marshaling vp_token: %w", err)
		}
		fragment.Set("vp_token", string(tokenJSON))
	}
	if idToken != "" {
		fragment.Set("id_token", idToken)
	}
	if state != "" {
		fragment.Set("state", state)
	}

	return redirectURI + "#" + fragment.Encode(), nil
}

// BuildFragmentErrorRedirect constructs a redirect URL with authorization error
// parameters as fragment members per OID4VP 1.0 fragment response mode.
func BuildFragmentErrorRedirect(redirectURI, state, errorCode, errorDescription string) string {
	fragment := url.Values{}
	fragment.Set("error", errorCode)
	if errorDescription != "" {
		fragment.Set("error_description", errorDescription)
	}
	if state != "" {
		fragment.Set("state", state)
	}
	return redirectURI + "#" + fragment.Encode()
}

// FormatDirectPostResult formats a direct post result for terminal output.
func FormatDirectPostResult(result *DirectPostResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Response: %d", result.StatusCode)
	if result.RedirectURI != "" {
		fmt.Fprintf(&sb, " → %s", result.RedirectURI)
	}
	return sb.String()
}

func applyVerifierResponse(result *DirectPostResult, headers http.Header, body []byte) error {
	if len(body) > 0 {
		var respJSON map[string]any
		if err := json.Unmarshal(body, &respJSON); err == nil {
			if redirectURI, ok := respJSON["redirect_uri"].(string); ok && redirectURI != "" {
				if err := validateAbsoluteURI("redirect_uri", redirectURI); err != nil {
					return err
				}
				result.RedirectURI = redirectURI
			}
		}
	}

	if loc := headers.Get("Location"); loc != "" {
		if err := validateAbsoluteURI("Location", loc); err != nil {
			return err
		}
		result.RedirectURI = loc
	}

	return nil
}
