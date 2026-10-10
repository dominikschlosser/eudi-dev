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

package format

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

// ProxyFunc picks the forward proxy for a remote request, like http.Transport.Proxy.
type ProxyFunc func(*http.Request) (*url.URL, error)

// ProxySettings overrides HTTP_PROXY, HTTPS_PROXY and NO_PROXY. Each non-empty field
// replaces its variable.
type ProxySettings struct {
	HTTPProxy  string
	HTTPSProxy string
	NoProxy    string
}

// NewProxyFunc reads the proxy environment variables and applies the overrides.
func NewProxyFunc(overrides ProxySettings) (ProxyFunc, error) {
	cfg := httpproxy.FromEnvironment()
	for _, o := range []struct {
		value  string
		target *string
	}{
		{overrides.HTTPProxy, &cfg.HTTPProxy},
		{overrides.HTTPSProxy, &cfg.HTTPSProxy},
	} {
		if value := strings.TrimSpace(o.value); value != "" {
			if err := validateProxyURL(value); err != nil {
				return nil, err
			}
			*o.target = value
		}
	}
	if noProxy := strings.TrimSpace(overrides.NoProxy); noProxy != "" {
		cfg.NoProxy = noProxy
	}
	pick := cfg.ProxyFunc()
	return func(req *http.Request) (*url.URL, error) {
		return pick(req.URL)
	}, nil
}

// ProxyURLs returns the forward proxies of the environment variables with the
// overrides applied. A proxy without a scheme uses http, as in NewProxyFunc.
func ProxyURLs(overrides ProxySettings) []string {
	cfg := httpproxy.FromEnvironment()
	var urls []string
	for _, proxy := range []string{
		firstNonBlank(overrides.HTTPProxy, cfg.HTTPProxy),
		firstNonBlank(overrides.HTTPSProxy, cfg.HTTPSProxy),
	} {
		if proxy == "" {
			continue
		}
		if !strings.Contains(proxy, "://") {
			proxy = "http://" + proxy
		}
		urls = append(urls, proxy)
	}
	return urls
}

func firstNonBlank(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func validateProxyURL(raw string) error {
	withScheme := raw
	if !strings.Contains(raw, "://") {
		// httpproxy accepts a bare host:port and assumes http.
		withScheme = "http://" + raw
	}
	parsed, err := url.Parse(withScheme)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("invalid proxy URL %q", raw)
	}
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
		return nil
	default:
		return fmt.Errorf("invalid proxy URL %q: scheme must be http, https, socks5 or socks5h", raw)
	}
}
