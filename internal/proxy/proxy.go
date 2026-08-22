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

package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type proxyContextKey string

const (
	proxyStartContextKey       proxyContextKey = "proxy-start"
	proxyRequestBodyContextKey proxyContextKey = "proxy-request-body"
	proxyOriginalURLContextKey proxyContextKey = "proxy-original-url"
	proxyDebugJWEKeyContextKey proxyContextKey = "proxy-debug-jwe-key"
)

// Config holds the configuration for the debugging reverse proxy.
type Config struct {
	TargetURL     *url.URL
	ProxyPort     int
	DashboardPort int
	NoDashboard   bool
	AllTraffic    bool // show all traffic including non-OID4VP/VCI requests
}

// Server is the OID4VP/VCI debugging reverse proxy.
type Server struct {
	config   Config
	store    *Store
	rewriter *Rewriter
	proxy    *httputil.ReverseProxy
	writer   EntryWriter
	classify *StatefulClassifier
	scanner  *OutputScanner // optional: scans subprocess stdout for keys/credentials
}

// NewServer creates a new debugging reverse proxy server.
func NewServer(cfg Config, writer EntryWriter) *Server {
	s := &Server{
		config:   cfg,
		store:    NewStore(1000),
		writer:   writer,
		classify: NewStatefulClassifier(),
	}

	proxyHost := fmt.Sprintf("localhost:%d", cfg.ProxyPort)
	targetHost := cfg.TargetURL.Host
	s.rewriter = NewRewriter(targetHost, proxyHost)

	s.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			in, out := pr.In, pr.Out
			forwardedHost := in.Header.Get("X-Forwarded-Host")
			if forwardedHost == "" {
				forwardedHost = in.Host
			}
			forwardedProto := in.Header.Get("X-Forwarded-Proto")
			if forwardedProto == "" {
				if in.TLS != nil {
					forwardedProto = "https"
				} else {
					forwardedProto = "http"
				}
			}
			forwardedPort := in.Header.Get("X-Forwarded-Port")
			if forwardedPort == "" {
				forwardedPort = forwardedPortForProto(forwardedProto)
			}
			out.URL.Scheme = cfg.TargetURL.Scheme
			out.URL.Host = cfg.TargetURL.Host
			out.Host = cfg.TargetURL.Host
			out.Header.Set("X-Forwarded-Host", forwardedHost)
			out.Header.Set("X-Forwarded-Proto", forwardedProto)
			out.Header.Set("X-Forwarded-Port", forwardedPort)
		},
		ModifyResponse: s.modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy: backend error for %q %q: %v", r.Method, r.URL.Path, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	return s
}

// SetScanner sets the output scanner for detecting keys/credentials from
// a proxied service's stdout.
func (s *Server) SetScanner(scanner *OutputScanner) {
	s.scanner = scanner
}

// Store returns the traffic store for use by the dashboard.
func (s *Server) Store() *Store {
	return s.store
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Capture original URL before the Director rewrites it to the target.
	// Reconstruct from the incoming request or honour existing forwarding headers
	// (e.g. when behind another reverse proxy).
	origURL := originalURL(r)

	// Capture request body
	var reqBody string
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			reqBody = string(bodyBytes)
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	// Capture and strip debug JWE key header before forwarding.
	debugJWEKey := r.Header.Get("X-Debug-JWE-CEK")
	r.Header.Del("X-Debug-JWE-CEK")

	ctx := r.Context()
	ctx = context.WithValue(ctx, proxyStartContextKey, start)
	ctx = context.WithValue(ctx, proxyRequestBodyContextKey, reqBody)
	ctx = context.WithValue(ctx, proxyOriginalURLContextKey, origURL)
	ctx = context.WithValue(ctx, proxyDebugJWEKeyContextKey, debugJWEKey)
	r = r.WithContext(ctx)

	s.proxy.ServeHTTP(w, r)
}

// originalURL reconstructs the URL the client originally requested.
// It honours X-Forwarded-Host / X-Forwarded-Proto if present (i.e. when
// the proxy itself sits behind another reverse proxy), otherwise it falls
// back to the incoming Host header and request URI.
func originalURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	return scheme + "://" + host + r.RequestURI
}

func forwardedPortForProto(proto string) string {
	if strings.EqualFold(proto, "https") {
		return "443"
	}
	return "80"
}

func (s *Server) modifyResponse(resp *http.Response) error {
	start := time.Now()
	if value, ok := resp.Request.Context().Value(proxyStartContextKey).(time.Time); ok {
		start = value
	}
	reqBody, _ := resp.Request.Context().Value(proxyRequestBodyContextKey).(string)
	origURL, _ := resp.Request.Context().Value(proxyOriginalURLContextKey).(string)
	debugJWEKey, _ := resp.Request.Context().Value(proxyDebugJWEKeyContextKey).(string)

	// Read response body
	var respBody string
	if resp.Body != nil {
		var reader io.ReadCloser
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			gz, err := gzip.NewReader(resp.Body)
			if err == nil {
				reader = gz
				resp.Header.Del("Content-Encoding")
				resp.Header.Del("Content-Length")
			} else {
				reader = resp.Body
			}
		default:
			reader = resp.Body
		}

		bodyBytes, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			// Body was consumed/closed. Provide an empty replacement so the
			// ReverseProxy does not try to copy from the closed original.
			resp.Body = io.NopCloser(strings.NewReader(""))
			resp.ContentLength = 0
		} else {
			respBody = string(bodyBytes)

			// Rewrite URLs in response
			contentType := resp.Header.Get("Content-Type")
			rewritten := s.rewriter.RewriteBody(respBody, contentType)
			s.rewriter.RewriteHeaders(resp.Header)

			resp.Body = io.NopCloser(strings.NewReader(rewritten))
			resp.ContentLength = int64(len(rewritten))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
		}
	}

	duration := time.Since(start)

	// Use the original URL (before Director rewrite) for display
	displayURL := origURL
	if displayURL == "" {
		displayURL = resp.Request.URL.String()
	}

	// Fall back to scanner-detected CEK if no debug header was present
	if debugJWEKey == "" && s.scanner != nil {
		debugJWEKey = s.scanner.LastCEK()
	}

	// Fall back to scanner-detected JWK private key for ECDH-ES decryption
	var debugJWK string
	if s.scanner != nil {
		debugJWK = s.scanner.LastJWK()
	}

	entry := &TrafficEntry{
		Timestamp:       start,
		Method:          resp.Request.Method,
		URL:             displayURL,
		RequestHeaders:  resp.Request.Header.Clone(),
		RequestBody:     reqBody,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: resp.Header.Clone(),
		ResponseBody:    respBody,
		Duration:        duration,
		DurationMS:      duration.Milliseconds(),
		DebugJWEKey:     debugJWEKey,
		DebugJWK:        debugJWK,
	}

	if s.classify != nil {
		s.classify.Classify(entry)
	} else {
		Classify(entry)
	}
	if !shouldEmitEntry(entry, s.config.AllTraffic) {
		return nil
	}

	s.store.Add(entry)

	if s.writer != nil {
		s.writer.WriteEntry(entry)
	}

	return nil
}

func shouldEmitEntry(entry *TrafficEntry, allTraffic bool) bool {
	return allTraffic || entry.Class != ClassUnknown
}
