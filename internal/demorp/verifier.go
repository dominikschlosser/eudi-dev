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

package demorp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/internal/validate"
)

// PIDVCT is the SD-JWT PID type the demo wallet holds by default.
const PIDVCT = "urn:eudi:pid:de:1"

// requestState tracks one verification request from creation to result.
type requestState struct {
	id       string
	queryID  string
	nonce    string
	clientID string
	expires  time.Time

	status string // pending | verified | failed
	err    string
	claims map[string]any
	checks []map[string]any
}

// VerifierHandler returns the demo verifier, meant to be mounted with the
// /verifier prefix stripped.
func (d *DemoRP) VerifierHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.serveStatic("static/verifier.html"))
	mux.HandleFunc("POST /api/requests", d.handleCreateRequest)
	mux.HandleFunc("GET /api/requests/{id}", d.handleRequestStatus)
	mux.HandleFunc("POST /response/{id}", d.handlePresentationResponse)
	return mux
}

type createRequestBody struct {
	Type string `json:"type"` // "ticket" (default) or "pid"
}

func (d *DemoRP) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body createRequestBody
	if err := decodeJSONBody(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	var vct string
	var claims []string
	switch body.Type {
	case "", "ticket":
		body.Type = "ticket"
		vct = TicketVCT
		claims = []string{"event", "tier", "seat", "given_name", "family_name"}
	case "pid":
		vct = PIDVCT
		claims = []string{"given_name", "family_name"}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be ticket or pid"})
		return
	}

	base := d.baseURL()
	req := &requestState{
		id:      randToken(),
		queryID: body.Type,
		nonce:   randToken(),
		status:  "pending",
		expires: time.Now().Add(entryTTL),
	}
	responseURI := base + "/verifier/response/" + req.id
	req.clientID = "redirect_uri:" + responseURI

	d.mu.Lock()
	d.pruneLocked()
	if len(d.requests) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open requests, try again later"})
		return
	}
	d.requests[req.id] = req
	d.mu.Unlock()

	dcqlClaims := make([]map[string]any, 0, len(claims))
	for _, c := range claims {
		dcqlClaims = append(dcqlClaims, map[string]any{"path": []string{c}})
	}
	dcql, err := json.Marshal(map[string]any{
		"credentials": []map[string]any{{
			"id":     req.queryID,
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []string{vct}},
			"claims": dcqlClaims,
		}},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	params := url.Values{
		"client_id":     {req.clientID},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {responseURI},
		"nonce":         {req.nonce},
		"state":         {req.id},
		"dcql_query":    {string(dcql)},
	}.Encode()

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         req.id,
		"wallet_url": base + "/authorize?" + params,
		"scheme_uri": "openid4vp://?" + params,
	})
}

func (d *DemoRP) handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d.mu.Lock()
	req, ok := d.requests[id]
	var doc map[string]any
	if ok {
		doc = map[string]any{
			"status": req.status,
			"claims": req.claims,
			"checks": req.checks,
		}
		if req.err != "" {
			doc["error"] = req.err
		}
	}
	d.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired request"})
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

// handlePresentationResponse is the direct_post response endpoint: it
// receives the vp_token, verifies it, and redirects the wallet's browser
// back to the verifier page.
func (d *DemoRP) handlePresentationResponse(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	id := r.PathValue("id")

	d.mu.Lock()
	req, ok := d.requests[id]
	if ok && time.Now().After(req.expires) {
		delete(d.requests, id)
		ok = false
	}
	d.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired request"})
		return
	}

	if err := r.ParseForm(); err != nil {
		d.finishRequest(req, nil, nil, fmt.Errorf("parsing response form: %w", err))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	claims, checks, err := d.verifyPresentation(req, r.PostFormValue("vp_token"))
	d.finishRequest(req, claims, checks, err)

	// Same-device UX: send the wallet's browser back to the verifier page,
	// which shows the result for this request.
	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_uri": d.baseURL() + "/verifier/?result=" + url.QueryEscape(id),
	})
}

func (d *DemoRP) finishRequest(req *requestState, claims map[string]any, checks []map[string]any, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	req.claims = claims
	req.checks = checks
	if err != nil {
		req.status = "failed"
		req.err = err.Error()
		return
	}
	req.status = "verified"
	req.err = ""
}

// verifyPresentation validates a vp_token holding one SD-JWT+KB
// presentation: issuer signature anchored in the wallet CA, key binding JWT
// signed by the cnf key, sd_hash over the presented credential, and the
// nonce and audience of this request.
func (d *DemoRP) verifyPresentation(req *requestState, vpToken string) (map[string]any, []map[string]any, error) {
	var checks []map[string]any
	check := func(name string, err error) error {
		entry := map[string]any{"name": name, "ok": err == nil}
		if err != nil {
			entry["error"] = err.Error()
		}
		checks = append(checks, entry)
		return err
	}

	if strings.TrimSpace(vpToken) == "" {
		return nil, checks, check("vp_token present", fmt.Errorf("the response carried no vp_token"))
	}
	var tokenDoc map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &tokenDoc); err != nil {
		return nil, checks, check("vp_token parses", fmt.Errorf("vp_token is not a JSON object of query id to presentations: %w", err))
	}
	presentations := tokenDoc[req.queryID]
	if err := check("vp_token holds the requested query id", errIf(len(presentations) == 0, "no presentation for query id %q", req.queryID)); err != nil {
		return nil, checks, err
	}

	token, err := sdjwt.Parse(presentations[0])
	if err = check("presentation parses as SD-JWT", err); err != nil {
		return nil, checks, err
	}

	// Issuer signature, anchored in the wallet CA via the x5c chain.
	caCert := d.wallet.CertChain[len(d.wallet.CertChain)-1]
	tlCerts := []trustlist.CertInfo{{
		Subject:   caCert.Subject.String(),
		PublicKey: caCert.PublicKey,
		Raw:       caCert.Raw,
	}}
	issuerKey, err := validate.ExtractAndValidateX5C(token.Header, tlCerts)
	if err == nil && issuerKey == nil {
		err = fmt.Errorf("the credential carries no x5c certificate chain")
	}
	if err = check("issuer certificate chains to the wallet CA", err); err != nil {
		return nil, checks, err
	}
	result := sdjwt.Verify(token, issuerKey)
	if err = check("issuer signature verifies", errIf(!result.SignatureValid, "issuer signature is invalid")); err != nil {
		return nil, checks, err
	}

	// Key binding JWT.
	kb := token.KeyBindingJWT
	if err = check("key binding JWT present", errIf(kb == nil, "the presentation has no key binding JWT")); err != nil {
		return nil, checks, err
	}
	cnf, _ := token.Payload["cnf"].(map[string]any)
	cnfJWK, _ := cnf["jwk"].(map[string]any)
	if err = check("credential is holder bound (cnf.jwk)", errIf(cnfJWK == nil, "the credential carries no cnf.jwk")); err != nil {
		return nil, checks, err
	}
	holderKey, err := holderKeyFromJWK(cnfJWK)
	if err = check("cnf.jwk parses", err); err != nil {
		return nil, checks, err
	}
	kbJWT, err := parseCompactJWT(kb.Raw)
	if err = check("key binding JWT parses", err); err != nil {
		return nil, checks, err
	}
	if err = check("key binding signature verifies with cnf key", errIf(!verifyES256(holderKey, kbJWT.signingInput, kbJWT.signature), "key binding signature is invalid")); err != nil {
		return nil, checks, err
	}

	// sd_hash covers everything up to and including the final ~.
	prefix := presentations[0][:strings.LastIndex(presentations[0], "~")+1]
	digest := sha256.Sum256([]byte(prefix))
	wantHash := base64.RawURLEncoding.EncodeToString(digest[:])
	gotHash, _ := kbJWT.payload["sd_hash"].(string)
	if err = check("sd_hash matches the presentation", errIf(gotHash != wantHash, "sd_hash does not match")); err != nil {
		return nil, checks, err
	}

	nonce, _ := kbJWT.payload["nonce"].(string)
	if err = check("nonce matches the request", errIf(nonce != req.nonce, "nonce mismatch")); err != nil {
		return nil, checks, err
	}
	aud, _ := kbJWT.payload["aud"].(string)
	if err = check("audience is this verifier", errIf(aud != req.clientID, "aud is %q, want %q", aud, req.clientID)); err != nil {
		return nil, checks, err
	}

	return disclosedClaims(token), checks, nil
}

func errIf(cond bool, format string, args ...any) error {
	if cond {
		return fmt.Errorf(format, args...)
	}
	return nil
}

// disclosedClaims returns the claims worth showing: resolved claims minus
// JWT plumbing.
func disclosedClaims(token *sdjwt.Token) map[string]any {
	internal := map[string]bool{
		"iss": true, "iat": true, "exp": true, "nbf": true, "cnf": true,
		"vct": true, "status": true, "_sd_alg": true, "_sd": true,
	}
	claims := make(map[string]any)
	for name, value := range token.ResolvedClaims {
		if !internal[name] {
			claims[name] = value
		}
	}
	claims["vct"] = token.ResolvedClaims["vct"]
	return claims
}
