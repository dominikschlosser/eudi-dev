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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/internal/httpsec"
	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/internal/statuslist"
	"github.com/dominikschlosser/eudi-dev/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/internal/validate"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

// PIDVCT and PIDDocType are what a PID request asks for, in each of the two
// formats the demo wallet holds a PID in. GermanPIDVCT is the national type
// that extends PIDVCT, which a request can ask for instead: a credential of
// it answers a request for PIDVCT, and never the other way round.
const (
	PIDVCT       = credtype.PIDVCT
	GermanPIDVCT = credtype.GermanPIDVCT
	PIDDocType   = credtype.PIDDocType
)

// requestState tracks one verification request from creation to result.
type requestState struct {
	id      string
	queryID string
	vct     string
	// docType is set for a request that also accepts the mdoc PID, and want
	// then holds the mdoc element names alongside the SD-JWT claim names.
	docType     string
	mdocQueryID string
	wantMDOC    []string
	want        []string // claim names the request asked for
	nonce       string
	clientID    string
	// interactiveEndpoint is set when this request was sent inside an
	// OpenID4VCI 1.1 §6 exchange. The presentation is then bound to that
	// Authorization Challenge Endpoint rather than to a client_id and a
	// response_uri (Appendix A.2.5, Appendix A.3.5).
	interactiveEndpoint string
	expires             time.Time
	answered            bool // a response was accepted, further ones are replays

	// requestObject is the signed JAR served from /verifier/request/{id}, and
	// encKey decrypts the direct_post.jwt response. Both are per request and
	// expire with it. HAIP requires the request to be signed and the response
	// encrypted, so a demo that is meant to model a real EUDI verifier needs
	// them even though a plain direct_post would be simpler.
	requestObject string
	encKey        *ecdsa.PrivateKey

	status string // pending | verified | failed
	err    string
	claims map[string]any
	checks []map[string]any
	// presentation is what the wallet actually returned in the vp_token: an
	// SD-JWT with its key binding JWT, or an mdoc DeviceResponse with its
	// device auth. It is kept whatever the outcome, because a presentation
	// that failed verification is the one worth looking at.
	presentation string
}

// queryIDs are the DCQL credential ids this request asked under, quoted for
// an error message.
func (r *requestState) queryIDs() []string {
	var ids []string
	for _, id := range []string{r.queryID, r.mdocQueryID} {
		if id != "" {
			ids = append(ids, fmt.Sprintf("%q", id))
		}
	}
	return ids
}

// VerifierHandler returns the demo verifier, meant to be mounted with the
// /verifier prefix stripped.
func (d *DemoRP) VerifierHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.serveStatic("static/verifier.html"))
	mux.HandleFunc("GET /verifier.js", d.serveStatic("static/verifier.js"))
	mux.HandleFunc("POST /api/requests", d.handleCreateRequest)
	mux.HandleFunc("GET /api/requests/{id}", d.handleRequestStatus)
	mux.HandleFunc("GET /request/{id}", d.handleRequestObject)
	mux.HandleFunc("POST /response/{id}", d.handlePresentationResponse)
	// Only /api/ is guarded, which is what the page itself calls. The
	// protocol endpoints below it are for wallets on other origins.
	return httpsec.GuardAPI(mux, d.baseURL())
}

// handleRequestObject serves the signed authorization request object that the
// wallet fetches through request_uri.
func (d *DemoRP) handleRequestObject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d.mu.Lock()
	req, ok := d.requests[id]
	var jar string
	if ok {
		jar = req.requestObject
		ok = !time.Now().After(req.expires)
	}
	d.mu.Unlock()
	if !ok || jar == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired request"})
		return
	}
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(jar))
}

type createRequestBody struct {
	Type string `json:"type"` // "ticket" (default) or "pid"
	// Format narrows a PID request to one credential format: "sd-jwt",
	// "mdoc", or "both" (the default). It does not apply to the ticket,
	// which the demo issuer only ever issues as an SD-JWT VC.
	Format string `json:"format"`
	// VCT names the PID type to ask for. Empty means the country-independent
	// urn:eudi:pid:1, which every PID answers. A domestic type such as
	// urn:eudi:pid:de:1 is answered only by a credential of that type, since
	// inheritance runs the other way.
	VCT string `json:"vct"`
}

// normalizePIDFormat maps what the API accepts onto the two formats a PID
// request can ask for. It returns whether each is wanted.
func normalizePIDFormat(format string) (sdjwt, mdoc bool, err error) {
	switch strings.TrimSpace(format) {
	case "", "both":
		return true, true, nil
	case "sd-jwt", "sdjwt", "dc+sd-jwt":
		return true, false, nil
	case "mdoc", "mso_mdoc":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("format must be sd-jwt, mdoc or both")
	}
}

// normalizePIDVCT checks the PID type a request asks for. An empty value is
// the country-independent PID. Anything outside the urn:eudi:pid: namespace is
// refused: PID_14 in Annex 2 of the ARF puts every PID type in it, so a value
// outside is not a PID type at all and nothing in this demo could answer it.
func normalizePIDVCT(vct string) (string, error) {
	vct = strings.TrimSpace(vct)
	if vct == "" {
		return PIDVCT, nil
	}
	if !strings.HasPrefix(vct, credtype.PIDVCTPrefix) {
		return "", fmt.Errorf("vct must be a PID type in %s", credtype.PIDVCTPrefix)
	}
	return vct, nil
}

func (d *DemoRP) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body createRequestBody
	if err := decodeJSONBody(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	var vct, docType string
	var claims, mdocClaims []string
	switch body.Type {
	case "", "ticket":
		body.Type = "ticket"
		wantSDJWT, _, err := normalizePIDFormat(body.Format)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// There is no mdoc ticket, so asking for one would promise something
		// no wallet can answer.
		if !wantSDJWT {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the demo ticket only exists as an SD-JWT VC"})
			return
		}
		vct = TicketVCT
		claims = []string{"event", "tier", "seat", "given_name", "family_name"}
	case "pid":
		// A PID exists in both formats, and a verifier that only knows one of
		// them turns a wallet's format choice into a failure. By default the
		// request asks for either and the wallet answers with what it holds.
		// Asking for one format on purpose is what shows a wallet refusing a
		// request it cannot satisfy.
		wantSDJWT, wantMDOC, err := normalizePIDFormat(body.Format)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		requested, err := normalizePIDVCT(body.VCT)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// A domestic PID type exists only in SD-JWT VC. ISO/IEC 18013-5 has no
		// inheritance between document types, so every PID carries the same
		// doctype and the national elements sit in a second namespace: a
		// doctype request for a national PID would be answered by any PID at
		// all, which would teach the opposite of the truth.
		domestic := requested != PIDVCT
		if domestic && wantMDOC && !wantSDJWT {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "a credential type has no mdoc form: every PID carries the doctype " + PIDDocType + ", so ask for the PID in mdoc instead",
			})
			return
		}
		if wantSDJWT {
			vct = requested
			claims = []string{"given_name", "family_name"}
		}
		if wantMDOC && !domestic {
			docType = PIDDocType
			mdocClaims = []string{"given_name", "family_name"}
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be ticket or pid"})
		return
	}

	base := d.baseURL()
	req := &requestState{
		id:       randToken(),
		vct:      vct,
		docType:  docType,
		want:     claims,
		wantMDOC: mdocClaims,
		nonce:    randToken(),
		status:   "pending",
		expires:  time.Now().Add(entryTTL),
	}
	// A query id per format the request asks for. An mdoc-only request has no
	// SD-JWT query id at all, so nothing invites an answer in a format the
	// request did not ask for.
	if vct != "" {
		req.queryID = body.Type
	}
	if docType != "" {
		req.mdocQueryID = body.Type + "_mdoc"
	}
	responseURI := base + "/verifier/response/" + req.id

	// The client identifier is the hash of the signing certificate, which is
	// what makes it verifiable without a trust list and what HAIP requires
	// (redirect_uri: is not an accepted prefix, and it cannot be combined
	// with a signed request object anyway).
	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil || len(chain) == 0 {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "no signing certificate available"})
		return
	}
	req.clientID = wallet.X509HashClientID(chain[0])

	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "generating response encryption key: " + err.Error()})
		return
	}
	req.encKey = encKey

	credentials := make([]map[string]any, 0, 2)
	if req.queryID != "" {
		dcqlClaims := make([]map[string]any, 0, len(claims))
		for _, c := range claims {
			dcqlClaims = append(dcqlClaims, map[string]any{"path": []string{c}})
		}
		credentials = append(credentials, map[string]any{
			"id":     req.queryID,
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []string{vct}},
			"claims": dcqlClaims,
		})
	}
	if req.mdocQueryID != "" {
		// mdoc claim paths are [namespace, element].
		mdocDCQLClaims := make([]map[string]any, 0, len(mdocClaims))
		for _, c := range mdocClaims {
			mdocDCQLClaims = append(mdocDCQLClaims, map[string]any{"path": []string{docType, c}})
		}
		credentials = append(credentials, map[string]any{
			"id":     req.mdocQueryID,
			"format": "mso_mdoc",
			"meta":   map[string]any{"doctype_value": docType},
			"claims": mdocDCQLClaims,
		})
	}
	dcql := map[string]any{"credentials": credentials}

	if req.queryID != "" && req.mdocQueryID != "" {
		// One credential set with two options: either format satisfies it, and
		// the wallet picks whichever it holds. Without the set both listed
		// credentials would be required, which no wallet holding one format
		// could answer.
		dcql["credential_sets"] = []map[string]any{{
			"options": [][]string{{req.queryID}, {req.mdocQueryID}},
		}}
	}

	// The purpose this verifier registered for the request, carried in a
	// wallet-relying-party registration certificate (rc-wrp+jwt, ETSI TS
	// 119 475) in verifier_info (OpenID4VP 1.0 §5.1), which is where the
	// wallet's consent dialog reads it from.
	purpose := "Admission to the demo event: checking your ticket"
	if body.Type == "pid" {
		purpose = "Confirming your identity for the demo"
	}
	now := time.Now()
	registration, err := wallet.SignRegistrationCertificateJWT(map[string]any{
		"sub":     "EUDI-DEV-DEMO-VERIFIER",
		"name":    "Demo Verifier",
		"iat":     now.Unix(),
		"purpose": []map[string]any{{"lang": "en", "value": purpose}},
	}, d.wallet.IssuerKey, chain)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "signing registration certificate: " + err.Error()})
		return
	}

	// Signed request object. Everything the wallet needs is inside it,
	// including the key it encrypts the response to.
	jar, err := wallet.SignRequestObjectJWT(map[string]any{
		"iss":             req.clientID,
		"aud":             "https://self-issued.me/v2",
		"iat":             now.Unix(),
		"exp":             req.expires.Unix(),
		"client_id":       req.clientID,
		"response_type":   "vp_token",
		"response_mode":   "direct_post.jwt",
		"response_uri":    responseURI,
		"nonce":           req.nonce,
		"state":           req.id,
		"dcql_query":      dcql,
		"client_metadata": responseEncryptionMetadata(encKey),
		"verifier_info": []map[string]any{{
			"format": "registration_cert",
			"data":   registration,
		}},
	}, d.wallet.IssuerKey, chain)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "signing request object: " + err.Error()})
		return
	}
	req.requestObject = jar

	d.mu.Lock()
	d.pruneLocked()
	if len(d.requests) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open requests, try again later"})
		return
	}
	d.requests[req.id] = req
	d.mu.Unlock()

	// By reference rather than inline: the signed object is far too long for
	// a scheme URI or a QR code.
	params := url.Values{
		"client_id":   {req.clientID},
		"request_uri": {base + "/verifier/request/" + req.id},
	}.Encode()

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         req.id,
		"wallet_url": base + "/authorize?" + params,
		"scheme_uri": "openid4vp://?" + params,
	})
}

// checkPresentationAudience holds a Key Binding JWT to the party that asked for
// it: the client_id over OpenID4VP, the Authorization Challenge Endpoint inside
// an Interactive Authorization exchange.
//
// Both `ia:` forms are accepted there. OpenID4VCI 1.1 Appendix A.3.5 asks for
// "the derived Origin ... of the Authorization Challenge Endpoint" while its
// own example, its sibling appendices and §6.2.1.5 all name the endpoint, so a
// wallet reading either sentence is answered rather than refused. What this
// does not accept is an audience naming somebody else.
func checkPresentationAudience(req *requestState, aud string) error {
	if req.interactiveEndpoint == "" {
		return errIf(aud != req.clientID, "aud is %q, want %q", aud, req.clientID)
	}
	endpoint := "ia:" + req.interactiveEndpoint
	origin := "ia:" + originOf(req.interactiveEndpoint)
	return errIf(aud != endpoint && aud != origin, "aud is %q, want %q", aud, endpoint)
}

// rebuildSessionTranscript recomputes what the holder signed over, which for an
// Interactive Authorization presentation is the handover of OpenID4VCI 1.1
// Appendix A.2.5 rather than the OpenID4VP one.
func (d *DemoRP) rebuildSessionTranscript(req *requestState) ([]byte, error) {
	if req.interactiveEndpoint != "" {
		// ia_post: the response is unencrypted, so the third element is null.
		return wallet.BuildOID4VCIIAESessionTranscript(req.interactiveEndpoint, req.nonce, nil)
	}
	return wallet.BuildOID4VPSessionTranscript(
		req.clientID, req.nonce, encryptionJWKThumbprint(req.encKey), d.baseURL()+"/verifier/response/"+req.id)
}

// originOf is the derived origin of a URL as RFC 6454 §4 defines it.
func originOf(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// responseEncryptionMetadata publishes the public half of the per-request
// encryption key. The wallet refuses direct_post.jwt without a usable JWK,
// and requires an explicit alg on it.
func responseEncryptionMetadata(key *ecdsa.PrivateKey) map[string]any {
	return map[string]any{
		"jwks": map[string]any{
			"keys": []map[string]any{{
				"kty": "EC",
				"crv": "P-256",
				"use": "enc",
				"alg": "ECDH-ES",
				"kid": "demo-verifier-response-enc",
				"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
				"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
			}},
		},
		// HAIP 1.0 §5: "Verifiers MUST list both A128GCM and A256GCM in
		// encrypted_response_enc_values_supported in their client metadata."
		"encrypted_response_enc_values_supported": []string{"A128GCM", "A256GCM"},
		"vp_formats_supported": map[string]any{
			"dc+sd-jwt": map[string]any{
				"sd-jwt_alg_values": []string{"ES256"},
				"kb-jwt_alg_values": []string{"ES256"},
			},
			// OID4VP 1.0 Appendix B.2.2 names these two members for mso_mdoc,
			// and their values are COSE algorithm identifiers rather than the
			// JOSE names used for JWTs (-7 is ES256).
			"mso_mdoc": map[string]any{
				"issuerauth_alg_values": []int{-7},
				"deviceauth_alg_values": []int{-7},
			},
		},
	}
}

func (d *DemoRP) handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d.mu.Lock()
	req, ok := d.requests[id]
	var doc map[string]any
	if ok {
		status := req.status
		// A request nobody answered stops being pending once it expires.
		// Without this the page polls a dead request forever, which is most
		// of the traffic an abandoned tab produces.
		if status == "pending" && time.Now().After(req.expires) {
			status = "expired"
		}
		doc = map[string]any{
			"status": status,
			"claims": req.claims,
			"checks": req.checks,
		}
		// So the page can offer it to the decoder: what arrived, exactly as it
		// arrived, key binding and device auth included.
		if req.presentation != "" {
			doc["presentation"] = req.presentation
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

// handlePresentationResponse is the direct_post.jwt response endpoint: it
// receives the encrypted response, decrypts it, verifies the vp_token, and
// redirects the wallet's browser back to the verifier page.
func (d *DemoRP) handlePresentationResponse(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	id := r.PathValue("id")

	d.mu.Lock()
	req, ok := d.requests[id]
	if ok && time.Now().After(req.expires) {
		delete(d.requests, id)
		ok = false
	}
	replay := ok && req.answered
	if ok && !replay {
		req.answered = true
	}
	d.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired request"})
		return
	}
	if replay {
		// The nonce is fixed per request, so a captured response would
		// otherwise verify again. One request, one answer.
		writeJSON(w, http.StatusConflict, map[string]string{"error": "this request was already answered"})
		return
	}

	if err := r.ParseForm(); err != nil {
		d.finishRequest(req, nil, nil, fmt.Errorf("parsing response form: %w", err))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	vpToken, err := decryptResponse(req, r.PostForm)
	if err != nil {
		d.finishRequest(req, nil, nil, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	claims, checks, err := d.verifyPresentation(req, vpToken)
	d.finishRequest(req, claims, checks, err)

	// Same-device UX: send the wallet's browser back to the verifier page,
	// which shows the result for this request.
	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_uri": d.baseURL() + "/verifier/?result=" + url.QueryEscape(id),
	})
}

// decryptResponse unwraps a direct_post.jwt response and returns the
// vp_token. The state inside the JWE is checked against the request, so a
// response encrypted for one request cannot be posted to another.
func decryptResponse(req *requestState, form url.Values) (string, error) {
	encrypted := strings.TrimSpace(form.Get("response"))
	if encrypted == "" {
		return "", fmt.Errorf("the response carried no encrypted response parameter (direct_post.jwt was requested)")
	}
	if req.encKey == nil {
		return "", fmt.Errorf("this request has no response encryption key")
	}

	plaintext, err := wallet.DecryptCompactJWE(encrypted, req.encKey)
	if err != nil {
		return "", fmt.Errorf("decrypting the response: %w", err)
	}

	var payload struct {
		VPToken any    `json:"vp_token"`
		State   string `json:"state"`
	}
	if err := json.Unmarshal([]byte(plaintext), &payload); err != nil {
		return "", fmt.Errorf("parsing the decrypted response: %w", err)
	}
	if payload.State != "" && payload.State != req.id {
		return "", fmt.Errorf("the decrypted response is for a different request")
	}
	if payload.VPToken == nil {
		return "", fmt.Errorf("the decrypted response carried no vp_token")
	}

	// vp_token is a JSON object keyed by query id, which verifyPresentation
	// already parses. Re-encode whatever shape arrived.
	raw, err := json.Marshal(payload.VPToken)
	if err != nil {
		return "", fmt.Errorf("re-encoding the vp_token: %w", err)
	}
	return string(raw), nil
}

// recordPresentation keeps what the wallet returned, so the page can hand it
// to the decoder however the verification turns out.
func (d *DemoRP) recordPresentation(req *requestState, presentation string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	req.presentation = presentation
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
	log := &checklist{}
	check := log.record

	if strings.TrimSpace(vpToken) == "" {
		return nil, log.entries, check("vp_token present", fmt.Errorf("the response carried no vp_token"))
	}
	var tokenDoc map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &tokenDoc); err != nil {
		return nil, log.entries, check("vp_token parses", fmt.Errorf("vp_token is not a JSON object of query id to presentations: %w", err))
	}
	// A PID request can offer both formats, so the wallet answers under
	// whichever query id it could satisfy.
	var presentations []string
	if req.queryID != "" {
		presentations = tokenDoc[req.queryID]
	}
	answeredMDOC := false
	if len(presentations) == 0 && req.mdocQueryID != "" {
		presentations = tokenDoc[req.mdocQueryID]
		answeredMDOC = len(presentations) > 0
	}
	if len(presentations) > 0 {
		// Recorded before anything is checked: a presentation that fails
		// verification is exactly the one someone will want to decode.
		d.recordPresentation(req, presentations[0])
	}
	if err := check("vp_token holds one of the requested query ids",
		errIf(len(presentations) == 0, "no presentation for query id %s", strings.Join(req.queryIDs(), " or "))); err != nil {
		return nil, log.entries, err
	}

	if err := check("vp_token holds exactly one presentation",
		errIf(len(presentations) != 1, "expected 1 presentation, got %d", len(presentations))); err != nil {
		return nil, log.entries, err
	}

	if answeredMDOC {
		return d.verifyMDOCPresentation(req, presentations[0], log)
	}

	token, err := sdjwt.Parse(presentations[0])
	if err = check("presentation parses as SD-JWT", err); err != nil {
		return nil, log.entries, err
	}

	if err = check("every disclosure is referenced by the credential", checkDisclosuresReferenced(token)); err != nil {
		return nil, log.entries, err
	}

	// Trusting the wallet to return the requested type would let any held
	// credential satisfy the request. A type extending the requested one is
	// accepted, because that is what the request asked for: a German PID
	// answers a request for the country-independent one, and says so in its
	// aka_vcts claim.
	gotVCT, _ := token.ResolvedClaims["vct"].(string)
	gotAka := credtype.AkaVCTs(token.ResolvedClaims)
	if err = check("credential type matches the request",
		errIf(!credtype.Answers(gotVCT, gotAka, req.vct), "vct is %q, requested %q", gotVCT, req.vct)); err != nil {
		return nil, log.entries, err
	}

	// HAIP 1.0 section 6.1.1 asks the issuer certificate to name the issuer,
	// so a verifier can tell that this certificate speaks for this iss. The
	// demo says so and carries on: the rule comes from the profile, and a
	// wallet still being brought into line is exactly who this demo is for.
	if certs, err := validate.X5CCertificates(token.Header); err == nil && len(certs) > 0 {
		iss, _ := token.ResolvedClaims["iss"].(string)
		if violations := validate.HAIPIssuerBinding(iss, certs); len(violations) > 0 {
			log.warn("issuer named in the signing certificate", fmt.Errorf("%s", strings.Join(violations, "; ")))
		} else {
			log.warn("issuer named in the signing certificate", nil)
		}
	}

	// Issuer signature. The CA this demo trusts is the one the built-in
	// issuer signs under, which is the root of the wallet's signing chain.
	// The check is named from the verifier's point of view: what it verifies
	// is that the issuer certificate chains to a CA it trusts.
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
	if err = check("issuer certificate chains to a trusted CA", err); err != nil {
		return nil, log.entries, err
	}
	result := sdjwt.Verify(token, issuerKey)
	if err = check("issuer signature verifies", errIf(!result.SignatureValid, "issuer signature is invalid")); err != nil {
		return nil, log.entries, err
	}
	if err = check("credential is within its validity period",
		errIf(result.Expired || result.NotYetValid, "credential is expired or not yet valid")); err != nil {
		return nil, log.entries, err
	}
	if err = d.checkRevocation(token, check); err != nil {
		return nil, log.entries, err
	}

	// Key binding JWT.
	kb := token.KeyBindingJWT
	if err = check("key binding JWT present", errIf(kb == nil, "the presentation has no key binding JWT")); err != nil {
		return nil, log.entries, err
	}
	cnf, _ := token.Payload["cnf"].(map[string]any)
	cnfJWK, _ := cnf["jwk"].(map[string]any)
	if err = check("credential is holder bound (cnf.jwk)", errIf(cnfJWK == nil, "the credential carries no cnf.jwk")); err != nil {
		return nil, log.entries, err
	}
	holderKey, err := holderKeyFromJWK(cnfJWK)
	if err = check("cnf.jwk parses", err); err != nil {
		return nil, log.entries, err
	}
	kbJWT, err := parseCompactJWT(kb.Raw)
	if err = check("key binding JWT parses", err); err != nil {
		return nil, log.entries, err
	}
	kbTyp, _ := kbJWT.header["typ"].(string)
	if err = check("key binding JWT is typed kb+jwt", errIf(kbTyp != "kb+jwt", "typ is %q", kbTyp)); err != nil {
		return nil, log.entries, err
	}
	if err = check("key binding signature verifies with cnf key", errIf(!verifyES256(holderKey, kbJWT.signingInput, kbJWT.signature), "key binding signature is invalid")); err != nil {
		return nil, log.entries, err
	}

	// sd_hash covers everything up to and including the final ~.
	prefix := presentations[0][:strings.LastIndex(presentations[0], "~")+1]
	digest := sha256.Sum256([]byte(prefix))
	wantHash := base64.RawURLEncoding.EncodeToString(digest[:])
	gotHash, _ := kbJWT.payload["sd_hash"].(string)
	if err = check("sd_hash matches the presentation", errIf(gotHash != wantHash, "sd_hash does not match")); err != nil {
		return nil, log.entries, err
	}

	nonce, _ := kbJWT.payload["nonce"].(string)
	if err = check("nonce matches the request", errIf(nonce != req.nonce, "nonce mismatch")); err != nil {
		return nil, log.entries, err
	}
	aud, _ := kbJWT.payload["aud"].(string)
	if err = check("audience is this verifier", checkPresentationAudience(req, aud)); err != nil {
		return nil, log.entries, err
	}

	disclosed := disclosedClaims(token)
	var missing []string
	for _, name := range req.want {
		if _, ok := disclosed[name]; !ok {
			missing = append(missing, name)
		}
	}
	if err = check("requested claims were disclosed",
		errIf(len(missing) > 0, "missing: %s", strings.Join(missing, ", "))); err != nil {
		return nil, log.entries, err
	}

	return disclosed, log.entries, nil
}

// checkDisclosuresReferenced enforces the SD-JWT rule that every disclosure be
// referenced by a digest in the issuer-signed payload, directly or from inside
// another disclosure. An unreferenced or duplicated one means the presentation
// was altered after issuance and must be rejected.
func checkDisclosuresReferenced(token *sdjwt.Token) error {
	referenced := sdjwt.ReferencedDigests(token)

	seen := make(map[string]bool, len(token.Disclosures))
	for _, d := range token.Disclosures {
		if !referenced[d.Digest] {
			name := d.Name
			if name == "" {
				name = "array element"
			}
			return fmt.Errorf("disclosure %q is not referenced by any digest in the credential", name)
		}
		if seen[d.Digest] {
			return fmt.Errorf("disclosure %q appears more than once", d.Name)
		}
		seen[d.Digest] = true
	}
	return nil
}

// checkRevocation resolves the credential's status list reference, if it has
// one. A verifier that only validates signatures would happily accept a
// revoked credential, which is exactly what the demo wallet's Revoke button
// produces.
func (d *DemoRP) checkRevocation(token *sdjwt.Token, check func(string, error) error) error {
	ref := statuslist.ExtractStatusRef(token.ResolvedClaims)
	if ref == nil {
		return check("revocation status (credential references no status list)", nil)
	}

	// Anchor the status list JWT in the same CA as the credential, so a
	// forged list cannot un-revoke a credential.
	caCert := d.wallet.CertChain[len(d.wallet.CertChain)-1]
	result, err := statuslist.CheckWithOptions(ref, statuslist.CheckOptions{
		TrustListCerts: []statuslist.TrustCert{{Raw: caCert.Raw}},
	})
	if err != nil {
		return check("credential is not revoked", fmt.Errorf("checking the status list: %w", err))
	}
	if result.SignatureValid != nil && !*result.SignatureValid {
		return check("credential is not revoked", fmt.Errorf("the status list signature did not verify: %s", result.SignatureInfo))
	}
	return check("credential is not revoked", errIf(result.Status != 0, "the issuer's status list marks this credential as revoked"))
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

// verifyMDOCPresentation validates an mdoc DeviceResponse: the doctype the
// request asked for, the issuer signature anchored in the wallet CA, the
// element digests the issuer signed, the holder signature over this request's
// session transcript, and the validity period.
func (d *DemoRP) verifyMDOCPresentation(req *requestState, presentation string, log *checklist) (map[string]any, []map[string]any, error) {
	check := log.record
	doc, err := mdoc.Parse(presentation)
	if err = check("presentation parses as an mdoc DeviceResponse", err); err != nil {
		return nil, log.entries, err
	}

	// Trusting the wallet to return the requested type would let any held
	// credential satisfy the request.
	if err = check("credential type matches the request",
		errIf(doc.DocType != req.docType, "doctype is %q, requested %q", doc.DocType, req.docType)); err != nil {
		return nil, log.entries, err
	}

	caCert := d.wallet.CertChain[len(d.wallet.CertChain)-1]
	tlCerts := []trustlist.CertInfo{{
		Subject:   caCert.Subject.String(),
		PublicKey: caCert.PublicKey,
		Raw:       caCert.Raw,
	}}
	issuerKey, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err == nil && issuerKey == nil {
		err = fmt.Errorf("the credential carries no x5c certificate chain")
	}
	if err = check("issuer certificate chains to a trusted CA", err); err != nil {
		return nil, log.entries, err
	}

	result := mdoc.Verify(doc, issuerKey)
	if err = check("issuer signature verifies", errIf(!result.SignatureValid, "issuer signature is invalid: %s", strings.Join(result.Errors, "; "))); err != nil {
		return nil, log.entries, err
	}
	if err = check("credential is within its validity period",
		errIf(result.Expired || result.NotYetValid, "credential is expired or not yet valid")); err != nil {
		return nil, log.entries, err
	}

	// The issuer signature only covers the MSO, so without this a holder could
	// hand back any element value it liked.
	if err = check("disclosed elements match the digests the issuer signed", mdoc.VerifyValueDigests(doc)); err != nil {
		return nil, log.entries, err
	}

	// The holder signs the session transcript, which binds the response to
	// this request. Rebuilding it here is what makes a captured response
	// useless anywhere else.
	transcript, err := d.rebuildSessionTranscript(req)
	if err = check("session transcript rebuilds", err); err != nil {
		return nil, log.entries, err
	}
	if err = check("holder signed this request", mdoc.VerifyDeviceAuth(doc, transcript)); err != nil {
		return nil, log.entries, err
	}

	claims := map[string]any{}
	for _, items := range doc.NameSpaces {
		for _, item := range items {
			claims[item.ElementIdentifier] = item.ElementValue
		}
	}
	var missing []string
	for _, want := range req.wantMDOC {
		if _, ok := claims[want]; !ok {
			missing = append(missing, want)
		}
	}
	if err = check("the requested elements are present",
		errIf(len(missing) > 0, "missing from the presentation: %s", strings.Join(missing, ", "))); err != nil {
		return nil, log.entries, err
	}
	return claims, log.entries, nil
}

// encryptionJWKThumbprint is the RFC 7638 thumbprint of the response
// encryption key, which the OID4VP session transcript binds to. It has to
// match what the wallet computed from the JWK in client_metadata, so it is
// built from the same members.
func encryptionJWKThumbprint(key *ecdsa.PrivateKey) []byte {
	if key == nil {
		return nil
	}
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
		base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))))
	sum := sha256.Sum256([]byte(canonical))
	return sum[:]
}

// checklist accumulates the verification steps and their outcome, so the UI
// can show what was checked rather than only whether it passed.
type checklist struct {
	entries []map[string]any
}

func (c *checklist) record(name string, err error) error {
	entry := map[string]any{"name": name, "ok": err == nil}
	if err != nil {
		entry["error"] = err.Error()
	}
	c.entries = append(c.entries, entry)
	return err
}

// warn records a check that says something without refusing the presentation.
// It is for rules a profile adds rather than the protocol: worth naming so a
// developer sees them, not worth failing a demo over.
func (c *checklist) warn(name string, err error) {
	entry := map[string]any{"name": name, "ok": true}
	if err != nil {
		entry["warning"] = err.Error()
	}
	c.entries = append(c.entries, entry)
}
