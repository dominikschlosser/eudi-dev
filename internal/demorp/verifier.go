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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/internal/format"
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
	// ticketQueryID is set when a PID request also asks for the demo ticket
	// (in one option next to the PID, or as an optional set of its own), and
	// ticketWant holds the ticket claim names it asks for.
	ticketQueryID string
	ticketWant    []string
	nonce         string
	clientID      string
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
	// encrypted.
	requestObject string
	encKey        *ecdsa.PrivateKey

	// custom drives verification of a request built by hand (the UI-guided
	// custom request), one entry per DCQL credential query. When it is set the
	// preset query ids above are not used.
	custom []customEntry

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
// The ticket query is not listed: this names what the PID entry lookup
// accepts, and the ticket rides along in its own entry.
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
	Type string `json:"type"` // "ticket" (default), "pid", or "custom"
	// Format narrows a PID request to one credential format: "sd-jwt",
	// "mdoc", or "both" (the default). It does not apply to the ticket,
	// which the demo issuer only ever issues as an SD-JWT VC.
	Format string `json:"format"`
	// VCT names the PID type to ask for. Empty means the country-independent
	// urn:eudi:pid:1, which every PID answers. A domestic type such as
	// urn:eudi:pid:de:1 is answered only by a credential of that type, since
	// inheritance runs the other way.
	VCT string `json:"vct"`
	// Ticket asks a PID request to also ask for the demo ticket, in one of
	// two DCQL credential_sets shapes: "combined" puts PID and ticket into
	// one option next to a PID-only option, "optional" adds a second set the
	// wallet may skip (required: false).
	Ticket string `json:"ticket"`
	// Credentials builds a request by hand, one DCQL credential query each,
	// used with type "custom".
	Credentials []customCredentialTO `json:"credentials"`
	// ClientIDScheme selects the client identifier prefix a custom request
	// runs under: "x509_hash" (the default), "x509_san_dns", "redirect_uri"
	// or "pre-registered". The x509 schemes deliver a signed request object,
	// the others an unsigned request.
	ClientIDScheme string `json:"client_id_scheme"`
	// ClientID sets the bare identifier for the pre-registered scheme, which the
	// other schemes derive from the certificate or the response endpoint. Empty
	// uses a default.
	ClientID string `json:"client_id"`
	// SigningKey optionally supplies the request object signing material as a
	// PEM bundle (an EC private key and its certificate chain). Empty uses the
	// demo verifier's own certificate.
	SigningKey string `json:"signing_key"`
	// VerifierInfo optionally replaces the verifier_info array (OpenID4VP 1.0
	// §5.1) the request carries. Empty uses the demo's registration certificate.
	VerifierInfo []any `json:"verifier_info"`
}

// customCredentialTO is one credential query of a request built by hand.
type customCredentialTO struct {
	Format  string  `json:"format"`  // dc+sd-jwt or mso_mdoc
	VCT     string  `json:"vct"`     // the type for dc+sd-jwt
	DocType string  `json:"doctype"` // the doctype for mso_mdoc
	Claims  [][]any `json:"claims"`  // each a DCQL claims path (strings, null, integers)
}

// customEntry drives verification of one credential query of a custom request.
type customEntry struct {
	queryID string
	format  string
	vct     string
	docType string
	want    []string
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

	if body.Type == "custom" {
		d.createCustomRequest(w, body)
		return
	}

	var vct, docType string
	var claims, mdocClaims []string
	ticketMode := strings.TrimSpace(body.Ticket)
	if ticketMode != "" && ticketMode != "combined" && ticketMode != "optional" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `ticket must be "combined" or "optional"`})
		return
	}
	switch body.Type {
	case "", "ticket":
		body.Type = "ticket"
		if ticketMode != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ticket applies to pid requests, which then ask for the ticket next to the PID"})
			return
		}
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
		// all.
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
		// The combined shape puts the ticket into one option next to the
		// SD-JWT PID, so it needs that PID in the request.
		if ticketMode == "combined" && !wantSDJWT {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ticket: combined needs the SD-JWT PID in the request, so use format sd-jwt or both"})
			return
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
	if ticketMode != "" {
		req.ticketQueryID = "ticket"
		req.ticketWant = []string{"event", "tier", "seat", "given_name", "family_name"}
	}
	responseURI := base + "/verifier/response/" + req.id

	// The client identifier is the hash of the signing certificate, which is
	// what makes it verifiable without a trust list and what HAIP requires
	// (redirect_uri: is not an accepted prefix, and it cannot be combined
	// with a signed request object anyway).
	signingKey, chain, err := d.wallet.DefaultSigningMaterial()
	if err != nil || signingKey == nil || len(chain) == 0 {
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
	if req.ticketQueryID != "" {
		ticketDCQLClaims := make([]map[string]any, 0, len(req.ticketWant))
		for _, c := range req.ticketWant {
			ticketDCQLClaims = append(ticketDCQLClaims, map[string]any{"path": []string{c}})
		}
		credentials = append(credentials, map[string]any{
			"id":     req.ticketQueryID,
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []string{TicketVCT}},
			"claims": ticketDCQLClaims,
		})
	}
	dcql := map[string]any{"credentials": credentials}

	// A PID offered in both formats needs a credential set with one option
	// per format: without it both listed credentials would be required,
	// which no wallet holding one format could answer. The two ticket shapes
	// build on that: "combined" puts the ticket into one option next to the
	// SD-JWT PID, "optional" adds a second set the wallet may skip.
	var sets []map[string]any
	switch ticketMode {
	case "combined":
		options := [][]string{{req.queryID, req.ticketQueryID}, {req.queryID}}
		if req.mdocQueryID != "" {
			options = append(options, []string{req.mdocQueryID})
		}
		sets = append(sets, map[string]any{"options": options})
	case "optional":
		var pidOptions [][]string
		if req.queryID != "" {
			pidOptions = append(pidOptions, []string{req.queryID})
		}
		if req.mdocQueryID != "" {
			pidOptions = append(pidOptions, []string{req.mdocQueryID})
		}
		sets = append(sets,
			map[string]any{"options": pidOptions},
			map[string]any{"options": [][]string{{req.ticketQueryID}}, "required": false})
	default:
		if req.queryID != "" && req.mdocQueryID != "" {
			sets = append(sets, map[string]any{"options": [][]string{{req.queryID}, {req.mdocQueryID}}})
		}
	}
	if len(sets) > 0 {
		dcql["credential_sets"] = sets
	}

	purpose := "Admission to the demo event: checking your ticket"
	if body.Type == "pid" {
		purpose = "Confirming your identity for the demo"
	}
	d.finalizeRequest(w, req, dcql, credentials, responseURI, base, purpose, signingKey, chain, nil)
}

// finalizeRequest signs the registration certificate and the request object for
// a built request, stores it, and returns the wallet URL. The purpose is
// carried in a wallet-relying-party registration certificate (rc-wrp+jwt, ETSI
// TS 119 475) in verifier_info (OpenID4VP 1.0 §5.1), which is where the wallet's
// consent dialog reads it from.
func (d *DemoRP) finalizeRequest(w http.ResponseWriter, req *requestState, dcql map[string]any, credentials []map[string]any, responseURI, base, purpose string, signingKey *ecdsa.PrivateKey, chain []*x509.Certificate, verifierInfo []any) {
	now := time.Now()
	if len(verifierInfo) == 0 {
		registration, err := wallet.SignRegistrationCertificateJWT(
			d.registrationCertificateClaims("EUDI-DEV-DEMO-VERIFIER", "Demo Verifier", purpose, credentials),
			signingKey, chain)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "signing registration certificate: " + err.Error()})
			return
		}
		verifierInfo = []any{map[string]any{"format": "registration_cert", "data": registration}}
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
		"client_metadata": responseEncryptionMetadata(req.encKey),
		"verifier_info":   verifierInfo,
	}, signingKey, chain)
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

// createCustomRequest builds a request from the credential queries a caller
// assembled by hand: each carries a format, a type, and DCQL claim paths. The
// client id scheme selects how the request is delivered, and an optional
// signing key and verifier_info override the defaults.
func (d *DemoRP) createCustomRequest(w http.ResponseWriter, body createRequestBody) {
	if len(body.Credentials) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a custom request needs at least one credential"})
		return
	}
	scheme := strings.TrimSpace(body.ClientIDScheme)
	if scheme == "" {
		scheme = "x509_hash"
	}
	signed := scheme == "x509_hash" || scheme == "x509_san_dns"

	signingKey, chain, err := d.customSigningMaterial(body.SigningKey)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.TrimSpace(body.SigningKey) != "" {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]string{"error": "signing material: " + err.Error()})
		return
	}
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "generating response encryption key: " + err.Error()})
		return
	}
	base := d.baseURL()
	req := &requestState{
		id:      randToken(),
		nonce:   randToken(),
		status:  "pending",
		expires: time.Now().Add(entryTTL),
		encKey:  encKey,
	}
	responseURI := base + "/verifier/response/" + req.id
	req.clientID, err = customClientID(scheme, chain, responseURI, body.ClientID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(body.VerifierInfo) > 0 && !signed {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a custom verifier_info needs a signed client_id scheme (x509_hash or x509_san_dns)"})
		return
	}

	credentials := make([]map[string]any, 0, len(body.Credentials))
	for i, c := range body.Credentials {
		format := strings.TrimSpace(c.Format)
		var meta map[string]any
		switch format {
		case "dc+sd-jwt":
			if strings.TrimSpace(c.VCT) == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a dc+sd-jwt credential needs a vct"})
				return
			}
			meta = map[string]any{"vct_values": []string{c.VCT}}
		case "mso_mdoc":
			if strings.TrimSpace(c.DocType) == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "an mso_mdoc credential needs a doctype"})
				return
			}
			meta = map[string]any{"doctype_value": c.DocType}
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be dc+sd-jwt or mso_mdoc"})
			return
		}

		dcqlClaims := make([]map[string]any, 0, len(c.Claims))
		seen := map[string]bool{}
		var want []string
		addWant := func(name string) {
			if name != "" && !seen[name] {
				seen[name] = true
				want = append(want, name)
			}
		}
		for _, path := range c.Claims {
			if len(path) == 0 {
				continue
			}
			dcqlClaims = append(dcqlClaims, map[string]any{"path": path})
			if format == "mso_mdoc" {
				addWant(lastStringComponent(path))
			} else if name, ok := path[0].(string); ok {
				addWant(name)
			}
		}

		id := fmt.Sprintf("cred_%d", i)
		q := map[string]any{"id": id, "format": format, "meta": meta}
		if len(dcqlClaims) > 0 {
			q["claims"] = dcqlClaims
		}
		credentials = append(credentials, q)
		req.custom = append(req.custom, customEntry{queryID: id, format: format, vct: c.VCT, docType: c.DocType, want: want})
	}

	dcql := map[string]any{"credentials": credentials}
	if signed {
		d.finalizeRequest(w, req, dcql, credentials, responseURI, base, "A request built by hand for testing", signingKey, chain, body.VerifierInfo)
		return
	}
	d.deliverUnsignedRequest(w, req, dcql, responseURI, base)
}

// customClientID forms the client identifier for a request built by hand under
// the selected prefix (OpenID4VP 1.0 §5.9). The x509 prefixes take the request
// object signing certificate, redirect_uri binds to the response endpoint, and
// pre-registered is a bare identifier the wallet has no key for.
func customClientID(scheme string, chain []*x509.Certificate, responseURI, preRegistered string) (string, error) {
	switch scheme {
	case "x509_hash":
		if len(chain) == 0 {
			return "", fmt.Errorf("x509_hash needs a signing certificate")
		}
		return wallet.X509HashClientID(chain[0]), nil
	case "x509_san_dns":
		if len(chain) == 0 {
			return "", fmt.Errorf("x509_san_dns needs a signing certificate")
		}
		if len(chain[0].DNSNames) == 0 {
			return "", fmt.Errorf("x509_san_dns needs a certificate with a DNS SAN, so supply a signing key whose certificate carries one")
		}
		return "x509_san_dns:" + chain[0].DNSNames[0], nil
	case "redirect_uri":
		return "redirect_uri:" + responseURI, nil
	case "pre-registered":
		if id := strings.TrimSpace(preRegistered); id != "" {
			return id, nil
		}
		return "eudi-dev-demo-verifier", nil
	default:
		return "", fmt.Errorf("unknown client_id scheme %q, use x509_hash, x509_san_dns, redirect_uri or pre-registered", scheme)
	}
}

// deliverUnsignedRequest stores a request whose prefix (redirect_uri or
// pre-registered) carries no signed request object and hands it to the wallet
// as plain query parameters (OpenID4VP 1.0 §5.10). The response is still
// encrypted to the per-request key the client_metadata publishes.
func (d *DemoRP) deliverUnsignedRequest(w http.ResponseWriter, req *requestState, dcql map[string]any, responseURI, base string) {
	dcqlJSON, err := json.Marshal(dcql)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encoding dcql_query: " + err.Error()})
		return
	}
	metaJSON, err := json.Marshal(responseEncryptionMetadata(req.encKey))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encoding client_metadata: " + err.Error()})
		return
	}

	d.mu.Lock()
	d.pruneLocked()
	if len(d.requests) >= maxEntries {
		d.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many open requests, try again later"})
		return
	}
	d.requests[req.id] = req
	d.mu.Unlock()

	params := url.Values{
		"client_id":       {req.clientID},
		"response_type":   {"vp_token"},
		"response_mode":   {"direct_post.jwt"},
		"response_uri":    {responseURI},
		"nonce":           {req.nonce},
		"state":           {req.id},
		"dcql_query":      {string(dcqlJSON)},
		"client_metadata": {string(metaJSON)},
	}.Encode()

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         req.id,
		"wallet_url": base + "/authorize?" + params,
		"scheme_uri": "openid4vp://?" + params,
	})
}

// customSigningMaterial parses the request object signing key from a PEM bundle
// (an EC private key and its certificate chain), or returns the demo verifier's
// own certificate when the bundle is empty.
func (d *DemoRP) customSigningMaterial(pemBundle string) (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	if strings.TrimSpace(pemBundle) == "" {
		return d.wallet.DefaultSigningMaterial()
	}
	var key *ecdsa.PrivateKey
	var chain []*x509.Certificate
	rest := []byte(pemBundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing EC private key: %w", err)
			}
			key = k
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing private key: %w", err)
			}
			ec, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, nil, fmt.Errorf("the signing key must be an EC key")
			}
			key = ec
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing certificate: %w", err)
			}
			chain = append(chain, c)
		}
	}
	if key == nil {
		return nil, nil, fmt.Errorf("the signing key PEM carries no private key")
	}
	if len(chain) == 0 {
		return nil, nil, fmt.Errorf("the signing key PEM carries no certificate")
	}
	return key, chain, nil
}

// lastStringComponent returns the last string element of a claims path, which
// for an mdoc path [namespace, element] is the element name.
func lastStringComponent(path []any) string {
	name := ""
	for _, p := range path {
		if s, ok := p.(string); ok {
			name = s
		}
	}
	return name
}

// registrationCertificateClaims builds a wallet-relying-party registration
// certificate payload the wallet's ARF content checks pass (ETSI TS 119 475
// §5.2.4). Its credentials register exactly the credential queries the request
// asks for, so the over-asking check (ARF RPRC_21) sees the demo request only
// what it registered for. dcqlCredentials are the request's DCQL credential
// queries, whose claims become the registered claim paths.
func (d *DemoRP) registrationCertificateClaims(sub, name, purpose string, dcqlCredentials []map[string]any) map[string]any {
	registered := make([]map[string]any, 0, len(dcqlCredentials))
	for _, c := range dcqlCredentials {
		registered = append(registered, map[string]any{
			"format": c["format"],
			"meta":   c["meta"],
			"claim":  c["claims"],
		})
	}
	now := time.Now()
	base := d.baseURL()
	return map[string]any{
		"sub":                   sub,
		"name":                  name,
		"country":               "EU",
		"registry_uri":          base + "/registrar",
		"srv_description":       []map[string]any{{"lang": "en", "value": name}},
		"entitlements":          []string{"https://uri.etsi.org/19475/Entitlement/Service_Provider"},
		"privacy_policy":        base + "/privacy-policy",
		"support_uri":           base + "/support",
		"supervisory_authority": map[string]any{"email": "dpa@eudi-test.dev", "uri": base + "/supervisory-authority"},
		"iat":                   now.Unix(),
		"exp":                   now.AddDate(0, 6, 0).Unix(),
		"purpose":               []map[string]any{{"lang": "en", "value": purpose}},
		"credentials":           registered,
	}
}

// checkPresentationAudience holds a Key Binding JWT to the party that asked for
// it: the client_id over OpenID4VP, the Authorization Challenge Endpoint inside
// an Interactive Authorization exchange.
//
// Both `ia:` forms are accepted there. OpenID4VCI 1.1 Appendix A.3.5 asks for
// "the derived Origin ... of the Authorization Challenge Endpoint" while its
// own example, its sibling appendices and §6.2.1.5 all name the endpoint, so a
// wallet reading either sentence is answered rather than refused.
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
	x, y, _ := format.ECPublicCoords(&key.PublicKey)
	return map[string]any{
		"jwks": map[string]any{
			"keys": []map[string]any{{
				"kty": "EC",
				"crv": "P-256",
				"use": "enc",
				"alg": "ECDH-ES",
				"kid": "demo-verifier-response-enc",
				"x":   base64.RawURLEncoding.EncodeToString(x),
				"y":   base64.RawURLEncoding.EncodeToString(y),
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
		// Without this the page polls a dead request forever.
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

// verifyPresentation validates the vp_token: the PID entry (an SD-JWT with
// its key binding JWT, or an mdoc DeviceResponse), and the ticket entry when
// the request asked for one. Every credential's issuer signature anchors in
// the wallet CA, and every key binding covers this request's nonce and
// audience.
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

	if len(req.custom) > 0 {
		return d.verifyCustomPresentation(req, tokenDoc, log)
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

	var resultClaims map[string]any
	var err error
	if answeredMDOC {
		resultClaims, _, err = d.verifyMDOCPresentation(req, presentations[0], log)
	} else {
		resultClaims, err = d.verifySDJWTEntry(req, presentations[0], req.vct, req.want, "", log)
	}
	if err != nil {
		return nil, log.entries, err
	}

	// The ticket entry, when the request asked for one. Its absence is an
	// answer too: the wallet chose a PID-only option or skipped the
	// optional set.
	if req.ticketQueryID != "" {
		ticketPresentations := tokenDoc[req.ticketQueryID]
		if len(ticketPresentations) == 0 {
			_ = log.record("ticket: not presented, which the request allows", nil)
		} else {
			if err := check("ticket: vp_token holds exactly one presentation",
				errIf(len(ticketPresentations) != 1, "expected 1 presentation, got %d", len(ticketPresentations))); err != nil {
				return nil, log.entries, err
			}
			ticketClaims, err := d.verifySDJWTEntry(req, ticketPresentations[0], TicketVCT, req.ticketWant, "ticket: ", log)
			if err != nil {
				// The failed entry is the one worth decoding, so it replaces
				// the PID entry recorded above.
				d.recordPresentation(req, ticketPresentations[0])
				return nil, log.entries, err
			}
			resultClaims["ticket"] = ticketClaims
		}
	}

	return resultClaims, log.entries, nil
}

// verifyCustomPresentation verifies a request built by hand: each credential
// query is verified on its own, dispatched by format. A query the wallet did
// not answer is noted rather than failed, since a custom request may ask for
// more than one credential.
func (d *DemoRP) verifyCustomPresentation(req *requestState, tokenDoc map[string][]string, log *checklist) (map[string]any, []map[string]any, error) {
	check := log.record
	result := map[string]any{}
	recorded := false
	for _, entry := range req.custom {
		presentations := tokenDoc[entry.queryID]
		label := entry.queryID + ": "
		if len(presentations) == 0 {
			_ = check(label+"not presented", nil)
			continue
		}
		if !recorded {
			d.recordPresentation(req, presentations[0])
			recorded = true
		}
		if err := check(label+"vp_token holds exactly one presentation",
			errIf(len(presentations) != 1, "expected 1 presentation, got %d", len(presentations))); err != nil {
			d.recordPresentation(req, presentations[0])
			return nil, log.entries, err
		}
		var claims map[string]any
		var err error
		if entry.format == "mso_mdoc" {
			req.docType, req.wantMDOC = entry.docType, entry.want
			claims, _, err = d.verifyMDOCPresentation(req, presentations[0], log)
		} else {
			claims, err = d.verifySDJWTEntry(req, presentations[0], entry.vct, entry.want, label, log)
		}
		if err != nil {
			// A presentation that failed verification is the one worth decoding.
			d.recordPresentation(req, presentations[0])
			return nil, log.entries, err
		}
		result[entry.queryID] = claims
	}
	if len(result) == 0 {
		return nil, log.entries, check("vp_token answers a requested credential", fmt.Errorf("the response carried no presentation for any requested credential"))
	}
	return result, log.entries, nil
}

// verifySDJWTEntry validates one SD-JWT presentation of the vp_token: the
// credential type the request asked for under this query, the issuer
// signature anchored in the wallet CA, revocation, and the key binding JWT
// over this request's nonce and audience. The label prefixes every check
// name, so the ticket's checks read apart from the PID's.
func (d *DemoRP) verifySDJWTEntry(req *requestState, presentation, expectedVCT string, want []string, label string, log *checklist) (map[string]any, error) {
	check := func(name string, err error) error {
		return log.record(label+name, err)
	}

	token, err := sdjwt.Parse(presentation)
	if err = check("presentation parses as SD-JWT", err); err != nil {
		return nil, err
	}
	for _, warning := range token.Warnings {
		log.warn(label+"credential is well-formed (RFC 9901)", fmt.Errorf("%s", warning))
	}

	// SD-JWT VC requires the issuer-signed JWT to carry typ dc+sd-jwt (vc+sd-jwt
	// during the transition). The demo warns rather than rejects it.
	log.warn(label+"issuer-signed JWT declares an SD-JWT VC typ", sdjwt.ValidateVCType(token.Header))

	if err = check("every disclosure is referenced by the credential", checkDisclosuresReferenced(token)); err != nil {
		return nil, err
	}

	// Trusting the wallet to return the requested type would let any held
	// credential satisfy the request. A type extending the requested one is
	// accepted, because that is what the request asked for: a German PID
	// answers a request for the country-independent one, and says so in its
	// aka_vcts claim.
	gotVCT, _ := token.ResolvedClaims["vct"].(string)
	gotAka := credtype.AkaVCTs(token.ResolvedClaims)
	if err = check("credential type matches the request",
		errIf(!credtype.Answers(gotVCT, gotAka, expectedVCT), "vct is %q, requested %q", gotVCT, expectedVCT)); err != nil {
		return nil, err
	}

	// HAIP 1.0 section 6.1.1 asks a credential to carry its issuer's signing
	// certificate and trust chain in x5c, with the trust anchor left out and
	// the leaf not self-signed. The demo says so and carries on, since the
	// rule comes from the profile.
	certs, _ := validate.X5CCertificates(token.Header)
	if violations := validate.HAIPCredentialChain(certs); len(violations) > 0 {
		log.warn(label+"issuer certificate chain follows HAIP", fmt.Errorf("%s", strings.Join(violations, ". ")))
	} else {
		log.warn(label+"issuer certificate chain follows HAIP", nil)
	}

	// Issuer signature. The check is named from the verifier's point of view:
	// what it verifies is that the issuer certificate chains to a CA it
	// trusts.
	tlCerts := d.trustedIssuerCerts()
	if len(tlCerts) == 0 {
		return nil, check("issuer certificate chains to a trusted CA", fmt.Errorf("this verifier has no CA certificate"))
	}
	issuerKey, err := validate.ExtractAndValidateX5C(token.Header, tlCerts)
	if err == nil && issuerKey == nil {
		err = fmt.Errorf("the credential carries no x5c certificate chain")
	}
	if err = check("issuer certificate chains to a trusted CA", err); err != nil {
		return nil, err
	}
	result := sdjwt.Verify(token, issuerKey)
	if err = check("issuer signature verifies", errIf(!result.SignatureValid, "issuer signature is invalid")); err != nil {
		return nil, err
	}
	if err = check("credential is within its validity period",
		errIf(result.Expired || result.NotYetValid, "credential is expired or not yet valid")); err != nil {
		return nil, err
	}
	if err = d.checkRevocation(token, check); err != nil {
		return nil, err
	}

	// Key binding JWT.
	kb := token.KeyBindingJWT
	if err = check("key binding JWT present", errIf(kb == nil, "the presentation has no key binding JWT")); err != nil {
		return nil, err
	}
	cnf, _ := token.Payload["cnf"].(map[string]any)
	cnfJWK, _ := cnf["jwk"].(map[string]any)
	if err = check("credential is holder bound (cnf.jwk)", errIf(cnfJWK == nil, "the credential carries no cnf.jwk")); err != nil {
		return nil, err
	}
	holderKey, err := holderKeyFromJWK(cnfJWK)
	if err = check("cnf.jwk parses", err); err != nil {
		return nil, err
	}
	kbJWT, err := parseCompactJWT(kb.Raw)
	if err = check("key binding JWT parses", err); err != nil {
		return nil, err
	}
	kbTyp, _ := kbJWT.header["typ"].(string)
	if err = check("key binding JWT is typed kb+jwt", errIf(kbTyp != "kb+jwt", "typ is %q", kbTyp)); err != nil {
		return nil, err
	}
	if err = check("key binding signature verifies with cnf key", errIf(!verifyES256(holderKey, kbJWT.signingInput, kbJWT.signature), "key binding signature is invalid")); err != nil {
		return nil, err
	}

	// RFC 9901 §7.3: "check that the creation time of the Key Binding JWT, as
	// determined by the iat claim, is within an acceptable window". The claim
	// is REQUIRED (§4.3), and the window is the one this demo applies to every
	// per-request proof.
	kbIat, hasIat := kbJWT.payload["iat"].(float64)
	iatErr := errIf(!hasIat, "the key binding JWT has no numeric iat")
	if iatErr == nil {
		if age := time.Since(time.Unix(int64(kbIat), 0)); age > proofClockSkew || age < -proofClockSkew {
			iatErr = fmt.Errorf("the key binding JWT iat is %s away from now, outside the %s window this verifier accepts", age.Round(time.Second), proofClockSkew)
		}
	}
	if err = check("key binding was created within an acceptable window", iatErr); err != nil {
		return nil, err
	}

	// sd_hash covers everything up to and including the final ~, hashed with the
	// credential's own _sd_alg (RFC 9901 §4.3), not SHA-256 unconditionally. Parse
	// already rejected an unsupported _sd_alg, so this only guards the impossible.
	prefix := presentation[:strings.LastIndex(presentation, "~")+1]
	wantHash, hErr := sdjwt.SDHash(prefix, token.SDAlg())
	if hErr != nil {
		return nil, check("sd_hash algorithm is supported", hErr)
	}
	gotHash, _ := kbJWT.payload["sd_hash"].(string)
	if err = check("sd_hash matches the presentation", errIf(gotHash != wantHash, "sd_hash does not match")); err != nil {
		return nil, err
	}

	nonce, _ := kbJWT.payload["nonce"].(string)
	if err = check("nonce matches the request", errIf(nonce != req.nonce, "nonce mismatch")); err != nil {
		return nil, err
	}
	aud, _ := kbJWT.payload["aud"].(string)
	if err = check("audience is this verifier", checkPresentationAudience(req, aud)); err != nil {
		return nil, err
	}

	disclosed := disclosedClaims(token)
	var missing []string
	for _, name := range want {
		if _, ok := disclosed[name]; !ok {
			missing = append(missing, name)
		}
	}
	if err = check("requested claims were disclosed",
		errIf(len(missing) > 0, "missing: %s", strings.Join(missing, ", "))); err != nil {
		return nil, err
	}

	return disclosed, nil
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
// one.
func (d *DemoRP) checkRevocation(token *sdjwt.Token, check func(string, error) error) error {
	ref := statuslist.ExtractStatusRef(token.ResolvedClaims)
	if ref == nil {
		return check("revocation status (credential references no status list)", nil)
	}

	// Anchor the status list JWT in the same CAs as the credential, so a
	// forged list cannot un-revoke a credential.
	anchors := d.trustedIssuerCerts()
	if len(anchors) == 0 {
		return check("credential is not revoked", fmt.Errorf("this verifier has no CA certificate"))
	}
	trustCerts := make([]statuslist.TrustCert, 0, len(anchors))
	for _, anchor := range anchors {
		trustCerts = append(trustCerts, statuslist.TrustCert{Raw: anchor.Raw})
	}
	result, err := statuslist.CheckWithOptions(ref, statuslist.CheckOptions{
		TrustListCerts: trustCerts,
	})
	if err != nil {
		return check("credential is not revoked", fmt.Errorf("checking the status list: %w", err))
	}
	if result.SignatureValid != nil && !*result.SignatureValid {
		return check("credential is not revoked", fmt.Errorf("the status list signature did not verify: %s", result.SignatureInfo))
	}
	return check("credential is not revoked", errIf(result.Status != 0, "the issuer's status list marks this credential as revoked"))
}

// trustedIssuerCerts is the anchor set every presented credential's issuer
// chain is validated against: the wallet CA the built-in issuer signs under,
// plus the anchors SetVerifierTrustAnchors added.
func (d *DemoRP) trustedIssuerCerts() []trustlist.CertInfo {
	var anchors []*x509.Certificate
	if caCert := d.wallet.TrustAnchorCertificate(); caCert != nil {
		anchors = append(anchors, caCert)
	}
	anchors = append(anchors, d.verifierTrustAnchors...)
	certs := make([]trustlist.CertInfo, 0, len(anchors))
	for _, anchor := range anchors {
		certs = append(certs, trustlist.CertInfo{
			Subject:   anchor.Subject.String(),
			PublicKey: anchor.PublicKey,
			Raw:       anchor.Raw,
		})
	}
	return certs
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

	tlCerts := d.trustedIssuerCerts()
	if len(tlCerts) == 0 {
		return nil, log.entries, check("issuer certificate chains to a trusted CA", fmt.Errorf("this verifier has no CA certificate"))
	}
	issuerKey, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err == nil && issuerKey == nil {
		err = fmt.Errorf("the credential carries no x5c certificate chain")
	}
	if err = check("issuer certificate chains to a trusted CA", err); err != nil {
		return nil, log.entries, err
	}

	result := mdoc.Verify(doc, issuerKey)
	if err = check("issuer signature verifies", errIf(!result.SignatureValid, "issuer signature is invalid: %s", strings.Join(result.Errors, ". "))); err != nil {
		return nil, log.entries, err
	}
	for _, warning := range result.Warnings {
		log.warn("mdoc MSO declares its required members", fmt.Errorf("%s", warning))
	}
	// ISO 18013-5 makes validityInfo (with validUntil) a required MSO member. An
	// mdoc that omits it has no stated expiry, so the period cannot be checked:
	// note that rather than affirm a validity that was never verified.
	if result.ValidUntil == nil {
		log.warn("credential is within its validity period",
			fmt.Errorf("the mdoc MSO carries no validUntil, so its validity cannot be checked (ISO 18013-5 requires validityInfo)"))
	} else if err = check("credential is within its validity period",
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
	x, y, err := format.ECPublicCoords(&key.PublicKey)
	if err != nil {
		return nil
	}
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
		base64.RawURLEncoding.EncodeToString(x),
		base64.RawURLEncoding.EncodeToString(y))
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
