# Architecture

## Package Structure

```
cmd/                        CLI commands (Cobra)
├── root.go                 Root command and global flags
├── wallet.go               Root wallet command, helpers, simple subcommands
├── wallet_serve.go         wallet serve (HTTP server + web UI)
├── wallet_present.go       OID4VP/VCI dispatch, consent flow, submission
├── wallet_scan.go          wallet accept, wallet scan (QR + URI dispatch)
├── wallet_generate.go      wallet generate-pid (deprecated)
├── wallet_logs.go          wallet logs (print + follow persisted interactions)
├── wallet_remote.go        wallet use, instances, kill, info (remote control)
├── wallet_remote_ops.go    Remote implementations of the management commands
├── templates.go            Credential template management commands
├── serve.go                Web UI server (decode + validate)
├── proxy.go                Reverse proxy with live dashboard
├── decode.go               Auto-detect & decode command
├── validate.go             Signature verification & revocation check
├── dcql.go                 DCQL query generation
├── issue.go                Test credential generation
└── version.go              Version command

internal/
├── config/                 Centralized defaults (ports, timeouts)
├── credtemplate/           Credential templates (pre-defined PID templates, user template files)
├── dcql/                   DCQL query parsing, evaluation, generation
├── format/                 Format detection, base64url, credential type constants
├── jsonutil/               Type-safe accessors for map[string]any
├── keys/                   PEM/JWK key loading and conversion
├── mdoc/                   mDOC/mDL parsing (CBOR) and COSE_Sign1 verification
├── mock/                   Test credential generators (SD-JWT, JWT, mDOC)
├── oid4vc/                 OID4VP/VCI request/response parsing
├── output/                 Terminal output formatting (color, JSON, tables)
├── proxy/                  HTTP reverse proxy, traffic classifier, dashboard
├── qr/                     QR code scanning (file + screen capture)
├── remote/                 Remote wallet management (REST client, instance discovery)
├── sdjwt/                  SD-JWT parsing, disclosure resolution, verification
├── statuslist/             Token Status List (RFC 9596) encoding/decoding
├── trustlist/              ETSI TS 119 612 trust list parsing
├── validate/               Orchestrates verification (sig, expiry, revocation)
├── wallet/                 Wallet state, server, OID4VP/VCI protocol logic
└── web/                    Embedded static assets (HTML/CSS/JS for web UIs)
```

## Data Flow

### CLI Decode/Validate

```
User input (file/URL/stdin/QR)
  → format.Detect()
  → sdjwt.Parse() / mdoc.Parse() / oid4vc.Parse*()
  → output.Print*() or validate.Validate()
```

### Wallet OID4VP Flow

```
Authorization Request (URI or /authorize endpoint)
  → oid4vc.ParseAuthorizationRequest()
  → wallet.ValidateRequestObject() (JAR signature + client_id verification)
  → wallet.ValidateHAIPCompliance() (optional, --haip flag)
  → dcql.Evaluate() (match credentials against DCQL query)
  → Consent UI or auto-accept
  → wallet.BuildPresentation() (SD-JWT VP token + KB-JWT, or mDOC DeviceResponse)
  → HTTP POST to response_uri (direct_post or direct_post.jwt)
```

### Wallet OID4VCI Flow

```
Credential Offer URI
  → oid4vc.ParseCredentialOffer()
  → Token endpoint (pre-authorized code + optional tx_code)
  → Credential endpoint (proof of possession via JWT)
  → wallet.ImportCredential()
```

### Proxy

```
Wallet ←→ Proxy (:9090) ←→ Verifier/Issuer (:target)
               ↓
         Dashboard (:9091) — classifies traffic as OID4VP/VCI steps
```

## Key Types

| Type | Package | Description |
|------|---------|-------------|
| `sdjwt.Token` | `internal/sdjwt` | Parsed SD-JWT with header, payload, disclosures, KB-JWT |
| `mdoc.Document` | `internal/mdoc` | Parsed mDOC with IssuerAuth (COSE_Sign1), namespaces, claims |
| `wallet.Wallet` | `internal/wallet` | Credential store, keys, configuration |
| `wallet.AuthorizationRequestParams` | `internal/wallet` | Parsed OID4VP authorization request |
| `oid4vc.RequestObjectJWT` | `internal/oid4vc` | Parsed JAR (JWT-secured Authorization Request) |
| `dcql.Query` | `internal/dcql` | DCQL query with credential descriptors and credential sets |
| `wallet.ConsentRequest` | `internal/wallet` | Data sent to consent UI (matched credentials, verifier info) |

## Credential Formats

The tool handles three credential formats throughout:

- **`dc+sd-jwt`**: SD-JWT with selective disclosure. Presented with a Key Binding JWT.
- **`mso_mdoc`**: ISO 18013-5 mDOC. CBOR-encoded, COSE_Sign1 signed. Presented as DeviceResponse.
- **`jwt_vc_json`**: Plain JWT Verifiable Credential (W3C format). Presented as-is.
