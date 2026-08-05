# Proxy

Intercept and debug OID4VP/VCI traffic between a wallet and a verifier/issuer. Point your wallet at the proxy instead of the real server. Every request and response is captured, classified by protocol step, decoded, and displayed both in the terminal and a live web dashboard.

```bash
eudi proxy --target http://localhost:8080
eudi proxy --target http://localhost:8080 --port 9090 --dashboard 9091
eudi proxy --target http://localhost:8080 --no-dashboard
```

```
Wallet  <-->  Proxy (:9090)  <-->  Verifier/Issuer (:8080)
                  |
            Live dashboard (:9091)
```

Optionally launch the target service as a subprocess. The proxy scans its stdout for encryption keys and credentials:

```bash
eudi proxy --target http://localhost:3000 -- mvn spring-boot:run
eudi proxy --target http://localhost:3000 -- npm start
```

## Traffic classification

Traffic is automatically classified into protocol steps:

| Badge               | Detected when                                                     |
|---------------------|-------------------------------------------------------------------|
| VP Auth Request     | `client_id` + `response_type` containing `vp_token` or `id_token` in query |
| VP Request Object   | Response body is a JWT (request object fetch)                     |
| VP Auth Response    | POST body contains `vp_token`, `presentation_submission`, `id_token`, or `response` (JARM) |
| VCI Credential Offer| `credential_offer` / `credential_offer_uri` in query              |
| VCI Metadata        | Path contains `.well-known/openid-credential-issuer`              |
| VCI Token Request   | POST to path ending `/token`                                      |
| VCI Credential Req  | POST to path ending `/credential`                                 |

By default, only OID4VP/VCI traffic is shown. Non-matching requests (favicon, health checks, etc.) are still proxied but hidden from the output. Pass `--all-traffic` or toggle the "All traffic" checkbox in the dashboard to see everything.

## Features

- **Smart decoding**: payloads are decoded inline (SD-JWT, JWT, mDOC, DCQL queries, JWE headers)
- **Credential decode hints**: detected credentials are printed as `eudi decode` commands for quick inspection
- **JARM/JWE decryption**: when the built-in wallet sends a `direct_post.jwt` response through the proxy, the encrypted payload is automatically decrypted (see [JWE Decryption](#jwe-decryption) below)
- **Flow correlation**: related protocol steps are grouped by shared `state`/`nonce` values
- **Web dashboard** at `http://localhost:9091` with live SSE updates, expandable cards, "View in Decoder" links, HAR export, and cURL copy
- **JARM/JWE detection**: shows encrypted response headers and the verifier's ephemeral public key
- **NDJSON output**: `--json` for machine-readable output, pipe to `jq` or log to file

## Flags

| Flag             | Default | Description                              |
|------------------|---------|------------------------------------------|
| `--target`       | —       | URL of the verifier/issuer (required)    |
| `--port`         | `9090`  | Proxy listen port                        |
| `--dashboard`    | `9091`  | Dashboard listen port                    |
| `--no-dashboard` | `false` | Disable web dashboard                    |
| `--all-traffic`  | `false` | Show all traffic, not just OID4VP/VCI    |
| `--json`         | `false` | NDJSON output to stdout (global flag)    |
| `-- <command>`   | —       | Launch target as subprocess, scan stdout |

## Example output

```
━━━ [14:32:05] GET /authorize?client_id=...  ← 200 (45ms)  [VP Auth Request]
    ┌ client_id: did:web:verifier.example
    ┌ response_mode: direct_post.jwt
    ┌ nonce: abc123
    ┌ dcql_query: { "credentials": [...] }

━━━ [14:32:05] GET /request/abc123  ← 200 (12ms)  [VP Request Object]
    ┌ header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
    ┌ payload: { ... }

━━━ [14:32:06] POST /response  ← 200 (89ms)  [VP Auth Response]
    ┌ response_type: JWE (decrypted via debug key)
    ┌ encryption_alg: ECDH-ES
    ┌ response_payload: {"vp_token":{...},"state":"abc123"}
  → eudi decode 'eyJhbGci...'  (vp_token)
```

## JWE decryption

When the built-in wallet (`eudi wallet`) sends an encrypted JARM response (`direct_post.jwt`) through the proxy, the proxy automatically decrypts the payload and shows the contained `vp_token` and `state`.

This works via a debug header: the wallet includes the AES content encryption key (CEK) in `X-Debug-JWE-CEK`. The proxy strips this header before forwarding the request to the verifier, so the verifier never sees it.

No configuration is needed. Simply route the wallet through the proxy:

```
eudi wallet                          # wallet sends to response_uri
eudi proxy --target http://verifier  # proxy intercepts, decrypts, forwards
```

### Automatic key detection from service stdout

When using a **third-party wallet** (not the built-in one), the debug header won't be present. If you launch the verifier service as a subprocess (with `--`), the proxy scans its stdout for CEK values and uses them to decrypt JWE responses automatically:

```bash
eudi proxy --target http://localhost:3000 -- mvn spring-boot:run
```

The proxy detects lines matching patterns like:
- `CEK: <base64url>` or `content encryption key: <base64url>`
- JWK objects containing a `"d"` (private key) parameter

This is best-effort. If no key is found, the proxy falls back to showing only the JWE header fields (`alg`, `enc`, `kid`, `epk`).

### Credential detection from service stdout

When running as a subprocess, the proxy also scans the service's stdout for JWT/SD-JWT credentials. Detected credentials are added to the activity log with decode links:

```
  → eudi decode 'eyJhbGci...'  (vp_token)
  → http://localhost:9091/decode?credential=eyJhbGci...
```

## Debugging tips

- The wallet logs credentials and encryption keys to stdout for local debugging:
  - `[VP] JWE content encryption key for proxy debugging: <base64url CEK>`
  - `[VP] SD-JWT presentation created: ...`
- Launch the target service with `--` to auto-detect keys/credentials from its stdout:
  ```bash
  eudi proxy --target http://localhost:3000 -- mvn spring-boot:run
  ```
  Service output appears with a `[service]` prefix. Detected credentials get decode links.
- Use `--all-traffic` to see non-OID4VP/VCI requests (health checks, favicon, etc.)
- Pipe to `jq` with `--json` for structured analysis: `eudi proxy --target ... --json | jq '.credentials'`
