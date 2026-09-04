# Proxy

Intercept and debug OID4VP/VCI traffic between a wallet and a verifier/issuer. Point the wallet at the proxy instead of the real server. Every request and response is captured, classified by protocol step, decoded, and shown in the terminal and a live web dashboard.

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

The proxy can launch the target service as a subprocess and scan its stdout for encryption keys and credentials:

```bash
eudi proxy --target http://localhost:3000 -- mvn spring-boot:run
eudi proxy --target http://localhost:3000 -- npm start
```

## Traffic classification

Traffic is classified into protocol steps:

| Badge               | Detected when                                                     |
|---------------------|-------------------------------------------------------------------|
| VP Auth Request     | `client_id` + `response_type` containing `vp_token` or `id_token` in query |
| VP Request Object   | Response body is a JWT (request object fetch)                     |
| VP Auth Response    | POST body contains `vp_token`, `presentation_submission`, `id_token`, or `response` (JARM) |
| VCI Credential Offer| `credential_offer` / `credential_offer_uri` in query              |
| VCI Metadata        | Path contains `.well-known/openid-credential-issuer`              |
| VCI Token Request   | POST to path ending `/token`                                      |
| VCI Credential Request | POST to path ending `/credential` or `/credentials`            |

By default only OID4VP/VCI traffic is shown. Other requests (favicon, health checks) are proxied but hidden. Pass `--all-traffic` or tick the "All traffic" checkbox in the dashboard to see everything.

## Features

- **Decoding**: payloads are decoded inline (SD-JWT, JWT, mDOC, DCQL queries, JWE headers)
- **Credential decode hints**: detected credentials are printed as `eudi decode` commands
- **JARM/JWE decryption**: a `direct_post.jwt` response from the built-in wallet is decrypted (see [JWE Decryption](#jwe-decryption))
- **Flow correlation**: related protocol steps are grouped by shared `state`/`nonce` values
- **Web dashboard** at `http://localhost:9091` with live SSE updates, expandable cards, "View in Decoder" links, HAR export, and cURL copy
- **JARM/JWE detection**: shows encrypted response headers and the verifier's ephemeral public key
- **NDJSON output**: `--json` for machine-readable output, pipe to `jq` or log to a file
- **Attach to a running proxy**: `eudi proxy logs` prints the traffic of a running proxy from another terminal (see [reading a running proxy](#reading-a-running-proxy))

## Flags

| Flag             | Default | Description                              |
|------------------|---------|------------------------------------------|
| `--target`       | —       | URL of the verifier/issuer (required)    |
| `--port`         | `9090`  | Proxy listen port                        |
| `--dashboard`    | `9091`  | Dashboard listen port                    |
| `--no-dashboard` | `false` | Disable web dashboard                    |
| `--all-traffic`  | `false` | Show all traffic                          |
| `--json`         | `false` | NDJSON output to stdout (global flag)    |
| `-- <command>`   | —       | Launch target as subprocess, scan stdout |

`eudi proxy logs [dashboard-url]` reads a proxy that is already running:

| Flag             | Default | Description                                        |
|------------------|---------|----------------------------------------------------|
| `[dashboard-url]`| `http://localhost:9091` | Dashboard of the proxy to read      |
| `-f, --follow`   | `false` | Keep printing as the proxy records traffic         |
| `--json`         | `false` | Print the recorded traffic as JSON (global flag)   |

## Reading a running proxy

A proxy in a container, in the background, or on another machine prints to a terminal you cannot see. `eudi proxy logs` reads its traffic from the dashboard:

```bash
# a proxy on this machine
eudi proxy logs

# a proxy whose dashboard port is published from a container
eudi proxy logs http://localhost:9091 --follow

# somewhere else entirely
eudi proxy logs https://proxy.internal.example --follow
```

The output is the same as the proxy's own output, with decode links pointing at that dashboard. `--follow` keeps printing as traffic arrives and reattaches when the stream ends, until you interrupt it. After a reattachment it re-reads the recorded traffic, so nothing that arrived in between is lost. This also covers a proxy restart. `--json` prints the recorded traffic as JSON and ends, so it cannot be combined with `--follow`.

The argument is the dashboard URL (port 9091 by default). A proxy started without `--all-traffic` records only OID4VP/VCI requests, so only those can be read back.

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

When the built-in wallet (`eudi wallet`) sends an encrypted JARM response (`direct_post.jwt`) through the proxy, the proxy decrypts the payload and shows the contained `vp_token` and `state`.

The wallet puts the AES content encryption key (CEK) in the `X-Debug-JWE-CEK` header. The proxy strips the header before forwarding, so the verifier never sees it. Route the wallet through the proxy:

```
eudi wallet serve                    # wallet sends to response_uri
eudi proxy --target http://verifier  # proxy intercepts, decrypts, forwards
```

### Automatic key detection from service stdout

A third-party wallet sends no debug header. When the verifier service runs as a subprocess (with `--`), the proxy scans its stdout for CEK values and uses them to decrypt JWE responses:

```bash
eudi proxy --target http://localhost:3000 -- mvn spring-boot:run
```

The proxy detects lines like:
- `CEK: <base64url>` or `content encryption key: <base64url>`
- JWK objects containing a `"d"` (private key) parameter

Without a key the proxy shows the JWE header fields only (`alg`, `enc`, `kid`, `epk`).

### Credential detection from service stdout

The proxy also scans the subprocess's stdout for JWT and SD-JWT credentials and adds them to the activity log with decode links:

```
  → eudi decode 'eyJhbGci...'  (vp_token)
  → http://localhost:9091/decode?credential=eyJhbGci...
```

## Debugging tips

- The wallet logs credentials and encryption keys to stdout for local debugging:
  - `[VP] JWE content encryption key for proxy debugging: <base64url CEK>`
  - `[VP] SD-JWT presentation created: ...`
- Output of a service launched with `--` appears with a `[service]` prefix.
- `--all-traffic` shows the hidden requests too (health checks, favicon)
- `--json` pipes to `jq`: `eudi proxy --target ... --json | jq '.credentials'`
