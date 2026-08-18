# Proxy

Intercept and debug OID4VP/VCI traffic between a wallet and a verifier/issuer. Point your wallet at the proxy instead of the real server. Every request and response is captured, classified by protocol step, decoded, and shown in the terminal and a live web dashboard.

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

By default, only OID4VP/VCI traffic is shown. Non-matching requests (favicon, health checks, etc.) are still proxied but hidden. Pass `--all-traffic` or toggle the "All traffic" checkbox in the dashboard to see everything.

## Features

- **Smart decoding**: payloads are decoded inline (SD-JWT, JWT, mDOC, DCQL queries, JWE headers)
- **Credential decode hints**: detected credentials are printed as `eudi decode` commands for quick inspection
- **JARM/JWE decryption**: when the built-in wallet sends a `direct_post.jwt` response through the proxy, the encrypted payload is automatically decrypted (see [JWE Decryption](#jwe-decryption) below)
- **Flow correlation**: related protocol steps are grouped by shared `state`/`nonce` values
- **Web dashboard** at `http://localhost:9091` with live SSE updates, expandable cards, "View in Decoder" links, HAR export, and cURL copy
- **JARM/JWE detection**: shows encrypted response headers and the verifier's ephemeral public key
- **NDJSON output**: `--json` for machine-readable output, pipe to `jq` or log to file
- **Attach to a running proxy**: `eudi proxy logs` prints the traffic of a proxy that is already running, from another terminal (see [reading a running proxy](#reading-a-running-proxy))

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

`eudi proxy logs [dashboard-url]` reads a proxy that is already running:

| Flag             | Default | Description                                        |
|------------------|---------|----------------------------------------------------|
| `[dashboard-url]`| `http://localhost:9091` | Dashboard of the proxy to read      |
| `-f, --follow`   | `false` | Keep printing as the proxy records traffic         |
| `--json`         | `false` | Print the recorded traffic as JSON (global flag)   |

## Reading a running proxy

A proxy in a container, in the background, or on another machine prints to a
terminal you do not have. The CLI reads its traffic from the dashboard
instead:

```bash
# a proxy on this machine
eudi proxy logs

# a proxy whose dashboard port is published from a container
eudi proxy logs http://localhost:9091 --follow

# somewhere else entirely
eudi proxy logs https://proxy.internal.example --follow
```

The output is the same the proxy prints itself, with decode links pointing at
that dashboard. `--follow` keeps printing as traffic arrives and keeps
reattaching when the stream ends, until you interrupt it: after each
reattachment it re-reads the recorded traffic, so what arrived while the
stream was down is printed too, including after a proxy restart (which numbers
its traffic from the beginning again). `--json` prints the recorded traffic as
JSON and cannot be combined with `--follow`.

The argument is the dashboard URL, not the proxy port. A proxy started without
`--all-traffic` never recorded non-OID4VP/VCI requests, so they cannot be read
back here either.

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

This works via a debug header. The wallet puts the AES content encryption key (CEK) in `X-Debug-JWE-CEK`. The proxy strips this header before forwarding, so the verifier never sees it.

No configuration is needed. Route the wallet through the proxy:

```
eudi wallet serve                    # wallet sends to response_uri
eudi proxy --target http://verifier  # proxy intercepts, decrypts, forwards
```

### Automatic key detection from service stdout

A **third-party wallet** does not send the debug header. If you launch the verifier service as a subprocess (with `--`), the proxy scans its stdout for CEK values and uses them to decrypt JWE responses:

```bash
eudi proxy --target http://localhost:3000 -- mvn spring-boot:run
```

The proxy detects lines matching patterns like:
- `CEK: <base64url>` or `content encryption key: <base64url>`
- JWK objects containing a `"d"` (private key) parameter

This is best-effort. If no key is found, the proxy shows only the JWE header fields (`alg`, `enc`, `kid`, `epk`).

### Credential detection from service stdout

The proxy also scans the subprocess's stdout for JWT/SD-JWT credentials. Detected credentials are added to the activity log with decode links:

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
