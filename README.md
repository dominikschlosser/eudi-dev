# oid4vc-dev

[![CI](https://github.com/dominikschlosser/oid4vc-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/dominikschlosser/oid4vc-dev/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/dominikschlosser/oid4vc-dev/graph/badge.svg)](https://codecov.io/gh/dominikschlosser/oid4vc-dev)
[![Release](https://img.shields.io/github/v/release/dominikschlosser/oid4vc-dev)](https://github.com/dominikschlosser/oid4vc-dev/releases/latest)

A developer toolkit for OpenID4VC — decode, issue, and present verifiable credentials, run a testing wallet, or proxy live wallet traffic for debugging.

## Highlights

- **Testing Wallet** — stateful CLI wallet with file persistence, OID4VP/VCI flows, QR scanning, and OS URL scheme registration ([wallet](#wallet))
- **Reverse Proxy** — intercept, classify, and decode OID4VP/VCI wallet traffic in real time ([proxy](#proxy))
- **Web UI** — paste, decode, and validate credentials in a split-pane browser interface ([serve](#serve))
- **Unified Decode** — a single `decode` command handles SD-JWT, JWT VC, JWT, mDOC, OID4VCI offers, OID4VP requests, and ETSI trust lists
- **QR Screen Capture** — scan a QR code straight from your screen to decode credentials or OpenID requests ([decode --screen](#decode))
- **Offline Decode & Validate** — SD-JWT, JWT VC, mDOC, JWT with signature verification and trust list support
- **DCQL Generation** — generate Digital Credentials Query Language queries from existing credentials

## Install

### From GitHub Releases

Download the latest binary for your platform from [Releases](https://github.com/dominikschlosser/oid4vc-dev/releases).

### From source

```bash
go install github.com/dominikschlosser/oid4vc-dev@latest
```

### Build locally

```bash
git clone https://github.com/dominikschlosser/oid4vc-dev.git
cd oid4vc-dev
go build -o oid4vc-dev .
```

### Docker

```bash
docker pull ghcr.io/dominikschlosser/oid4vc-dev:latest
docker run -p 8085:8085 -p 8086:8086 ghcr.io/dominikschlosser/oid4vc-dev
```

The default CMD starts the wallet server with pre-loaded PID credentials in headless mode — ready for automated verifier testing out of the box.

→ [Full Docker & verifier testing guide](docs/docker.md)
→ [OIDF conformance status](docs/conformance.md), [runbook](docs/conformance-run.md), and [results](docs/conformance-results.md)
→ [Examples](docs/examples.md)

## Usage

```
oid4vc-dev [--json] [--no-color] [-v] <command> [flags] [input]
```

Input can be a **file path**, **URL**, **raw credential string**, or piped via **stdin**.

### Commands

| Command    | Purpose                                                    |
|------------|------------------------------------------------------------|
| `wallet`   | Stateful testing wallet with CLI-driven OID4VP/VCI flows   |
| `issue`    | Generate test SD-JWT, JWT, or mDOC credentials for development |
| `proxy`    | Debugging reverse proxy for OID4VP/VCI wallet traffic      |
| `serve`    | Web UI for decoding and validating credentials in the browser |
| `decode`   | Auto-detect & inspect credentials, OpenID4VCI/VP, and trust lists; may auto-verify issuer metadata when resolvable |
| `validate` | Verify signatures, check expiry, and check revocation status |
| `dcql`     | Generate a DCQL query from a credential's claims            |
| `version`  | Print version                                               |

---

### Wallet

A stateful testing wallet with file persistence, CLI-driven OID4VP/VCI flows, QR scanning, and OS URL scheme registration.

```bash
oid4vc-dev wallet generate-pid          # Generate PID credentials
oid4vc-dev wallet serve                 # Start web UI + OID4VP endpoints
oid4vc-dev wallet ca-cert --out wallet-ca-cert.pem
oid4vc-dev wallet tls-cert --out wallet-tls-cert.pem
oid4vc-dev wallet accept 'openid4vp://authorize?...'
oid4vc-dev wallet scan --screen         # QR scan → auto-dispatch
oid4vc-dev wallet logs -f               # Follow persisted wallet interactions
```

> **Security:** The wallet server exposes unauthenticated HTTP endpoints for credential management and presentation flows. It is designed exclusively for **local development and testing** — never expose it to untrusted networks.

`wallet serve` starts the local wallet UI plus HTTP and HTTPS wallet endpoints for presentation, issuer metadata, trust lists, status lists, and test registrar responses. `wallet generate-pid` gives you a ready-to-use PID wallet, `issue ... --wallet` adds new credentials into the same wallet context, and `wallet ca-cert` / `wallet tls-cert` export the trust root or exact HTTPS leaf certificate when a verifier needs them. All of these wallet operations are also available on the server's unauthenticated [HTTP API](docs/wallet.md#http-api). This lets automated tests manage and drive a hosted or containerized wallet entirely over HTTP.

For day-to-day use, the main commands are:
- `wallet serve` to run the wallet
- `wallet generate-pid` to preload PID credentials
- `wallet trust-list` to get the verifier trust-list URL or JWT
- `wallet logs` to inspect wallet-side OID4VP/OID4VCI interactions
- `wallet ca-cert` and `wallet tls-cert` to export certificate material
- `wallet --mode debug|strict` and `--preferred-format ...` to control runtime behavior

When a wallet exposes multiple trust-list profiles, `/api/trustlists` gives you the available IDs and routes. Use the entry's relative `path` when you access the wallet through Docker port mappings or similar local indirection.

![Wallet UI](docs/wallet-ui.png)

→ [Full documentation](docs/wallet.md) — subcommands, flags, endpoints, logs, trust lists, storage, URL scheme registration
→ [Flow diagrams](docs/diagrams/README.md) — GitHub-rendered OID4VP / OID4VCI interaction diagrams and parameter checklists

---

### Issue

Generate test SD-JWT, JWT, or mDOC credentials for development and testing.

```bash
oid4vc-dev issue sdjwt --pid
oid4vc-dev issue jwt --claims '{"name":"Test","age":30}'
oid4vc-dev issue mdoc --claims '{"name":"Test"}' --doc-type com.example.test
oid4vc-dev issue sdjwt | oid4vc-dev decode
```

→ [Full documentation](docs/issue.md) — all flags, round-trip examples

---

### Proxy

Intercept and debug OID4VP/VCI traffic between a wallet and a verifier/issuer with a live web dashboard.

```bash
oid4vc-dev proxy --target http://localhost:8080
```

```
Wallet  <-->  Proxy (:9090)  <-->  Verifier/Issuer (:8080)
                  |
            Live dashboard (:9091)
```

→ [Full documentation](docs/proxy.md) — traffic classification, features, flags

---

### Serve

Start a local web UI for decoding and validating credentials in the browser.

```bash
oid4vc-dev serve
oid4vc-dev serve --port 3000
oid4vc-dev serve credential.txt
```

Opens a split-pane interface at `http://localhost:8080` (default) with auto-decode on paste, format detection, collapsible sections, signature verification, and dark/light theme. Pass a credential as an argument to pre-fill the input on load.

![Web UI screenshot](docs/web-ui.png)

> **Warning:** Only run locally — credentials are sent to the local server for decoding.

---

### Decode

Auto-detect and decode credentials (SD-JWT, JWT VC, mDOC), OpenID4VCI/VP requests, and ETSI trust lists.

```bash
oid4vc-dev decode credential.txt
oid4vc-dev decode 'openid4vp://authorize?...'
oid4vc-dev decode --screen                    # QR scan from screen
```

→ [Full documentation](docs/decode.md) — auto-detection order, format override, QR scanning, flags

---

### Validate

Verify signatures, check expiry, and check revocation status.

```bash
oid4vc-dev validate --key issuer-key.pem credential.txt
oid4vc-dev validate --trust-list trust-list.jwt credential.txt
oid4vc-dev validate credential.txt
```

→ [Full documentation](docs/validate.md) — flags, trust list explanation

---

### DCQL

Generate a DCQL (Digital Credentials Query Language) query from a credential's claims. Always outputs JSON.

```bash
oid4vc-dev dcql credential.txt
```

The wallet evaluates `credential_sets` constraints when processing DCQL queries, selecting the best matching option from each set.

**Example output (SD-JWT):**

```json
{
  "credentials": [
    {
      "id": "urn_eudi_pid_1",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
      "claims": [
        { "path": ["birth_date"] },
        { "path": ["family_name"] },
        { "path": ["given_name"] }
      ]
    }
  ]
}
```

---

## Supported Formats

| Format | Description |
|--------|-------------|
| **SD-JWT** (`dc+sd-jwt`) | Header/payload, disclosures, `_sd` resolution, key binding JWT. Signature: ES256/384/512, RS256/384/512, PS256 |
| **JWT VC** (`jwt_vc_json`) | Plain JWT Verifiable Credentials (W3C JWT VC format). Presented as-is without selective disclosure |
| **mDOC** (`mso_mdoc`) | CBOR IssuerSigned & DeviceResponse (hex/base64url), COSE_Sign1 issuerAuth, MSO |
| **OpenID4VCI / VP** | Credential offers, authorization requests, URI schemes (`openid-credential-offer://`, `haip-vci://`, `openid4vp://`, `haip-vp://`, `eudi-openid4vp://`) |
| **ETSI Trust Lists** | TS 119 602 trust list JWTs with entity names, identifiers, and service types |

## Spec Compliance

See [docs/spec-compliance.md](docs/spec-compliance.md) for detailed compliance status against OID4VP 1.0, OID4VCI 1.0, the currently implemented HAIP subset, SD-JWT, mDoc (ISO 18013-5), ETSI trust lists, and RFC 9596.
For a system-level view of the implemented issuer and verifier interactions, see [docs/diagrams/README.md](docs/diagrams/README.md).

## Global Flags

| Flag         | Description              |
|--------------|--------------------------|
| `--json`     | Output as JSON           |
| `--no-color` | Disable colored output   |
| `-v`         | Verbose output (x5c chain, device key, digest IDs) |

## License

Apache-2.0
