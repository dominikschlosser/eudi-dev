<p align="center">
  <img src="docs/assets/logo-mark.svg" alt="eudi-dev logo" width="110">
</p>

# eudi-dev

[![CI](https://github.com/dominikschlosser/eudi-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/dominikschlosser/eudi-dev/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/dominikschlosser/eudi-dev/graph/badge.svg)](https://codecov.io/gh/dominikschlosser/eudi-dev)
[![Release](https://img.shields.io/github/v/release/dominikschlosser/eudi-dev)](https://github.com/dominikschlosser/eudi-dev/releases/latest)

[![OpenID4VP](https://img.shields.io/badge/OpenID4VP-1.0-blue)](docs/spec-compliance.md#oid4vp-10-openid-for-verifiable-presentations)
[![OpenID4VCI](https://img.shields.io/badge/OpenID4VCI-1.0%20%2B%201.1%20draft-blue)](docs/spec-compliance.md#oid4vci-10-openid-for-verifiable-credential-issuance)
[![HAIP](https://img.shields.io/badge/HAIP-1.0-blue)](docs/spec-compliance.md#haip-10-high-assurance-interoperability-profile)
[![SD-JWT](https://img.shields.io/badge/SD--JWT-RFC%209901-blue)](docs/spec-compliance.md#sd-jwt-selective-disclosure-jwt)
[![SD-JWT VC](https://img.shields.io/badge/SD--JWT%20VC-draft--18-blue)](docs/spec-compliance.md#sd-jwt-selective-disclosure-jwt)
[![mdoc](https://img.shields.io/badge/mdoc-ISO%2018013--5-blue)](docs/spec-compliance.md#mdoc--iso-18013-5)
[![Token Status List](https://img.shields.io/badge/Token%20Status%20List-draft--21-blue)](docs/spec-compliance.md#token-status-list-draft-ietf-oauth-status-list)
[![ETSI](https://img.shields.io/badge/ETSI-TS%20119%20602-blue)](docs/spec-compliance.md#etsi-ts-119-602-trusted-entity-lists)

An unofficial developer toolkit for the EUDI and OpenID4VC ecosystem. Decode, issue, and present verifiable credentials, run a testing wallet, or proxy live wallet traffic for debugging. The CLI command is `eudi`.

> **Try it online:** a shared public demo of the wallet and decoder runs at **<https://eudi-test.dev>**. Issue, present, and decode test credentials in the browser. State is shared between all visitors and resets daily, so do not enter personal data.

## Highlights

- **Wallet**: test issuance and presentation from the CLI or browser. Store state in files, memory or Postgres ([wallet](#wallet)).
- **Proxy**: inspect live OID4VP and OID4VCI traffic ([proxy](#proxy)).
- **Decoder**: inspect credentials, requests, offers and trust lists in the CLI or browser ([decode](#decode), [serve](#serve)).
- **Validation**: check signatures, expiry and status, with optional trust lists ([validate](#validate)).
- **QR scanning**: read credentials and requests from an image or your screen ([decode](#decode)).
- **DCQL**: generate a query from a credential ([dcql](#dcql)).

## Compared to other EUDI tooling

Use eudi-dev as a wallet to test your issuer or verifier. The table below shows how it compares with other EUDI tools.

| Tool | What it tests | Runs locally | Scriptable |
|---|---|---|---|
| **eudi-dev** | your issuer or verifier | yes | CLI and HTTP API |
| [Animo OpenID4VC Playground](https://playground.animo.id/) | your wallet | self-hostable | no, web UI |
| [EUDIPLO Playground](https://playground.eudi-wallet.org/) | your wallet | self-hostable | no, web UI |
| [EUDI reference issuer and verifier](https://docs.eudi.dev/latest/test/issuer/) | your wallet | issuer only | no, web UI |
| [EUDI Web Wallet Tester](https://github.com/eu-digital-identity-wallet/eudi-app-web-wallet-tester-py) | your issuer, OID4VCI only | yes | no, web UI |
| [EUDI reference wallet](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui) (Android, iOS) | your issuer or verifier | on a device | no |
| [Procivis One](https://github.com/procivis/one-wallet) trial apps | your issuer or wallet | on a device | no |
| [Multipaz](https://github.com/openwallet-foundation/multipaz) | your wallet or issuer, and proximity | SDK, apps, [hosted issuer and verifier](https://verifier.multipaz.org) | no |
| [Paradym debuggers](https://paradym.id/articles/developer-tool-sdjwtvc-debugger) | one credential, decoded | no | no |
| SDKs: [walt.id](https://docs.walt.id/), [Sphereon](https://github.com/Sphereon-Opensource/OID4VC), [Credo](https://github.com/openwallet-foundation/credo-ts), [Procivis One](https://github.com/procivis/one-core) | whatever you build | yes | as you write it |

When to use something else:

- For certification, the OIDF suite is the authority. This repository runs its plans (see [conformance](docs/conformance.md)), but only the OIDF certifies.
- To test a wallet, point it at one of the hosted issuer or verifier services above.
- To ship a product, use an SDK. Everything here is under `internal/`.
- For proximity flows (BLE, NFC), use Multipaz. This tool implements OID4VP over HTTP.
- To read a single credential, use a hosted decoder.

Never use real credentials (see [SECURITY.md](SECURITY.md)).

## Install

### Homebrew (macOS and Linux)

```bash
brew install dominikschlosser/tap/eudi-dev
```

Installs the `eudi` command with shell completion (plus `oid4vc-dev` as a legacy alias).

### From GitHub Releases

Download the latest binary for your platform from [Releases](https://github.com/dominikschlosser/eudi-dev/releases).

### From source

```bash
go install github.com/dominikschlosser/eudi-dev/v2@latest
```

This installs the binary as `eudi-dev` (Go names it after the module). The documentation calls the command `eudi`. Link it for the shorter name: `ln -s "$(go env GOPATH)/bin/eudi-dev" "$(go env GOPATH)/bin/eudi"`.

The v2 module path is `github.com/dominikschlosser/eudi-dev/v2`. The `/v2` suffix is required for v2 releases. Earlier v2 tags, through v2.4.2, have an incorrect module path and must be installed from release binaries or built from source.

### Build locally

```bash
git clone https://github.com/dominikschlosser/eudi-dev.git
cd eudi-dev
go build -o eudi .
```

### Docker

```bash
docker pull ghcr.io/dominikschlosser/eudi-dev:latest
docker run -p 8085:8085 -p 8086:8086 ghcr.io/dominikschlosser/eudi-dev
```

The default CMD starts the wallet server headless with pre-loaded PID credentials. The container keeps its state in memory and needs no volume.

→ [Full Docker & verifier testing guide](docs/docker.md)
→ [OIDF conformance status](docs/conformance.md), [runbook](docs/conformance-run.md), and [results](docs/conformance-results.md)
→ [Examples](docs/examples.md)

## Usage

```
eudi [--json] [--no-color] [-v] <command> [flags] [input]
```

Input can be a **file path**, **URL**, **raw credential string**, or piped via **stdin**.

Shell completion covers all subcommands, flags, and known values (template names, credential IDs, running wallet instances). Install it for bash, zsh, or fish (detected from `$SHELL`):

```bash
eudi completion install
```

### Commands

| Command    | Purpose                                                    |
|------------|------------------------------------------------------------|
| `wallet`   | Stateful testing wallet with CLI-driven OID4VP/VCI flows   |
| `issue`    | Generate test SD-JWT, JWT, or mDOC credentials for development |
| `proxy`    | Debugging reverse proxy for OID4VP/VCI wallet traffic      |
| `serve`    | Web UI for decoding and validating credentials in the browser |
| `decode`   | Detect and inspect credentials, OpenID4VCI/VP requests, and trust lists. Verifies issuer metadata when resolvable |
| `validate` | Verify signatures, check expiry, and check revocation status |
| `templates` | Manage credential templates (`list`, `show`, `save`, `import`, `delete`) |
| `dcql`     | Generate a DCQL query from a credential's claims            |
| `completion` | Generate or install shell completion (`completion install`) |
| `version`  | Print version                                               |

---

### Wallet

A stateful testing wallet with CLI-driven OID4VP/VCI flows, QR scanning, and OS URL scheme registration. State lives in files by default, or in memory or Postgres with `--storage`.

```bash
eudi issue sdjwt --wallet --template pid-sdjwt         # Issue a PID into the wallet
eudi wallet serve                 # Start web UI + OID4VP endpoints
eudi wallet ca-cert --out wallet-ca-cert.pem
eudi wallet tls-cert --out wallet-tls-cert.pem
eudi wallet accept 'openid4vp://authorize?...'
eudi wallet scan --screen         # QR scan → auto-dispatch
eudi wallet logs -f               # Follow persisted wallet interactions
```

> **Security:** Anyone who can reach the wallet port controls its credentials. Use localhost or an isolated test network and store test data only. The API rejects requests from other web origins, except `/api/dc-api`, which uses the caller origin and consent dialog. For public hosting, use the `--demo` profile described in [public demo hosting](docs/public-demo.md).

`wallet serve` hosts the UI and protocol endpoints, including issuer metadata, trust lists and status lists. Use `issue ... --wallet --template pid-sdjwt` to add a PID. `wallet ca-cert` and `wallet tls-cert` export certificates for verifier trust stores. The same operations are available through the [HTTP API](docs/wallet/http-api.md) for automated tests.

The main commands:

- `wallet serve` to run the wallet
- `issue ... --wallet` (with `--template` or `--pid`) to preload credentials
- `wallet ps` to find running wallet servers
- `wallet use <url>` to select a remote or containerized wallet
- `wallet kill` to stop a wallet server
- `wallet trust-list` to get the verifier trust-list URL or JWT
- `wallet logs` to inspect wallet-side OID4VP/OID4VCI interactions
- `wallet ca-cert` and `wallet tls-cert` to export certificate material
- `wallet --mode debug|strict` and `--preferred-format ...` to control runtime behavior
- `wallet serve --haip` to check verifiers and issuers against HAIP 1.0

`--haip` adds HAIP 1.0 checks. `--mode strict` stops on findings, while `--mode debug` reports them and continues. This applies to HAIP findings too. See [HAIP enforcement](docs/wallet/presenting.md#haip-10-enforcement).

When a server already serves the selected wallet directory, CLI commands use its API. After `wallet use <url>`, commands and clicked offer or presentation links go to that target. Discovery lists local instances and the active remote target.

Use `/api/trustlists` to list trust-list profiles. Each entry has a relative `path` that works with Docker port mappings. The web UI shows these URLs above the certificate downloads.

![Wallet UI](docs/assets/wallet-ui.png)

→ [Full documentation](docs/wallet.md): subcommands, flags, endpoints, logs, trust lists, storage, URL scheme registration
→ [Public demo hosting](docs/public-demo.md): run a shared internet-facing demo with `--demo` (hardened endpoints, periodic reset, imprint page)
→ [Flow diagrams](docs/diagrams/README.md): OID4VP / OID4VCI interaction diagrams and parameter checklists

---

### Issue

Generate test SD-JWT, JWT, or mDOC credentials for development and testing.

```bash
eudi issue sdjwt --pid
eudi issue sdjwt --template employee-card --claims '{"employee_id": "E-42"}'
eudi issue sdjwt --pid --always-disclosed issuing_country,address.country
eudi issue jwt --claims '{"name":"Test","age":30}'
eudi issue mdoc --claims '{"name":"Test"}' --doc-type com.example.test
eudi issue sdjwt | eudi decode
```

Credential templates hold reusable claim sets (`templates list|show|save|import|delete`). A template carries the credential type, default claims, and the always disclosed claims. Templates work in the CLI, the HTTP API, and the wallet UI.

→ [Full documentation](docs/issue.md): all flags, round-trip examples
→ [Credential templates](docs/templates.md): template files, management commands, always disclosed claims

---

### Proxy

Intercept and debug OID4VP/VCI traffic between a wallet and a verifier/issuer with a live web dashboard.

```bash
eudi proxy --target http://localhost:8080
```

```
Wallet  <-->  Proxy (:9090)  <-->  Verifier/Issuer (:8080)
                  |
            Live dashboard (:9091)
```

→ [Full documentation](docs/proxy.md): traffic classification, features, flags

---

### Serve

Start a local web UI for decoding and validating credentials in the browser.

```bash
eudi serve
eudi serve --port 3000
eudi serve credential.txt
```

The UI opens at `http://localhost:8080` by default. Paste a credential to decode it, expand its sections and check its signature. A credential passed on the command line fills the input automatically. `--imprint-file` adds a legal notice at `/imprint`.

![Web UI screenshot](docs/assets/web-ui.png)

> **Warning:** Credentials are sent to the server for decoding. Run it locally, or see [public demo hosting](docs/public-demo.md) for an internet-facing setup.

---

### Decode

Auto-detect and decode credentials (SD-JWT, JWT VC, mDOC), OpenID4VCI/VP requests, and ETSI trust lists.

```bash
eudi decode credential.txt
eudi decode 'openid4vp://authorize?...'
eudi decode --screen                    # QR scan from screen
```

→ [Full documentation](docs/decode.md): auto-detection order, format override, QR scanning, flags

---

### Validate

Verify signatures, check expiry, and check revocation status.

```bash
eudi validate --key issuer-key.pem credential.txt
eudi validate --trust-list trust-list.jwt credential.txt
eudi validate credential.txt
```

→ [Full documentation](docs/validate.md): flags, trust list explanation

---

### DCQL

Generate a DCQL (Digital Credentials Query Language) query from a credential's claims. Output is always JSON.

```bash
eudi dcql credential.txt
```

**Example output (SD-JWT):**

```json
{
  "credentials": [
    {
      "id": "urn_eudi_pid_1",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:eudi:pid:1"] },
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
| **SD-JWT** (`dc+sd-jwt`) | Header/payload, disclosures, `_sd` resolution, key binding JWT. Signature: ES256/384/512, RS256/384/512, PS256/384/512 |
| **JWT VC** (`jwt_vc_json`) | Plain JWT Verifiable Credentials (W3C JWT VC format), presented as-is |
| **mDOC** (`mso_mdoc`) | CBOR IssuerSigned & DeviceResponse (hex/base64url), COSE_Sign1 issuerAuth, MSO |
| **OpenID4VCI / VP** | Credential offers, authorization requests, URI schemes (`openid-credential-offer://`, `haip-vci://`, `openid4vp://`, `haip-vp://`, `eudi-openid4vp://`) |
| **ETSI Trust Lists** | TS 119 602 trust list JWTs with entity names, identifiers, and service types |

## Spec Compliance

See [docs/spec-compliance.md](docs/spec-compliance.md) for the compliance status against OID4VP 1.0, OID4VCI 1.0, HAIP 1.0, SD-JWT (RFC 9901) and SD-JWT VC, mDoc (ISO 18013-5), ETSI trust lists, and Token Status List.
For the issuer and verifier interactions as diagrams, see [docs/diagrams/README.md](docs/diagrams/README.md).

## Global Flags

| Flag         | Description              |
|--------------|--------------------------|
| `--json`     | Output as JSON           |
| `--no-color` | Disable colored output   |
| `-v`         | Verbose output (x5c chain, device key, digest IDs) |

## Notices

**No EU affiliation:** This is an independent open source project, not affiliated with or endorsed by the European Commission or the European Union. "EUDI" is used descriptively (a developer tool for the European Digital Identity ecosystem). For official EUDI Wallet resources see the [eu-digital-identity-wallet](https://github.com/eu-digital-identity-wallet) organization.

**Renamed from oid4vc-dev:** The old name keeps working. A binary named `oid4vc-dev` behaves identically (help and completion adapt to the invoked name). The legacy `~/.oid4vc-dev` state directory and `OID4VC_DEV_HOME` variable are honored. The `ghcr.io/dominikschlosser/oid4vc-dev` image receives releases.

## License

Apache-2.0
