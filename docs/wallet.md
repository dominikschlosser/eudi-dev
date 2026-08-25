# Wallet

A stateful testing wallet with file persistence, CLI-driven OID4VP/VCI flows, QR scanning, and OS URL scheme registration. Credentials and keys are stored in `~/.eudi-dev/wallet/` (configurable via `--wallet-dir`) and persist across invocations.

The wallet has two validation modes. Both run the same checks. The mode decides what happens to a finding:
- `debug` (default) reports each finding and keeps processing the request, so the failure surfaces where its effect is visible. During DCQL evaluation it warns and keeps a credential match when some required claim paths are missing but other requested claims still match
- `strict` treats the same findings as errors and refuses the request

`--haip` is a separate switch and not a third mode. See [HAIP 1.0 enforcement](wallet/presenting.md#haip-10-enforcement).

For OpenID Foundation conformance work, see [docs/conformance.md](./conformance.md).
For interaction diagrams of the implemented OID4VP and OID4VCI flows, see [docs/diagrams](./diagrams/README.md).

## Subcommands

| Subcommand     | Purpose                                                         |
|----------------|-----------------------------------------------------------------|
| `serve`        | Start wallet HTTP server with web UI, OID4VP endpoints, and optional URL scheme handling |
| `list`         | List stored credentials                                         |
| `show`         | Show a stored credential by ID (raw or decoded)                 |
| `import`       | Import a credential from file, stdin, or raw string (SD-JWT, JWT VC, mDoc) |
| `remove`       | Remove a credential by ID                                       |
| `generate-pid` | Deprecated. Generate default EUDI PID credentials (SD-JWT + mDoc) from the pre-defined PID templates, of the type `--vct` names. Use `issue ... --wallet --template pid-sdjwt|pid-mdoc` (or the `german-pid-*` ones) instead |
| `accept`       | Accept an OID4VP presentation request or OID4VCI credential offer (auto-detects) |
| `scan`         | Scan a QR code and auto-dispatch to accept/import               |
| `refresh`      | Ask a credential's issuer for a fresh copy over the refresh token grant |
| `deferred`     | Credentials an issuer deferred and the wallet is still collecting (`check`, `abandon`) |
| `logs`         | Show persisted wallet-side OID4VP/OID4VCI interaction logs      |
| `trust-list`   | Print the trust list JWT (`--list` for the profiles, `--url` for the URL) |
| `ca-cert`      | Print or export the shared wallet CA certificate                |
| `tls-cert`     | Print or export the HTTPS wallet certificate used by HTTPS wallet endpoints |
| `instances`    | Manage running wallet instances: `list`, `use <url|local>`, `kill <pid|port|url>` |
| `info`         | Show the configuration of the managed wallet (local or remote)  |
| `register`     | Register OS URL scheme handlers on macOS. No-op elsewhere       |
| `unregister`   | Remove OS URL scheme handlers on macOS. No-op elsewhere         |

All wallet management operations (list, show, import, remove, issue, generate-pid, credential templates, cert export) are also available over HTTP on a running `wallet serve` instance, so hosted or containerized wallets can be driven remotely. See [Wallet HTTP API](wallet/http-api.md).

## Quick start

```bash
# Issue PID credentials from the pre-defined templates and list them
eudi issue sdjwt --wallet --template pid-sdjwt
eudi issue mdoc --wallet --template pid-mdoc
eudi wallet list

# The German PID, which extends the country-independent one
eudi issue sdjwt --wallet --template german-pid-sdjwt
eudi issue mdoc --wallet --template german-pid-mdoc

# Deprecated equivalent (issues both PIDs at once, will be removed later)
eudi wallet generate-pid

# Show a credential (raw)
eudi wallet show <id>

# Show a credential (human-readable decoded)
eudi wallet show --decoded <id>

# Start the wallet web UI with stored credentials
eudi wallet serve

# Start the wallet and register URL scheme handlers
eudi wallet serve --register

# Export the shared wallet CA for verifier trust stores
eudi wallet ca-cert --out wallet-ca-cert.pem

# Export the HTTPS wallet certificate for verifier trust stores
eudi wallet tls-cert --out wallet-tls-cert.pem

# Process an OID4VP request from the CLI
eudi wallet accept 'openid4vp://authorize?client_id=...'

# Accept a credential offer (auto-detected from URI)
eudi wallet accept 'openid-credential-offer://...'

# Scan a QR code from screen and auto-detect the flow
eudi wallet scan --screen

# Show wallet-side interactions
eudi wallet logs
eudi wallet logs -f

# Import a credential from a file
eudi wallet import credential.txt

# Register URL scheme handlers so openid4vp:// links open the wallet on macOS
eudi wallet register
```

On Linux and Windows, `wallet register` and `wallet unregister` are accepted as no-ops so shared scripts stay portable. Use `eudi wallet accept '<uri>'` with copied `openid4vp://` or `openid-credential-offer://` links instead.

The macOS URL handler honors the active remote wallet. While a remote target is set with `wallet instances use <url>`, clicked links are submitted to that instance instead of the local listener (useful when the wallet runs in a Docker container). The handler also opens the remote consent UI after submitting the link, since a remote instance cannot open a browser on this desktop. It never restarts or replaces a remote instance. `wallet instances use local` switches link handling back to the local wallet server.

## Credential type inheritance

A domestic PID extends the country-independent one. ARF Annex 2 (v3.0.0) PID_14 requires the vct to be "`urn:eudi:pid:1` for the type defined in this document or a domestic type that extends it", so `urn:eudi:pid:de:1` carries every attribute `urn:eudi:pid:1` defines plus the German ones.

The wallet matches a DCQL `vct_values` entry against the credential's own type and every type it extends. A request for `urn:eudi:pid:1` is answered by any PID, a request for `urn:eudi:pid:de:1` by a German PID. The `[DCQL]` server log names the requested type whenever a credential matched under a type other than its own.

The relationship comes from two places:

- the PID type itself. A segment after `urn:eudi:pid:` that is a country or region code (`urn:eudi:pid:de:1`, `urn:eudi:pid:fr:1`) marks a domestic type, which extends `urn:eudi:pid:1`. A segment that is a version number (`urn:eudi:pid:1`, `urn:eudi:pid:2`) marks the country-independent type
- the `aka_vcts` claim ([SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) §2.2.2.2), which lists further types a credential is also of. It applies to every credential type, and the German PID this tool issues carries it

Inheritance states what a credential is, not who may issue it (§6.6: "Verifiers and Holders MUST NOT assume that any issuer who issues a credential extending a known type is authorized to do so"). Issuer authorization stays with the signature and trust list checks.

In mdoc every PID carries the doctype `eu.europa.ec.eudi.pid.1` (PID_05), and national elements sit in a domestic namespace built by appending the country or region code to it (`eu.europa.ec.eudi.pid.de.1`, PID_06). A `doctype_value` request therefore reaches every PID, and a claim query addresses a national element by its namespace: `"path": ["eu.europa.ec.eudi.pid.de.1", "birth_name"]`.

## Storage

Everything the wallet holds is stored unencrypted, including private keys and any access or refresh tokens an issuer hands over. This is a development and test wallet. The store is meant to be readable, not to hold credentials or tokens that matter. Point it at test issuers and treat the wallet directory as disposable.

All wallet state is stored in `~/.eudi-dev/wallet/` by default:

```
~/.eudi-dev/
├── wallet-ca-cert.pem  # Shared CA certificate used across wallet instances
├── wallet-ca-key.pem   # Shared CA private key
├── remote.json         # Active remote wallet target set by wallet instances use
├── instances/          # Registry of running wallet servers (one file per pid)
└── wallet/
    ├── wallet.json       # Credentials + metadata
    ├── holder.pem        # Holder EC private key (auto-generated on first use)
    ├── issuer.pem        # Issuer EC private key (for self-issued credentials)
    ├── wallet-log-cleaned-at # Timestamp marker written by wallet logs clean
    ├── wallet-tls-cert.pem # HTTPS certificate for wallet endpoints on port+1
    ├── wallet-tls-key.pem  # HTTPS private key for wallet endpoints on port+1
    ├── assets/             # Display images (card art) referenced from wallet.json
    └── templates/          # User credential templates (see templates.md)
```

A credential's display images (logo, background) are kept as content-addressed files in `assets/`, and `wallet.json` holds a reference (`asset:<hash>.<ext>`) rather than the image bytes. This keeps `wallet.json` small enough to reparse on every request on a busy hosted instance. The same image is stored once (content-addressed), and an image the wallet embedded before this layout (a `data:` URI inside `wallet.json`) is still served and moves to `assets/` on the next save.

Wallet interaction logs are stored in `wallet.json` under the top-level `log` field. `wallet logs clean` clears those entries and writes `wallet-log-cleaned-at` so an already-running wallet server cannot later save old in-memory log entries back to disk. If you use `--wallet-dir`, both files live in that custom wallet directory instead.

Keys are P-256 EC keys, auto-generated on first use and reused across invocations. Wallets under the same wallet base directory share a persisted **CA key** and build certificate chains from it:

1. **CA certificate**: self-signed, used as trust anchor in the trust list (`/api/trustlist`)
2. **Leaf certificate**: signed by the CA, wraps the issuer key's public key

Generated credentials are signed with the **issuer key**. SD-JWT credentials include a deterministic `kid` header, expose the signing key through JWT VC issuer metadata, and include the leaf signing certificate in `x5c`. The shared trust-anchor CA stays in the wallet trust list so verifiers can validate the signing key through the exposed trust chain instead of trusting a bare public key.

Each wallet keeps its own issuer key. Its credential-signing leaf certificate and HTTPS wallet certificate are generated from the shared CA.

Generated credentials expire in **30 days** by default. Use `--exp` to override (e.g. `--exp 720h` for 30 days, `--exp 24h` for 1 day). Use `--nbf` to set a not-before time (RFC3339 or duration, e.g. `--nbf 2025-01-15T00:00:00Z` or `--nbf -1h`).

![Wallet UI](./assets/wallet-ui.png)

## `wallet show <id>`

Displays a stored credential by its ID (as shown in `wallet list`). An unambiguous id prefix also resolves, so the short id `wallet list` prints is enough. By default, outputs the raw credential string and nothing else, so it can be piped. Use `--decoded` for human-readable output (supports the `--json` and `-v` global flags). Decoded output begins with a validity line, since the payload states the expiry only as a Unix timestamp.

`wallet list` shows the same in its `VALID` column: the time left (`29d`, `5h`, `expired`) or `-` for a credential that states no lifetime.

```bash
eudi wallet show <id>                  # Raw credential string
eudi wallet show --decoded <id>        # Human-readable output
eudi wallet show --decoded --json <id> # JSON output
```

| Flag        | Default | Description                                          |
|-------------|---------|------------------------------------------------------|
| `--decoded` | `false` | Show human-readable decoded output instead of raw    |

## `wallet logs`

Displays persisted wallet-side protocol interactions, including OID4VP request-object fetches, parsed presentation requests, wallet presentation responses, verifier responses, Browser API responses, OID4VCI credential offers, metadata fetches, token exchanges, credential requests, deferred/notification calls, and imported credentials.

Each entry prints on one line so the output is easy to scan and pipe. Compact lines include protocol markers such as `event`, `direction`, source, endpoint, method, URL, client ID, issuer, response mode, nonce, status code, and payload-presence flags. The global `-v` / `--verbose` flag expands structured details such as request objects, DCQL queries, wallet metadata, token and credential request payloads, sent VP tokens, actual presented credentials, selected claims, verifier response bodies, received credential responses, and imported credential material. `-f` / `--follow` attaches to the wallet log and prints new entries as they are persisted, similar to `kubectl logs -f`.

```bash
eudi wallet logs              # One line per persisted wallet interaction
eudi wallet logs -v           # Expand request/response details
eudi wallet logs -f           # Print existing logs, then follow new entries
eudi wallet logs clean        # Remove old persisted wallet logs
eudi wallet logs --json       # JSON array of log entries
```

| Flag       | Default | Description                                      |
|------------|---------|--------------------------------------------------|
| `-f, --follow` | `false` | Keep running and print new entries as they appear. Local wallets only (a remote wallet is refused) |
| `-v, --verbose` | `false` | Global flag. Expand structured log details        |
| `--json`   | `false` | Global flag. Output the persisted log entries as JSON. Cannot be combined with `--follow` |

## Serving the wallet

`wallet serve` runs the persistent HTTP server: the web UI, the OID4VP and OID4VCI endpoints, the trust lists, and the management API. It loads credentials from disk, shows a browser consent dialog for incoming requests, and can register OS URL scheme handlers.

```bash
eudi wallet serve                      # web UI on http://localhost:8085
eudi wallet serve --auto-accept --pid  # headless, with default PIDs, for tests
```

See [serving the wallet](wallet/serve.md) for the endpoints it exposes, the trust lists and their profiles, certificate export (`ca-cert`, `tls-cert`), URL scheme registration (`register`), changing the conformance settings at runtime, and every `wallet serve` flag.

## Presenting from the wallet

`wallet accept` answers an OID4VP presentation request (and dispatches a credential offer to issuance). `wallet scan` does the same from a QR code, and the same flows are reachable at the wallet's own `/authorize` and `/credential-offer` URLs without a custom scheme.

```bash
eudi wallet accept 'openid4vp://authorize?...'   # evaluate DCQL, consent, submit
eudi wallet scan --screen                        # scan a QR and dispatch
```

See [presenting from the wallet](wallet/presenting.md) for `wallet accept` and `wallet scan` in full, invoking the wallet by URL, and holding incoming requests to HAIP 1.0.

## Issuing into the wallet

A credential offer is accepted with `wallet accept` (or the UI, a scanned QR, or the `/credential-offer` URL). The wallet handles sign-in at the issuer, deferred issuance, later renewal, and interactive (presentation-during-issuance) authorization.

```bash
eudi wallet accept 'openid-credential-offer://...'   # accept an offer
eudi wallet deferred                                 # what is still being collected
eudi wallet refresh <credential-id>                  # ask for a fresh copy
```

See [issuing into the wallet](wallet/issuing.md) for sign-in during issuance, renewing a credential, deferred issuance, the wallet attestation the wallet sends, the OpenID4VCI feature level (`--vci-version`), and interactive authorization.

## HTTP API

Everything the CLI does locally is also on a running `wallet serve` instance over HTTP (list, show, import, remove, issue, generate PIDs, manage templates, set status, export certificates, introspect, shut down). The API has no authentication and is for local development and isolated test networks.

```bash
curl http://localhost:8085/api/credentials
curl -X POST http://localhost:8085/api/issue -d '{"format":"sdjwt","pid":true}'
```

See [the wallet HTTP API](wallet/http-api.md) for every endpoint and for remote control (driving another instance from the CLI).

## Shared flags

All wallet subcommands accept `--wallet-dir` to override the storage directory and `--templates-dir` to override the credential template directory (see [templates](templates.md)):

```bash
eudi wallet list --wallet-dir /tmp/test-wallet
eudi wallet serve --templates-dir ./my-templates
```
