[← Wallet](../wallet.md)

# Serving the wallet

`wallet serve` runs the persistent wallet HTTP server (web UI, OID4VP and OID4VCI endpoints, trust lists, optional URL scheme handling). This page also covers the certificate exports (`ca-cert`, `tls-cert`), the `trust-list` command, URL scheme registration (`register`, `unregister`), and the runtime conformance settings.

## `wallet serve`

Starts the wallet HTTP server with a web UI for managing credentials and handling OID4VP/OID4VCI flows. It loads credentials from disk, saves state on every credential change, logs requests, and shows a consent dialog for incoming requests.

The server exposes:
- Web UI for credential management and consent (list, show, import, remove, and issue credentials, with credential templates and CA and TLS certificate downloads)
- OID4VP authorization endpoint (`/authorize`)
- OID4VCI credential offer endpoint (`/credential-offer`). Accepts `credential_offer` / `credential_offer_uri` query parameters, so offer links can target the wallet URL instead of a custom scheme (see [Invoking the wallet by URL](presenting.md#invoking-the-wallet-by-url))
- Legacy ETSI trust list endpoint (`/api/trustlist`). Use this URL as `--trust-list` when validating PID credentials issued by the wallet
- Trust-list index endpoint (`/api/trustlists`) with one JWT endpoint per coherent trust-list profile
- HTTPS wallet endpoints on the wallet's effective issuer URL, including `/.well-known/jwt-vc-issuer`, `/.well-known/openid-credential-issuer`, `/api/trustlist`, `/api/trustlists`, `/api/statuslist`, and `/api/registrar/wrp`
- A management API mirroring the wallet CLI (list, show, import, and remove credentials, issue credentials, generate PIDs, export certificates). It has no authentication (see [HTTP API](http-api.md))

The consent dialog for a credential offer shows the issuer's name and origin, the flow the offer uses, whether a transaction code is required, and for each offered credential its format, type, display name, description and claims. Everything beyond the offer itself comes from the issuer's metadata and is optional. An offer delivered as a `credential_offer_uri` is fetched for the dialog and fetched again on approval (OpenID4VCI 1.0 §4.1.3). When an issuer consumes the offer on the first read, the approved issuance continues with the offer the dialog resolved, and the activity log warns about the failed read. When the dialog could not retrieve the offer at all, it shows the issuer the URI points at, and approving retries. An offer whose pre-authorized grant requires a `tx_code` is refused before the pre-authorized code is used when the issuance has no code (an auto-accepting wallet, or an API caller that left it out). The refusal states the length and input mode the offer asked for.

Once a credential is stored, the wallet calls the issuer's Notification Endpoint where one is published. The endpoint is optional (OpenID4VCI 1.0 §11), so a refused call produces a warning and the credential stays in the wallet. The warning quotes the answer and compares it with §11.3 (an Authorization Error Response for a rejected token, a 400 for a bad `notification_id`).

The consent dialog for a presentation request also shows the purpose the verifier registered. The wallet reads it from the wallet-relying-party registration certificate (typ `rc-wrp+jwt`, in a `verifier_info` entry of format `registration_cert`) per OpenID4VP 1.0 §5.1. A certificate whose signature fails against its own x5c leaf is skipped with a warning in the activity log. The built-in demo verifier and demo issuer send such certificates with every request.

The dialog opens with the wallet's automatic selection. When a request has alternatives (several stored credentials match a query, or the DCQL `credential_sets` offer more than one option), a row above the credential cards says so and offers **Edit**. The Edit view lists the set options the wallet can satisfy and, per credential query id, the matching credentials. Changes apply immediately, **Done** returns to the summary, and **reset to auto** restores the wallet's choice. Deny and Approve apply to the whole presentation on both screens. The claim checkboxes stay on the main screen and belong to the picked credential. The consent request carries the alternatives as `credential_options`. `POST /api/requests/{id}/approve` takes the selection as `picks` (query id to credential id) and `set_choices` (option index per set, `-1` skips an optional set) next to `selected_claims`, so API clients can make the same choice. An approval that selects credentials the request did not offer is refused with `400` and the request stays pending. Auto-accept wallets submit the auto-selection without a dialog.

![Consent dialog](../assets/wallet-consent-ui.png)

![Consent credential selection](../assets/wallet-consent-edit-ui.png)

A credential card shows the appearance the issuer declared (display name, logo, text and background colors, and a background image). Without one the card shows a monogram from the name or a generic glyph. An About control opens the credential's description. Two credentials of the same type differ by display name (the two PIDs are named `EUDI PID` and `German PID`). The technical type and a short id are on the meta line below.

The Issue Credential dialog issues credentials from the web UI. It shows format specific fields and offers a claim builder next to a raw JSON editor. Selecting a credential template (for example `german-pid-sdjwt`) fills all fields for review before issuing. A status list selector controls the embedded status reference (the wallet's own list when configured, none, or a custom URI and index).

Credential cards show the revocation status when a credential carries a status list reference. Credentials on the wallet's own status list show a live Active or Revoked badge plus a Revoke or Activate button. Credentials pointing at an external status list show a Check status action that fetches the list and resolves the current value.

Every interactive control has a stable element id for browser automation. Credential cards expose data attributes for selection (`data-credential-id`, `data-format`, `data-vct`, `data-doctype`, `data-status`), so a test can select a card with `.credential-card[data-vct="urn:eudi:pid:1"]` and click its buttons (`show-<id>`, `delete-<id>`, `revoke-<id>`, `status-check-<id>`). Template manager rows (`template-row-<name>`, `template-edit-<name>`, `template-delete-<name>`) and the consent dialog (`consent-approve`, `consent-deny`, `consent-credential-<id>`, claim checkboxes with `data-cred` and `data-claim`, the selection controls `consent-edit-selection`, `consent-selection-done` and `consent-selection-reset`, set option radios `consent-set-<n>-option-<m>` (plus `consent-set-<n>-none` for an optional set), query sections `consent-query-<id>`, and candidate rows `consent-candidate-<query>-<credential>` with `data-query` and `data-cred`) follow the same pattern.

![Issue credential dialog](../assets/wallet-issue-ui.png)

The UI header links to the project on GitHub and to CLI install instructions. It also has an Auto-accept toggle (filled while active) that changes the setting at runtime on a locally hosted wallet. The demo keeps it fixed. The **Trust & certificates** dialog (opened from the header) lists the wallet's trust list URLs with copy buttons, each labelled with the provider profile it describes, plus downloads for the CA, signing and HTTPS keys. A verifier uses them to trust the wallet's self-issued credentials. An issuer uses them to verify the wallet attestation and key attestation. Both chain to the same CA.

A fresh wallet uses a local issuer URL on `https://localhost:<port+1>`. An https `--base-url` becomes the issuer URL directly, so issuer metadata, trust lists, and status lists are served from the public origin behind an external TLS terminator (see [public demo hosting](../public-demo.md)).

For a local https origin without a terminator, add `--serve-tls`. The wallet then binds the base URL's own port with its own TLS certificate, next to the plain HTTP port. It requires an https `--base-url` with an explicit port. The [demo issuer and verifier conformance run](../conformance-run-demorp.md) uses this because the OIDF suite requires https endpoints.

The demo verifier accepts presented credentials whose issuer chains end in the wallet's own CA. `--demo-verifier-trust-anchor <pem>` (repeatable) adds further anchors for presentations issued outside this wallet (the OIDF conformance suite signs the credentials it presents under its own CAs).

`wallet ca-cert` exports the shared wallet CA for verifier trust stores or CI fixtures. `wallet tls-cert` exports the per-wallet HTTPS leaf certificate.

The wallet persists an issued-attestation registry alongside the stored credentials. Each issued or imported credential type can register:
- its attestation identifier (`vct` or `docType`)
- its registrar entitlements
- its trust-list profile data such as LoTE type, entity name, and issuance or revocation service type identifiers

Trust lists are created from that registry:
- `wallet generate-pid` and `wallet serve --pid` register PID attestation types with the PID trust-list profile
- `issue ... --wallet` issues with the wallet issuer context, stores the credential, and registers one issued-attestation entry for its credential type
- `wallet import` registers a default issued-attestation entry for the imported credential type
- credentials whose stored trust-list profile fields are identical are grouped into the same trust list

Credential-signing certificates are derived per trust-list profile. The wallet keeps one shared CA root. Credentials for different profiles can carry different leaf certificates that chain to that same CA.

An issuer needs the same CA. The wallet attestation (`OAuth-Client-Attestation`) and the key attestation in credential proofs are signed by the wallet's issuer key and carry only the leaf in `x5c`. The anchor comes from `/api/certificates/ca` or from any trust list (they all embed the same CA). A trust list id such as `pid` identifies the credential profile it describes.

`wallet serve` reuses persisted issuer and status-list URLs unless `--base-url` or `--docker` replaces them, so credentials generated earlier keep resolving against the same endpoints. Issuance commands (`issue ... --wallet`, `wallet generate-pid`) follow the same rule and print a note when no server serves the embedded URLs.

The startup banner warns about a persisted Docker hostname outside Docker and about stored credentials whose issuer or status list URLs this server does not serve. Those credentials fail validation and status checks until they are issued again.

Every trust list a wallet serves carries the same certificate, its own CA. The profiles differ in what they declare that CA to be (LoTE type, entity name, service types). `eudi wallet trust-list` uses the wallet the CLI is pointed at, so with an active remote target it fetches from that wallet.

The wallet groups registered attestation entries by trust-list profile. Each group is exposed as its own trust list under `/api/trustlists/{id}`. The `id` is a stable profile identifier:
- `pid` for the built-in PID profile
- `wallet-provider` for the Wallet Provider profile (always present, an issuer uses it to check the wallet attestation)
- `local` for the built-in local ETSI-shaped profile
- `tl-<hash>` for any additional custom profile

`eudi wallet trust-list --list` prints the same profiles from the CLI:

```
ID               DEFAULT  CATEGORY              PATH
pid              yes      Credential providers  /api/trustlists/pid
wallet-provider           Wallet providers      /api/trustlists/wallet-provider
```

With `--json` it prints the `/api/trustlists` body unchanged.

`/api/trustlists` is a local discovery endpoint for those profiles. Each entry includes:
- `id`, for example `pid` or `local`
- `path`, for example `/api/trustlists/pid`
- `advertised_url` when the wallet has an issuer URL configured, for example `https://localhost:8086/api/trustlists/pid`
- `url`, an alias for `advertised_url`

Clients that call the wallet through Docker port mappings, reverse proxies, or Testcontainers should resolve `path` against the URL they used to reach `/api/trustlists`. `advertised_url` is the wallet's configured publication URL and may differ from the caller's route.

`/api/trustlist` is the legacy endpoint. Its selection rules are:
- if a PID trust-list profile exists, `/api/trustlist` returns that PID trust list
- if no PID profile exists, `/api/trustlist` returns the first available profile
- `vct` and `doctype` query parameters select the trust list for a specific credential type

Examples:
- `/api/trustlists/pid`
- `/api/trustlists/local`
- `/api/trustlist?vct=eu.europa.ec.eudi.pid.1`
- `/api/trustlist?doctype=org.iso.23220.photoid.1`

Example discovery response:

```json
{
  "trust_lists": [
    {
      "id": "pid",
      "default": true,
      "path": "/api/trustlists/pid",
      "advertised_url": "https://localhost:8086/api/trustlists/pid",
      "url": "https://localhost:8086/api/trustlists/pid",
      "loTEType": "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"
    },
    {
      "id": "local",
      "default": false,
      "path": "/api/trustlists/local",
      "advertised_url": "https://localhost:8086/api/trustlists/local",
      "url": "https://localhost:8086/api/trustlists/local",
      "loTEType": "http://uri.etsi.org/19602/LoTEType/local"
    }
  ]
}
```

When the wallet needs a local default profile, it uses:
- `LoTEType = http://uri.etsi.org/19602/LoTEType/local`
- `SvcType/Issuance`
- `SvcType/Revocation`

Use `--register` to also register OS URL scheme handlers so that `openid4vp://`, `eudi-openid4vp://`, `haip-vp://`, `openid-credential-offer://`, and `haip-vci://` links open the wallet on macOS. On Linux and Windows, `--register` is accepted as a no-op.

```bash
eudi wallet serve
eudi wallet serve --port 9000 --auto-accept
eudi wallet serve --pid --credential extra.txt
eudi wallet serve --register           # also register URL scheme handlers using the current interactive/auto-accept mode
eudi wallet serve --register --port 9000
eudi wallet serve -d                   # run in the background (stop with `eudi wallet kill`)
```

| Flag                    | Default  | Description                                      |
|-------------------------|----------|--------------------------------------------------|
| `--port`                | `8085`   | Server port                                      |
| `--auto-accept`         | `false`  | Auto-approve everything. Without it, only interactive channels (web invocation URLs, scheme dispatches, browser DC-API) show the consent dialog. API submissions (`POST /api/offers`, `/api/presentations`) auto-accept either way, since the call itself is the consent (opt in per request with `"interactive": true`) |
| `--credential`          | —        | Import credential from file (repeatable)         |
| `--pid`                 | `false`  | Generate default EUDI PID credentials on start   |
| `--key`                 | —        | Override holder key (PEM/JWK)                    |
| `--issuer-key`          | —        | Override issuer key (PEM/JWK)                    |
| `--mode`                | `debug`  | Validation mode: `debug` or `strict`             |
| `--session-transcript`  | `oid4vp` | mDoc session transcript mode: `oid4vp` or `iso`  |
| `--register`            | `false`  | Register OS URL scheme handlers                  |
| `--no-register`         | `false`  | Skip URL scheme registration (overrides --register) |
| `--key-attestation-level` | — | What the key attestation claims as `key_storage` and `user_authentication` (OpenID4VCI Appendix D.2): whatever the issuer requires (default), `none`, or a level such as `iso_18045_high` for both. The wallet keeps its keys in plain files, so this is a test setting (see [SECURITY.md](../../SECURITY.md)). Changeable at runtime from the Conformance panel |
| `--preferred-format`    | —        | Preferred credential format when multiple match: `dc+sd-jwt`, `mso_mdoc`, or `jwt_vc_json` |
| `--status-list`         | `false`  | Embed status list references in generated credentials |
| `--base-url`            | —        | Base URL for the wallet's HTTP endpoints. An https base URL becomes the issuer URL directly (external TLS terminator). An http base URL derives a self-signed HTTPS issuer URL on port+1. Existing persisted issuer URLs are reused unless this flag is set |
| `--docker`              | `false`  | Use `host.docker.internal` instead of `localhost` when deriving new HTTP and HTTPS wallet endpoint URLs |
| `--vci-client-id`       | —        | Client ID to use for OID4VCI authorization-code flows |
| `--vci-redirect-uri`    | —        | Redirect URI to use for OID4VCI authorization-code flows |
| `--vci-version`         | `1.0`    | OpenID4VCI feature level the wallet uses as a client: `1.0` (the published version) or `1.1` (also uses what the 1.1 draft adds, where an issuer offers it). See [OpenID4VCI feature level](issuing.md#openid4vci-feature-level) |
| `--haip`                | `false`  | Check incoming presentations and credential offers against HAIP 1.0. `--mode` decides what a violation does: strict refuses the flow, debug reports it and continues |
| `--client-attestation`  | `false`  | Send the wallet attestation on OID4VCI token requests even when the issuer does not advertise `attest_jwt_client_auth` (see [wallet attestation](issuing.md#wallet-attestation)) |
| `--adhoc-display-images` | `false` | Keep a display logo or background referenced by an **https** URL in issuer metadata as that URL and fetch it on demand. Nothing is stored, but the issuer sees each card render. A data URI, a template's own images, and http URLs are fetched once and stored (an http image is mixed content on an https page). Reported as `adhoc_display_images` by `GET /api/config` |
| `--require-encrypted-request` | `false` | Refuse an unencrypted Request Object. The wallet always sends an encryption key in `wallet_metadata`, so this requires the Verifier to use it |
| `--demo`                | `false`  | Public demo profile: implies `--pid`, `--mode debug`, `--haip` and `--vci-version 1.1` (all overridable), disables process and filesystem endpoints, blocks fetches to internal networks. Browser flows keep the consent dialog, API flows auto-accept (see [public demo hosting](../public-demo.md)) |
| `--demo-issuer-client-auth` | `required` | What the built-in demo issuer's authorization server requires at its PAR and token endpoints: `required` (HAIP 1.0 §4.4.1) or `optional`, which also serves wallets that send no wallet attestation (see [public demo hosting](../public-demo.md)) |
| `--demo-verifier-trust-anchor` | — | CA certificate PEM file the demo verifier accepts issuer chains under, next to the wallet's own CA (repeatable). For presentations issued outside this wallet, such as an OIDF conformance suite run |
| `--serve-tls`           | `false`  | Serve an https `--base-url` locally with the wallet's own TLS certificate instead of expecting an external TLS terminator. Requires an https base URL with an explicit port. The HTTP port stays bound as well |
| `--demo-reset`          | `1h`     | When to restore the demo baseline: an interval (`24h`), a daily wall-clock time (`00:00`), or one with a timezone (`"00:00 Europe/Berlin"`). `0` disables. Requires `--demo` |
| `--imprint-file`        | —        | HTML snippet with the operator's legal notice, served at `/imprint` |
| `-d, --detached`        | `false`  | Run the server as a background process and return once it responds. Output goes to `<wallet-dir>/serve.log`. Stop it with `wallet kill` |

## `wallet trust-list`

Prints the ETSI trust list JWT containing the wallet's CA certificate (trust anchor). Verifiers use it to validate the x5c/x5chain certificate chain embedded in credentials. Issuer authorization data such as provider entitlements and `providesAttestations` comes from `/.well-known/openid-credential-issuer` and `/api/registrar/wrp`.

`wallet trust-list` prints the same trust list as the legacy `/api/trustlist` endpoint: the PID trust list when the wallet has a PID trust-list profile, otherwise the first available profile.

Use `--id`, `--vct`, or `--doctype` to pick a specific trust-list profile. Typical profile IDs are `pid` and `local`.

The output can be piped to a file or used directly with `--trust-list` in the `validate` command. `--url` prints only the URL for a running wallet server.

```bash
eudi wallet trust-list                          # Print the trust list JWT
eudi wallet trust-list > trustlist.jwt          # Save to file
eudi wallet trust-list --url                    # http://localhost:8085/api/trustlist
eudi wallet trust-list --id pid --url           # http://localhost:8085/api/trustlists/pid
eudi wallet trust-list --id local --url         # http://localhost:8085/api/trustlists/local
eudi wallet trust-list --doctype org.iso.23220.photoid.1 --url
eudi wallet trust-list --url --port 9000        # http://localhost:9000/api/trustlist
eudi wallet trust-list --url --docker           # http://host.docker.internal:8085/api/trustlist
```

| Flag       | Default | Description                                        |
|------------|---------|----------------------------------------------------|
| `--url`    | `false` | Print only the trust list URL (for a running server) |
| `--list`   | `false` | List the trust list profiles this wallet serves instead of printing one |
| `--id`     | —       | Select a trust-list profile ID such as `pid` or `local` |
| `--vct`    | —       | Select the trust list covering this SD-JWT `vct`    |
| `--doctype`| —       | Select the trust list covering this mdoc `docType`  |
| `--port`   | `8085`  | Wallet server port (used with --url)                |
| `--docker` | `false` | Use `host.docker.internal` instead of `localhost` (used with --url) |

## `wallet ca-cert`

Loads or creates the shared wallet CA certificate and prints exactly one PEM certificate. All wallets under the same wallet base directory use this CA for trust lists, status-list `x5c` chains, issuer-metadata `x5c` chains, and HTTPS wallet endpoints.

`--jwks` exports the certificate as a JWKS document instead of PEM: the certificate's public key as a JWK with `kid`, `alg`, `use`, the certificate chain in `x5c`, and the leaf hash in `x5t#S256`. This is the format JWKS-based trust configuration expects.

```bash
eudi wallet ca-cert
eudi wallet ca-cert --out wallet-ca-cert.pem
eudi wallet ca-cert --jwks
```

On a running wallet server the same export is available as `GET /api/certificates/ca` (`?format=jwks` for JWKS). See [Certificate export](http-api.md#certificate-export).

| Flag     | Default | Description |
|----------|---------|-------------|
| `--out`  | —       | Write the shared wallet CA certificate to a file instead of stdout |
| `--pem`  | `false` | Output as PEM (the default when no format flag is set) |
| `--jwks` | `false` | Output as JWKS (public key with `x5c` chain) |

## `wallet tls-cert`

Loads or creates the HTTPS leaf certificate of the wallet's HTTPS endpoints and prints exactly one PEM certificate. `--out` writes it to a file for verifier trust stores in automated tests. `wallet ca-cert` exports the shared trust root instead of the leaf.

```bash
eudi wallet tls-cert
eudi wallet tls-cert --out wallet-tls-cert.pem
eudi wallet tls-cert --docker --out wallet-tls-cert.pem
eudi wallet tls-cert --base-url http://wallet:8085 --out wallet-tls-cert.pem
eudi wallet tls-cert --jwks
```

Use the same `--port`, `--docker`, and `--base-url` flags as `wallet serve` so the exported certificate matches the HTTPS wallet host the running wallet presents.

On a running wallet server the same export is available as `GET /api/certificates/tls` (`?format=jwks` for JWKS). It always matches the running server's HTTPS wallet host. See [Certificate export](http-api.md#certificate-export).

| Flag         | Default | Description |
|--------------|---------|-------------|
| `--out`      | —       | Write the certificate to a file instead of stdout |
| `--port`     | `8085`  | Wallet server port (certificate will match HTTPS wallet endpoints on `port+1`) |
| `--docker`   | `false` | Use `host.docker.internal` instead of `localhost` when deriving the HTTPS wallet host |
| `--base-url` | —       | Base URL used to derive the HTTPS wallet host |
| `--pem`      | `false` | Output as PEM (the default when no format flag is set) |
| `--jwks`     | `false` | Output as JWKS (public key with `x5c` chain) |

## `wallet register` / `wallet unregister`

Registers (or removes) OS-level URL scheme handlers so that `openid4vp://`, `eudi-openid4vp://`, `haip-vp://`, `openid-credential-offer://`, and `haip-vci://` links open the wallet.

The handler script starts a local `wallet serve` instance when none is running and forwards the incoming URI to it. An open UI tab is notified over its event stream. Otherwise the wallet opens its UI with the request id in the URL, so that tab answers it.

`--auto-accept` keeps URL handling silent: the handler first POSTs to a running `wallet serve` instance and otherwise falls back to `wallet accept`.

- **macOS**: Creates an AppleScript `.app` bundle in `~/Applications/` and registers via Launch Services
- **Other platforms**: `register` / `unregister` are accepted as no-ops so scripts stay portable. Use `wallet accept <uri>` instead

```bash
eudi wallet register               # Register URL handlers and open the wallet UI by default
eudi wallet register --auto-accept # Keep URL handling silent / background-only
eudi wallet register --port 9000   # Use custom listener port
eudi wallet unregister             # Remove URL handlers
```

| Flag            | Default | Description                                                    |
|-----------------|---------|----------------------------------------------------------------|
| `--port`        | `8085`  | Listener port for handler script to try before falling back to CLI |
| `--auto-accept` | `false` | Handle incoming URLs silently without opening the wallet UI    |

## Changing the conformance settings

The **Conformance** panel in the wallet header shows five settings: validation mode (strict or debug), HAIP, encrypted requests, the [OpenID4VCI feature level](issuing.md#openid4vci-feature-level), and what the key attestation claims about its key storage (see [SECURITY.md](../../SECURITY.md)).

**A locally hosted wallet** changes them from that panel, which calls `PUT /api/config/conformance` (`DELETE` restores the startup values). The change lasts until the process restarts and applies to every flow reaching this wallet (the UI, a scanned QR, and `openid4vp://` or credential-offer links routed here by the CLI or the macOS handler).

**The public demo** shows the settings read-only and runs HAIP in debug mode for every visitor. A counterparty that breaks a rule produces a warning in the activity log and the flow continues, so the demo stays usable against issuers and verifiers under development. `PUT` and `DELETE /api/config/conformance` return 403. Run the wallet locally to change the settings.

`eudi wallet config` (alias of `wallet info`) reports the active fields for a local or remote wallet.
