[← Wallet](../wallet.md)

# Serving the wallet

`wallet serve` runs the persistent wallet HTTP server: the web UI, the OID4VP and OID4VCI endpoints, the trust lists, and optional URL scheme handling. The certificate exports (`ca-cert`, `tls-cert`), the `trust-list` command, and URL scheme registration (`register`, `unregister`) pair with it, and the conformance settings can change at runtime.

## `wallet serve`

Starts a persistent wallet HTTP server with a web UI for managing credentials and handling OID4VP/OID4VCI flows. Loads credentials from disk and saves state on credential changes. Includes request logging with timestamps and a browser-based consent UI for incoming requests.

The server exposes:
- Web UI for credential management and consent (list, show, import, remove, and issue credentials, with credential templates and CA and TLS certificate downloads)
- OID4VP authorization endpoint (`/authorize`)
- OID4VCI credential offer endpoint (`/credential-offer`). Accepts `credential_offer` / `credential_offer_uri` query parameters, so offer links can target the wallet URL instead of a custom scheme (see [Invoking the wallet by URL](presenting.md#invoking-the-wallet-by-url))
- Legacy ETSI trust list endpoint (`/api/trustlist`). Use this URL as `--trust-list` when validating PID credentials issued by the wallet
- Trust-list index endpoint (`/api/trustlists`) with one JWT endpoint per coherent trust-list profile
- HTTPS wallet endpoints on the wallet's effective issuer URL, including `/.well-known/jwt-vc-issuer`, `/.well-known/openid-credential-issuer`, `/api/trustlist`, `/api/trustlists`, `/api/statuslist`, and `/api/registrar/wrp`
- A management API mirroring the wallet CLI (list, show, import, and remove credentials, issue credentials, generate PIDs, export certificates). It has no authentication (see [HTTP API](http-api.md))

The consent dialog for a credential offer shows the issuer's name and origin, the flow the offer uses, whether a transaction code will be required, and for each offered credential its format, type, display name, description and declared claims. Everything beyond the offer itself is read from the issuer's metadata and is optional. An offer delivered as a `credential_offer_uri` is dereferenced for the dialog too, and fetched again when the offer is approved (OpenID4VCI 1.0 §4.1.3 asks the wallet to fetch it "unless it is already cached"). Some issuers consume the offer on the first read and refuse the second: the approved issuance then continues with the offer the dialog resolved, and a warning in the activity log names the read that failed. If the dialog could not retrieve the offer at all, it names the issuer the URI points at and approving retries. An offer whose pre-authorized grant names a `tx_code` and reaches an issuance with none (an auto-accepting wallet, or an API caller that left it out) is refused before the pre-authorized code is spent, naming the length and input mode the offer asked for.

Once a credential is stored, the wallet calls the issuer's Notification Endpoint where one is published. An issuer that refuses that call leaves a warning naming the endpoint and the credential stays in the wallet, because OpenID4VCI 1.0 §11 makes the endpoint optional and the credential has already been handed over. The warning also says what the answer was against §11.3, which defines only an Authorization Error Response for a token the endpoint will not take and a 400 for a bad `notification_id`.

The consent dialog for a presentation request also shows the purpose the verifier registered for it. The wallet reads it from the wallet-relying-party registration certificate (typ `rc-wrp+jwt`, in a `verifier_info` entry of format `registration_cert`) per OpenID4VP 1.0 §5.1. A certificate whose signature fails against its own x5c leaf is not shown and leaves a warning in the activity log. The built-in demo verifier and demo issuer present such certificates with every request.

The dialog always opens on the wallet's auto-selected answer. When a request has alternatives (several stored credentials match a query, or the DCQL `credential_sets` offer more than one option), a row above the credential cards says so and offers **Edit**. The Edit view lists the set options the wallet can satisfy and, per credential query id, the matching credentials. Changes apply immediately, **Done** returns to the summary, and **reset to auto** restores the wallet's choice. Deny and Approve keep meaning the presentation itself on both screens. The claim checkboxes stay on the main screen and follow the picked credential. The consent request carries the alternatives as `credential_options`, and `POST /api/requests/{id}/approve` takes the selection as `picks` (query id to credential id) and `set_choices` (option index per set, `-1` skips an optional set) next to `selected_claims`, so API clients can drive the same choice. An approval naming credentials the request did not offer is refused with `400` and the request stays pending. Auto-accept wallets never see the dialog and submit the auto-selection unchanged.

![Consent dialog](../assets/wallet-consent-ui.png)

![Consent credential selection](../assets/wallet-consent-edit-ui.png)

A credential card shows the appearance the issuer declared (a display name, a logo, text and background colors, and a background image where the issuer set one). Where the issuer set no appearance the card falls back to a monogram from the name or a generic glyph. An About control opens the credential's declared description. Two credentials of the same type read apart by their display name (the two PIDs carry `EUDI PID` and `German PID`), with the technical type and a short id on the meta line below.

Credentials can be issued interactively from the web UI. The Issue Credential dialog shows format specific fields and offers a claim builder next to a raw JSON editor. Selecting a credential template (for example the pre-defined `german-pid-sdjwt`) fills all fields so they can be reviewed and edited before issuing. A status list selector controls the embedded status reference (the wallet's own list when configured, none, or a custom URI and index).

Credential cards show the revocation status when a credential carries a status list reference. Credentials on the wallet's own status list show a live Active or Revoked badge plus a Revoke or Activate button. Credentials pointing at an external status list show a Check status action that fetches the list and resolves the current value.

The whole UI is built for browser automation. Every interactive control has a stable element id, and credential cards expose selection hooks as data attributes (`data-credential-id`, `data-format`, `data-vct`, `data-doctype`, `data-status`), so a test can select a card with `.credential-card[data-vct="urn:eudi:pid:1"]` and drive its buttons (`show-<id>`, `delete-<id>`, `revoke-<id>`, `status-check-<id>`). Template manager rows (`template-row-<name>`, `template-edit-<name>`, `template-delete-<name>`) and the consent dialog (`consent-approve`, `consent-deny`, `consent-credential-<id>`, claim checkboxes with `data-cred` and `data-claim`, the selection controls `consent-edit-selection`, `consent-selection-done` and `consent-selection-reset`, set option radios `consent-set-<n>-option-<m>` (plus `consent-set-<n>-none` for an optional set), query sections `consent-query-<id>`, and candidate rows `consent-candidate-<query>-<credential>` with `data-query` and `data-cred`) follow the same pattern.

![Issue credential dialog](../assets/wallet-issue-ui.png)

The UI header links to the project on GitHub and to CLI install instructions. The header also has an Auto-accept toggle button (filled while active, since consent dialogs never appear then). It flips the setting at runtime on a locally-hosted wallet. The demo refuses the change, like its other fixed settings. The **Trust & certificates** dialog (opened from the header) lists the wallet's trust list URLs with copy buttons, each labelled with the provider profile it describes, plus direct downloads for the CA, signing and HTTPS keys. It covers both counterparties: a verifier trusting the wallet's self-issued credentials, and an issuer verifying the wallet attestation and key attestation the wallet sends during issuance. Both chain to the same CA.

By default, a fresh wallet uses a local issuer URL on `https://localhost:<port+1>`. An https `--base-url` is used as the issuer URL directly, so issuer metadata, trust lists, and status lists live on the public origin and an external TLS terminator serves them (see [public demo hosting](../public-demo.md)). If the wallet already has a persisted issuer URL, `wallet serve` reuses it unless `--base-url` or `--docker` replaces it.

For a local https origin without a terminator, add `--serve-tls`. The wallet then binds the base URL's own port and serves it with its own TLS certificate, next to the plain HTTP port. It requires an https `--base-url` with an explicit port. The [demo issuer and verifier conformance run](../conformance-run-demorp.md) uses this, because the OIDF suite requires https endpoints from the party under test.

The demo verifier accepts presented credentials whose issuer chains anchor in the wallet's own CA. `--demo-verifier-trust-anchor <pem>` (repeatable) adds further anchors, for presentations issued outside this wallet (the OIDF conformance suite signs the credentials it presents under its own CAs).

The shared wallet CA can be exported with `wallet ca-cert` for verifier trust stores or CI fixtures. `wallet tls-cert` exports the per-wallet HTTPS leaf certificate when you need the exact server certificate.

The wallet persists an issued-attestation registry alongside the stored credentials. Each issued or imported credential type can register:
- its attestation identifier (`vct` or `docType`)
- its registrar entitlements
- its trust-list profile data such as LoTE type, entity name, and issuance or revocation service type identifiers

Trust lists are created from that registry:
- `wallet generate-pid` and `wallet serve --pid` register PID attestation types with the PID trust-list profile
- `issue ... --wallet` issues with the wallet issuer context, stores the credential, and registers one issued-attestation entry for its credential type
- `wallet import` registers a default issued-attestation entry for the imported credential type
- credentials whose stored trust-list profile fields are identical are grouped into the same trust list

Credential-signing certificates are derived per trust-list profile. The wallet keeps one shared CA root, but credentials for different profiles can present different leaf certificates while still chaining to that same CA.

An issuer needs the same shared CA on the other side of the flow. The wallet attestation (`OAuth-Client-Attestation`) and the key attestation in credential proofs are signed by the wallet's issuer key and carry only the leaf in `x5c`. The anchor comes from `/api/certificates/ca` or from any trust list (they all embed the same CA). A trust list id such as `pid` names the credential profile it describes, and every list anchors the same CA.

`wallet serve` reuses persisted issuer and status-list URLs by default, so credentials generated earlier keep resolving against the same issuer metadata, trust-list, and status-list endpoints. `--base-url` or `--docker` replaces them. Issuance commands (`issue ... --wallet`, `wallet generate-pid`) follow the same rule and print a note when the embedded URLs are not live because no server is running.

The startup banner warns about serving config that cannot work in the current environment: a persisted Docker hostname when the server does not run in Docker, and stored credentials that embed issuer or status list URLs this server does not serve (they keep failing validation and status checks until they are issued again).

Every trust list a wallet serves carries the same certificate, its own CA. The profiles differ in what they declare that CA to be (LoTE type, entity name, service types). `eudi wallet trust-list` follows the wallet the CLI is pointed at: with an active remote target it fetches from that wallet, because the local store holds a different CA that anchors nothing the remote issues.

The wallet groups registered attestation entries by trust-list profile. Each group is exposed as its own trust list under `/api/trustlists/{id}`. The `id` is a stable profile identifier:
- `pid` for the built-in PID profile
- `wallet-provider` for the Wallet Provider profile (always present, this is the one an issuer uses to check the wallet attestation)
- `local` for the built-in local ETSI-shaped profile
- `tl-<hash>` for any additional custom profile

`eudi wallet trust-list --list` prints the same profiles from the CLI:

```
ID               DEFAULT  CATEGORY              PATH
pid              yes      Credential providers  /api/trustlists/pid
wallet-provider           Wallet providers      /api/trustlists/wallet-provider
```

With `--json` it emits the `/api/trustlists` body unchanged, so a caller parsing one parses the other.

`/api/trustlists` is a local discovery endpoint for those profiles. Each entry includes:
- `id`, for example `pid` or `local`
- `path`, for example `/api/trustlists/pid`
- `advertised_url` when the wallet has an issuer URL configured, for example `https://localhost:8086/api/trustlists/pid`
- `url`, an alias for `advertised_url`

Clients that call the wallet through Docker port mappings, reverse proxies, or Testcontainers should resolve `path` against the URL they actually used to reach `/api/trustlists`. `advertised_url` is the wallet's configured publication URL and may differ from the caller's local route.

`/api/trustlist` is the legacy endpoint. Its selection rules are:
- if a PID trust-list profile exists, `/api/trustlist` returns that PID trust list
- if no PID profile exists, `/api/trustlist` returns the first available profile
- `vct` and `doctype` query parameters can be used to select the trust list for a specific credential type

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

Use `--register` to also register OS URL scheme handlers so that `openid4vp://`, `eudi-openid4vp://`, `haip-vp://`, `openid-credential-offer://`, and `haip-vci://` links automatically open the wallet on macOS. On Linux and Windows, `--register` is accepted but does not install OS handlers.

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
| `--auto-accept`         | `false`  | Auto-approve everything. Without it, only interactive channels (web invocation URLs, scheme dispatches, browser DC-API) show the consent dialog. API submissions (`POST /api/offers`, `/api/presentations`) auto-accept either way, the call is the caller's consent (opt back in per request with `"interactive": true`) |
| `--credential`          | —        | Import credential from file (repeatable)         |
| `--pid`                 | `false`  | Generate default EUDI PID credentials on start   |
| `--key`                 | —        | Override holder key (PEM/JWK)                    |
| `--issuer-key`          | —        | Override issuer key (PEM/JWK)                    |
| `--mode`                | `debug`  | Validation mode: `debug` or `strict`             |
| `--session-transcript`  | `oid4vp` | mDoc session transcript mode: `oid4vp` or `iso`  |
| `--register`            | `false`  | Register OS URL scheme handlers                  |
| `--no-register`         | `false`  | Skip URL scheme registration (overrides --register) |
| `--key-attestation-level` | — | What the key attestation claims as `key_storage` and `user_authentication` (OpenID4VCI Appendix D.2): whatever the issuer requires (default), `none`, or a level such as `iso_18045_high` for both. The wallet holds its keys in files and can prove none of them (see [SECURITY.md](../../SECURITY.md)). Changeable at runtime from the Conformance panel |
| `--preferred-format`    | —        | Preferred credential format when multiple match: `dc+sd-jwt`, `mso_mdoc`, or `jwt_vc_json` |
| `--status-list`         | `false`  | Embed status list references in generated credentials |
| `--base-url`            | —        | Base URL for the wallet's HTTP endpoints. An https base URL becomes the issuer URL directly (external TLS terminator). An http base URL derives a self-signed HTTPS issuer URL on port+1. Existing persisted issuer URLs are reused unless this flag is set |
| `--docker`              | `false`  | Use `host.docker.internal` instead of `localhost` when deriving new HTTP and HTTPS wallet endpoint URLs |
| `--vci-client-id`       | —        | Client ID to use for OID4VCI authorization-code flows |
| `--vci-redirect-uri`    | —        | Redirect URI to use for OID4VCI authorization-code flows |
| `--vci-version`         | `1.0`    | OpenID4VCI feature level the wallet uses as a client: `1.0` (the published version) or `1.1` (also uses what the 1.1 draft adds, where an issuer offers it). See [OpenID4VCI feature level](issuing.md#openid4vci-feature-level) |
| `--haip`                | `false`  | Hold incoming presentations and credential offers to HAIP 1.0. What a violation does follows `--mode`: strict refuses the flow, debug reports it and carries on |
| `--client-attestation`  | `false`  | Send the wallet attestation on OID4VCI token requests even when the issuer does not advertise `attest_jwt_client_auth` (see [wallet attestation](issuing.md#wallet-attestation)) |
| `--adhoc-display-images` | `false` | Keep a display logo or background named by an **https** URL in issuer metadata as that URL, and fetch it on demand, instead of fetching it once and storing the image. Nothing is stored, but the issuer sees each card render. A data URI, a template's own art, and http URLs are still fetched and stored (an http image is mixed content a browser blocks on an https page). Reported as `adhoc_display_images` by `GET /api/config` |
| `--require-encrypted-request` | `false` | Reject a Verifier's Request Object that is not encrypted. The wallet always sends an encryption key in `wallet_metadata`, so this only requires the Verifier to use it |
| `--demo`                | `false`  | Public demo profile: implies `--pid`, `--mode debug`, `--haip` and `--vci-version 1.1` (all overridable), disables process and filesystem endpoints, blocks fetches to internal networks. Browser flows keep the consent dialog, API flows auto-accept (see [public demo hosting](../public-demo.md)) |
| `--demo-issuer-client-auth` | `required` | What the built-in demo issuer's authorization server demands at its PAR and token endpoints: `required` (HAIP 1.0 §4.4.1) or `optional`, which also serves wallets that send no wallet attestation (see [public demo hosting](../public-demo.md)) |
| `--demo-verifier-trust-anchor` | — | CA certificate PEM file the demo verifier accepts issuer chains under, next to the wallet's own CA (repeatable). For presentations issued outside this wallet, such as an OIDF conformance suite run |
| `--serve-tls`           | `false`  | Serve an https `--base-url` locally with the wallet's own TLS certificate instead of expecting an external TLS terminator. Requires an https base URL with an explicit port. The HTTP port stays bound as well |
| `--demo-reset`          | `1h`     | When to restore the demo baseline: an interval (`24h`), a daily wall-clock time (`00:00`), or one with a timezone (`"00:00 Europe/Berlin"`). `0` disables. Requires `--demo` |
| `--imprint-file`        | —        | HTML snippet with the operator's legal notice, served at `/imprint` |
| `-d, --detached`        | `false`  | Run the server as a background process and return once it responds. Output goes to `<wallet-dir>/serve.log`. Stop it with `wallet kill` |

## `wallet trust-list`

Generates and prints the ETSI trust list JWT containing the wallet's CA certificate (trust anchor). Verifiers use it to validate the x5c/x5chain certificate chain embedded in credentials. Issuer authorization data such as provider entitlements and `providesAttestations` is exposed through `/.well-known/openid-credential-issuer` and `/api/registrar/wrp`.

`wallet trust-list` prints the same trust list as the legacy `/api/trustlist` endpoint. If the wallet has a PID trust-list profile, that PID trust list is printed. Otherwise the first available profile is printed.

Use `--id`, `--vct`, or `--doctype` when you want a specific trust-list profile instead of the legacy default. Typical profile IDs are `pid` and `local`.

The output can be piped to a file or used directly with `--trust-list` in the `validate` command. Use `--url` to print only the URL for a running wallet server instead.

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

Use `--jwks` to export the certificate as a JWKS document instead of PEM: the certificate's public key as a JWK with `kid`, `alg`, `use`, the certificate chain in `x5c`, and the leaf hash in `x5t#S256`. This is the format expected by JWKS-based trust configuration.

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

Loads or creates the HTTPS leaf certificate used by the wallet's HTTPS endpoints and prints exactly one PEM certificate. Use `--out` to write the certificate to a file for verifier trust stores in automated tests. Use `wallet ca-cert` when you want the shared trust root instead of the leaf.

```bash
eudi wallet tls-cert
eudi wallet tls-cert --out wallet-tls-cert.pem
eudi wallet tls-cert --docker --out wallet-tls-cert.pem
eudi wallet tls-cert --base-url http://wallet:8085 --out wallet-tls-cert.pem
eudi wallet tls-cert --jwks
```

Use the same `--port`, `--docker`, and `--base-url` flags as `wallet serve` so the exported certificate matches the HTTPS wallet host that the running wallet presents.

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

Registers (or removes) OS-level URL scheme handlers so that `openid4vp://`, `eudi-openid4vp://`, `haip-vp://`, `openid-credential-offer://`, and `haip-vci://` links automatically open the wallet.

By default, the handler script makes sure a local `wallet serve` instance is available and forwards the incoming URI to it. The wallet opens its UI for the request when no tab is already watching, and names the request in the URL it opens so that tab answers it. A tab that is already open is told over its event stream.

Use `--auto-accept` to keep URL handling silent: the handler first tries to POST to a running `wallet serve` instance and otherwise falls back to invoking the CLI directly (`wallet accept`).

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

The **Conformance** panel in the wallet header shows five settings: validation mode (strict/debug), HAIP, encrypted requests, the [OpenID4VCI feature level](issuing.md#openid4vci-feature-level), and what the key attestation claims about its key storage (see [SECURITY.md](../../SECURITY.md)).

**A locally-hosted wallet** changes them from that panel, which calls `PUT /api/config/conformance` (`DELETE` restores the startup values). The change is process-level and holds until the process restarts. Every flow reaching this wallet honors it: the UI, a scanned QR, and `openid4vp://` or credential-offer links routed here by the CLI or the macOS handler.

**The public demo** shows the settings read-only. It runs HAIP in debug mode, fixed for every visitor. A counterparty that breaks a rule produces a warning in the activity log and the flow continues, so the demo stays usable against issuers and verifiers still being brought into line. `PUT` and `DELETE /api/config/conformance` return 403. Run the wallet locally to change the settings.

`eudi wallet config` (alias of `wallet info`) reports the active fields for a local or remote wallet.
