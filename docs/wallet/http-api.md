[← Wallet](../wallet.md)

# Wallet HTTP API

Everything the wallet CLI can do locally is also available over HTTP on a running `wallet serve` instance: credential management, issuing, templates, certificate export, status, deferred issuance, the activity log, and simulated errors. [Remote control](#remote-control) controls another instance from the CLI through this same API.

## HTTP API

Use it to manage a wallet on another host or to drive a hosted instance from automated tests (CI jobs, Testcontainers, E2E suites). It also controls wallet behavior for tests (simulated errors, preferred credential format).

> **Security: no authentication.** The wallet's HTTP API has no authentication or authorization. Anyone who can reach the wallet's port has full control over the wallet and its credentials. It is a testing wallet for local development and isolated test networks. Keep it off untrusted networks and never store real credentials in it. To host it on the public internet, use [`--demo`](../public-demo.md), which turns off the admin endpoints (shutdown, template writes, error injection, changes to the format, auto-accept and conformance settings, log and error clearing), blocks server-side fetches into private networks, and resets state periodically. The remaining endpoints stay open, so treat everything in such a wallet as public and disposable.

> **Cross-origin requests are refused.** An `/api/` request with an `Origin` header from another site is answered `403`, since any web page can reach localhost. CLI, curl, CI jobs and Testcontainers tests send no `Origin`, and the wallet's own UI is on the same origin. Behind a reverse proxy that drops the public `Host`, `--base-url` also counts as the wallet's own origin.

> **Pending consent requests are listed per caller.** `GET /api/requests` and the event stream return the requests the caller owns plus the unowned ones, so several people using one wallet do not answer each other's flows. A caller that names no page (curl, a CI job, a CLI running non-interactively or with `--no-open`) creates unowned requests and sees every unowned request. A client that opens the wallet UI for a user names that page with `owner` in the URL it opens and with the `X-Eudi-Owner` header on its API call. Its submissions are then shown only on that page. The CLI does this, and so does the URL handler when it routes to a remote wallet. Request documents include a `mine` field that is true when the caller owns the request. Clients this project ships also send `X-Eudi-Client: <name>/<release>`. An interactive submission without it is reported once in the activity log.

`GET /api/error` and `DELETE /api/error` are scoped the same way: a caller reads and clears its own last error and the unowned ones. `POST /api/requests/{id}/approve` and `/deny` answer `404` when the caller neither owns the request nor passes `?request=<id>` (the id in the URL the wallet redirected that browser to).

`GET /api/credentials` accepts optional `limit` and `offset` query parameters and reports the full number of stored credentials in the `X-Total-Count` response header. Without parameters it returns every credential. An offset past the end returns an empty array. The web UI uses this to page through long lists ten credentials at a time.

Credentials carrying `"protected": true` in the wallet file are refused by `DELETE /api/credentials/{id}` and `POST /api/credentials/{id}/status` with 403, and `DELETE /api/credentials` keeps them (its response reports `kept_protected`). The flag is for shared deployments that need a stable baseline. Set or clear it by editing `wallet.json`. `--demo` marks the PID credentials it generates.

### Credential management

The credential endpoints mirror `wallet list`, `wallet show`, `wallet import`, and `wallet remove`:

| Method   | Path                    | Body                  | Description                                        | CLI equivalent        |
|----------|-------------------------|-----------------------|----------------------------------------------------|-----------------------|
| `GET`    | `/api/credentials`      | —                     | List stored credentials                            | `wallet list --json`  |
| `GET`    | `/api/credentials/{id}` | —                     | Show one credential (id, format, claims, raw)      | `wallet show <id>`    |
| `POST`   | `/api/credentials`      | raw credential string | Import a credential (see [Credential import](#credential-import)) | `wallet import`       |
| `DELETE` | `/api/credentials/{id}` | —                     | Remove a credential by ID (`204` on success)       | `wallet remove <id>`  |
| `DELETE` | `/api/credentials`      | —                     | Remove all credentials (returns `{"deleted": n}`)  | `wallet remove --all` |

```bash
# List credentials, pick one, inspect it, then delete it
curl http://localhost:8085/api/credentials
curl http://localhost:8085/api/credentials/<id>
curl -X DELETE http://localhost:8085/api/credentials/<id>

# Wipe the wallet
curl -X DELETE http://localhost:8085/api/credentials
```

### Issuing credentials

`POST /api/issue` issues a credential with the wallet's issuer key and certificate chain and imports it into the wallet. It is the HTTP equivalent of `issue sdjwt|jwt|mdoc --wallet`. All fields except `format` are optional:

| Field             | Type    | Description                                                                                  |
|-------------------|---------|----------------------------------------------------------------------------------------------|
| `format`          | string  | `sdjwt`, `jwt`, or `mdoc`. Required unless a `template` with a format is given               |
| `template`        | string  | Credential template name (see [templates](../templates.md)). Template claims become the base claim set and `claims` overrides individual claims |
| `claims`          | object  | Credential claims (default is a small test claim set, or the PID claim set with `pid`)       |
| `pid`             | bool    | Use the full EUDI PID Rulebook claims (like `--pid`)                                         |
| `omit`            | array   | Top-level claim names to drop from the claim set (like `--omit`)                             |
| `always_disclosed`| array   | Claims issued plainly instead of selectively disclosable, with dotted paths for nested claims (sdjwt only, like `--always-disclosed`) |
| `save_as_template`| string  | Save the resolved issuance parameters as a template with this name after issuing             |
| `vct`             | string  | SD-JWT/JWT VC type (default is the default PID VCT)                                          |
| `doctype`         | string  | mdoc doc type (default `eu.europa.ec.eudi.pid.1`)                                            |
| `namespace`       | string  | Default namespace for mdoc claims (default is `doctype`). A claim key of the form `namespace:element` places that element in its own namespace instead |
| `exp`             | string  | Expiration duration such as `720h` or `24h` (default `720h`)                                 |
| `nbf`             | string  | Not-before as RFC3339 (`2025-01-15T00:00:00Z`) or relative duration (`-1h`)                  |
| `status_list_uri` | string  | Status list URI to embed. Default is the wallet's own status list when configured. `""` disables it |
| `status_list_idx` | int     | Status list index (default is the next free index on the wallet's status list)               |
| `trust_profile`   | string  | Trust-list profile for registration metadata: `auto` (default), `pid`, or `local`            |
| `trust`           | object  | Trust/registration metadata to persist with the credential type (same fields as the `issue` trust flags, e.g. `entitlements`, `trust_list_type`, `entity_name`) |
| `display`         | object  | Card appearance: `name`, `description`, `background_color`, `text_color`, `logo`, `logo_alt_text`, `background_image` (the `--display-*` flags). A public demo drops operator-supplied images |
| `display_template`| string  | Template whose logo and background image the credential uses (for a form that flattened the template's claims into `claims`) |
| `batch`           | int     | Issue this many distinct-key copies, so the wallet presents an unused one each time (like `--batch`) |
| `unbound`         | bool    | Issue a bearer credential without a holder key (like `--unbound`). By default the credential is bound to the wallet |
| `signing_key`     | string  | PEM or JWK private key that signs the credential instead of the wallet issuer key. Requires `signing_cert` (like `--key` with `--cert`). Refused in public demo mode |
| `signing_cert`    | string  | PEM certificate chain, leaf first, embedded as the credential's x5c. The leaf must certify `signing_key` and the chain is embedded as given (a chain that includes its self-signed root produces a warning in debug mode and is refused in strict mode). The chain replaces the request's trust profile and registration metadata |

The response is `201` with the stored credential (`id`, `format`, `claims`, `raw`, `status_list_idx` when the credential was registered on the wallet's status list, and `template_path` when `save_as_template` was used).

```bash
# Issue an SD-JWT PID into the wallet
curl -X POST http://localhost:8085/api/issue \
  -H 'Content-Type: application/json' \
  -d '{"format": "sdjwt", "pid": true}'

# Issue an mDoc with custom claims that expires in 24 hours
curl -X POST http://localhost:8085/api/issue \
  -H 'Content-Type: application/json' \
  -d '{"format": "mdoc", "claims": {"given_name": "Erika"}, "exp": "24h"}'

# Issue an already-expired credential for negative tests
curl -X POST http://localhost:8085/api/issue \
  -H 'Content-Type: application/json' \
  -d '{"format": "sdjwt", "nbf": "-48h", "exp": "24h"}'
```

`POST /api/generate-pid` regenerates the default EUDI PID credentials (SD-JWT + mDoc) and replaces existing PIDs of the same type. It is the HTTP equivalent of `wallet generate-pid`. **Deprecated**: like the CLI command it will be removed in a future release. Use `POST /api/issue` with the pre-defined PID templates instead (`{"template": "pid-sdjwt"}`). The body is optional. `claims` merges overrides into the template claims, and `vct` selects the PID type and with it the claim set: the country-independent `pid-sdjwt` and `pid-mdoc` templates by default, `german-pid-sdjwt` and `german-pid-mdoc` for `urn:eudi:pid:de:1` (user overrides of those templates apply). Returns `201` with the full credential list.

```bash
curl -X POST http://localhost:8085/api/generate-pid \
  -H 'Content-Type: application/json' \
  -d '{"claims": {"given_name": "MAX", "family_name": "POWER"}}'
```

### Credential templates

The template endpoints manage the same template store as the `templates` CLI commands (user templates live in the wallet directory's `templates/` subdirectory). See [templates](../templates.md) for the document format.

| Endpoint | Description |
|----------|-------------|
| `GET /api/templates` | List all templates (pre-defined and user), including claims |
| `GET /api/templates/{name}` | Get one template |
| `PUT /api/templates/{name}` | Create or replace a user template. The body is a full template document, so this doubles as the import endpoint for shared templates |
| `DELETE /api/templates/{name}` | Delete a user template. Deleting an override of a pre-defined template restores the pre-defined version |

```bash
curl -X PUT http://localhost:8085/api/templates/employee-card \
  -H 'Content-Type: application/json' \
  -d '{"format": "sdjwt", "vct": "urn:example:employee", "claims": {"employee_id": "E-1"}, "always_disclosed": ["employee_id"]}'

curl -X POST http://localhost:8085/api/issue \
  -H 'Content-Type: application/json' \
  -d '{"template": "employee-card", "claims": {"employee_id": "E-42"}}'
```

### Certificate export

The certificate endpoints mirror `wallet ca-cert` and `wallet tls-cert` (e.g. for provisioning verifier trust stores in automated tests). Both return PEM by default. With `?format=jwks` they return a JWKS document (public key with `x5c` chain) instead.

| Method | Path                            | Description                                              | CLI equivalent   |
|--------|---------------------------------|----------------------------------------------------------|------------------|
| `GET`  | `/api/certificates/ca`          | Shared wallet CA certificate (PEM)                       | `wallet ca-cert` |
| `GET`  | `/api/certificates/ca?format=jwks`  | Shared wallet CA certificate as JWKS                 | `wallet ca-cert --jwks` |
| `GET`  | `/api/certificates/tls`         | HTTPS leaf certificate for the wallet's issuer URL (PEM) | `wallet tls-cert` |
| `GET`  | `/api/certificates/tls?format=jwks` | HTTPS leaf certificate as JWKS                       | `wallet tls-cert --jwks` |

```bash
curl http://localhost:8085/api/certificates/ca > wallet-ca-cert.pem
curl 'http://localhost:8085/api/certificates/tls?format=jwks'
```

The TLS certificate matches the HTTPS wallet host of the running server (its effective issuer URL).

### One-shot error override

Pre-program the wallet to return an error for the next presentation request, even in auto-accept mode. The override is consumed after one use.

**Set override:**

```bash
curl -X POST http://localhost:8085/api/next-error \
  -H 'Content-Type: application/json' \
  -d '{"error": "access_denied", "error_description": "User denied consent"}'
```

The next OID4VP authorization request returns the configured error:

```json
{
  "status": "error",
  "error": "access_denied",
  "error_description": "User denied consent"
}
```

**Clear override without consuming:**

```bash
curl -X DELETE http://localhost:8085/api/next-error
```

| Method   | Path              | Body                                                        | Description                |
|----------|-------------------|-------------------------------------------------------------|----------------------------|
| `POST`   | `/api/next-error` | `{"error": "...", "error_description": "..."}`              | Set one-shot error override |
| `DELETE` | `/api/next-error` | —                                                           | Clear override              |

### Preferred credential format

When a DCQL query matches both SD-JWT and mDoc credentials (e.g. both PID formats), the preferred format setting decides which format is presented.

**Set preference:**

```bash
curl -X PUT http://localhost:8085/api/config/preferred-format \
  -H 'Content-Type: application/json' \
  -d '{"format": "dc+sd-jwt"}'
```

**Clear preference:**

```bash
curl -X PUT http://localhost:8085/api/config/preferred-format \
  -H 'Content-Type: application/json' \
  -d '{"format": ""}'
```

| Method | Path                           | Body                    | Description                    |
|--------|--------------------------------|-------------------------|--------------------------------|
| `GET`  | `/api/config`                  | —                       | Full instance introspection document (see [Introspection](#introspection)) |
| `PUT`  | `/api/config/preferred-format` | `{"format": "dc+sd-jwt"}`  | Prefer SD-JWT when multiple match |
| `PUT`  | `/api/config/preferred-format` | `{"format": "mso_mdoc"}`   | Prefer mDoc when multiple match   |
| `PUT`  | `/api/config/preferred-format` | `{"format": "jwt_vc_json"}` | Prefer JWT VC when multiple match |
| `PUT`  | `/api/config/preferred-format` | `{"format": ""}`            | Clear preference (default)        |
| `PUT`  | `/api/config/auto-accept`      | `{"enabled": true}`         | Approve every presentation and offer without asking, until the process restarts. `false` restores consent. Refused in demo mode |

The preference can also be set at startup via `--preferred-format`:

```bash
eudi wallet serve --auto-accept --pid --preferred-format dc+sd-jwt
```

### Credential import

Credentials can be imported at runtime via `POST /api/credentials`. The body is the raw credential string. Supported formats:

| Format | Detection | Stored as |
|--------|-----------|-----------|
| SD-JWT | Contains `~` separator | `dc+sd-jwt` |
| Plain JWT | 3-part JWT without `~` | `jwt_vc_json` |
| mDoc | CBOR-encoded | `mso_mdoc` |

Plain JWT VCs are presented as-is (no selective disclosure, no KB-JWT). Use `"format": "jwt_vc_json"` in DCQL queries to match them.

A credential whose issuer key is a DID (`kid` or `iss` starting with `did:`) is imported with its issuer signature unverified, and a status list token signed the same way is treated the same way. The wallet resolves issuer keys through the x5c chain (HAIP 1.0 §6.1.1) or the SD-JWT VC issuer metadata ([ADR-0013](../adr/0013-only-the-eudi-stack-is-supported.md)). The DID appears in the activity log entry, in `issuer_key_did` on the credential summary, and in the HAIP findings of `eudi validate --haip`.

An imported credential that contains a holder key in its `cnf` (SD-JWT) or its MSO `deviceKey` (mdoc) can only be presented by the wallet holding that key. The wallet signs key binding with its own holder key, so a verifier refuses a presentation of a credential issued to another wallet. The import reports this in the activity log, `wallet import` and `wallet scan` print a warning, the credential card shows a **Wrong holder binding** badge, and the credential summary carries `key_binding_not_held`.

```bash
# Import an SD-JWT
curl -X POST http://localhost:8085/api/credentials \
  -d 'eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ...~eyJhbGci...~'

# Import a plain JWT VC
curl -X POST http://localhost:8085/api/credentials \
  -d 'eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ...'
```

### Status list

PID credentials from `wallet generate-pid` or `wallet serve --pid` carry a `status.status_list` claim pointing to the wallet's HTTPS status list endpoint. `--status-list` turns this on for other generated credentials too. The URI in the credential is `https://<host>:<port+1>/api/statuslist`.

The HTTPS issuer URL of wallet-issued credentials uses the same host. By default it is `https://localhost:<port+1>` and serves `/.well-known/jwt-vc-issuer`, the signed `/.well-known/openid-credential-issuer` metadata, and `/api/registrar/wrp` for registrar-style authorization data. Those endpoints use certificate chains rooted in the shared wallet CA.

If the verifier runs in Docker (or anywhere else without access to `localhost`), use `--docker` (or `--base-url` for a custom URL) so the status list URL and the issuer metadata host are reachable:

```bash
# Verifier on the same host
eudi wallet serve --pid

# Verifier in Docker (shortcut for --base-url http://host.docker.internal:<port>)
eudi wallet serve --pid --docker

# Custom base URL
eudi wallet serve --pid --base-url http://my-host:8085
```

The status of a credential can be changed at runtime (the wallet UI has Revoke and Activate buttons on the credential cards for this):

```bash
# Revoke a credential (status=1)
curl -X POST http://localhost:8085/api/credentials/<id>/status \
  -H 'Content-Type: application/json' \
  -d '{"status": 1}'

# Un-revoke (status=0)
curl -X POST http://localhost:8085/api/credentials/<id>/status \
  -H 'Content-Type: application/json' \
  -d '{"status": 0}'

# Resolve the current status (from the wallet's own list, or by fetching an
# external status list referenced by the credential)
curl http://localhost:8085/api/credentials/<id>/status
```

Any Status Type from 0 to 255 is accepted, so a credential can be set to SUSPENDED (`2`) or to an application specific value. The published list is 1, 2, 4 or 8 bits wide depending on the largest status it contains (the issuer's choice under section 7) and carries the exact value that was set.

The GET response contains `status`, `managed`, `uri`, `idx`, and `source` (`wallet` for the wallet's own list, `remote` for a fetched external list). It returns 404 for credentials without any status list reference, 422 for a malformed reference, and 502 when an external status list cannot be fetched.

Credential listings (`GET /api/credentials` and `GET /api/credentials/{id}`) include a `status` object for credentials that carry a status list reference: `uri` and `idx` from the credential, `managed` (true when the entry is on this wallet's own status list), and the current `status` value for managed entries.

The Status List Token is served at `GET /api/statuslist` on both the HTTP wallet port and the HTTPS wallet port. Content negotiation picks the representation (section 8.1): `Accept: application/statuslist+cwt` receives the CWT form, anything else (including a client asking for both equally) receives the JWT. The endpoint sends CORS headers for browser-based clients and answers `501` to the `time` query parameter (section 8.4, no historical resolution).

```bash
curl -H 'Accept: application/statuslist+jwt' http://localhost:8085/api/statuslist
curl -H 'Accept: application/statuslist+cwt' http://localhost:8085/api/statuslist --output statuslist.cwt
```

The wallet and `eudi validate` read both forms. When they resolve a credential's status reference, they ask for both media types and parse whichever comes back.

`GET /api/crl` serves the certificate revocation list of the wallet CA as a DER CRL (`application/pkix-crl`). The CRL distribution points of generated document signer certificates point to this URL (ISO/IEC 18013-5 Table B.3). The list is empty (credential revocation runs over the status list) and is freshly signed with a week of validity.

### Deferred issuance

An issuer that cannot issue a credential immediately answers with a transaction id, and the wallet keeps collecting it in the background. `wallet deferred` drives these endpoints:

| Method   | Path                          | Description                                                       | CLI equivalent              |
|----------|-------------------------------|-------------------------------------------------------------------|-----------------------------|
| `GET`    | `/api/deferred`               | List the credentials still being collected, with attempt counts   | `wallet deferred`           |
| `POST`   | `/api/deferred/{id}/collect`  | Ask the issuer now instead of waiting for the next attempt       | `wallet deferred check <id>`   |
| `DELETE` | `/api/deferred/{id}`          | Stop collecting one (returns the issuer and transaction id it dropped, `404` when the id is unknown) | `wallet deferred abandon <id>` |

```bash
curl http://localhost:8085/api/deferred
curl -X POST http://localhost:8085/api/deferred/<id>/collect
```

### Activity log

The wallet UI and `wallet logs` show the activity log. Each entry carries a timestamp, a category (`presentation`, `issuance`, `management`), a description, a success flag, and for protocol steps a `details` object holding the request or response as sent or received.

| Method   | Path       | Description                                     | CLI equivalent |
|----------|------------|--------------------------------------------------|----------------|
| `GET`    | `/api/log` | The persisted activity log, newest last          | `wallet logs`  |
| `DELETE` | `/api/log` | Clear it (`204`, and the wallet UI's Clear button). Demo mode refuses with `403` | —              |

```bash
curl http://localhost:8085/api/log
curl -X DELETE http://localhost:8085/api/log
```

### Last error

The UI polls this on page load so a failure that happened while no page was open is still reported. `GET` answers `200` either way, with `null` when there is nothing to report.

| Method   | Path         | Description                                        |
|----------|--------------|-----------------------------------------------------|
| `GET`    | `/api/error` | The last error (`message` and `detail`), or `null` |
| `DELETE` | `/api/error` | Clear it                                            |

### Encrypted request objects (`request_uri_method=post`)

OID4VP 1.0 Section 5.10 defines an optional mechanism where the wallet POSTs its capabilities and an encryption key to the verifier's `request_uri` endpoint. This lets the verifier encrypt the request object so that only the wallet can read it. HAIP 1.0 does not mention `wallet_metadata`, `wallet_nonce`, or `request_uri_method`.

When a request sets `request_uri_method=post`, the wallet:

1. Has an ECDSA P-256 encryption key (generated at startup)
2. POSTs to the `request_uri` with:
   - `wallet_metadata`. A JSON object with `vp_formats_supported`, `response_types_supported`, the response modes, the Authorization Response encryption algorithms (`authorization_encryption_alg/enc_values_supported`), `request_object_signing_alg_values_supported` when the client identifier prefix permits a signed Request Object, `jwks` with the wallet's public encryption key, and the `request_object_encryption_alg/enc_values_supported` algorithms for it
   - `wallet_nonce`. A base64url-encoded random nonce for replay protection
3. Accepts either an encrypted request object (a JWE using ECDH-ES with A128GCM or A256GCM, which it decrypts with its key) or a signed or unsecured request object JWT
4. Checks that a `wallet_nonce` echoed in the request object matches the one sent and stops the flow on a mismatch. A request object without one is accepted and logged (the parameter is optional)

The wallet always sends the encryption key. `--require-encrypted-request` makes encryption mandatory (a `request_uri` response that is not a compact JWE is rejected):

```bash
eudi wallet serve --auto-accept --pid --require-encrypted-request
```

The proxy dashboard shows `request_uri_method`, `wallet_metadata`, and `wallet_nonce` in the decoded traffic view.

### Example: E2E test flow

```bash
# 1. Start wallet in headless mode with both PID formats
eudi wallet serve --auto-accept --pid --preferred-format dc+sd-jwt &

# 2. Import an additional credential
curl -X POST http://localhost:8085/api/credentials -d @credential.txt

# 3. Run normal presentation (succeeds, uses SD-JWT)
curl -X POST http://localhost:8085/api/presentations \
  -H 'Content-Type: application/json' \
  -d '{"uri": "openid4vp://authorize?..."}'

# 4. Pre-program an error for the next request
curl -X POST http://localhost:8085/api/next-error \
  -H 'Content-Type: application/json' \
  -d '{"error": "access_denied", "error_description": "Simulated denial"}'

# 5. Next presentation returns the error (consumed after one use)
curl -X POST http://localhost:8085/api/presentations \
  -H 'Content-Type: application/json' \
  -d '{"uri": "openid4vp://authorize?..."}'

# 6. Switch to mDoc preference
curl -X PUT http://localhost:8085/api/config/preferred-format \
  -H 'Content-Type: application/json' \
  -d '{"format": "mso_mdoc"}'

# 7. Next presentation uses mDoc instead of SD-JWT
curl -X POST http://localhost:8085/api/presentations \
  -H 'Content-Type: application/json' \
  -d '{"uri": "openid4vp://authorize?..."}'
```

## Remote control

In remote mode the CLI manages a running wallet server through its REST API instead of the local store. This works for `wallet list`, `show`, `import`, `remove`, `generate-pid`, `refresh`, `deferred`, `logs` (except `--follow`, which is local-only), `accept`, `trust-list`, `ca-cert`, `tls-cert`, `info`, for `issue ... --wallet`, and for all `templates` commands. Commands that need the local machine (`serve`, `scan`, `register`) stay local.

```bash
# Switch management to a running instance (persisted until switched back)
eudi wallet use http://localhost:8085
eudi wallet list                     # lists the remote wallet's credentials
eudi issue sdjwt --wallet --template german-pid-sdjwt   # issues on the remote wallet
eudi wallet use local                # back to the local store

# One-off remote target without switching
eudi wallet list --remote http://localhost:8085

# Inspect the managed wallet (remote: the /api/config introspection document)
eudi wallet info
```

Remote commands print the same output as local ones. `eudi wallet use` (without arguments) or `eudi wallet info` shows which wallet is managed. In remote mode templates resolve against the remote instance's template directory. `wallet use <url>` verifies the target is reachable before persisting it (in `~/.eudi-dev/remote.json`, or `$EUDI_DEV_HOME/remote.json` when the env variable is set).

#### Version compatibility

Every instance reports its release on `GET /api/version` (`version`, alongside `build_id`). `wallet use <url>` compares the CLI release with the instance release by semantic versioning:

- A differing major release is refused. `--force` selects it anyway.
- Minor and patch differences are accepted.
- A development build on either side, or an instance too old to report a version, skips the check.

The instance version is shown when a target is selected, in the `VERSION` column of `wallet ps` (and the `version` field of its `--json` output), and in the automatic routing notice below. `wallet ps` marks an incompatible instance with `(!)` and explains it on stderr.

### Automatic routing (single writer)

A running wallet server is the single writer of its wallet directory. When no remote target is configured and a live instance serves the same wallet directory, the CLI routes its commands through that instance's REST API and prints `Routing through the running wallet instance <url>` (with release and pid) to stderr. An incompatible instance is reported there too.

Two flags bypass the routing and access the files directly: `--remote local` and an explicit `--templates-dir`. Direct writes while a server runs can diverge from the server's state, so prefer the routed default.

`wallet info` compares a running instance's configuration with the wallet file and warns when they differ (the file changed after the server started). Restarting `wallet serve` applies the file again.

### Instances

The CLI finds running wallet instances on the local system, stops them, and switches management to them:

```bash
eudi wallet ps                       # list running instances (URL, version, pid, wallet dir)
eudi wallet use http://localhost:18924
eudi wallet kill 18924               # stop by port, pid, or URL
eudi wallet kill --all               # stop every running instance
```

`wallet instances list`, `wallet instances use`, and `wallet instances kill` are hidden deprecated aliases.

Every `wallet serve` registers itself in `~/.eudi-dev/instances/` and deregisters on shutdown. Discovery combines that registry with a scan of the local process list, health checks each candidate (`GET /api/version`), and prunes stale registry entries. The health check also supplies the release and build id shown in the `VERSION` column. `wallet kill` asks the instance to exit via `POST /api/shutdown` and falls back to SIGTERM for local processes that stopped responding.

Discovery finds the instances running on this system plus the active remote target. After `wallet use <url>` (for example `wallet use http://localhost:9085` for a wallet published by a container) the target is health checked and listed with source `active` as long as it responds. The `ACTIVE` column marks the instance the CLI currently manages with `*`, including the auto-routed case (a running instance serving the local wallet directory while no remote target is set). In `--json` output this is the `active` field. When the active remote stops responding, `wallet ps` prints a warning instead of listing it.

### Introspection

`GET /api/config` returns the full introspection document of an instance: `port`, `build_id`, `version`, `base_url`, `issuer_url`, `status_list_url`, `preferred_format`, `key_attestation_level`, `validation_mode`, `vci_version`, `auto_accept`, `session_transcript`, `require_haip`, `require_haip_issuance`, `require_encrypted_request`, `force_client_attestation`, `tls_listener`, `imprint`, and `credential_count`. Outside demo mode it also reports `pid`, `wallet_dir` and `templates_dir`. In demo mode a `demo` object replaces them. `POST /api/shutdown` stops the instance (the response is sent before the process exits).
