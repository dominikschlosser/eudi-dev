# Issue

Generate test SD-JWT, JWT, or mDOC credentials for development and testing. Produces valid, signed credentials using an ephemeral P-256 key by default (prints the public JWK to stderr).

Use `--wallet-dir` on `issue` when `--wallet` should target a non-default wallet store.

```bash
oid4vc-dev issue sdjwt
oid4vc-dev issue sdjwt --pid
oid4vc-dev issue sdjwt --pid --omit place_of_birth,sex,personal_administrative_number
oid4vc-dev issue sdjwt --pid --always-disclosed issuing_country,address.country
oid4vc-dev issue sdjwt --template employee-card
oid4vc-dev issue sdjwt --template employee-card --claims '{"employee_id": "E-42"}'
oid4vc-dev issue sdjwt --claims '{"name":"Test","age":30}' --save-template my-test-cred
oid4vc-dev issue sdjwt --claims '{"name":"Test","age":30}'
oid4vc-dev issue sdjwt --iss https://my-issuer.example --vct my-type --exp 48h --nbf 2025-06-01T00:00:00Z
oid4vc-dev issue sdjwt --key signing-key.pem
oid4vc-dev issue sdjwt --wallet                # Issue and import into wallet
oid4vc-dev issue sdjwt --wallet --trust-profile pid
oid4vc-dev issue sdjwt --wallet --entitlement https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider --trust-list-type http://example.com/LoTEType/Custom --issuance-service-type http://example.com/SvcType/Custom/Issuance --revocation-service-type http://example.com/SvcType/Custom/Revocation
oid4vc-dev issue jwt                           # Plain JWT VC (no selective disclosure)
oid4vc-dev issue jwt --pid
oid4vc-dev issue jwt --claims '{"name":"Test","age":30}'
oid4vc-dev issue mdoc
oid4vc-dev issue mdoc --pid
oid4vc-dev issue mdoc --claims '{"name":"Test"}' --doc-type com.example.test
oid4vc-dev issue mdoc --pid --wallet           # Issue mDoc and import into wallet
```

Round-trip with decode:

```bash
oid4vc-dev issue sdjwt | oid4vc-dev decode
oid4vc-dev issue jwt   | oid4vc-dev decode
oid4vc-dev issue mdoc  | oid4vc-dev decode
```

## Flags

`issue` also supports:

| Flag | Default | Description |
|------|---------|-------------|
| `--wallet-dir` | `~/.oid4vc-dev/wallet/` | Wallet storage directory used by `--wallet` |
| `--templates-dir` | `<wallet-dir>/templates/` | Credential template directory used by `--template` and `--save-template` |

### `issue sdjwt`

| Flag       | Default                   | Description                                    |
|------------|---------------------------|------------------------------------------------|
| `--claims` | —                         | Claims as JSON string or `@filepath`           |
| `--key`    | —                         | Private key file (PEM or JWK); ephemeral if omitted |
| `--iss`    | `https://issuer.example`  | Issuer URL                                     |
| `--vct`    | `urn:eudi:pid:de:1`       | Verifiable Credential Type                     |
| `--exp`    | `720h` (30 days)          | Expiration duration                            |
| `--nbf`    | —                         | Not-before time (RFC3339 or duration, e.g. `-1h`) |
| `--pid`    | `false`                   | Use full EUDI PID Rulebook claims              |
| `--omit`   | —                         | Comma-separated claim names to exclude         |
| `--template` | —                       | Credential template name or file (see [templates](templates.md)) |
| `--always-disclosed` | —               | Claims issued plainly instead of selectively disclosable (dotted paths for nested claims) |
| `--save-template` | —                  | Save the issued claims and settings as a template with this name |
| `--wallet` | `false`                   | Import the issued credential into the wallet   |
| `--status-list-uri` | —              | Status list URI to embed in credential         |
| `--status-list-idx` | `0`            | Status list index to embed in credential       |

### `issue jwt`

| Flag       | Default                   | Description                                    |
|------------|---------------------------|------------------------------------------------|
| `--claims` | —                         | Claims as JSON string or `@filepath`           |
| `--key`    | —                         | Private key file (PEM or JWK); ephemeral if omitted |
| `--iss`    | `https://issuer.example`  | Issuer URL                                     |
| `--vct`    | `urn:eudi:pid:de:1`       | Verifiable Credential Type                     |
| `--exp`    | `720h` (30 days)          | Expiration duration                            |
| `--nbf`    | —                         | Not-before time (RFC3339 or duration, e.g. `-1h`) |
| `--pid`    | `false`                   | Use full EUDI PID Rulebook claims              |
| `--omit`   | —                         | Comma-separated claim names to exclude         |
| `--template` | —                       | Credential template name or file (see [templates](templates.md)) |
| `--save-template` | —                  | Save the issued claims and settings as a template with this name |
| `--wallet` | `false`                   | Import the issued credential into the wallet   |
| `--status-list-uri` | —              | Status list URI to embed in credential         |
| `--status-list-idx` | `0`            | Status list index to embed in credential       |

Unlike SD-JWT, the JWT subcommand produces a standard JWT with all claims directly in the payload — no selective disclosure, no `_sd` or `_sd_alg` fields.

### `issue mdoc`

| Flag          | Default                        | Description                                    |
|---------------|--------------------------------|------------------------------------------------|
| `--claims`    | —                              | Claims as JSON string or `@filepath`           |
| `--key`       | —                              | Private key file (PEM or JWK); ephemeral if omitted |
| `--doc-type`  | `eu.europa.ec.eudi.pid.1`      | Document type                                  |
| `--namespace` | `eu.europa.ec.eudi.pid.1`      | Namespace                                      |
| `--exp`       | `720h` (30 days)               | Expiration duration                            |
| `--nbf`       | —                              | Not-before time (RFC3339 or duration, e.g. `-1h`) |
| `--pid`       | `false`                        | Use full EUDI PID Rulebook claims              |
| `--omit`      | —                              | Comma-separated claim names to exclude         |
| `--template`  | —                              | Credential template name or file (see [templates](templates.md)) |
| `--save-template` | —                          | Save the issued claims and settings as a template with this name |
| `--wallet`    | `false`                        | Import the issued credential into the wallet   |
| `--status-list-uri` | —                       | Status list URI to embed in credential         |
| `--status-list-idx` | `0`                     | Status list index to embed in credential       |

When no `--claims` are provided, a minimal set of PID-like claims is used (given_name, family_name, birth_date). With `--pid`, the full EUDI PID Rulebook claim set is generated (27 claims including address, nationality, age attributes, document metadata, etc.). The PID claim sets come from the pre-defined `german-pid-sdjwt` and `german-pid-mdoc` credential templates, so a user template saved under one of those names changes what `--pid` issues.

With `--template`, the template supplies the claim set and any type, namespace, and expiry defaults for flags that were not set explicitly. `--claims` then overrides individual top level claims and `--omit` removes claims from the merged result. See [templates](templates.md) for the template file format and the `templates` management commands.

By default every SD-JWT claim is selectively disclosable. `--always-disclosed` (or the template's `always_disclosed` list) embeds the named claims plainly in the signed payload instead, so they are always visible and cannot be withheld during presentation. Nested subclaims use dotted paths (`address.country`). This is rejected for mdoc (every mdoc element is selectively disclosable by design) and ignored for jwt (all claims are plain there anyway).

## Wallet Registration Metadata

When `--wallet` is used, the credential is issued with the wallet's issuer key and a trust-profile-specific leaf certificate chain under the shared wallet CA, then stored in the wallet together with an issued-attestation entry for that credential type. That stored entry is what later drives:
- `/.well-known/openid-credential-issuer`
- `/api/registrar/wrp`
- `/api/trustlist`
- `/api/trustlists`

Unless you explicitly override the status-list flags, `--wallet` also uses the wallet's own status-list endpoint and registers a wallet-managed status entry for the new credential.

That means trust lists are created from the wallet's issued-attestation registry:
- each issued or imported credential type contributes one registry entry
- entries with the same trust-list profile fields are grouped into one trust list
- the legacy `/api/trustlist` endpoint stays PID-first
- the full set of groups is exposed through `/api/trustlists`, with concrete IDs such as `pid` or `local`, a relative `path` for local resolution, and an optional `advertised_url` for the configured issuer URL

If you do not pass any trust-metadata flags, the wallet derives defaults from the credential type:
- PID attestation types default to the PID trust-list and entitlement profile
- other attestation types default to `Non_Q_EAA_Provider` plus the local ETSI-shaped trust-list profile

Use the following flags when you need explicit control over the stored trust or issuer metadata for that credential type:

| Flag | Default | Description |
|------|---------|-------------|
| `--trust-profile` | `auto` | Built-in trust-list profile for `--wallet` metadata: `auto`, `pid`, or `local` |
| `--entitlement` | — | Registrar entitlement URI to store for the credential type; repeatable |
| `--trust-list-type` | — | LoTE type URI to store for the credential type |
| `--status-determination-approach` | — | Trust-list status determination approach URI to store |
| `--scheme-community-rule` | — | Trust-list scheme community rule URI to store |
| `--scheme-territory` | — | Trust-list scheme territory to store |
| `--trust-entity-name` | — | Trust-list entity name to store |
| `--issuance-service-type` | — | Issuance service type identifier to store |
| `--revocation-service-type` | — | Revocation service type identifier to store |
| `--issuance-service-name` | — | Issuance service name to store |
| `--revocation-service-name` | — | Revocation service name to store |
