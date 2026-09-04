# Issue

Issue test SD-JWT, JWT, or mDOC credentials. The output is signed with an ephemeral P-256 key by default (the public JWK goes to stderr).

```bash
eudi issue sdjwt
eudi issue sdjwt --pid
eudi issue sdjwt --pid --omit place_of_birth,sex,personal_administrative_number
eudi issue sdjwt --pid --always-disclosed issuing_country,address.country
eudi issue sdjwt --template employee-card
eudi issue sdjwt --template employee-card --claims '{"employee_id": "E-42"}'
eudi issue sdjwt --claims '{"name":"Test","age":30}' --save-template my-test-cred
eudi issue sdjwt --claims '{"name":"Test","age":30}'
eudi issue sdjwt --iss https://my-issuer.example --vct my-type --exp 48h --nbf 2025-06-01T00:00:00Z
eudi issue sdjwt --key signing-key.pem
eudi issue sdjwt --wallet                # Issue and import into wallet
eudi issue sdjwt --wallet --trust-profile pid
eudi issue sdjwt --wallet --entitlement https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider --trust-list-type http://example.com/LoTEType/Custom --issuance-service-type http://example.com/SvcType/Custom/Issuance --revocation-service-type http://example.com/SvcType/Custom/Revocation
eudi issue jwt                           # Plain JWT VC (no selective disclosure)
eudi issue jwt --pid
eudi issue jwt --claims '{"name":"Test","age":30}'
eudi issue mdoc
eudi issue mdoc --pid
eudi issue mdoc --claims '{"name":"Test"}' --doc-type com.example.test
eudi issue mdoc --pid --wallet           # Issue mDoc and import into wallet
```

Round-trip with decode:

```bash
eudi issue sdjwt | eudi decode
eudi issue jwt   | eudi decode
eudi issue mdoc  | eudi decode
```

## Flags

Flags shared by all three subcommands:

| Flag | Default | Description |
|------|---------|-------------|
| `--wallet-dir` | `~/.eudi-dev/wallet/` | Wallet storage directory used by `--wallet` |
| `--templates-dir` | `<wallet-dir>/templates/` | Credential template directory used by `--template` and `--save-template` |
| `--remote` | — | With `--wallet`: issue on the remote wallet server at this URL (`local` forces the local store) |

### `issue sdjwt`

| Flag       | Default                   | Description                                    |
|------------|---------------------------|------------------------------------------------|
| `--claims` | —                         | Claims as JSON string or `@filepath`           |
| `--key`    | —                         | Private key file (PEM or JWK). Ephemeral if omitted |
| `--cert`   | —                         | Certificate chain file (PEM, leaf first) embedded as x5c. Requires `--key` |
| `--iss`    | `https://issuer.example`  | Issuer URL                                     |
| `--vct`    | `urn:eudi:pid:1`       | Verifiable Credential Type                     |
| `--exp`    | `720h` (30 days)          | Expiration duration                            |
| `--nbf`    | —                         | Not-before time (RFC3339 or duration, e.g. `-1h`) |
| `--pid`    | `false`                   | Use full EUDI PID Rulebook claims              |
| `--omit`   | —                         | Comma-separated claim names to exclude         |
| `--template` | —                       | Credential template name or file (see [templates](templates.md)) |
| `--always-disclosed` | —               | Claims issued plainly instead of selectively disclosable (dotted paths for nested claims) |
| `--save-template` | —                  | Save the issued claims and settings as a template with this name |
| `--wallet` | `false`                   | Import the issued credential into the wallet   |
| `--batch`  | `0`                       | With `--wallet`: issue this many distinct-key copies, so the wallet presents an unused one each time |
| `--unbound` | `false`                  | With `--wallet`: issue without a holder key (a bearer credential with no cnf). The default binds it to the wallet |
| `--status-list-uri` | —              | Status list URI to embed in credential         |
| `--status-list-idx` | `0`            | Status list index to embed in credential       |

### `issue jwt`

| Flag       | Default                   | Description                                    |
|------------|---------------------------|------------------------------------------------|
| `--claims` | —                         | Claims as JSON string or `@filepath`           |
| `--key`    | —                         | Private key file (PEM or JWK). Ephemeral if omitted |
| `--cert`   | —                         | Certificate chain file (PEM, leaf first) embedded as x5c. Requires `--key` |
| `--iss`    | `https://issuer.example`  | Issuer URL                                     |
| `--vct`    | `urn:eudi:pid:1`       | Verifiable Credential Type                     |
| `--exp`    | `720h` (30 days)          | Expiration duration                            |
| `--nbf`    | —                         | Not-before time (RFC3339 or duration, e.g. `-1h`) |
| `--pid`    | `false`                   | Use full EUDI PID Rulebook claims              |
| `--omit`   | —                         | Comma-separated claim names to exclude         |
| `--template` | —                       | Credential template name or file (see [templates](templates.md)) |
| `--save-template` | —                  | Save the issued claims and settings as a template with this name |
| `--wallet` | `false`                   | Import the issued credential into the wallet   |
| `--status-list-uri` | —              | Status list URI to embed in credential         |
| `--status-list-idx` | `0`            | Status list index to embed in credential       |

The JWT subcommand produces a standard JWT with all claims directly in the payload (no `_sd` or `_sd_alg` fields).

### `issue mdoc`

| Flag          | Default                        | Description                                    |
|---------------|--------------------------------|------------------------------------------------|
| `--claims`    | —                              | Claims as JSON string or `@filepath`           |
| `--key`       | —                              | Private key file (PEM or JWK). Ephemeral if omitted |
| `--cert`      | —                              | Certificate chain file (PEM, leaf first) embedded as x5c. Requires `--key` |
| `--doc-type`  | `eu.europa.ec.eudi.pid.1`      | Document type                                  |
| `--namespace` | `eu.europa.ec.eudi.pid.1`      | Namespace                                      |
| `--exp`       | `720h` (30 days)               | Expiration duration                            |
| `--nbf`       | —                              | Not-before time (RFC3339 or duration, e.g. `-1h`) |
| `--pid`       | `false`                        | Use full EUDI PID Rulebook claims              |
| `--omit`      | —                              | Comma-separated claim names to exclude         |
| `--template`  | —                              | Credential template name or file (see [templates](templates.md)) |
| `--save-template` | —                          | Save the issued claims and settings as a template with this name |
| `--wallet`    | `false`                        | Import the issued credential into the wallet   |
| `--batch`     | `0`                            | With `--wallet`: issue this many distinct-key copies, so the wallet presents an unused one each time |
| `--unbound`   | `false`                        | With `--wallet`: issue without an MSO device key (a malformed mdoc for testing verifier rejection). The default binds it to the wallet |
| `--status-list-uri` | —                       | Status list URI to embed in credential         |
| `--status-list-idx` | `0`                     | Status list index to embed in credential       |

Without `--claims`, a minimal PID-like claim set is used (given_name, family_name, birthdate). `--pid` issues the full PID claim set: fifteen top-level SD-JWT claims (including the nested `address` and `place_of_birth` objects) or nineteen mdoc elements, matching the [EUDI PID Rulebook](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md) (version 1.7).

`issue jwt --pid` puts the same claim set in a plain JWT VC for verifier testing.

`--vct urn:eudi:pid:de:1` selects the German PID: fourteen top-level SD-JWT claims (including `aka_vcts` and the age thresholds) or twenty-three mdoc elements across two namespaces. The claim sets come from the pre-defined `pid-sdjwt`, `pid-mdoc`, `german-pid-sdjwt` and `german-pid-mdoc` templates. A user template saved under one of those names changes what `--pid` issues. See [templates](templates.md).

`--template` supplies the claim set and defaults for type, namespace, and expiry. Explicit flags override the template. `--claims` overrides individual top level claims. `--omit` removes claims from the result. See [templates](templates.md) for the file format and the `templates` commands.

Every SD-JWT claim is selectively disclosable by default. `--always-disclosed` (or the template's `always_disclosed` list) embeds the named claims plainly in the signed payload, so they cannot be withheld during presentation. Nested subclaims use dotted paths (`address.country`). `_sd`, `_sd_alg` and `...` are reserved by RFC 9901 and rejected as claim names. See [always disclosed claims](templates.md#always-disclosed-claims) for the registered claims that are always plain and for the mdoc and jwt behavior.

## Wallet Registration Metadata

With `--wallet`, the credential is signed with the wallet's issuer key and a trust-profile-specific leaf certificate under the shared wallet CA. `--key` alone replaces the issuer key, and the wallet issues a new leaf certificate for it. `--key` together with `--cert` signs with exactly that key and chain. The trust profile and registration metadata flags are then skipped, and the credential type is registered like that of an imported credential. A chain carrying its self-signed root warns in debug mode and is refused in strict mode. The wallet stores the credential together with an issued-attestation entry for its credential type. The wallet builds these from that entry:
- `/.well-known/openid-credential-issuer`
- `/api/registrar/wrp`
- `/api/trustlist`
- `/api/trustlists`

Without explicit status-list flags, `--wallet` registers the credential in the wallet's own status list.

If a wallet server is running for the same wallet directory, `--wallet` issues through its REST API (see [remote control](wallet/http-api.md#automatic-routing-single-writer)). Otherwise the command writes directly into the store and the embedded URLs resolve once `wallet serve` runs.

Trust lists come from the wallet's issued-attestation registry:
- each issued or imported credential type contributes one registry entry
- entries with the same trust-list profile fields are grouped into one trust list
- the legacy `/api/trustlist` endpoint serves the PID trust list first
- `/api/trustlists` lists every group with its ID (`pid`, `local`), a relative `path`, and an optional `advertised_url`

Without trust-metadata flags, the defaults follow the credential type:
- PID attestation types default to the PID trust-list and entitlement profile
- other attestation types default to `Non_Q_EAA_Provider` plus the local ETSI-shaped trust-list profile

These flags set the stored trust and issuer metadata for the credential type:

| Flag | Default | Description |
|------|---------|-------------|
| `--trust-profile` | `auto` | Built-in trust-list profile for `--wallet` metadata: `auto`, `pid`, or `local` |
| `--entitlement` | — | Registrar entitlement URI to store for the credential type. Repeatable |
| `--trust-list-type` | — | LoTE type URI to store for the credential type |
| `--status-determination-approach` | — | Trust-list status determination approach URI to store |
| `--scheme-community-rule` | — | Trust-list scheme community rule URI to store |
| `--scheme-territory` | — | Trust-list scheme territory to store |
| `--trust-entity-name` | — | Trust-list entity name to store |
| `--issuance-service-type` | — | Issuance service type identifier to store |
| `--revocation-service-type` | — | Revocation service type identifier to store |
| `--issuance-service-name` | — | Issuance service name to store |
| `--revocation-service-name` | — | Revocation service name to store |

### Display metadata

These flags set the card appearance of the imported credential and apply with `--wallet` on all three subcommands. Colors must fit OpenID4VCI 1.0 §12.2.4 (an invalid one is dropped with a warning). Images pass the same address policy and size cap as an issuer's display metadata. A public demo ignores the logo and background-image flags and keeps the template's images.

| Flag | Default | Description |
|------|---------|-------------|
| `--display-name` | — | The credential's display name |
| `--display-description` | — | The credential's display description (shown behind the card's About control) |
| `--background-color` | — | The card background color, a CSS color (e.g. `#3d59a1`) |
| `--text-color` | — | The card text color, a CSS color |
| `--logo` | — | The card logo, a file path, a data URI, or an http(s) URL |
| `--logo-alt` | — | The logo's alt text |
| `--background-image` | — | The card background image, a file path, a data URI, or an http(s) URL |
