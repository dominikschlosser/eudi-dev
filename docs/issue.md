# Issue

Generate test SD-JWT, JWT, or mDOC credentials for development and testing. Output is valid and signed, using an ephemeral P-256 key by default (the public JWK is printed to stderr).

Use `--wallet-dir` on `issue` when `--wallet` should target a non-default wallet store.

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

`issue` also supports:

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
| `--unbound`   | `false`                        | With `--wallet`: issue without an MSO device key (a deliberately malformed mdoc for testing verifier rejection). The default binds it to the wallet |
| `--status-list-uri` | —                       | Status list URI to embed in credential         |
| `--status-list-idx` | `0`                     | Status list index to embed in credential       |

Without `--claims`, a minimal set of PID-like claims is used (given_name, family_name, birthdate). `--pid` generates the full PID claim set of the requested type: fifteen top-level SD-JWT claims (including the nested `address` and `place_of_birth` objects) and nineteen mdoc elements, matching the [EUDI PID Rulebook](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md) (version 1.7) attribute for attribute.

The PID Rulebook defines the PID in two encodings, SD-JWT VC and ISO 18013-5 mdoc. `issue jwt --pid` puts the same claim set in a plain JWT VC, a test artifact for exercising verifiers.

`--vct urn:eudi:pid:de:1` selects the German PID, following the German PID Rulebook: fourteen top-level SD-JWT claims (including `aka_vcts` and the age thresholds) and twenty-three mdoc elements across that rulebook's two namespaces. Both claim sets come from the pre-defined `pid-sdjwt`, `pid-mdoc`, `german-pid-sdjwt` and `german-pid-mdoc` templates. A user template saved under one of those names changes what `--pid` issues. See [templates](templates.md).

`--template` supplies the claim set plus type, namespace, and expiry defaults for flags not set explicitly. `--claims` overrides individual top level claims. `--omit` removes claims from the merged result. See [templates](templates.md) for the file format and the `templates` management commands.

Every SD-JWT claim is selectively disclosable by default, apart from the registered claims SD-JWT VC §2.2.2.3 says cannot be (`iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` and `status`, plus `iat`, which the generator writes itself). Those are always embedded plainly. `_sd`, `_sd_alg` and `...` are reserved by RFC 9901 and rejected as claim names. `--always-disclosed` (or the template's `always_disclosed` list) embeds further named claims plainly in the signed payload, so they cannot be withheld during presentation. Nested subclaims use dotted paths (`address.country`). The flag exists only on `issue sdjwt`. A template's `always_disclosed` list is rejected for mdoc (every mdoc element is selectively disclosable by design) and ignored for jwt (all claims are plain there).

## Wallet Registration Metadata

With `--wallet`, the credential is issued with the wallet's issuer key and a trust-profile-specific leaf certificate chain under the shared wallet CA. `--key` alone swaps the issuer key and re-leafs the wallet chain for it. `--key` together with `--cert` signs with exactly that key and chain instead (the trust profile and registration metadata of the request are not applied, the type registers like an imported credential). The chain is embedded as given. One carrying its self-signed root warns in debug mode and is refused in strict mode. The credential is stored in the wallet together with an issued-attestation entry for that credential type. That entry later drives:
- `/.well-known/openid-credential-issuer`
- `/api/registrar/wrp`
- `/api/trustlist`
- `/api/trustlists`

Unless you override the status-list flags, `--wallet` also uses the wallet's own status-list endpoint and registers a wallet-managed status entry for the new credential.

If a wallet server is already running for the same wallet directory, `--wallet` issuance routes through that instance's REST API to keep its state consistent (see [remote control](wallet/http-api.md#automatic-routing-single-writer)). Without a running server the command issues directly into the store, keeps any persisted issuer and base URLs untouched, and notes that the embedded URLs resolve once `wallet serve` runs.

Trust lists are created from the wallet's issued-attestation registry:
- each issued or imported credential type contributes one registry entry
- entries with the same trust-list profile fields are grouped into one trust list
- the legacy `/api/trustlist` endpoint serves the PID trust list first
- the full set of groups is exposed through `/api/trustlists`, with concrete IDs such as `pid` or `local`, a relative `path` for local resolution, and an optional `advertised_url` for the configured issuer URL

If you do not pass any trust-metadata flags, the wallet derives defaults from the credential type:
- PID attestation types default to the PID trust-list and entitlement profile
- other attestation types default to `Non_Q_EAA_Provider` plus the local ETSI-shaped trust-list profile

These flags give explicit control over the stored trust and issuer metadata for that credential type:

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

These flags set the appearance the imported credential shows on its card, so they apply with `--wallet` (on all three subcommands). Colors are held to the OpenID4VCI 1.0 §12.2.4 value space (a bad one is dropped with a warning) and images run through the policed, size-capped cache, the same as an issuer's display metadata. A public demo takes no operator image (the logo and background-image flags are ignored there), while a template's own art still applies.

| Flag | Default | Description |
|------|---------|-------------|
| `--display-name` | — | The credential's display name |
| `--display-description` | — | The credential's display description (shown behind the card's About control) |
| `--background-color` | — | The card background color, a CSS color (e.g. `#3d59a1`) |
| `--text-color` | — | The card text color, a CSS color |
| `--logo` | — | The card logo, a file path, a data URI, or an http(s) URL |
| `--logo-alt` | — | The logo's alt text |
| `--background-image` | — | The card background image, a file path, a data URI, or an http(s) URL |
