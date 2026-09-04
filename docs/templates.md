# Credential Templates

Credential templates are named, reusable claim sets for issuing test credentials. A template carries the credential type (VCT or doc type), a default claim set, an optional expiry, and an optional list of claims issued without selective disclosure. Templates work in the CLI, the HTTP API, and the wallet UI.

Four pre-defined templates ship with the binary:

| Name | Format | Contents |
|------|--------|----------|
| `pid-sdjwt` | sdjwt | EUDI PID (`urn:eudi:pid:1`) |
| `pid-mdoc` | mdoc | EUDI PID (ISO 18013-5 elements, `eu.europa.ec.eudi.pid.1`) |
| `german-pid-sdjwt` | sdjwt | German PID (`urn:eudi:pid:de:1`), which extends the EUDI PID |
| `german-pid-mdoc` | mdoc | German PID (ISO 18013-5 elements, `eu.europa.ec.eudi.pid.1` plus `eu.europa.ec.eudi.pid.de.1`) |

The `pid-*` templates follow the attribute tables of the [EUDI PID Rulebook](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md) (version 1.7) and carry its Jan Wijnand ('t Hart) example identity. The `german-pid-*` templates follow the claim table of the [German PID Rulebook](https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/content/features/PID/german-pid-rulebook/) (version 1.0.0) and carry the ERIKA MUSTERMANN specimen. Each pre-defined PID links its rulebook in its display description.

The German rulebook adds national attributes (`birth_name`, `academic_title`, `source_document_type`, `raw_eid_birth_date`, and the age thresholds in `age_equal_or_over`). The EU rulebook carries attributes the German eID lacks (`sex`, `document_number`, `personal_administrative_number`, `date_of_issuance`, `birth_family_name`). Some shared attributes differ in encoding. The birth name is `birth_name` in the German PID and `birth_family_name` in the EU PID. The German street address includes the house number where the EU PID has `address.house_number`.

The German SD-JWT PID carries an `aka_vcts` claim naming `urn:eudi:pid:1` ([SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) §2.2.2.2), so it matches a request for the country-independent PID. See [credential type inheritance](wallet.md#credential-type-inheritance).

The German mdoc PID spans two namespaces: the European elements in `eu.europa.ec.eudi.pid.1` and the national additions (`birth_name`, `academic_title`, `source_document_type`, `raw_eid_birth_date`, `age_over_*`) in `eu.europa.ec.eudi.pid.de.1`. Its doctype is `eu.europa.ec.eudi.pid.1` like every PID. An mdoc claim key with a `namespace:element` prefix goes into that namespace. Other keys go into the template's namespace. Dates get the ISO 18013-5 CBOR tags: full-date (tag 1004) for a calendar day and tdate (tag 0) for a timestamp.

Regenerating a PID replaces the mdoc PID with the same namespaces. Give an overridden `german-pid-mdoc` at least one `eu.europa.ec.eudi.pid.de.1` element so it stays distinguishable from `pid-mdoc`.

`issue ... --pid` uses these templates: the `pid-*` pair by default, the `german-pid-*` pair for `--vct urn:eudi:pid:de:1`. So do the deprecated `wallet generate-pid` and `POST /api/generate-pid`. Saving a user template under the same name overrides the pre-defined version everywhere. Delete the override to restore the original.

## Template files and storage

Pre-defined templates are compiled into the binary. User templates are JSON files in the wallet directory's `templates/` subdirectory (`~/.eudi-dev/wallet/templates/` by default, or `<dir>/templates/` with `--wallet-dir <dir>`). Both `.json` and `.template` extensions are recognized. A `name` field inside the document names the template. Without one, the file name without extension is used.

`--templates-dir` points the wallet, the issue commands, and the `templates` commands at another directory, for example a folder in your project or a container mount.

```bash
eudi wallet serve --templates-dir ./my-templates
eudi issue sdjwt --template employee-card --templates-dir ./my-templates
eudi templates list --templates-dir ./my-templates
```

```json
{
  "description": "Employee badge for verifier testing",
  "format": "sdjwt",
  "vct": "urn:example:employee",
  "exp": "720h",
  "claims": {
    "employee_id": "E-1",
    "department": "IT",
    "address": { "country": "DE", "locality": "KÖLN" }
  },
  "always_disclosed": ["department", "address.country"]
}
```

All fields except `claims` are optional:

| Field | Description |
|-------|-------------|
| `name` | Template name (defaults to the file name) |
| `description` | Free text shown in listings |
| `format` | `sdjwt`, `jwt`, or `mdoc` (empty means any format). The aliases `sd-jwt`, `dc+sd-jwt`, `jwt_vc_json`, and `mso_mdoc` are accepted |
| `vct` | Credential type for sdjwt/jwt |
| `doctype`, `namespace` | Type identifiers for mdoc |
| `exp` | Default expiry as a Go duration (for example `720h`) |
| `claims` | The default claim set |
| `always_disclosed` | Claims issued plainly instead of selectively disclosable (see below) |
| `display` | Card appearance for credentials issued from the template (`name`, `description`, `background_color`, `text_color`, `logo`, `logo_alt_text`, `background_image`). Image fields take a data URI or an http(s) URL. The pre-defined PID templates set it |
| `predefined` | Set on pre-defined templates in listings and exports. Ignored on import |

A template reference (`--template`, `--from`) with a path separator or a `.json` or `.template` extension loads that file. Any other value is looked up in the template directory (both extensions), then among the pre-defined templates.

To share a template, share the file (or the output of `templates show`).

## Card appearance (display)

The optional `display` object sets the card appearance of credentials issued from the template (OpenID4VCI 1.0 §12.2.4). The wallet UI renders it on the credential card and in the consent and offer dialogs.

| Field | Description |
|-------|-------------|
| `name` | Display name (the card headline, defaults to the technical type) |
| `description` | Free text shown behind the card's About control |
| `background_color` | Card background, a CSS color such as `#3d59a1` |
| `text_color` | Card text, a CSS color such as `#ffffff` |
| `logo` | Card logo image (see image sources below) |
| `logo_alt_text` | Alt text for the logo image |
| `background_image` | Full card background image behind the name (see image sources below) |

The two image fields (`logo`, `background_image`) take one of three sources:

- a `data:` URI, embedded directly
- an `https://` URL, fetched once at issuance
- `embedded:<file>`, a bundled asset (pre-defined templates only)

A fetched image goes through the wallet's size-capped cache and is embedded as a `data:` URI on the issued credential.

The pre-defined PID templates set `display`: `background_color` `#3d59a1`, `text_color` `#ffffff`, and `logo` `embedded:logo.svg`. The German PID adds `background_image` `embedded:german-id-specimen.jpg` (the public Personalausweis specimen).

Display values given at issue time override the template's field by field: the `issue` flags `--display-name`, `--display-description`, `--background-color`, `--text-color`, `--logo`, `--logo-alt` and `--background-image`, and the same fields in the Issue dialog and `POST /api/issue`. Setting only a name keeps the template's images.

```json
{
  "description": "Employee badge for verifier testing",
  "format": "sdjwt",
  "vct": "urn:example:employee",
  "claims": { "employee_id": "E-1", "department": "IT" },
  "display": {
    "name": "Acme Employee",
    "description": "A demo employee badge issued for verifier testing.",
    "background_color": "#0f766e",
    "text_color": "#ffffff",
    "logo": "https://acme.example/badge-logo.svg",
    "logo_alt_text": "Acme logo"
  }
}
```

## Always disclosed claims

Every SD-JWT claim is selectively disclosable by default. The registered claims SD-JWT VC §2.2.2.3 excludes (`iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts`, `status` and `iat`) are always embedded plainly. Claims listed in `always_disclosed` are embedded plainly too, so they cannot be withheld during presentation.

Entries name top level claims (`issuing_country`) or nested subclaims with dotted paths (`address.country`). A top level entry embeds the whole claim value plainly. A dotted entry keeps the parent selectively disclosable but embeds that subclaim plainly inside the parent's disclosure. Entries that match no claim are ignored.

JWT VCs carry all claims plainly, so the list is ignored there. mDocs reject it (every ISO 18013-5 element is selectively disclosable).

## CLI

```bash
# List and inspect templates
eudi templates list
eudi templates show german-pid-sdjwt

# Issue from a template, optionally overriding individual claims
eudi issue sdjwt --template pid-sdjwt
eudi issue sdjwt --template german-pid-sdjwt --claims '{"given_name": "MAX"}'

# Make claims non disclosable at issuance time
eudi issue sdjwt --pid --always-disclosed issuing_country,address.country

# Save the current issuance as a template while issuing
eudi issue sdjwt --vct urn:example:employee --claims '{"employee_id": "E-1"}' --save-template employee-card

# Create or update a template directly
eudi templates save employee-card --format sdjwt --vct urn:example:employee --claims '{"employee_id": "E-1"}' --always-disclosed employee_id

# Customize a pre-defined template (the copy overrides it when saved under the same name)
eudi templates save german-pid-sdjwt --from german-pid-sdjwt --vct urn:custom:pid

# Import a shared template (file, JSON string, or - for stdin)
eudi templates import shared-template.json
eudi templates import '{"format":"sdjwt","claims":{"a":1}}' --name my-cred
eudi templates show employee-card > share-me.json

# Delete a user template (deleting an override restores the pre-defined version)
eudi templates delete employee-card
```

All `templates` subcommands accept `--wallet-dir` to target a non default wallet store. With `--remote <url>` (or after `wallet use <url>`) list, show, save, import, and delete operate on a remote instance's template store through its REST API. See [remote control](wallet/http-api.md#remote-control).

### `templates save`

| Flag | Description |
|------|-------------|
| `--from` | Copy this template (name or file) as the starting point |
| `--format` | `sdjwt`, `jwt`, or `mdoc` (empty means any) |
| `--vct` | Credential type (sdjwt/jwt) |
| `--doc-type` | Document type (mdoc) |
| `--namespace` | Default namespace (mdoc) |
| `--exp` | Default expiry duration |
| `--claims` | Claims as JSON string or `@filepath` |
| `--always-disclosed` | Comma separated claim paths issued without selective disclosure |
| `--description` | Free text description |

## HTTP API

The wallet server exposes the same template store:

| Endpoint | Description |
|----------|-------------|
| `GET /api/templates` | List all templates (pre-defined and user), including claims |
| `GET /api/templates/{name}` | Get one template |
| `PUT /api/templates/{name}` | Create or replace a user template (body is a full template document, so this is also the import endpoint) |
| `DELETE /api/templates/{name}` | Delete a user template (deleting an override of a pre-defined template restores the pre-defined version) |

`POST /api/issue` accepts `template`, `always_disclosed`, and `save_as_template` fields. See the [wallet HTTP API](wallet/http-api.md#issuing-credentials).

```bash
# Import a template and issue from it
curl -X PUT http://localhost:8085/api/templates/employee-card \
  -H 'Content-Type: application/json' \
  -d '{"format": "sdjwt", "vct": "urn:example:employee", "claims": {"employee_id": "E-1"}, "always_disclosed": ["employee_id"]}'

curl -X POST http://localhost:8085/api/issue \
  -H 'Content-Type: application/json' \
  -d '{"template": "employee-card", "claims": {"employee_id": "E-42"}}'
```

## Wallet UI

The issue dialog has a template dropdown that pre-fills the form (format, type, expiry, claims, and non disclosable claims). Everything stays editable. Each claims builder row has an SD checkbox (uncheck it to issue that claim without selective disclosure). In JSON mode the same list is the "Always visible" field, which also accepts dotted paths for nested claims. A name in "Save as template" stores the dialog contents as a template on successful issuance.

The Templates button opens a manager for listing, editing, importing (paste the JSON), and deleting templates.
