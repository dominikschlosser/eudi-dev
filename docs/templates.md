# Credential Templates

Credential templates are named, reusable claim sets for issuing test credentials. A template carries the credential type (VCT or doc type), a default claim set, an optional expiry, and an optional list of claims issued without selective disclosure. Templates work in the CLI, the HTTP API, and the wallet UI.

Four pre-defined templates ship with the binary, a PID per format for each of the two PID types:

| Name | Format | Contents |
|------|--------|----------|
| `pid-sdjwt` | sdjwt | EUDI PID (`urn:eudi:pid:1`) |
| `pid-mdoc` | mdoc | EUDI PID (ISO 18013-5 elements, `eu.europa.ec.eudi.pid.1`) |
| `german-pid-sdjwt` | sdjwt | German PID (`urn:eudi:pid:de:1`), which extends the EUDI PID |
| `german-pid-mdoc` | mdoc | German PID (ISO 18013-5 elements, `eu.europa.ec.eudi.pid.1` plus `eu.europa.ec.eudi.pid.de.1`) |

The `pid-*` templates follow the attribute tables of the [EUDI PID Rulebook](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md) (version 1.7) and carry the rulebook's own Jan Wijnand ('t Hart) example identity. The `german-pid-*` templates follow the claim table of the [German PID Rulebook](https://demo.pid-provider.bundesdruckerei.de/credential-claims) and carry the German ERIKA MUSTERMANN specimen. The two describe different people.

Each rulebook defines its own attribute set. The German one adds national attributes (`birth_name`, `title`, `also_known_as`, `source_document_type`, `no_place_info`, and the age thresholds in `age_equal_or_over`). The EU one carries attributes the German eID leaves to other documents (`sex`, `document_number`, `personal_administrative_number`, `date_of_issuance`, `birth_family_name`). Shared attributes can be encoded differently: the German birth name is `birth_name` where the EU one is `birth_family_name`, and the German street address holds the house number where the EU one has `address.house_number`.

The German SD-JWT PID carries an `aka_vcts` claim naming `urn:eudi:pid:1` ([SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) §2.2.2.2), so a request for the country-independent PID is answered by it. See [credential type inheritance](wallet.md#credential-type-inheritance).

The German mdoc PID spans two namespaces, as the rulebook prescribes: the European elements in `eu.europa.ec.eudi.pid.1` and the national additions (`birth_name`, `academic_title`, `also_known_as`, `no_place_info`, `source_document_type`, `age_over_*`) in `eu.europa.ec.eudi.pid.de.1`. Its doctype is `eu.europa.ec.eudi.pid.1`, the one every PID carries. An mdoc claim key with a `namespace:element` prefix goes into that namespace. Everything else lands in the template's namespace. Dates are CBOR tagged as ISO 18013-5 expects, a calendar day as full-date (tag 1004) and a timestamp as tdate (tag 0).

Regenerating a PID (`wallet generate-pid`, `POST /api/generate-pid`) replaces the mdoc PID that uses the same namespaces, since the two share a doctype. Give an overridden `german-pid-mdoc` at least one `eu.europa.ec.eudi.pid.de.1` element to keep it apart from `pid-mdoc`.

The PID convenience paths (`issue ... --pid`, `wallet generate-pid`, and `POST /api/generate-pid`) resolve through these templates: the `pid-*` pair by default, the `german-pid-*` pair for `--vct urn:eudi:pid:de:1`. Saving a user template under the same name overrides the pre-defined version everywhere, including those paths. Delete the override to restore the original. `wallet generate-pid` and `POST /api/generate-pid` are deprecated. Issue with the template names instead.

## Template files and storage

Pre-defined templates are compiled into the binary and need no files on disk. User templates are JSON files in the wallet directory's `templates/` subdirectory (`~/.eudi-dev/wallet/templates/` by default, or `<dir>/templates/` with `--wallet-dir <dir>`). Both `.json` and `.template` extensions are recognized. A `name` field inside the document names the template. Without one, the file name without extension is used.

The `--templates-dir` flag points the wallet, the issue commands, and the `templates` commands at any directory instead. Keep a folder of template JSON files in your project (or mount one into a container) and start the wallet with it.

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
| `display` | The appearance credentials issued from the template wear (`name`, `description`, `background_color`, `text_color`, `logo`, `logo_alt_text`, `background_image`). Image fields take a data URI or an http(s) URL. The pre-defined PID templates set it |
| `predefined` | Set by the server on pre-defined templates in listings and exports. Ignored on import |

A template reference (`--template`, `--from`) resolves in this order. A value containing a path separator or a `.json` or `.template` extension loads that file directly. Otherwise the name is looked up in the template directory (both extensions), then in the pre-defined templates.

A template is a single JSON document, so sharing one means sharing the file (or the output of `templates show`).

## Always disclosed claims

Every claim in an SD-JWT is selectively disclosable by default, apart from the registered claims SD-JWT VC §2.2.2.3 excludes (`iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts`, `status` and `iat`), which are always embedded plainly. Claims listed in `always_disclosed` are also embedded plainly in the signed payload, so a verifier always sees them and they cannot be withheld during presentation.

Entries name top level claims (`issuing_country`) or nested subclaims with dotted paths (`address.country`). A top level entry embeds the whole claim value plainly. A dotted entry keeps the parent selectively disclosable but embeds that subclaim plainly inside the parent's disclosure. Entries that match no claim are ignored.

This only applies to SD-JWT. JWT VCs carry all claims plainly anyway, so the list is ignored there. mDocs reject it (in ISO 18013-5 every element is selectively disclosable by design).

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

All `templates` subcommands accept `--wallet-dir` to target a non default wallet store. With `--remote <url>` (or after `wallet instances use <url>`) list, show, save, import, and delete operate on a remote instance's template store through its REST API. See [remote control](wallet.md#remote-control).

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
| `PUT /api/templates/{name}` | Create or replace a user template (body is a full template document, which makes this the import endpoint) |
| `DELETE /api/templates/{name}` | Delete a user template (deleting an override of a pre-defined template restores the pre-defined version) |

`POST /api/issue` accepts `template`, `always_disclosed`, and `save_as_template` fields. See the [wallet HTTP API](wallet.md#issuing-credentials).

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

The issue dialog has a template dropdown that pre-fills the form (format, type, expiry, claims, and non disclosable claims). Everything stays editable. Edited form contents win over the template. Each claims builder row has an SD checkbox (uncheck it to issue that claim without selective disclosure). In JSON mode the same list is the "Always visible" field, which also accepts dotted paths for nested claims. A name in "Save as template" stores the dialog contents as a template on successful issuance.

The Templates button opens a manager for listing, editing, importing (paste the JSON), and deleting templates.
