# Registrar

The wallet includes a relying party registrar. Each member state runs a registrar like this one (ARF Topic 27). You register a verifier or an issuer with it and get two certificates:

- An **access certificate** (ETSI TS 119 411-8 V1.1.1). You send a certificate signing request and keep the private key. A verifier signs its request objects with that key and puts the certificate in `x5c`. An issuer signs its Credential Issuer Metadata with it (ARF ISSU_22 and ISSU_32).
- A **registration certificate** (ETSI TS 119 475 V1.2.1, typ `rc-wrp+jwt`). A verifier gets one for each intended use. It lists which credentials and claims the verifier may request, and the purpose shown in the consent dialog. The verifier sends it in `verifier_info` (OpenID4VP 1.0 §5.1). An issuer gets one for its service (ARF RPRC_13). It lists which attestation types the issuer may issue, and the issuer publishes it in `issuer_info` (ETSI TS 119 472-3 V1.1.1 §4.2.3).

Both certificates contain the same identifier (ARF Reg_32 and RPRC_07). The registrar API follows the TS05 v1.5 data model and registry API. The wallet's own issuer is in the register too.

The registrar also keeps a [catalogue of attestations](#attestation-catalogue).

## Registrations

A relying party offers services. A verifier's service has intended uses, and each intended use lists which credentials and claims the verifier may request (TS05 v1.5 §2.4). A credential has the format `dc+sd-jwt` or `mso_mdoc` and its type in `meta`. Every credential lists at least one claim (TS05 v1.5 §2.4.5).

If a registration has no identifier, the registrar assigns one. It is an `organizationIdentifier` such as `NTRNL-1A2B3C4D5E6F7A8B`: the identifier type (`LEI`, `NTR`, `VAT`, `EOR` or `EXC`), a country code, a dash and the value (ETSI TS 119 475 §5.1.3).

Anyone with access to the wallet can register, change and delete relying parties and revoke their certificates. This works the same as for credentials. On a shared instance every visitor sees every registration and can delete it.

An update can add identifiers. The first identifier never changes, because the issued certificates contain it.

Registrations are part of the wallet state. With file or Postgres storage they survive a restart. With memory storage they are lost, but if the keys are [seeded](../wallet.md#seeded-keys), certificates issued before the restart still verify. The wallet checks only their signatures. A demo reset deletes all registrations.

## Issuers

An issuer registers as an attestation provider. Its service has an entitlement from ETSI TS 119 475 V1.2.1 Annex A.2 (`PID_Provider`, `QEAA_Provider`, `PUB_EAA_Provider` or `Non_Q_EAA_Provider`) and lists its attestation types in `providesAttestations` (ARF RPRC_15). Each type has a format and its `vct` or `doctype` in `meta`. A service that lists attestation types needs one of these entitlements, and a provider needs at least one type.

With `--arf` a PID needs `PID_Provider` (ISSU_24a). Any other attestation needs `QEAA_Provider`, `PUB_EAA_Provider` or `Non_Q_EAA_Provider` (ISSU_34a). The wallet treats these three alike. The choice only changes the content of the registration certificate. The wallet does not validate qualified signatures.

An issuer's registration certificate covers its service. It has `entitlements` and `provides_attestations`. It has no intended use (ARF RPRC_05). So it has no purpose, privacy policy or credentials. The registrar returns it inside an `issuer_info` array with two entries: the `registrar_dataset` (identifier, description, registry URI and the attestation types) and the `registration_cert` (ETSI TS 119 472-3 V1.1.1 §4.2.3).

To use the certificates, an issuer:

1. puts the `issuer_info` array at the top level of its Credential Issuer Metadata
2. signs the metadata as OpenID4VCI 1.0 §12.2.3 describes, with the key of its access certificate and the access certificate chain in `x5c` (ETSI TS 119 472-3 §4.2.2)
3. serves the signed metadata when a wallet asks for `application/jwt`

A wallet with `--arf` then checks the issuer before it requests a credential (see [issuing](issuing.md#arf-checks)).

A provider that also requests attributes, for example to authenticate the user during issuance, registers intended uses too. The registrar then adds the `Service_Provider` entitlement (ARF RPRC_05 note).

## Revocation

Every registration certificate has a `status` claim that points to an entry in the registrar's status list (ETSI TS 119 475 V1.2.1 Table 7). The registrar publishes the list at `/api/registrar/status-list` as a Token Status List, signed with the registrar key.

You revoke a certificate with **Revoke** in the UI, `wallet registrar revoke` or the status endpoint. **Activate**, `wallet registrar activate` or the same endpoint makes it valid again.

An intended use or an issuer service has one valid certificate at a time. The registrar also revokes certificates itself, and you can't activate these again:

- when you issue a new certificate for the same intended use or service
- when an update changes a field in the certificate (name, legal name, country, purpose, privacy policy, support URL, supervisory authority, credentials and claims, entitlements or attestation types)
- when an update removes the intended use or the service
- when the relying party is deleted

If you request a certificate while someone updates the same registration, the request fails with HTTP 409. Try again.

Each certificate gets a random entry. The wallet's own registration certificates (in its issuer metadata and from the demo issuer) all use entry 0, which is never revoked. With memory storage the revocations are lost on restart, and a demo reset clears them. After a restart or a reset, a revoked certificate is valid again. Rarely, a new certificate gets the same entry as an old one, and revoking it revokes the old one too.

## In the web UI

**Registrar** in the header opens a submenu. On a phone it is under **Menu**.

![Relying parties](../assets/registrar-parties.png)

**Relying parties** lists all registrations. The wallet's own registration comes first, then the others, newest first. You can filter by verifiers or issuers and search as you type. The search looks at names, identifiers, purposes and credential types, and suggests names and identifiers. The list shows 10 relying parties per page.

Each verifier shows its intended uses with their credentials and claims, and each issuer its service with the entitlement and the attestation types. Both show the status of their registration certificates: **No certificate**, **Active** or **Revoked**.

- **Issue certificate** issues a registration certificate for the intended use or the service and shows its `verifier_info` or `issuer_info` value. Once there is one, the button reads **Issue new certificate**. It issues a new certificate and revokes the old one. The registrar doesn't store issued certificates, so this is also how you get the value again.
- **Revoke** revokes the certificate. **Activate** makes it valid again. If the registrar revoked a certificate itself, it shows **Revoked** and has no **Activate** button.
- **Add registration certificate** registers another purpose for a verifier, with its credentials and claims. The registrar adds it as a new intended use and issues a certificate for it. The existing certificates stay valid.
- **Delete** removes the relying party and revokes all its certificates.

![Register a verifier](../assets/registrar-register.png)

The buttons below the list open the register dialogs. **Register a verifier** registers a relying party with one intended use and issues both certificates in one step. **Register an issuer** registers an issuer with its entitlement and its attestation types, and issues both certificates too. The fields are filled with defaults or may stay empty, so you can register right away. If you leave the CSR empty, the browser creates the key and the CSR, and the key never leaves the browser. **Create the key and CSR yourself** shows the `openssl` commands for doing it on your machine. After registering, the button shows **Registered**. Once you edit a field, you can register again.

Each credential row has a format, a type and the claims. For SD-JWT, separate path segments with dots (`address.locality`). For mdoc, write the element name if it is in the doctype's namespace, or put another namespace in front with a colon (`eu.europa.ec.eudi.pid.de.1:birth_name`). An issuer's attestation rows have a format and a type. The type fields suggest types from the catalogue.

![Registration result](../assets/registrar-result.png)

The result shows the identifier, the PEM box and the `verifier_info` or `issuer_info` value. A verifier also gets its client identifiers. If the browser created the key, the PEM contains the key and the access certificate chain. With your own CSR it contains only the chain. The registration certificate is in the `data` field of the `registration_cert` entry. After **Add registration certificate** the result shows only the identifier and the `verifier_info` value.

Every element has an ID for automated tests:

| Element | IDs |
|---------|-----|
| Registrar menu | `registrar-menu-toggle` opens the submenu with `registrar-parties-link` and `registrar-catalog-link` |
| Relying parties | Filters `registrar-filter-all`, `registrar-filter-verifiers`, `registrar-filter-issuers`. `registrar-search` searches, with suggestions in `registrar-search-suggestions`. `registrar-page-prev`, `registrar-page-next` and `registrar-page-info` page through the list. `registrar-parties-register` and `registrar-parties-register-issuer` open the register dialogs, and `registrar-parties-close` closes the dialog. A party is `registrar-party-<identifier>` with `-name`, `-identifier`, `-role-verifier`, `-role-issuer`, `-add-use` and `-delete`. An intended use is `registrar-party-<identifier>-use-<intended use>` with `-purpose`, `-status`, `-credentials`, `-issue` and `-revoke` (Revoke or Activate). An issued certificate shows in `-result` with `-verifier-info` and `-copy`. An issuer service is `registrar-party-<identifier>-service-<service>` (`default` without a service identifier) with `-entitlement`, `-status`, `-attestations`, `-issue`, `-revoke`, and `-result` with `-issuer-info` and `-copy`. In `<identifier>`, `<intended use>` and `<service>`, characters other than letters, digits, `_` and `-` become `_` |
| Register dialogs | `registrar-title`, `registrar-name`, `registrar-identifier`, `registrar-legal-name`, `registrar-country`, `registrar-support-uri`, `registrar-service-id`, `registrar-purpose`, `registrar-privacy-policy`, credential rows `registrar-credential-<n>-format`, `-type`, `-claims` and `-remove`, `registrar-add-credential`, `registrar-entitlement`, attestation rows `registrar-attestation-<n>-format`, `-type` and `-remove`, `registrar-add-attestation`, `registrar-registration-validity`, `registrar-csr`, `registrar-dns`, `registrar-access-validity`, `registrar-csr-help-toggle`, `registrar-copy-csr-command`, `registrar-error`, `registrar-submit`, `registrar-close`. Results in `registrar-result` with `registrar-result-identifier`, `registrar-client-id-<n>`, `registrar-pem` (labelled by `registrar-pem-label`), `registrar-download-pem`, `registrar-verifier-info` and `registrar-issuer-info`. `registrar-copy-pem`, `registrar-copy-verifier-info` and `registrar-copy-issuer-info` copy a result field. `registrar-client-id-<n>` counts from 0 |
| Attestation catalogue | `registrar-catalog-search`, `registrar-catalog-list`, `registrar-catalog-close`, `registrar-catalog-add`. An entry is `registrar-catalog-entry-<id>` with `-name`, `-template`, `-los`, `-binding`, `-id`, `-version`, `-formats`, `-schema-<n>`, `-rulebook`, `-trust` and `-delete`. **Add attestation** opens `registrar-catalog-add-overlay` with `registrar-catalog-name`, format rows `registrar-catalog-format-<n>-format`, `-type`, `-claims` and `-remove`, `registrar-catalog-add-format`, `registrar-catalog-rulebook`, `registrar-catalog-los`, `registrar-catalog-binding`, `registrar-catalog-trust`, `registrar-catalog-form-error`, `registrar-catalog-cancel` and `registrar-catalog-save` |
| Offer consent | With `--arf`, `offer-arf-warnings` lists the findings about the issuer in `offer-arf-warnings-list`, one `offer-arf-warning-<n>` each |

## Fields and where they go

| Field | Access certificate | Registration certificate |
|-------|--------------------|--------------------------|
| Name | Common name | `name` and `srv_description` |
| Identifier | `organizationIdentifier` | `sub` |
| Legal name | Organization | `sub_ln` |
| Country | Country | `country` |
| Support URL | URI in the subject alternative name | `support_uri` |
| Service | Organizational unit | Not included |
| Purpose (verifier) | Not included | `purpose` |
| Privacy policy (verifier) | Not included | `privacy_policy` |
| Credentials and claims (verifier) | Not included | `credentials` |
| Entitlement (issuer) | Not included | `entitlements` |
| Attestation types (issuer) | Not included | `provides_attestations` |
| Validity (registration certificate) | Not included | `iat` and `exp`, at most 12 months (GEN-5.2.4-08) |
| CSR | Public key | Not included |
| DNS names (verifier) | DNS names in the subject alternative name | Not included |
| Validity (access certificate) | Validity period, at most one year | Not included |
| (assigned) | Not included | `status`, the entry in the registrar's status list |

The registrar fills in the rest. `registry_uri` points to the registration in the registrar API, a verifier's `entitlements` contains the service provider entitlement, and `supervisory_authority` names a test authority. `policy_id` is `0.4.0.19475.3.1` (ETSI TS 119 475 V1.2.1 OVR-6.1.3-01), and `certificate_policy` links to [test certificates](../test-certificates.md). An empty support URL becomes `<issuer URL>/support`, and an empty privacy policy becomes `<issuer URL>/privacy-policy`. The supervisory authority links to `<issuer URL>/supervisory-authority`. The wallet serves a placeholder page at each of these URLs.

The access certificate has the policy `0.4.0.194118.1.2` (ETSI TS 119 411-8 §5.3) and is signed by the relying party access CA. That CA is a separate root. Access certificates from the registrar never chain to the wallet CA. The wallet CA is the trust anchor for credential issuers. The registrar key signs the registration certificates. You can download the registrar certificate and the relying party access CA under **Trust & certificates**.

## What the wallet checks

The consent dialog shows the registered purpose and a link to the privacy policy (ARF RPA_10). API clients find them in `purposes` and `privacy_policies` of a pending request. The wallet shows them whenever the registration certificate's signature matches its `x5c` certificate, even without `--arf`.

With `--arf` the wallet checks the access and registration certificates of every verifier and issuer. It doesn't matter which registrar issued them (see [ARF checks for verifiers](presenting.md#arf-checks) and [for issuers](issuing.md#arf-checks)). It trusts two sets of CAs:

- **Access certificates** must chain to the relying party access CA, the wallet CA (which signs the access certificates of the demo verifier and the demo issuer) or a CA from `--relying-party-ca`.
- **Registration certificates** must chain to the wallet CA (which signs the registrar certificate) or a CA from `--relying-party-ca`. The relying party access CA is not trusted here, because it signs every visitor's CSR. Otherwise anyone with an access certificate could sign their own registration certificate.

Certificates from this registrar pass both checks. `--relying-party-ca` adds the CAs of other registrars. A registered credential without a claim list declares no attributes (ETSI TS 119 475 V1.2.1 Annex B.2.9), so requesting any claim counts as over-asking. TS05 registrars always list the claims.

The wallet reads its own registrar's status list directly. It fetches other registrars' lists with its proxy and TLS settings.

The wallet does not check these:

- **The service identifier.** ARF RPRC_17a also compares the service identifier, but ETSI TS 119 475 V1.2.1 has no claim for it. The access certificate has it as organizational unit.
- **Access certificate revocation.** The registrar does not revoke access certificates. A deleted relying party keeps a valid access certificate until it expires.
- **The register.** The wallet does not look up `registry_uri`. Under ARF RPRC_19 and RPRC_22 the relying party sends the certificate itself, so no lookup is needed.

## The demo verifier

![Demo verifier identity](../assets/verifier-identity.png)

The demo issuer and the demo verifier share the wallet's access certificate, so the registrar lists them as one relying party, **EUDI Dev Demo**, with two services. **EUDI Dev Demo Issuer** has the provider entitlements and the attestation types of the templates. **EUDI Dev Demo Verifier** has one intended use. It registers the top-level claims of every predefined template, so the demo requests ask only for registered claims. Their registration certificates use the entry of the wallet's own certificates in the status list, which the registrar never revokes.

The demo issuer signs its metadata with the access certificate and publishes its registration certificate in `issuer_info`. On the demo verifier page you choose how the verifier identifies itself:

- **Registered** (default): the request is signed with the access certificate and carries the registration certificate in `verifier_info`. It passes the `--arf` checks. A custom request for a claim that no template has gets an over-asking finding (RPRC_21).
- **Not registered**: the request is signed with the access certificate and has no `verifier_info`, so `--arf` reports RPRC_19.
- **Own certificates**: you paste a PEM bundle with your key and access certificate chain, and optionally a `verifier_info` value.

The identity buttons are `identity-registered`, `identity-unregistered` and `identity-own`. In **Own certificates** mode you paste into `signing-key` and `verifier-info`. The request API takes `"identity": "unregistered"` for the second option.

## Attestation catalogue

The registrar keeps a catalogue of attestation types, like the catalogue of attestations in EC TS11 v1.0 (§4.3 and §5). Each entry describes one attestation type: its formats with the schema of each, its rulebook, its level of security, how it is bound to its holder and the trusted list of its issuers.

Every predefined credential template is in the catalogue. Templates with the same display name share one entry, so the EUDI PID has its SD-JWT VC and its mdoc type in one entry. The rulebook is the last URL in the template's description. A PID has the level of security `iso_18045_high` and links the wallet's PID provider list. The demo ticket gets the defaults below. These entries can't be changed or deleted.

To add a user template, tick "Add the template to the attestation catalogue" when you save it (see [templates](../templates.md#attestation-catalogue)). You can delete that entry like any type you added.

You can add other attestation types and delete them again. An added type needs a unique name and at least one format with its `vct` or doctype. Without a rulebook URL it links a placeholder page at `<issuer URL>/rulebook`. The level of security defaults to `iso_18045_basic`, and the holder binding to `key`. Rulebooks and trusted lists are http or https URLs. A demo reset deletes the added types.

The holder binding is the TS11 `bindingType`. It says how the attestation is bound to its holder: `key` for a key in the holder's wallet, `claim` when it is linked to another credential of the holder (such as a PID), `biometric`, or `none`.

A trusted list is an `etsi_tl` entry with `isLOTE` set. TS11 §4.3.3 uses this for a list of trusted entities (ETSI TS 119 602).

The wallet serves the schema behind each schema URI:

- for `dc+sd-jwt`, SD-JWT VC Type Metadata (draft-ietf-oauth-sd-jwt-vc-19 §5.2) with the `vct`, the name and the claims
- for `mso_mdoc`, the doctype with its namespaces and element identifiers. TS11 asks for the DocType format of ISO 23220-2 here, and eudi-dev has not checked this document against it.

What each field changes:

| Field | Effect |
|-------|--------|
| Name | Shown in the catalogue and in the type suggestions |
| Formats and types | Suggested when you register a verifier or an issuer. With `--arf` the wallet warns when an issuer offers a type without an entry. It also uses the type to find the trusted list for a received credential |
| Claims | Listed in the served schema (template entries only) |
| Trusted list (LoTE) | With `--arf` a received credential of this type must chain to a certificate on the list (ARF ISSU_07 to ISSU_10, see [issuing](issuing.md#arf-checks)). The wallet reads ETSI TS 119 602 lists of trusted entities only |
| Rulebook | Published in the `SchemaMeta` only |
| Level of security | Published in the `SchemaMeta` only |
| Holder binding | Published in the `SchemaMeta` only. The wallet binds every credential to a key, whatever the entry says |
| Version | Published in the `SchemaMeta` only |

**Attestation catalogue** in the registrar menu lists the entries. **Add attestation** opens a dialog for a new type. When you register a verifier or an issuer, the type fields suggest the catalogue's types.

TS11 leaves adding entries to the Commission's registration process (§4.5), so `POST /api/catalog/attestations` is this catalogue's own method. The TS11 methods work on the `SchemaMeta` of an entry.

## Registrar API

The read endpoints follow the TS05 v1.5 registry API. They answer with a JWT signed by the registrar key, containing `iss`, `iat`, `data` and, for searches, `pagination`. If the `Accept` header asks for `application/json` but not `application/jwt`, you get the same payload unsigned. The catalogue's read endpoints are signed the same way, and a catalogue search pages inside `data` as TS11 describes.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/registrar/wrp` | Search registrations. Filters: `identifier`, `serviceidentifier`, `legalname`, `tradename`, `entitlement`, `providedattestation`, `intendeduseidentifier`, `credentialformat`, `credentialmeta`. Pages with `limit` and `cursor` |
| `GET` | `/api/registrar/wrp/{identifier}` | One registration |
| `GET` | `/api/registrar/wrp/{identifier}/services/{serviceidentifier}` | One service of a registration |
| `GET` | `/api/registrar/wrp/check-intended-use` | Checks whether the relying party `identifier` registered the intended use `intendeduseidentifier`. With `credentialformat`, `credentialmeta` and `claimpath` it also checks whether that intended use covers the claim |
| `POST` | `/api/registrar/wrp` | Register a relying party (TS05 JSON). Answers `201` with the stored registration |
| `PUT` | `/api/registrar/wrp` | Replace a registration. Send an intended use with its `intendedUseIdentifier` to keep that identifier. If an intended use or a service changes or is missing, its certificates are revoked |
| `DELETE` | `/api/registrar/wrp/{identifier}` | Delete a registration |
| `POST` | `/api/registrar/access-certificates` | Issue an access certificate. Fields `identifier`, `serviceIdentifier`, `csr`, `dnsNames`, `validity`. Answers `certificate`, `chain` and `clientIds` |
| `POST` | `/api/registrar/registration-certificates` | Issue a registration certificate. Fields `identifier`, `serviceIdentifier`, `intendedUseIdentifier`, `validity`. With an intended use it answers `registrationCertificate` and `verifierInfo`. Without one it certifies the issuer service and answers `registrationCertificate` and `issuerInfo`. `409` if the registration changed meanwhile |
| `GET` | `/api/registrar/registration-certificates` | The status list entries of the issued registration certificates, for one relying party with `identifier` or for all without it. An issuer's entry has `service` and an empty `intendedUse` |
| `POST` | `/api/registrar/registration-certificates/status` | Revoke (`revoked: true`) or activate (`revoked: false`) the registration certificates of the intended use `intendedUseIdentifier`, or of the service `serviceIdentifier`. Leave both out to change all certificates of `identifier`. Returns `changed`, the number of changed certificates |
| `GET` | `/api/registrar/status-list` | The status list of the registration certificates (`application/statuslist+jwt`) |
| `GET` | `/api/catalog/schemas` | The catalogue (TS11 v1.0 §5.3.1). Filters: `id`, `supportedFormats` (comma separated), `attestationLoS`, `bindingType`, `trustedAuthoritiesFrameworkType`, `trustedAuthoritiesValue`, `schemaUri`, `rulebookUri`. Pages with `limit` and `offset`. `data` has `total`, `limit`, `offset` and `data` |
| `GET` | `/api/catalog/schemas/{id}` | One `SchemaMeta` |
| `PUT` | `/api/catalog/schemas/{id}` | Replace the `SchemaMeta` of an added entry (TS11 §5.3.2). The formats and schema URIs follow from the entry's types and can't change. Built-in entries answer `403` |
| `DELETE` | `/api/catalog/schemas/{id}` | Delete an added entry (TS11 §5.3.3) |
| `GET` | `/api/catalog/schemas/{id}/{format}` | The schema behind a schema URI |
| `GET` | `/api/catalog/attestations` | The catalogue with names and types, as the UI shows it |
| `POST` | `/api/catalog/attestations` | Add an entry: `name`, `credentials` (each `format`, `type` and optional `claims` paths) and `schema` without `id`, `supportedFormats` and `schemaURIs`. Answers `201` with the entry |
| `GET` | `/privacy-policy`, `/support`, `/supervisory-authority`, `/rulebook` | Placeholder pages for the registrar's default URLs |

If the wallet's own registration as a credential provider matches the filters, it comes first in the search results.

TS11 describes `GET /schemas/{schemaId}` in §5.3.1, but its OpenAPI file (Annex A.3) leaves it out. The wallet serves it as the text describes. For `PUT` the text asks for a signed response and the OpenAPI file for JSON. The wallet answers with JSON, like the OpenAPI file.

## `wallet registrar` and `wallet catalog`

The CLI uses the same registrar. If a wallet is running, it calls the API. Otherwise it changes the wallet state directly.

```bash
eudi wallet registrar verifiers add --name "Example Shop" --purpose "Age check" --dcql query.json
eudi wallet registrar issuers add --name "Example University" --attestation dc+sd-jwt:urn:example:diploma:1
eudi wallet registrar verifiers
eudi wallet registrar issuers
openssl ecparam -name prime256v1 -genkey -noout -out verifier.key
openssl req -new -key verifier.key -subj "/" -out verifier.csr
eudi wallet registrar access-cert --identifier NTRNL-1A2B3C4D5E6F7A8B --csr verifier.csr --dns shop.example > verifier.pem
eudi wallet registrar registration-cert --identifier NTRNL-1A2B3C4D5E6F7A8B
eudi wallet registrar revoke --identifier NTRNL-1A2B3C4D5E6F7A8B
eudi wallet registrar activate --identifier NTRNL-1A2B3C4D5E6F7A8B
eudi wallet registrar verifiers rm NTRNL-1A2B3C4D5E6F7A8B
eudi wallet catalog
eudi wallet catalog add --name "University diploma" --type dc+sd-jwt:urn:example:diploma:1 --claim dc+sd-jwt:degree
eudi wallet catalog rm 3f1c3b0d-71ad-496b-9f94-68198503e761
```

`verifiers` and `issuers` list the registered verifiers and issuers, and so do `verifiers list` and `issuers list`. `add` registers one and prints the assigned identifier, and `rm` deletes a registration and revokes its certificates. `verifiers add` takes the credentials and claims of a DCQL query, so requests with that query pass the over-asking check (ARF RPRC_21). `issuers add` takes the entitlement and the attestation types.

`access-cert` prints the PEM certificate and writes the client identifiers to stderr: `x509_hash` for the certificate and `x509_san_dns` for each `--dns` name (OpenID4VP 1.0 §5.9.3). In the certificate, the name is the common name, the legal name is the organization and the service identifier is the organizational unit. It also contains the identifier as `organizationIdentifier`, the country, the support URLs in the subject alternative name and the certificate policy `0.4.0.194118.1.2` (ETSI TS 119 411-8 §5.3). The key must be P-256, because HAIP 1.0 requires ES256 for request objects.

`registration-cert` prints the `verifier_info` value for an intended use, or the `issuer_info` value for an issuer service. Both contain the certificate. Without `--intended-use` it certifies the only intended use, or the only issuer service. A relying party with both needs `--intended-use`, or `--service-id` with `--provider`. `--print certificate` prints the bare certificate instead, for example to pipe it into `eudi decode`. `--json` prints both.

`catalog` and `catalog list` list the catalogue, `catalog add` adds an attestation type and prints its schema URIs, and `catalog rm` deletes one you added.

| Command | Flag | Default | Description |
|---------|------|---------|-------------|
| `verifiers add`, `issuers add` | `--name` | None | Trade name (required) |
| `verifiers add`, `issuers add` | `--identifier` | Assigned | `organizationIdentifier` |
| `verifiers add`, `issuers add` | `--legal-name` | `--name` | Legal name |
| `verifiers add`, `issuers add` | `--country` | The identifier's country (`NL` for an assigned identifier) | Country code |
| `verifiers add`, `issuers add` | `--support-uri` | `<issuer URL>/support` | Support contact URL |
| `verifiers add`, `issuers add` | `--service-id` | None | Service identifier |
| `verifiers add` | `--dcql` | None | DCQL query to register (file, JSON or `-` for stdin, required) |
| `verifiers add` | `--purpose` | None | Purpose of the intended use |
| `verifiers add` | `--privacy-policy` | `<issuer URL>/privacy-policy` | Privacy policy URL of the intended use |
| `issuers add` | `--attestation` | None | Attestation type as `format:type`, such as `dc+sd-jwt:urn:eudi:pid:1` (repeatable, required) |
| `issuers add` | `--entitlement` | `eaa` | `pid`, `qeaa`, `pub-eaa` or `eaa` (non-qualified) |
| `access-cert` | `--identifier` | None | Registered identifier (required) |
| `access-cert` | `--service-id` | The first service | Service the certificate is for |
| `access-cert` | `--csr` | None | PEM certificate signing request (file or `-` for stdin, required) |
| `access-cert` | `--dns` | None | DNS name for the `x509_san_dns` client identifier (repeatable) |
| `access-cert` | `--validity` | `8760h` | Validity as a Go duration, at most `8760h` |
| `registration-cert` | `--identifier` | None | Registered identifier (required) |
| `registration-cert` | `--service-id` | Any service | Service of the intended use, or the issuer service |
| `registration-cert` | `--intended-use` | The only one | Intended use to certify |
| `registration-cert` | `--provider` | `false` | Certify the issuer service instead of an intended use |
| `registration-cert` | `--print` | `info` | `info` (`verifier_info` or `issuer_info`) or `certificate` (the bare JWT) |
| `registration-cert` | `--validity` | `4320h` | Validity as a Go duration, at most `8760h` (ETSI TS 119 475 GEN-5.2.4-08) |
| `revoke`, `activate` | `--identifier` | None | Registered identifier (required) |
| `revoke`, `activate` | `--intended-use` | All | Only change the certificates of this intended use |
| `revoke`, `activate` | `--service-id` | All | Only change the certificates of this service |
| `catalog add` | `--name` | None | Name of the attestation type (required, unique) |
| `catalog add` | `--type` | None | Format and type, such as `mso_mdoc:org.example.diploma.1` (repeatable, once per format, required) |
| `catalog add` | `--claim` | None | Format and claim, such as `dc+sd-jwt:address.locality` or `mso_mdoc:degree` (repeatable) |
| `catalog add` | `--los` | `basic` | Level of security: `basic`, `enhanced-basic`, `moderate` or `high` |
| `catalog add` | `--binding` | `key` | How the attestation is bound to its holder: `key` (a key in the wallet), `claim` (linked to another credential, such as a PID), `biometric` or `none` |
| `catalog add` | `--rulebook` | `<issuer URL>/rulebook` | Rulebook URL |
| `catalog add` | `--trusted-list` | None | URL of the trusted list of issuers for this type |
