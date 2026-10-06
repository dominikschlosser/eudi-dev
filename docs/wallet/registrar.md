# Registrar

The wallet includes a relying party registrar, like the one each member state runs (ARF Topic 27). You register a relying party with it and get two certificates:

- An **access certificate** (ETSI TS 119 411-8 V1.1.1). You send a certificate signing request and keep the private key. Your verifier signs its request objects with that key and puts the certificate in `x5c`.
- A **registration certificate** (ETSI TS 119 475 V1.2.1, typ `rc-wrp+jwt`) for one intended use. It lists which credentials and claims the verifier may request, and the purpose shown in the consent dialog. The verifier sends it in `verifier_info` (OpenID4VP 1.0 §5.1).

Both certificates contain the same identifier (ARF Reg_32 and RPRC_07). The registrar API follows the TS05 v1.5 data model and registry API. You can register verifiers. The wallet's own issuer is the only issuer in the register.

## Registrations

A relying party offers services. Each service has intended uses, and each intended use lists the credentials and claims it may request (TS05 v1.5 §2.4). A credential has the format `dc+sd-jwt` or `mso_mdoc` and its type in `meta`. Every credential lists at least one claim (TS05 v1.5 §2.4.5).

If a registration has no identifier, the registrar assigns one. It is an `organizationIdentifier` such as `NTRNL-1A2B3C4D5E6F7A8B`: the identifier type (`LEI`, `NTR`, `VAT`, `EOR` or `EXC`), a country code, a dash and the value (ETSI TS 119 475 §5.1.3).

Like credentials, anyone with access to the wallet can register, change and delete relying parties and revoke their certificates. On a shared instance every visitor sees every registration and can delete it.

An update can add identifiers. The first identifier never changes, because the issued certificates contain it.

Registrations are part of the wallet state. With file or Postgres storage they survive a restart. With memory storage they are lost, but if the keys are [seeded](../wallet.md#seeded-keys), certificates issued before the restart still verify. The wallet checks them by signature, not against the register. A demo reset deletes all registrations.

## Revocation

Every registration certificate has a `status` claim that points to an entry in the registrar's status list (ETSI TS 119 475 V1.2.1 Table 7). The registrar publishes the list at `/api/registrar/status-list` as a Token Status List, signed with the registrar key.

You revoke a certificate with **Revoke** in the UI, `wallet registrar revoke` or the status endpoint. **Activate**, `wallet registrar activate` or the same endpoint makes it valid again.

An intended use has one valid certificate at a time. The registrar also revokes certificates itself, and you can't activate these again:

- when you issue a new certificate for the same intended use
- when an update changes a field in the certificate (name, legal name, country, purpose, privacy policy, support URL, supervisory authority, credentials or claims)
- when an update removes the intended use
- when the relying party is deleted

If you request a certificate while someone updates the same registration, the request fails with HTTP 409. Try again.

Each certificate gets a random entry. The wallet's own registration certificates (in its issuer metadata and from the demo issuer) all use entry 0, which is never revoked. With memory storage the revocations are lost on restart, and a demo reset clears them. A certificate revoked before then is valid again. Rarely, a new certificate gets the same entry as an old one, and revoking it revokes the old one too.

## In the web UI

**Registrar** in the header opens a submenu. On a phone it is under **Menu**.

![Relying parties](../assets/registrar-parties.png)

**Relying parties** lists all registrations. The wallet's own registration comes first, then the others, newest first. You can filter by verifiers or issuers and search as you type. The search looks at names, identifiers, purposes and credential types, and suggests names and identifiers. The list shows 10 relying parties per page.

Each verifier shows its intended uses with their credentials and claims, and the status of their registration certificates: **No certificate**, **Active** or **Revoked**.

- **Issue certificate** issues a registration certificate for the intended use and shows its `verifier_info` value. Once there is one, the button reads **Issue new certificate**, which replaces the certificate and revokes the old one. The registrar doesn't store issued certificates, so this is also how you get a `verifier_info` value again.
- **Revoke** revokes the certificate. **Activate** makes it valid again. A certificate the registrar revoked itself shows **Revoked** without **Activate**.
- **Add registration certificate** asks for another purpose with its credentials and claims. The registrar adds it as a new intended use and issues a certificate for it. The existing certificates stay valid.
- **Delete** removes the relying party and revokes all its certificates.

![Register a verifier](../assets/registrar-register.png)

**Register a verifier** registers a relying party with one intended use and issues both certificates in one step. The fields are filled with defaults or may stay empty, so you can click **Register verifier** right away. If you leave the CSR empty, the browser creates the key and the CSR, and the key never leaves the browser. **Create the key and CSR yourself** shows the `openssl` commands for doing it on your machine. After registering, the button shows **Registered**. Once you edit a field, you can register again.

Each credential row has a format, a type and the claims. For SD-JWT, separate path segments with dots (`address.locality`). For mdoc, write the element name if it is in the doctype's namespace, or put another namespace in front with a colon (`eu.europa.ec.eudi.pid.de.1:birth_name`).

![Registration result](../assets/registrar-result.png)

The result shows the identifier, the client identifiers, a PEM box and the `verifier_info` value. If the browser created the key, the PEM contains the key and the access certificate chain. With your own CSR it contains only the chain. The registration certificate is in the `data` field of `verifier_info`. After **Add registration certificate** the result shows only the identifier and the `verifier_info` value.

Every element has an ID for automated tests:

| Element | IDs |
|---------|-----|
| Registrar menu | `registrar-menu-toggle` opens the submenu with `registrar-parties-link` and `registrar-register-verifier-link` |
| Relying parties | Filters `registrar-filter-all`, `registrar-filter-verifiers`, `registrar-filter-issuers`. `registrar-search` searches, with suggestions in `registrar-search-suggestions`. `registrar-page-prev`, `registrar-page-next` and `registrar-page-info` page through the list. `registrar-parties-register` opens Register a verifier, and `registrar-parties-close` closes the dialog. A party is `registrar-party-<identifier>` with `-name`, `-identifier`, `-role-verifier`, `-role-issuer`, `-add-use` and `-delete`. An intended use is `registrar-party-<identifier>-use-<intended use>` with `-purpose`, `-status`, `-credentials`, `-issue` and `-revoke` (Revoke or Activate). An issued certificate shows in `-result` with `-verifier-info` and `-copy`. In `<identifier>` and `<intended use>`, characters other than letters, digits, `_` and `-` become `_` |
| Register a verifier | `registrar-name`, `registrar-identifier`, `registrar-legal-name`, `registrar-country`, `registrar-support-uri`, `registrar-service-id`, `registrar-purpose`, `registrar-privacy-policy`, credential rows `registrar-credential-<n>-format`, `-type`, `-claims` and `-remove`, `registrar-add-credential`, `registrar-registration-validity`, `registrar-csr`, `registrar-dns`, `registrar-access-validity`, `registrar-csr-help-toggle`, `registrar-copy-csr-command`, `registrar-error`, `registrar-submit`, `registrar-close`. Results in `registrar-result` with `registrar-result-identifier`, `registrar-client-id-<n>`, `registrar-pem` (labelled by `registrar-pem-label`), `registrar-download-pem` and `registrar-verifier-info`. `registrar-copy-pem` and `registrar-copy-verifier-info` copy a result field. `registrar-client-id-<n>` counts from 0 |

## Fields and where they go

| Field | Access certificate | Registration certificate |
|-------|--------------------|--------------------------|
| Name | Common name | `name` and `srv_description` |
| Identifier | `organizationIdentifier` | `sub` |
| Legal name | Organization | `sub_ln` |
| Country | Country | `country` |
| Support URL | URI in the subject alternative name | `support_uri` |
| Service | Organizational unit | Not included |
| Purpose | Not included | `purpose` |
| Privacy policy | Not included | `privacy_policy` |
| Credentials and claims | Not included | `credentials` |
| Validity (registration certificate) | Not included | `iat` and `exp`, at most 12 months (GEN-5.2.4-08) |
| CSR | Public key | Not included |
| DNS names | DNS names in the subject alternative name | Not included |
| Validity (access certificate) | Validity period, at most one year | Not included |
| (assigned) | Not included | `status`, the entry in the registrar's status list |

The registrar fills in the rest. `registry_uri` points to the registration in the registrar API, `entitlements` contains the service provider entitlement, and `supervisory_authority` names a test authority. An empty support URL becomes `<issuer URL>/support`, and an empty privacy policy becomes `<issuer URL>/privacy-policy`. The supervisory authority links to `<issuer URL>/supervisory-authority`. The wallet serves a placeholder page at each of these URLs.

The access certificate has the policy `0.4.0.194118.1.2` (ETSI TS 119 411-8 §5.3) and is signed by the relying party access CA. That CA is a separate root, so access certificates from the registrar never chain to the wallet CA, which is the trust anchor for credential issuers. The registrar key signs the registration certificates. You can download the registrar certificate and the relying party access CA under **Trust & certificates**.

## What the wallet checks

The consent dialog shows the registered purpose and a link to the privacy policy (ARF RPA_10). API clients find them in `purposes` and `privacy_policies` of a pending request. The wallet shows them whenever the registration certificate's signature matches its `x5c` certificate, even without `--arf`.

With `--arf` the wallet checks the access certificate and the registration certificates of every request, whichever registrar issued them (see [ARF checks](presenting.md#arf-checks)). It trusts two sets of CAs:

- **Access certificates** must chain to the relying party access CA, the wallet CA (which signs the demo verifier's access certificate) or a CA from `--relying-party-ca`.
- **Registration certificates** must chain to the wallet CA (which signs the registrar certificate) or a CA from `--relying-party-ca`. The relying party access CA is not trusted here, because it signs every visitor's CSR. Otherwise anyone with an access certificate could sign their own registration.

Certificates from this registrar pass both checks. `--relying-party-ca` adds the CAs of other registrars. A registered credential without a claim list declares no attributes (ETSI TS 119 475 V1.2.1 Annex B.2.9), so any claim the request asks for counts as over-asking. TS05 registrars always list the claims.

The wallet reads its own registrar's status list directly. It fetches other registrars' lists with its proxy and TLS settings.

The wallet does not check these:

- **The service identifier.** ARF RPRC_17a also compares the service identifier, but ETSI TS 119 475 V1.2.1 has no claim for it. The access certificate has it as organizational unit.
- **Access certificate revocation.** The registrar does not revoke access certificates. A deleted relying party keeps a valid access certificate until it expires.
- **The register.** The wallet does not look up `registry_uri`. Under ARF RPRC_19 the verifier sends the certificate itself, so no lookup is needed.

## The demo verifier

![Demo verifier identity](../assets/verifier-identity.png)

On the demo verifier page you choose how the verifier identifies itself:

- **Demo certificate** (default): the request is signed with the demo verifier's access certificate. It has no registration certificate, so `--arf` reports RPRC_19.
- **Registrar certificates**: the first request registers the verifier through the registrar API. The browser creates the key and sends it to the demo verifier with each request, so the demo verifier can sign. The privacy policy is the registrar's placeholder page. The credential rows match the selected request until you edit them. If you change the name, the purpose or the rows, the next request registers again.
- **Own certificates**: you paste a PEM bundle with your key and access certificate chain, and optionally a `verifier_info` value.

The identity buttons are `identity-demo`, `identity-registrar` and `identity-own`. The registration fields are `identity-name`, `identity-purpose` and the rows `identity-credential-<n>-format`, `-type`, `-claims` and `-remove`, with `identity-add-credential`. `identity-registered-id` shows the assigned identifier. In **Own certificates** mode you paste into `signing-key` and `verifier-info`.

## Registrar API

The read endpoints follow the TS05 v1.5 registry API. They answer with a JWT signed by the registrar key, containing `iss`, `iat`, `data` and, for searches, `pagination`. If the `Accept` header asks for `application/json` but not `application/jwt`, you get the same payload unsigned.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/registrar/wrp` | Search registrations. Filters: `identifier`, `serviceidentifier`, `legalname`, `tradename`, `entitlement`, `providedattestation`, `intendeduseidentifier`, `credentialformat`, `credentialmeta`. Pages with `limit` and `cursor` |
| `GET` | `/api/registrar/wrp/{identifier}` | One registration |
| `GET` | `/api/registrar/wrp/{identifier}/services/{serviceidentifier}` | One service of a registration |
| `GET` | `/api/registrar/wrp/check-intended-use` | Checks whether the relying party `identifier` registered the intended use `intendeduseidentifier`. With `credentialformat`, `credentialmeta` and `claimpath` it also checks whether that intended use covers the claim |
| `POST` | `/api/registrar/wrp` | Register a relying party (TS05 JSON). Answers `201` with the stored registration |
| `PUT` | `/api/registrar/wrp` | Replace a registration. Send an intended use with its `intendedUseIdentifier` to keep that identifier. If an intended use changes or is missing, its certificates are revoked |
| `DELETE` | `/api/registrar/wrp/{identifier}` | Delete a registration |
| `POST` | `/api/registrar/access-certificates` | Issue an access certificate. Fields `identifier`, `serviceIdentifier`, `csr`, `dnsNames`, `validity`. Answers `certificate`, `chain` and `clientIds` |
| `POST` | `/api/registrar/registration-certificates` | Issue a registration certificate. Fields `identifier`, `serviceIdentifier`, `intendedUseIdentifier`, `validity`. Answers `registrationCertificate` and `verifierInfo`, or `409` if the registration changed meanwhile |
| `GET` | `/api/registrar/registration-certificates` | The status list entries of the issued registration certificates, for one relying party with `identifier` or for all without it |
| `POST` | `/api/registrar/registration-certificates/status` | Revoke (`revoked: true`) or activate (`revoked: false`) the registration certificates of the intended use `intendedUseIdentifier`, or of every intended use of `identifier` if you leave it out. Returns `changed`, the number of changed certificates |
| `GET` | `/api/registrar/status-list` | The status list of the registration certificates (`application/statuslist+jwt`) |
| `GET` | `/privacy-policy`, `/support`, `/supervisory-authority` | Placeholder pages behind the registrar's default contact URLs |

If the wallet's own registration as a credential provider matches the filters, it comes first in the search results.

## `wallet registrar`

The CLI uses the same registrar. If a wallet is running, it calls the API. Otherwise it changes the wallet state directly.

```bash
eudi wallet registrar register --name "Example Shop" --purpose "Age check" --dcql query.json
eudi wallet registrar list
openssl ecparam -name prime256v1 -genkey -noout -out verifier.key
openssl req -new -key verifier.key -subj "/" -out verifier.csr
eudi wallet registrar access-cert --identifier NTRNL-1A2B3C4D5E6F7A8B --csr verifier.csr --dns shop.example > verifier.pem
eudi wallet registrar registration-cert --identifier NTRNL-1A2B3C4D5E6F7A8B
eudi wallet registrar revoke --identifier NTRNL-1A2B3C4D5E6F7A8B
eudi wallet registrar activate --identifier NTRNL-1A2B3C4D5E6F7A8B
```

`register` prints the assigned identifier and the intended use identifier. `--dcql` registers the credentials and claims of a DCQL query. Requests with that query then pass the over-asking check (ARF RPRC_21).

`access-cert` prints the PEM certificate and writes the client identifiers to stderr: `x509_hash` for the certificate and `x509_san_dns` for each `--dns` name (OpenID4VP 1.0 §5.9.3). In the certificate, the name is the common name, the legal name is the organization and the service identifier is the organizational unit. It also contains the identifier as `organizationIdentifier`, the country, the support URLs in the subject alternative name and the certificate policy `0.4.0.194118.1.2` (ETSI TS 119 411-8 §5.3). The key must be P-256, because HAIP 1.0 requires ES256 for request objects.

`registration-cert` prints the `verifier_info` value, which contains the certificate (OpenID4VP 1.0 §5.1). A verifier sends this value with its requests. `--print certificate` prints the bare certificate instead, for example to pipe it into `eudi decode`. `--json` prints both. `--intended-use` defaults to the only intended use of the relying party.

| Command | Flag | Default | Description |
|---------|------|---------|-------------|
| `register` | `--name` | None | Trade name (required) |
| `register` | `--identifier` | Assigned | `organizationIdentifier` |
| `register` | `--legal-name` | `--name` | Legal name |
| `register` | `--country` | The identifier's country (`NL` for an assigned identifier) | Country code |
| `register` | `--support-uri` | `<issuer URL>/support` | Support contact URL |
| `register` | `--service-id` | None | Service identifier |
| `register` | `--purpose` | None | Purpose of the intended use |
| `register` | `--dcql` | None | DCQL query to register (file, JSON or `-` for stdin). Required for an intended use |
| `register` | `--privacy-policy` | `<issuer URL>/privacy-policy` | Privacy policy URL of the intended use |
| `access-cert` | `--identifier` | None | Registered identifier (required) |
| `access-cert` | `--service-id` | The first service | Service the certificate is for |
| `access-cert` | `--csr` | None | PEM certificate signing request (file or `-` for stdin, required) |
| `access-cert` | `--dns` | None | DNS name for the `x509_san_dns` client identifier (repeatable) |
| `access-cert` | `--validity` | `8760h` | Validity as a Go duration, at most `8760h` |
| `registration-cert` | `--identifier` | None | Registered identifier (required) |
| `registration-cert` | `--service-id` | Any | Service of the intended use |
| `registration-cert` | `--intended-use` | The only one | Intended use to certify |
| `registration-cert` | `--print` | `verifier-info` | `verifier-info` or `certificate` (the bare JWT) |
| `registration-cert` | `--validity` | `4320h` | Validity as a Go duration, at most `8760h` (ETSI TS 119 475 GEN-5.2.4-08) |
| `revoke`, `activate` | `--identifier` | None | Registered identifier (required) |
| `revoke`, `activate` | `--intended-use` | All | Only change the certificates of this intended use |
