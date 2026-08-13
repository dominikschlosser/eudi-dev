# Spec Compliance

Status of implemented features against the relevant specifications.

Two independent settings decide what a finding does to a flow:

- `--mode strict` and `--mode debug` decide what happens to a general specification finding. Findings are collected in both modes. Strict stops the flow, debug reports each one and carries on so the rest of the exchange stays observable.
- `--haip` decides whether the counterparty is held to HAIP 1.0. Every check in the HAIP section below is a MUST in that profile, so a violation is an error whenever `--haip` is on, whatever the validation mode says. Asking for HAIP is asserting that the counterparty follows it.

## OID4VP 1.0 (OpenID for Verifiable Presentations)

| Feature | Status | Notes |
|---------|--------|-------|
| Authorization request parsing | Implemented | `openid4vp://`, `haip-vp://`, `eudi-openid4vp://` schemes |
| Request Object parameter extraction | Enforced | The Request Object replaces the parameter set (§5.10.1: "The Wallet MUST only use the parameters in this Request Object, even if the same parameter was provided in an Authorization Request query parameter"). A parameter the Request Object omits is absent rather than inherited from the query string, and a Request Object whose `client_id` differs from the outer one stops the flow |
| Validation findings | Implemented | Collected in every mode. Strict makes each finding an error, debug reports it as a warning and continues |
| Required request parameters | Enforced | `nonce` (§5.2), exactly one of `dcql_query` and `scope` on a `vp_token` request (§5.1), and no `redirect_uri` alongside `response_uri` (§8.2) |
| `request_uri` (GET) | Implemented | Fetches and parses signed request objects |
| `request_uri_method=post` | Implemented | Sends `wallet_metadata` and `wallet_nonce`. Strict mode rejects missing `wallet_nonce` in the response |
| Encrypted request objects (JWE) | Implemented | `--require-encrypted-request` flag |
| DCQL query evaluation | Implemented | Including `credential_sets` constraints. Debug mode warns and continues when some required claim paths are missing from an otherwise matching credential, while strict mode treats that credential as non-matching |
| `vct_values` matching across extending types | Implemented | A credential answers a `vct_values` entry naming its own type, a type its `aka_vcts` claim lists, or a type it extends, so a request for `urn:eudi:pid:1` is answered by any domestic PID (`urn:eudi:pid:de:1`, `urn:eudi:pid:fr:1`, …) as ARF Annex 2 v3.0.0 PID_14 defines them. Never the other way round, and never a trust decision (see [credential type inheritance](wallet.md#credential-type-inheritance)) |
| One credential per credential query | Implemented | A credential query asks for one credential, and `multiple` is not implemented, so the wallet presents the most recently issued credential that answers each query. The consent dialog and the activity log show exactly what is sent |
| `direct_post` response mode | Implemented | |
| `direct_post.jwt` response mode | Implemented | JARM-encrypted responses |
| `dc_api` response mode | Implemented | Browser API responses via `/api/dc-api` |
| `dc_api.jwt` response mode | Implemented | Encrypted Browser API responses via `/api/dc-api` |
| JAR (signed request objects) | Implemented | The JWS signature is verified with the leaf `x5c` key in every mode. Strict rejects a failure, debug reports it and continues, and `--haip` makes it an error. The chain is checked for internal consistency but not anchored to a pre-registered verifier CA (a test wallet has none), so this proves the request is self-consistent, not that it came from a trusted verifier (see [SECURITY.md](../SECURITY.md)) |
| `x509_san_dns:` client_id | Implemented | Verified against leaf cert SAN |
| `x509_hash:` client_id | Implemented | SHA-256 of the leaf certificate matched against the prefix value |
| `redirect_uri:` client_id | Implemented | Requires unsigned request objects and checks that the prefix value matches `response_uri` |
| `verifier_attestation:` client_id | Validated | Checks JWT structure in header, verifies `sub` claim matches client_id |
| `decentralized_identifier:` client_id | Validated | DID format validation, `kid` cross-check (full DID resolution not implemented) |
| Pre-registered client (no prefix) | Implemented | A Client Identifier carrying no `:` references a pre-registered client (§5.9.2) and is not reported as an unknown prefix |
| `origin:` client_id | Refused | §5.9.3 reserves the prefix: "The Wallet MUST NOT accept this Client Identifier Prefix in requests". It names the audience of a Digital Credentials API presentation, which the wallet derives from the origin the platform reports |
| `openid_federation:` client_id | Refused | §5.9.3 defers the prefix to OpenID Federation, whose trust chain resolution is not implemented here, so the request is refused rather than accepted unverified |
| Unsigned Digital Credentials API requests | Implemented | Appendix A.2: such a request carries no `client_id` at all, and both `client_id` and `expected_origins` are discarded before anything reads them. The caller is the origin the platform reports, and the presentation audience is that origin prefixed with `origin:` |
| `expected_origins` on signed Digital Credentials API requests | Enforced | Appendix A.2 requires the parameter on a signed request and requires an error when the caller origin is not among its entries |
| VP Token as JSON array | Implemented | Multiple credentials in a single response |
| `fragment` response mode | Implemented | Builds redirect URL with vp_token/state as fragment params. Not the default |
| SIOPv2 self-issued `id_token` | Implemented | `response_type=vp_token id_token` or `id_token` alone |
| Request object `typ` header | Enforced in strict mode | Debug mode logs a warning and continues |
| `trusted_authorities` (`etsi_tl`, `aki`) | Implemented | Filters credentials by issuer certificate chain against ETSI trust lists or matching Authority Key Identifier values |
| `transaction_data` | Enforced in strict mode | §5 obliges a wallet that does not support the parameter to reject a request carrying it. Strict mode does, debug mode logs a warning and continues |


## OID4VCI 1.0 (OpenID for Verifiable Credential Issuance)

| Feature | Status | Notes |
|---------|--------|-------|
| Credential offer parsing | Implemented | `openid-credential-offer://` and `haip-vci://` schemes |
| Pre-authorized code grant | Implemented | With optional `tx_code` |
| Authorization code grant | Implemented | Requires wallet `client_id` / `redirect_uri` configuration. Uses PAR, DPoP and client attestation when the issuer's metadata advertises them. PAR is optional, and the flow falls back to the authorization endpoint when it is absent |
| Pushed Authorization Request (PAR) | Implemented | Used by the authorization-code flow |
| Token endpoint | Implemented | Exchanges pre-authorized code or authorization code for access token |
| Credential endpoint | Implemented | Uses OID4VCI 1.0 final `proofs.jwt` and sends `credential_identifier` or `credential_configuration_id` as required (§8.2 forbids both together and forbids either one where the token response did not call for it) |
| Nonce endpoint | Implemented | The only source of the key-proof challenge (§8.2). The request is unauthenticated, as §7.1 says it is not a protected resource. Strict mode refuses a `c_nonce` in the token response, debug mode uses it and logs the issuer as pre-1.0 |
| `invalid_nonce` retry | Implemented | A rejected challenge is fetched again from the Nonce Endpoint and the request is sent once more with rebuilt proofs (§8.3.1.2) |
| Credential response shape | Enforced | Only the `credentials` array of objects of §8.3 is read. A top-level `credential` string and an array of bare strings are draft shapes and are refused |
| Batch credential issuance | Implemented | Requests multiple proofs and selects the holder-bound credential from the batch |
| Deferred credential issuance | Implemented | Authorization-code flow follows `transaction_id` to `deferred_credential_endpoint`. The poll carries the issuer's required request encryption and its own `credential_response_encryption` (§9.1). Pending is HTTP 202 with `transaction_id` and `interval` (§9.2) |
| Credential response encryption | Implemented | Requests `credential_response_encryption` when advertised, and only where the request itself can be encrypted, which §8.2 requires whenever the parameter is sent |
| Credential Issuer Metadata retrieval | Implemented | `Accept: application/json, application/jwt` (§12.2.2). The response is refused unless `credential_issuer` is identical to the requested identifier (§12.2.4) |
| Signed Credential Issuer Metadata verification | Implemented | `typ`, an asymmetric `alg`, a `sub` matching the issuer identifier and a valid signature over the `x5c` leaf are all checked. Anchoring the signer to a configured trust anchor is attempted but not required: a test wallet holds no issuer trust anchors, so a signer that cannot be placed is read as signed-but-unplaced (logged) rather than rejected (§12.2.3) |
| Credential configuration display and claims | Implemented | Read from the `credential_metadata` object of §12.2.4 for the consent dialog |
| Authorization server selection | Implemented | The offer's `authorization_server` grant parameter selects the entry to use, and a value matching no entry of `authorization_servers` stops the flow (§12.2.4) |
| Credential Issuer metadata publication | Implemented | Wallet serves `/.well-known/openid-credential-issuer` as unsigned `application/json` by default and as signed `application/jwt` to a client that asks for it (§12.2.2), with `issuer_info` / `registrar_dataset` |
| Registrar-style issuer authorization data | Implemented | Wallet serves `/api/registrar/wrp` with dynamic `entitlements` and `providesAttestations` filters for PID and non-PID attestation sets |
| HTTPS JWT VC issuer metadata publication | Implemented | Wallet serves `/.well-known/jwt-vc-issuer` with JWKS for wallet-issued SD-JWTs |

## HAIP 1.0 (Current wallet coverage)

Every row here is a MUST in the profile, so `--haip` makes each one an error on its own, independent of `--mode`. A request that fails any of them is answered with HTTP 400 naming the checks that failed.

| Feature | Status | Notes |
|---------|--------|-------|
| VP `response_type` | Enforced | §5: "The Response type MUST be vp_token" |
| VP response modes | Enforced | Only `direct_post.jwt` (§5.1) and `dc_api.jwt` (§5.2) |
| VP Client Identifier Prefix | Enforced | §5 names `x509_hash` and only `x509_hash` for signed requests, so `x509_san_dns:` is refused even though OpenID4VP defines it |
| VP request signature | Enforced | The Request Object signature is verified, and the `x509_hash` value must be the SHA-256 of the certificate that signed it. Checking the prefix string while accepting an unverifiable signature would be enforcement in name only |
| VP signing certificate rules | Enforced | §5: the certificate signing the request must not be self-signed, and the trust anchor must not travel in the `x5c` header |
| VP signed request object (JAR) | Enforced | §5.1 requires JAR with the `request_uri` parameter, so an inline request object over redirects is refused. Unsigned requests are accepted only over the Digital Credentials API, where §5.2 obliges the wallet to support them and they carry no `client_id` |
| VP DCQL query | Enforced | §5: "The DCQL query and response MUST be used as defined in Section 6 of [OIDF.OID4VP]" |
| VP credential formats | Enforced | `mso_mdoc` (§5.3.1) or `dc+sd-jwt` (§5.3.2). Any other format identifier in the query is refused |
| VP Verifier response encryption metadata | Enforced | §5: a Verifier must list both `A128GCM` and `A256GCM` in `encrypted_response_enc_values_supported` |
| VP `expected_origins` | Enforced | A signed Digital Credentials API request must list the caller origin (OpenID4VP Appendix A.2, which §5.2 incorporates) |
| VP Request Object `alg` | Enforced | `ES256`, the floor §7 sets and the value the wallet advertises in `request_object_signing_alg_values_supported` |
| VCI authorization-code profile pieces | Enforced | The client uses PAR, PKCE S256 and DPoP. An offer that drives the authorization endpoint is rejected unless the authorization server supports the authorization code flow and offers a pushed authorization request endpoint. It is also rejected when the server advertises PKCE without `S256` or DPoP without `ES256`. Metadata that says nothing about PKCE, DPoP or client authentication is not a violation, because §4 defers those to FAPI 2.0, which puts the obligation on behaviour rather than on metadata. A pre-authorized code offer is held only to the https transport rule, per §4 |
| VCI encrypted credential responses | Implemented | Requests `credential_response_encryption` and decrypts returned compact JWEs |

This is the HAIP behavior currently exercised by the wallet and the current OIDF Final + HAIP wallet plans. It should not be read as a blanket claim that every HAIP deployment profile or auxiliary feature is implemented beyond those flows.

## SD-JWT (Selective Disclosure JWT)

Selective disclosure itself is RFC 9901. The credential profile on top of it is `draft-ietf-oauth-sd-jwt-vc-18`, which is still an Internet-Draft.

| Feature | Status | Notes |
|---------|--------|-------|
| Parsing (header, payload, disclosures) | Implemented | |
| RFC 9901 §7.1 verification and processing | Enforced | Parsing applies the whole of §7.1 and refuses a credential that meets any of its MUST-reject conditions (a disclosure named `_sd` or `...`, a disclosure whose claim name already exists at the level of its `_sd` key, a disclosure whose element count does not match where its digest sits, a digest that appears twice, a disclosure that no digest refers to) |
| `_sd` claim resolution | Implemented | Recursive. `_sd` must hold an array of strings (§4.2.4.1) |
| Array disclosures | Implemented | A `{"...": digest}` element must carry that one key and nothing else (§4.2.4.2). An element whose digest has no disclosure is removed rather than left in the claims (§7.1 step 3.d) |
| `_sd_alg` handling | Implemented | Compared case-sensitively, defaults to `sha-256`, and refused in any object nested within the payload (§4.1.1) |
| Key Binding JWT | Implemented | Generated during presentation |
| Signature verification (ES256/384/512) | Implemented | |
| Signature verification (RS256/384/512, PS256) | Implemented | |
| SHA-256/384/512 disclosure digests | Implemented | |
| Disclosure digest integrity check | Implemented | Verifies each disclosure hash appears in `_sd` arrays |
| `kid` header on generated SD-JWTs | Implemented | Deterministic RFC 7638 thumbprint of the signing key |
| X.509 trust-chain based issuer key publication | Implemented | Generated SD-JWTs carry leaf `x5c`. Trust anchor remains in wallet trust list |
| SD-JWT VC `typ` header | Implemented | Generated credentials carry `dc+sd-jwt`. Reading one accepts that value and `vc+sd-jwt`, which SD-JWT VC §2.2.1 keeps valid for a transitional period, and nothing else |
| Credentials with no selectively disclosable claims | Implemented | `_sd` is omitted from the payload and the serialization ends in a single tilde (SD-JWT VC §2.2.2.5 and RFC 9901 §4) |
| Registered claims that cannot be selectively disclosed | Enforced | `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` and `status` are embedded plainly when generating a credential (SD-JWT VC §2.2.2.3), and `iat` with them because the generator writes one itself |
| `aka_vcts` claim | Implemented | Read when deciding whether a credential answers a requested type (§2.2.2.2), and written into the credentials this tool issues for a type that extends another. Never treated as evidence of issuer authorization (§6.6) |
| Type Metadata `extends` | Not implemented | The relationship is resolved from PID_14 for PID types, and from `aka_vcts` for any type, instead. Retrieving Type Metadata (§4.4) says nothing about the EUDI PID types, whose `vct` values are URNs, and the ARF only asks a Scheme Provider to "consider defining" a Type Metadata Document (Annex 2 v3.0.0, ARB_31) |
| JWT VC Issuer Metadata key resolution | Implemented | `/.well-known/jwt-vc-issuer` is inserted between the host and the path of `iss` (SD-JWT VC §3), so a tenant-scoped issuer resolves. The document must carry `issuer` identical to `iss` and either `jwks` or `jwks_uri`, never both (§3.2 and §3.3) |

## mDOC / ISO 18013-5

| Feature | Status | Notes |
|---------|--------|-------|
| IssuerSigned CBOR parsing | Implemented | |
| DeviceResponse generation | Implemented | |
| COSE_Sign1 verification | Implemented | ES256/384/512, PS256, RS256 |
| MSO (Mobile Security Object) parsing | Implemented | |
| Validity info (validFrom, validUntil) | Implemented | |
| IssuerSignedItem digest verification | Implemented | |
| Session transcript (OID4VP mode) | Implemented | Default |
| Session transcript (ISO 18013-7 mode) | Implemented | `--session-transcript iso` |
| DeviceSigned generation | Implemented | Wallet generates DeviceAuth in DeviceResponse |

## ETSI TS 119 602 Trusted Entity Lists

| Feature | Status | Notes |
|---------|--------|-------|
| Trusted entity list JWT generation | Implemented | Wallet generates ETSI TS 119 602 JSON-binding JWT lists with the required top-level `LoTE` object |
| Trusted entity list JWT parsing | Implemented | Signature not verified (intentional for debugging). Requires the ETSI JSON-binding `LoTE` wrapper and accepts current EUDI-style fields such as `ListIssueDateTime` |
| Certificate chain validation against trusted entity list | Implemented | In `validate` command |

The implementation target for the EUDI wallet trust infrastructure is ETSI TS 119 602, which defines the EUDI trusted-entity list data model and LoTE structures. It does not implement the classic ETSI TS 119 612 XML trusted-list format used for eIDAS trust-service status lists.

## Token Status List (`draft-ietf-oauth-status-list`)

An Internet-Draft with no RFC number, so nothing here cites one. The version tracked is the editor's copy at <https://drafts.oauth.net/draft-ietf-oauth-status-list/draft-ietf-oauth-status-list.html>, and the section numbers below are its.

| Feature | Status | Notes |
|---------|--------|-------|
| Status List Token generation (JWT) | Implemented | Available for generated wallet credentials (`--pid` or `--status-list`) |
| Status List Token generation (CWT) | Implemented | Served under `application/statuslist+cwt` when the client asks for it |
| Status List Token parsing (JWT and CWT) | Implemented | Both media types are requested and both are read |
| Content negotiation on the status list endpoint | Implemented | Section 8.1, JWT is the default |
| CORS on the status list endpoint | Implemented | Section 8.1 (browser-based clients) |
| Historical resolution (the `time` query parameter) | Not implemented | The endpoint answers 501 as section 8.4 says it should |
| Status List Token validation rules (section 8.3) | Implemented | Signature, `typ`, `sub` against the credential's `uri`, `iat`, `exp`, `bits`, index bounds. A token that fails any of them yields no status at all |
| Status List Token signature verification | Implemented | Always performed. Key from the trust list chain, a caller-supplied key, `x5c`/`x5chain`, or the token's own `jwk`. A key that is not trust anchored is reported as such |
| Status Types (section 7.1) | Implemented | Reported by name (VALID, INVALID, SUSPENDED, application specific, unknown) |
| Revocation status check | Implemented | In `validate` and the validate UI when a status reference is present |
| Runtime status changes via API | Implemented | `POST /api/credentials/<id>/status`. Any Status Type value from 0 to 255 is accepted and the published list widens to 1, 2, 4 or 8 bits so it carries the real value |
| Status List Aggregation (section 9) | Not implemented | |
| Appendix C test vectors | Verified | The 1, 2, 4 and 8-bit vectors are a table test in `internal/statuslist` |
