# Spec Compliance

Status of implemented features against the relevant specifications.

## OID4VP 1.0 (OpenID for Verifiable Presentations)

| Feature | Status | Notes |
|---------|--------|-------|
| Authorization request parsing | Implemented | `openid4vp://`, `haip-vp://`, `eudi-openid4vp://` schemes |
| `request_uri` (GET) | Implemented | Fetches and parses signed request objects |
| `request_uri_method=post` | Implemented | Sends `wallet_metadata` and `wallet_nonce`. Strict mode rejects missing `wallet_nonce` in the response |
| Encrypted request objects (JWE) | Implemented | `--require-encrypted-request` flag |
| DCQL query evaluation | Implemented | Including `credential_sets` constraints. Debug mode warns and continues when some required claim paths are missing from an otherwise matching credential, while strict mode treats that credential as non-matching |
| `direct_post` response mode | Implemented | |
| `direct_post.jwt` response mode | Implemented | JARM-encrypted responses |
| `dc_api` response mode | Implemented | Browser API responses via `/api/dc-api` |
| `dc_api.jwt` response mode | Implemented | Encrypted Browser API responses via `/api/dc-api` |
| JAR (signed request objects) | Implemented | Strict mode verifies the JWS signature with the leaf `x5c` key and rejects failures. Debug mode logs findings and continues |
| `x509_san_dns:` client_id | Implemented | Verified against leaf cert SAN |
| `x509_hash:` client_id | Implemented | SHA-256 thumbprint matching |
| `web-origin:` client_id | Implemented | Verified against the caller `Origin` for Browser API requests |
| `redirect_uri:` client_id | Implemented | Requires unsigned request objects and checks that the prefix value matches `response_uri` |
| `verifier_attestation:` client_id | Validated | Checks JWT structure in header, verifies `sub` claim matches client_id |
| `decentralized_identifier:` client_id | Validated | DID format validation, `kid` cross-check (full DID resolution not implemented) |
| VP Token as JSON array | Implemented | Multiple credentials in a single response |
| `fragment` response mode | Implemented | Builds redirect URL with vp_token/state as fragment params. Not the default |
| SIOPv2 self-issued `id_token` | Implemented | `response_type=vp_token id_token` or `id_token` alone |
| Request object `typ` header | Enforced in strict mode | Debug mode logs a warning and continues |
| `trusted_authorities` (`etsi_tl`, `aki`) | Implemented | Filters credentials by issuer certificate chain against ETSI trust lists or matching Authority Key Identifier values |
| `transaction_data` | Enforced in strict mode | Debug mode logs a warning and continues. Strict mode rejects unsupported `transaction_data` |


## OID4VCI 1.0 (OpenID for Verifiable Credential Issuance)

| Feature | Status | Notes |
|---------|--------|-------|
| Credential offer parsing | Implemented | `openid-credential-offer://` and `haip-vci://` schemes |
| Pre-authorized code grant | Implemented | With optional `tx_code` |
| Authorization code grant | Implemented | Requires wallet `client_id` / `redirect_uri` configuration plus issuer metadata with PAR and DPoP support |
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
| Signed Credential Issuer Metadata verification | Enforced | `typ`, an asymmetric `alg` and a `sub` matching the issuer identifier, plus trust established in the signer through an `x5c` chain that ends in a configured anchor. Metadata whose signer cannot be placed is rejected (§12.2.3) |
| Credential configuration display and claims | Implemented | Read from the `credential_metadata` object of §12.2.4 for the consent dialog |
| Authorization server selection | Implemented | The offer's `authorization_server` grant parameter selects the entry to use, and a value matching no entry of `authorization_servers` stops the flow (§12.2.4) |
| Credential Issuer metadata publication | Implemented | Wallet serves `/.well-known/openid-credential-issuer` as unsigned `application/json` by default and as signed `application/jwt` to a client that asks for it (§12.2.2), with `issuer_info` / `registrar_dataset` |
| Registrar-style issuer authorization data | Implemented | Wallet serves `/api/registrar/wrp` with dynamic `entitlements` and `providesAttestations` filters for PID and non-PID attestation sets |
| HTTPS JWT VC issuer metadata publication | Implemented | Wallet serves `/.well-known/jwt-vc-issuer` with JWKS for wallet-issued SD-JWTs |

## HAIP 1.0 (Current wallet coverage)

| Feature | Status | Notes |
|---------|--------|-------|
| VP encrypted response modes | Enforced | With `--haip`, only `direct_post.jwt` and `dc_api.jwt` are accepted |
| VP allowed `client_id` schemes | Enforced | With `--haip`, `x509_hash:`, `x509_san_dns:`, and Browser API `web-origin:` are accepted |
| VP signed request object (JAR) | Enforced | Required with `--haip`, except unsigned Browser API `web-origin:` `dc_api.jwt` requests |
| VP DCQL query | Enforced | `presentation_definition` is rejected with `--haip` |
| VP Request Object `alg` | Enforced | `ES256` required with `--haip` when a request object is present |
| VCI authorization-code profile pieces | Enforced | The client uses PAR, PKCE S256 and DPoP. With `--haip`, an offer that drives the authorization endpoint is rejected unless the issuer requires PAR and supports PKCE S256, DPoP and client authentication. A pre-authorized code offer is held only to the https transport rule, per §4 |
| VCI encrypted credential responses | Implemented | Requests `credential_response_encryption` and decrypts returned compact JWEs |

This is the HAIP behavior currently exercised by the wallet and the current OIDF Final + HAIP wallet plans. It should not be read as a blanket claim that every HAIP deployment profile or auxiliary feature is implemented beyond those flows.

## SD-JWT (Selective Disclosure JWT)

Selective disclosure itself is RFC 9901 (published, no longer a draft). The credential profile on top of it is `draft-ietf-oauth-sd-jwt-vc-18`.

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

Still an Internet-Draft, in the RFC Editor queue at the time of writing. It has no RFC number yet, so nothing here cites one.

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
