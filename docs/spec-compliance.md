# Spec Compliance

Status of implemented features against the relevant specifications.

## OID4VP 1.0 (OpenID for Verifiable Presentations)

| Feature | Status | Notes |
|---------|--------|-------|
| Authorization request parsing | Implemented | `openid4vp://`, `haip-vp://`, `eudi-openid4vp://` schemes |
| `request_uri` (GET) | Implemented | Fetches and parses signed request objects |
| `request_uri_method=post` | Implemented | Sends `wallet_metadata` and `wallet_nonce`; strict mode rejects missing `wallet_nonce` in the response |
| Encrypted request objects (JWE) | Implemented | `--require-encrypted-request` flag |
| DCQL query evaluation | Implemented | Including `credential_sets` constraints; debug mode warns and continues when some required claim paths are missing from an otherwise matching credential, while strict mode treats that credential as non-matching |
| `direct_post` response mode | Implemented | |
| `direct_post.jwt` response mode | Implemented | JARM-encrypted responses |
| `dc_api` response mode | Implemented | Browser API responses via `/api/dc-api` |
| `dc_api.jwt` response mode | Implemented | Encrypted Browser API responses via `/api/dc-api` |
| JAR (signed request objects) | Implemented | Strict mode verifies the JWS signature with the leaf `x5c` key and rejects failures; debug mode logs findings and continues |
| `x509_san_dns:` client_id | Implemented | Verified against leaf cert SAN |
| `x509_hash:` client_id | Implemented | SHA-256 thumbprint matching |
| `web-origin:` client_id | Implemented | Verified against the caller `Origin` for Browser API requests |
| `redirect_uri:` client_id | Implemented | Requires unsigned request objects and checks that the prefix value matches `response_uri` |
| `verifier_attestation:` client_id | Validated | Checks JWT structure in header, verifies `sub` claim matches client_id |
| `decentralized_identifier:` client_id | Validated | DID format validation, `kid` cross-check (full DID resolution not implemented) |
| VP Token as JSON array | Implemented | Multiple credentials in a single response |
| `fragment` response mode | Implemented | Builds redirect URL with vp_token/state as fragment params; not the default |
| SIOPv2 self-issued `id_token` | Implemented | `response_type=vp_token id_token` or `id_token` alone |
| Request object `typ` header | Enforced in strict mode | Debug mode logs a warning and continues |
| `trusted_authorities` (`etsi_tl`, `aki`) | Implemented | Filters credentials by issuer certificate chain against ETSI trust lists or matching Authority Key Identifier values |
| `transaction_data` | Enforced in strict mode | Debug mode logs a warning and continues; strict mode rejects unsupported `transaction_data` |


## OID4VCI 1.0 (OpenID for Verifiable Credential Issuance)

| Feature | Status | Notes |
|---------|--------|-------|
| Credential offer parsing | Implemented | `openid-credential-offer://` and `haip-vci://` schemes |
| Pre-authorized code grant | Implemented | With optional `tx_code` |
| Authorization code grant | Implemented | Requires wallet `client_id` / `redirect_uri` configuration plus issuer metadata with PAR and DPoP support |
| Pushed Authorization Request (PAR) | Implemented | Used by the authorization-code flow |
| Token endpoint | Implemented | Exchanges pre-authorized code or authorization code for access token |
| Credential endpoint | Implemented | Uses OID4VCI 1.0 final `proofs.jwt` and sends `credential_identifier` or `credential_configuration_id` as required |
| Batch credential issuance | Implemented | Requests multiple proofs and selects the holder-bound credential from the batch |
| Deferred credential issuance | Implemented | Authorization-code flow follows `transaction_id` to `deferred_credential_endpoint` |
| Credential response encryption | Implemented | Requests `credential_response_encryption` when advertised and decrypts compact JWE responses |
| Signed OpenID Credential Issuer metadata publication | Implemented | Wallet serves `/.well-known/openid-credential-issuer` as signed `openidvci-issuer-metadata+jwt` with `issuer_info` / `registrar_dataset` |
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
| VCI authorization-code profile pieces | Enforced | The client uses PAR, PKCE S256 and DPoP. With `--haip`, an offer that drives the authorization endpoint is rejected unless the issuer requires PAR and supports PKCE S256, DPoP and client authentication; a pre-authorized code offer is held only to the https transport rule, per §4 |
| VCI encrypted credential responses | Implemented | Requests `credential_response_encryption` and decrypts returned compact JWEs |

This is the HAIP behavior currently exercised by the wallet and the current OIDF Final + HAIP wallet plans. It should not be read as a blanket claim that every HAIP deployment profile or auxiliary feature is implemented beyond those flows.

## SD-JWT (Selective Disclosure JWT)

| Feature | Status | Notes |
|---------|--------|-------|
| Parsing (header, payload, disclosures) | Implemented | |
| `_sd` claim resolution | Implemented | Recursive |
| Array disclosures | Implemented | `...` sentinel values |
| Key Binding JWT | Implemented | Generated during presentation |
| Signature verification (ES256/384/512) | Implemented | |
| Signature verification (RS256/384/512, PS256) | Implemented | |
| SHA-256/384/512 disclosure digests | Implemented | |
| Disclosure digest integrity check | Implemented | Verifies each disclosure hash appears in `_sd` arrays |
| `kid` header on generated SD-JWTs | Implemented | Deterministic RFC 7638 thumbprint of the signing key |
| X.509 trust-chain based issuer key publication | Implemented | Generated SD-JWTs carry leaf `x5c`; trust anchor remains in wallet trust list |

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
| Trusted entity list JWT parsing | Implemented | Signature not verified (intentional for debugging); requires the ETSI JSON-binding `LoTE` wrapper and accepts current EUDI-style fields such as `ListIssueDateTime` |
| Certificate chain validation against trusted entity list | Implemented | In `validate` command |

The implementation target for the EUDI wallet trust infrastructure is ETSI TS 119 602, which defines the EUDI trusted-entity list data model and LoTE structures. It does not implement the classic ETSI TS 119 612 XML trusted-list format used for eIDAS trust-service status lists.

## Token Status List (RFC 9596)

| Feature | Status | Notes |
|---------|--------|-------|
| Status list JWT generation | Implemented | Available for generated wallet credentials (`--pid` or `--status-list`) |
| Status list JWT parsing | Implemented | |
| Revocation status check | Implemented | In `validate` and the validate UI when a status reference is present |
| Runtime status changes via API | Implemented | `POST /api/credentials/<id>/status` |
