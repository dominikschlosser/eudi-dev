# Spec Compliance

Status of the implemented features against the specifications the EUDI Architecture and Reference Framework builds on. A mechanism none of them defines is recognised and reported, never used ([ADR-0013](adr/0013-only-the-eudi-stack-is-supported.md)).

Two independent settings decide what a finding does to a flow:

- `--mode` decides what a finding does. Findings are collected in both modes. Strict stops the flow, debug reports the finding and continues. Every finding starts with the specification and rule it cites (for example `OID4VP 1.0 §5.2: nonce is required`, `HAIP 1.0 §5.1: ...`, `ARF RPRC_19: ...`, `ETSI TS 119 475 GEN-5.2.4-08: ...`).
- `--haip` turns on the HAIP 1.0 checks listed below. The validation mode decides what a violation does, as for every other finding.

`--vci-version` selects the OpenID4VCI version the wallet follows as a client. `--vci-version 1.0` (the default) uses the published version alone. `--vci-version 1.1` adds the 1.1 draft features listed in the OID4VCI 1.1 section below, each only where the issuer's metadata offers it (see [OpenID4VCI feature level](wallet/issuing.md#openid4vci-feature-level)).

## OID4VP 1.0 (OpenID for Verifiable Presentations)

| Feature | Status | Notes |
|---------|--------|-------|
| Authorization request parsing | Implemented | `openid4vp://`, `haip-vp://`, `eudi-openid4vp://` schemes |
| Request Object parameter extraction | Enforced | The Request Object replaces the parameter set (§5.10.1: "The Wallet MUST only use the parameters in this Request Object, even if the same parameter was provided in an Authorization Request query parameter"). A parameter the Request Object omits is absent, and a Request Object whose `client_id` differs from the outer one stops the flow |
| Validation findings | Implemented | Collected in every mode. Strict makes each finding an error, debug reports it as a warning and continues |
| Undefined parameters | Warned | Request parameters OID4VP 1.0 does not define, and response fields other than `redirect_uri` (§8.2), produce a warning in every mode (RFC 6749 §3.1 requires ignoring unrecognized parameters) |
| Required request parameters | Enforced | `nonce` (§5.2), exactly one of `dcql_query` and `scope` on a `vp_token` request (§5.1), and no `redirect_uri` alongside `response_uri` (§8.2) |
| `request_uri` (GET) | Implemented | Fetches and parses signed request objects |
| `request_uri_method=post` | Implemented | Sends `wallet_metadata` and `wallet_nonce`. A `wallet_nonce` echoed in the request object must match the one sent, and a request object without one is accepted (the parameter is optional in the response) |
| Encrypted request objects (JWE) | Implemented | The wallet always sends an encryption key in `wallet_metadata` and decrypts an encrypted request object. `--require-encrypted-request` rejects an unencrypted one |
| DCQL query evaluation | Implemented | Including `credential_sets` constraints. Debug mode warns and continues when some required claim paths are missing from an otherwise matching credential, while strict mode treats that credential as non-matching |
| `vct_values` matching across extending types | Implemented | A credential matches a `vct_values` entry that names its own type, a type its `aka_vcts` claim lists, or a type it extends, so a request for `urn:eudi:pid:1` is matched by any domestic PID (`urn:eudi:pid:de:1`, `urn:eudi:pid:fr:1`, …) as ARF Annex 2 v3.0.0 PID_14 defines them. The match works in that direction only and is never a trust decision (see [credential type inheritance](wallet.md#credential-type-inheritance)) |
| One credential per credential query | Implemented | The wallet presents the most recently issued credential that matches each query (`multiple` is not implemented). The consent dialog and the activity log show exactly what is sent |
| `direct_post` response mode | Implemented | |
| `direct_post.jwt` response mode | Implemented | JARM-encrypted responses |
| `dc_api` response mode | Implemented | Browser API responses via `/api/dc-api` |
| `dc_api.jwt` response mode | Implemented | Encrypted Browser API responses via `/api/dc-api` |
| Response encryption key | Implemented | The response JWE is encrypted to the Verifier's `client_metadata.jwks` key. ECDH-ES for an EC P-256 key (the OID4VP baseline, preferred when the Verifier offers both) or RSA-OAEP for an RSA key. A Verifier that publishes only a signing-marked key gets a warning in debug mode (the wallet encrypts to it anyway) and a refusal in strict mode. Under `--haip` only ECDH-ES on P-256 is conformant (§5), so any other key is a violation |
| JAR (signed request objects) | Implemented | The JWS signature is verified with the leaf `x5c` key in every mode. Strict rejects a failure, debug reports it and continues. The chain is checked for internal consistency and is not anchored to a pre-registered verifier CA (see [SECURITY.md](../SECURITY.md)) |
| `x509_san_dns:` client_id | Implemented | Verified against leaf cert SAN |
| `x509_hash:` client_id | Implemented | SHA-256 of the leaf certificate matched against the prefix value |
| `redirect_uri:` client_id | Implemented | Requires unsigned request objects and checks that the prefix value matches `response_uri` |
| `verifier_attestation:` client_id | Validated | Checks JWT structure in header, verifies `sub` claim matches client_id. The Request Object signature is reported as not verified: its key is in the attestation's `cnf` claim, which the wallet does not read |
| `decentralized_identifier:` client_id | Validated | DID format validation, `kid` cross-check. DID resolution is not implemented, so the Request Object signature is reported as not verified ([ADR-0013](adr/0013-only-the-eudi-stack-is-supported.md)) |
| Pre-registered client (no prefix) | Validated | A Client Identifier carrying no `:` references a pre-registered client (§5.9.2) and is not reported as an unknown prefix. The Request Object signature is reported as not verified, since no client key is pre-registered with this wallet |
| `origin:` client_id | Refused | §5.9.3 reserves the prefix: "The Wallet MUST NOT accept this Client Identifier Prefix in requests". It identifies the audience of a Digital Credentials API presentation, which the wallet derives from the origin the platform reports |
| `openid_federation:` client_id | Refused | §5.9.3 defers the prefix to OpenID Federation. Trust chain resolution is not implemented, so the request is refused |
| Unsigned Digital Credentials API requests | Implemented | Appendix A.2: such a request carries no `client_id` at all, and both `client_id` and `expected_origins` are discarded before anything reads them. The caller is the origin the platform reports, and the presentation audience is that origin prefixed with `origin:` |
| `expected_origins` on signed Digital Credentials API requests | Enforced | Appendix A.2 requires the parameter on a signed request and requires an error when the caller origin is not among its entries |
| VP Token as JSON array | Implemented | Multiple credentials in a single response |
| `fragment` response mode | Implemented | Builds redirect URL with vp_token/state as fragment params. Not the default |
| SIOPv2 self-issued `id_token` | Implemented | `response_type=vp_token id_token` or `id_token` alone |
| Request object `typ` header | Enforced in strict mode | Debug mode logs a warning and continues |
| `trusted_authorities` (`etsi_tl`, `aki`) | Implemented | Filters credentials by issuer certificate chain against ETSI trust lists or matching Authority Key Identifier values |
| `transaction_data` | Enforced in strict mode | §5 requires a wallet that does not support the parameter to reject a request carrying it. Strict mode does, debug mode logs a warning and continues |
| `verifier_info` | Implemented | The purpose in a wallet-relying-party registration certificate (typ `rc-wrp+jwt` per ETSI TS 119 475, format `registration_cert` per ETSI TS 119 472-2) is shown in the consent dialog (§5.1). The certificate's signature is checked against its own x5c leaf, without anchoring to a trust list. Its `sub` identifies the registered legal entity, so it is not compared with the request's client_id. Other attestation formats are ignored |


## OID4VCI 1.0 (OpenID for Verifiable Credential Issuance)

| Feature | Status | Notes |
|---------|--------|-------|
| Credential offer parsing | Implemented | `openid-credential-offer://` and `haip-vci://` schemes |
| Pre-authorized code grant | Implemented | With optional `tx_code` |
| Authorization code grant | Implemented | Requires wallet `client_id` / `redirect_uri` configuration. Uses PAR, DPoP and client attestation when the issuer's metadata advertises them. Client attestation follows drafts 07, 08 and 10 of attestation-based client authentication per [ADR-0014](adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md): the configured OpenID4VCI version selects the claim set that is sent. The draft-10 additions (`attest_jwt_client_auth_dpop`, `client_attestation_pop_methods_supported`, the challenge headers) are negotiated through metadata. PAR is optional, and the flow falls back to the authorization endpoint when it is absent |
| Pushed Authorization Request (PAR) | Implemented | Used by the authorization-code flow |
| Token endpoint | Implemented | Exchanges pre-authorized code or authorization code for access token |
| Credential endpoint | Implemented | Uses OID4VCI 1.0 final `proofs.jwt` or `proofs.attestation` (Appendix F.1 and F.3, chosen from the configuration's `proof_types_supported`) and sends `credential_identifier` or `credential_configuration_id` as required (§8.2 forbids both together and forbids either one where the token response did not require it) |
| Key proof `iss` | Implemented | The JWT key proof sets `iss` to the client (Appendix F.1) when the wallet obtained the access token as an identified client (the authorization code flow, or a pre-authorized flow that authenticated the client), so an issuer that binds the token to a client can match it. An anonymous pre-authorized flow omits `iss` |
| Nonce endpoint | Implemented | The only source of the key-proof challenge (§8.2). The request is unauthenticated (§7.1). Strict mode refuses a `c_nonce` in the token response, debug mode uses it and logs the issuer as pre-1.0 |
| `invalid_nonce` retry | Implemented | A rejected challenge is fetched again from the Nonce Endpoint and the request is sent once more with rebuilt proofs (§8.3.1.2) |
| Credential response shape | Enforced | Only the `credentials` array of objects of §8.3 is read. A top-level `credential` string and an array of bare strings are draft formats and are refused |
| Batch credential issuance | Implemented | Requests one key per copy (one `jwt` proof each, or a single key attestation listing every key, Appendix F.1 and F.3) and imports what the issuer returns, one credential per key (§8.3), even fewer than requested and none bound to the holder key. Each copy records its own key so the wallet can sign its key binding |
| Proof signing algorithm | Implemented | The proof (and its key attestation) is signed with ES256, and a configuration whose `proof_signing_alg_values_supported` for the chosen proof type leaves ES256 out is refused in strict mode and reported in debug mode (Appendix F.1 and F.3 require `alg` to match that list, and HAIP §7 requires issuers to support ES256) |
| Key attestation proof types | Implemented | The key attestation (Appendix D) is carried in the `key_attestation` header of a `jwt` proof (F.1) or is the proof itself under the `attestation` proof type (F.3, the issuer's `c_nonce` inside the attestation). The proof type follows `proof_types_supported`: `attestation` when it is the only type offered or when the `jwt` type requires a key attestation, `jwt` otherwise |
| Deferred credential issuance | Implemented | Both grant flows poll `deferred_credential_endpoint` with the `transaction_id`. The poll carries the issuer's required request encryption and its own `credential_response_encryption` (§9.1). Pending is HTTP 202 with `transaction_id` and `interval` (§9.2) |
| Notification Endpoint | Implemented | A `credential_accepted` notification is sent wherever the issuer publishes `notification_endpoint` and the response carries a `notification_id`, on both grant flows and for a deferred credential once it is collected. §11 makes the endpoint OPTIONAL, so a refusal is a warning and the credential is kept. Any 2xx is a success (§11.2). A response outside the two §11.3 defines is reported as such |
| Transaction code | Implemented | The wallet supplies a `tx_code` when the offer's pre-authorized grant requires one (§4.1.1): the consent dialog asks for it, and `wallet accept` prompts at the terminal when it runs the flow itself. An issuance without one is refused before the pre-authorized code is used, and the refusal states the length and input mode the offer asked for |
| Credential response encryption | Implemented | Requests `credential_response_encryption` when advertised, and only where the request itself can be encrypted, which §8.2 requires whenever the parameter is sent |
| Credential Issuer Metadata retrieval | Implemented | `Accept: application/json, application/jwt` (§12.2.2). The response is refused unless `credential_issuer` is identical to the requested identifier (§12.2.4) |
| Signed Credential Issuer Metadata verification | Implemented | `typ`, an asymmetric `alg`, a `sub` matching the issuer identifier and a valid signature over the `x5c` leaf are all checked. Anchoring the signer to a configured trust anchor is attempted. A signer that matches no anchor is logged as unanchored and accepted (§12.2.3) |
| Credential configuration display and claims | Implemented | Read from the `credential_metadata` object of §12.2.4 for the consent dialog. The first display entry's name, description, logo, colors and background image are stored with the issued credential and rendered on its card and in the presentation consent dialog (the background image over the background color fills the card). Images (https or data scheme) are fetched once at issuance (up to 4MB, bounded to 32 megapixels) through the policed client and cached at 256KB, downscaled to card size when larger. A color outside the CSS Color Module Level 3 value space is dropped with a warning, a pair below 3:1 contrast is warned about. Style findings never fail an issuance |
| Authorization server selection | Implemented | The offer's `authorization_server` grant parameter selects the entry to use, and a value matching no entry of `authorization_servers` stops the flow (§12.2.4). The selected server's `grant_types_supported` is checked against the grant the issuance uses before the code is used. Strict mode refuses a stated mismatch. Debug mode warns and continues with the first advertised server whose metadata lists the grant, and stays with the selected one when none does |
| Credential Issuer metadata publication | Implemented | Wallet serves `/.well-known/openid-credential-issuer` as unsigned `application/json` by default and as signed `application/jwt` to a client that asks for it (§12.2.2), with `issuer_info` / `registrar_dataset` |
| Registrar-style issuer authorization data | Implemented | Wallet serves `/api/registrar/wrp` with dynamic `entitlements` and `providesAttestations` filters for PID and non-PID attestation sets |
| HTTPS JWT VC issuer metadata publication | Implemented | Wallet serves `/.well-known/jwt-vc-issuer` with JWKS for wallet-issued SD-JWTs |

## OID4VCI 1.1 draft (selected with `--vci-version 1.1`)

None of these run at the default feature level. Each row also needs the issuer's metadata to offer it.

1.1 is an editor's draft. The wallet implements the revision of 4 August 2026 and `draft-ietf-oauth-first-party-apps-04`, which §6 profiles.

| Feature | Status | Notes |
|---------|--------|-------|
| Interactive Authorization (§6) | Implemented | Used where the authorization server publishes `authorization_challenge_endpoint` (§13.3). It replaces the redirect flow of §5 and works without `--vci-redirect-uri`. At feature level 1.0 the activity log states which flag would use it |
| Authorization Challenge Request (§6.1) | Implemented | The initial request carries `interaction_types_supported`, PKCE S256, the credential scope and the offer's `issuer_state`. Intermediate requests carry `auth_session`, which is re-read from every response (§5.3.1 of the first-party-apps specification: clients "MUST NOT assume that auth_session values are static"). The code is returned in `authorization_code`, and the token request for it omits `redirect_uri` (first-party-apps §6). A code from the auth_via_web browser redirect repeats the redirect URI instead, as RFC 6749 §4.1.3 requires |
| Presentation interaction (§6.2.1.1) | Implemented | The wallet advertises only interactions it can complete (§6.2.1). The `openid4vp_request` is read signed or unsigned, `response_mode` must be `ia_post` or `ia_post.jwt`, and the response is sent as `openid4vp_response` in the next challenge request. A wallet with no matching credential answers with an OpenID4VP error |
| Presentation binding, SD-JWT VC (Appendix A.3.5) | Implemented, with a caveat | The Key Binding JWT `aud` is the Authorization Challenge Endpoint prefixed with `ia:`. A.3.5 alone says "the derived **Origin** ... of the Authorization Challenge Endpoint". A.1.1.5 (JWT VC), A.1.2.5 (Data Integrity) and A.2.5 (mdoc) bind the endpoint itself, §6.2.1.5 describes "binding the Authorization Challenge Endpoint to the Verifiable Presentation", and A.3.5's own example uses the endpoint. So the wallet sends the endpoint. A verifier that reads A.3.5 literally computes `ia:https://host` and refuses the presentation |
| Presentation binding, mdoc (Appendix A.2.5) | Implemented | `OpenID4VCIIAEHandover` over the challenge endpoint, the nonce, and the encryption key thumbprint for `ia_post.jwt` only. Checked against the worked example in the appendix |
| `expected_origins` check (§6.2.1.1, §6.2.1.5) | Enforced | When present it must contain only the derived origin of the challenge endpoint. This detects a request one authorization server forwarded from another. It is checked on unsigned requests too, since no platform reports the caller origin here |
| `auth_session` beyond one issuance | Deliberate deviation | Section 5.3.1 of the first-party-apps specification says a client "MUST store the auth_session beyond the issuance of the authorization code to be able to use it in future requests". This wallet keeps it for one exchange only. A stored session lets an authorization server correlate later issuances, and dropping it only means one more interaction |
| The `presentation_during_issuance_session` extension | Not implemented | A community extension outside the OpenID4VCI drafts. It answers the challenge endpoint with HTTP 400, a `presentation` member carrying an `openid4vp://` request URI and no `interaction_type_required`, and expects the presentation at the verifier's own `response_uri` rather than back at the challenge endpoint. Only that response tells such a server apart from a §6 one. The wallet aborts there and states the missing member (§6.2.1) |
| Authorization via web (§6.2.1.2) | Implemented | `urn:openid:dcp:ia:auth_via_web` is advertised when a redirect URI is configured and the server publishes an `authorization_endpoint`. The response's `request_uri` becomes an authorization request as RFC 9126 §4 defines, the sign-in URL is passed to the user's browser, and the redirect back is accepted with a `code` or with the `auth_session` that continues the challenge exchange. The token request repeats the redirect URI for a code obtained this way (RFC 6749 §4.1.3) and omits it for one from the challenge endpoint (first-party-apps §6). A server that requests an interaction the wallet did not advertise is refused |
| Custom interaction types (§6.2.1.3) | Not implemented | An unsupported `interaction_type_required` aborts the issuance (§6.2.1) |

## HAIP 1.0 (High Assurance Interoperability Profile)

Every row is a MUST in the profile and runs under `--haip`. In strict mode a request that fails any of them is answered with HTTP 400 naming the failed checks. In debug mode the findings are logged as warnings and the flow continues.

| Feature | Status | Notes |
|---------|--------|-------|
| VP `response_type` | Enforced | §5: "The Response type MUST be vp_token" |
| VP response modes | Enforced | Only `direct_post.jwt` (§5.1) and `dc_api.jwt` (§5.2) |
| VP Client Identifier Prefix | Enforced | §5 allows only `x509_hash` for signed requests, so `x509_san_dns:` is refused |
| VP request signature | Enforced | The Request Object signature is verified, and the `x509_hash` value must be the SHA-256 of the certificate that signed it |
| VP signing certificate rules | Enforced | §5: the certificate signing the request must not be self-signed, and the trust anchor must not be in the `x5c` header |
| VP signed request object (JAR) | Enforced | §5.1 requires JAR with the `request_uri` parameter, so an inline request object over redirects is refused. Unsigned requests are accepted only over the Digital Credentials API, where §5.2 requires them and they carry no `client_id` |
| VP DCQL query | Enforced | §5: "The DCQL query and response MUST be used as defined in Section 6 of [OIDF.OID4VP]" |
| VP credential formats | Enforced | `mso_mdoc` (§5.3.1) or `dc+sd-jwt` (§5.3.2). Any other format identifier in the query is refused |
| VP Verifier response encryption metadata | Enforced | §5: a Verifier must list both `A128GCM` and `A256GCM` in `encrypted_response_enc_values_supported` |
| VP `expected_origins` | Enforced | A signed Digital Credentials API request must list the caller origin (OpenID4VP Appendix A.2, which §5.2 incorporates) |
| VP Request Object `alg` | Enforced | `ES256`, the minimum §7 sets and the value the wallet advertises in `request_object_signing_alg_values_supported` |
| DPoP proof shape | Implemented | `htm` and `htu` per RFC 9449 §4.2, with `htu` carrying the target URI "without query and fragment parts", `ath` (the SHA-256 of the access token) wherever a proof accompanies one, a fresh `jti` per proof, and the server's `DPoP-Nonce` echoed and retried once when it asks for one |
| VCI authorization-code profile pieces | Enforced | The client uses PAR, PKCE S256 and DPoP. An offer that uses the authorization endpoint is rejected unless the authorization server supports the authorization code flow and offers a pushed authorization request endpoint (or an `authorization_challenge_endpoint`, since interactive authorization pushes nothing). It is also rejected when the server advertises PKCE without `S256` or DPoP without `ES256`. Metadata that says nothing about PKCE, DPoP or client authentication passes, because §4 defers those to FAPI 2.0, which constrains behaviour only. Only the https transport rule applies to a pre-authorized code offer, per §4 |
| VCI encrypted credential responses | Implemented | Requests `credential_response_encryption` and decrypts returned compact JWEs |

The OIDF HAIP wallet conformance plans test these rules.

## SD-JWT (Selective Disclosure JWT)

Selective disclosure is RFC 9901. The credential profile on top of it is `draft-ietf-oauth-sd-jwt-vc-19`.

| Feature | Status | Notes |
|---------|--------|-------|
| Parsing (header, payload, disclosures) | Implemented | |
| RFC 9901 §7.1 verification and processing | Enforced | Parsing applies the whole of §7.1 and refuses a credential that meets any of its MUST-reject conditions (a disclosure named `_sd` or `...`, a disclosure whose claim name already exists at the level of its `_sd` key, a disclosure whose element count does not match the position of its digest, a digest that appears twice, a disclosure that no digest refers to) |
| `_sd` claim resolution | Implemented | Recursive. `_sd` must hold an array of strings (§4.2.4.1) |
| Array disclosures | Implemented | A `{"...": digest}` element must carry that one key and nothing else (§4.2.4.2). An element whose digest has no disclosure is removed (§7.1 step 3.d) |
| `_sd_alg` handling | Implemented | Compared case-sensitively, defaults to `sha-256`, and refused in any object nested within the payload (§4.1.1) |
| Key Binding JWT | Implemented | Generated during presentation |
| Signature verification (ES256/384/512) | Implemented | |
| Signature verification (RS256/384/512, PS256) | Implemented | |
| SHA-256/384/512 disclosure digests | Implemented | |
| Disclosure digest integrity check | Implemented | Verifies each disclosure hash appears in `_sd` arrays |
| `kid` header on generated SD-JWTs | Implemented | Deterministic RFC 7638 thumbprint of the signing key |
| X.509 trust-chain based issuer key publication | Implemented | Generated SD-JWTs carry leaf `x5c`. Trust anchor remains in wallet trust list |
| SD-JWT VC `typ` header | Implemented | Generated credentials carry `dc+sd-jwt`. Reading one also accepts the earlier `vc+sd-jwt` value and reports it as a deviation (strict mode refuses it). |
| Credentials with no selectively disclosable claims | Implemented | `_sd` is omitted from the payload and the serialization ends in a single tilde (SD-JWT VC §2.2.2.5 and RFC 9901 §4) |
| Registered claims that cannot be selectively disclosed | Enforced | `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` and `status` are embedded plainly when generating a credential (SD-JWT VC §2.2.2.3), and `iat` with them because the generator writes one itself |
| `aka_vcts` claim | Implemented | Read when deciding whether a credential answers a requested type (§2.2.2.2), and written into the credentials this tool issues for a type that extends another. Never treated as evidence of issuer authorization (§6.6) |
| Type Metadata `extends` | Not implemented | The relationship is resolved from PID_14 for PID types and from `aka_vcts` for any type. EUDI PID `vct` values are URNs, which §4.4 does not cover, and the ARF only asks a Scheme Provider to "consider defining" a Type Metadata Document (Annex 2 v3.0.0, ARB_31) |
| JWT VC Issuer Metadata key resolution | Implemented | `/.well-known/jwt-vc-issuer` is inserted between the host and the path of `iss` (SD-JWT VC §3), so a tenant-scoped issuer resolves. The document must contain `issuer` identical to `iss` and either `jwks` or `jwks_uri`, never both (§3.2 and §3.3) |

## mDOC / ISO 18013-5

| Feature | Status | Notes |
|---------|--------|-------|
| IssuerSigned CBOR parsing | Implemented | |
| DeviceResponse generation | Implemented | |
| COSE_Sign1 verification | Implemented | ES256/384/512, PS256 |
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
| Trusted entity list JWT parsing | Implemented | The signature is not verified (a debugging choice). Requires the ETSI JSON-binding `LoTE` wrapper and accepts current EUDI-style fields such as `ListIssueDateTime` |
| Certificate chain validation against trusted entity list | Implemented | In `validate` command |

ETSI TS 119 602 defines the EUDI trusted-entity list data model and LoTE structures. The ETSI TS 119 612 XML trusted-list format is not implemented.

## Token Status List (`draft-ietf-oauth-status-list`)

The tracked revision is **draft-ietf-oauth-status-list-21** (editor's copy at <https://drafts.oauth.net/draft-ietf-oauth-status-list/draft-ietf-oauth-status-list.html>). Section numbers below refer to it.

| Feature | Status | Notes |
|---------|--------|-------|
| Status List Token generation (JWT) | Implemented | Available for generated wallet credentials (`--pid` or `--status-list`) |
| Status List Token generation (CWT) | Implemented | Served under `application/statuslist+cwt` when the client asks for it |
| Status List Token parsing (JWT and CWT) | Implemented | Both media types are requested and both are read |
| Content negotiation on the status list endpoint | Implemented | Section 8.1, JWT is the default |
| CORS on the status list endpoint | Implemented | Section 8.1 (browser-based clients) |
| Historical resolution (the `time` query parameter) | Not implemented | The endpoint answers 501 (section 8.4) |
| Status List Token validation rules (section 8.3) | Implemented | Signature, `typ`, `sub` against the credential's `uri`, `iat`, `exp`, `bits`, index bounds. A token that fails any of them yields no status |
| Status List Token signature verification | Implemented | Always performed. Key from the trust list chain, a caller-supplied key, `x5c`/`x5chain`, or the token's own `jwk`. A key that is not trust anchored is reported as such |
| Status Types (section 7.1) | Implemented | Reported by name (VALID, INVALID, SUSPENDED, application specific, unknown) |
| Revocation status check | Implemented | In `validate` and the validate UI when a status reference is present |
| Runtime status changes via API | Implemented | `POST /api/credentials/<id>/status`. Any Status Type value from 0 to 255 is accepted and the published list widens to 1, 2, 4 or 8 bits so it can hold the value |
| Status List Aggregation (section 9) | Not implemented | |
| Appendix C test vectors | Verified | The 1, 2, 4 and 8-bit vectors are a table test in `internal/statuslist` |
