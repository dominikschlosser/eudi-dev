[← Wallet](../wallet.md)

# Presenting from the wallet

The wallet answers an OID4VP presentation request from the CLI (`wallet accept`), from a scanned QR (`wallet scan`), or at its own `/authorize` URL. `--haip` checks the request against HAIP 1.0. The same `wallet accept` command dispatches a credential offer (see [issuing into the wallet](issuing.md)).

## `wallet accept <uri>`

Detects the URI type and dispatches to the matching flow:

- `openid4vp://`, `haip-vp://`, `eudi-openid4vp://`: OID4VP presentation (evaluates DCQL, shows the consent UI, submits the VP token)
  - Supports `response_type=vp_token id_token` (SIOPv2 + OID4VP combined flow). Generates a self-issued ID token alongside the VP token
  - Supports `response_type=id_token` (SIOPv2 only). Generates a self-issued ID token without VP token
- `openid-credential-offer://`, `haip-vci://`: OID4VCI credential issuance (fetches the credential from the issuer)

In interactive mode (the default), OID4VP requests start a temporary consent UI server and open it in the browser. With `--auto-accept`, the wallet submits one credential per credential query (the most recently issued one that matches it).

When a verifier answers a presentation with a `redirect_uri`, the wallet prints the URL and opens it in a browser (a same-device flow returns to the verifier's site). A scripted run, or a host without a desktop, only prints it. `--no-open` disables opening.

`debug` mode matches DCQL queries loosely, which helps troubleshoot verifier queries. A credential that matches the requested format and metadata and at least one requested claim counts as a match with a warning, even when other required claim paths are missing. `strict` mode requires every claim path.

```bash
eudi wallet accept 'openid4vp://authorize?...' --auto-accept
eudi wallet accept 'openid-credential-offer://...'
eudi wallet accept 'openid-credential-offer://...' --tx-code 123456
```

| Flag                    | Default  | Description                                      |
|-------------------------|----------|--------------------------------------------------|
| `--port`                | `8085`   | Server port for OID4VP                           |
| `--auto-accept`         | `false`  | Auto-approve OID4VP presentations                |
| `--mode`                | `debug`  | Validation mode: `debug` or `strict`             |
| `--session-transcript`  | `oid4vp` | mDoc session transcript mode: `oid4vp` or `iso`  |
| `--tx-code`             | —        | Transaction code for OID4VCI pre-authorized code flow |
| `--docker`              | `false`  | Serve the trust and status lists under `host.docker.internal` so a verifier in a container reaches them |
| `--key-attestation-level` | — | What the key attestation claims as `key_storage` and `user_authentication`: whatever the issuer requires (default), `none`, or an Appendix D.2 level such as `iso_18045_high` for both (see [SECURITY.md](../../SECURITY.md)). A running wallet server applies its own setting |
| `--haip`                | `false`  | Check incoming presentations and credential offers against HAIP 1.0. `--mode` decides what a violation does: strict refuses the flow, debug reports it and continues |

Pre-authorized code offers work directly with `wallet accept`. Authorization-code offers require a running `wallet serve` instance. The client id and redirect URI default to the wallet's own origin and its `/callback` endpoint (`--vci-client-id` and `--vci-redirect-uri` override them). PAR and DPoP are used where the issuer's metadata advertises them. The wallet server answers with the issuer's authorization URL. `wallet accept` prints it and opens it only when no wallet page is handling the flow, since the request behind that URL can be used once (RFC 9126 §4). The user authenticates at the issuer, the issuer redirects back to the wallet's callback URI, and the wallet exchanges the code. The CLI follows the flow until the credential arrives or the issuance fails. A remote wallet works the same way (see [sign-in during issuance](issuing.md#sign-in-during-issuance)). With `--haip` the wallet checks a pre-authorized code offer only against the https transport rule. The PAR, PKCE, DPoP and client authentication requirements apply to offers that use the authorization endpoint.

## `wallet scan`

Scans a QR code from an image file or screen capture and detects the content:

- `openid4vp://`: delegates to `accept` (OID4VP presentation)
- `openid-credential-offer://`: delegates to `accept` (OID4VCI issuance)
- SD-JWT / mDoc raw credential: delegates to `import`

```bash
eudi wallet scan qr-image.png
eudi wallet scan --screen              # macOS interactive screen capture
eudi wallet scan --screen --auto-accept # auto-approve if it's a presentation
```

For OID4VP requests and OID4VCI offers, `wallet scan` behaves like `wallet accept` with a scan step first. It routes the scanned request to a running or remote wallet when one is configured (opening that wallet's consent UI), and otherwise runs the local flow. The wallet that handles the offer fetches it, so a `credential_offer_uri` an issuer serves once still works, and that wallet's consent dialog asks for the transaction code. The local flow prompts for the code at the terminal when stdin is a terminal and no `--tx-code` was given ([ADR-0012](../adr/0012-every-entry-point-runs-the-same-flow.md)). `wallet scan` uses the persistent `wallet --mode` flag and takes the same `--auto-accept`, `--tx-code`, and `--haip` flags as `accept`.

## Invoking the wallet by URL

Both wallet flows can also be invoked at the wallet's own URL, wherever a verifier or issuer would emit a custom-scheme link. This works in hosted environments, automated tests, containers, and on platforms without scheme registration (custom schemes are registered on macOS only).

The URLs take exactly the same query parameters as their custom-scheme counterparts:

| Custom scheme | Wallet URL |
|---------------|------------|
| `openid4vp://?<params>` or `openid4vp://authorize?<params>` | `http://localhost:8085/authorize?<params>` |
| `openid-credential-offer://?<params>` | `http://localhost:8085/credential-offer?<params>` |

To convert a link, replace everything before the `?` with the wallet endpoint URL and keep the query string unchanged.

In a custom-scheme URI the part between `://` and `?` has no meaning, so `openid4vp://?...` and `openid4vp://authorize?...` are the same request. A web URL needs a path to identify the flow. `/authorize` follows the OAuth convention (in OID4VP the wallet is the authorization server), and `/credential-offer` is named after the OID4VCI credential offer endpoint.

```bash
# Presentation request: standard OID4VP authorization request parameters
curl 'http://localhost:8085/authorize?client_id=...&request_uri=...'

# Credential offer by reference
curl 'http://localhost:8085/credential-offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F123'

# Credential offer by value (url-encoded offer JSON), with a transaction code
curl 'http://localhost:8085/credential-offer?credential_offer=%7B...%7D&tx_code=1234'
```

`/credential-offer` accepts `credential_offer` or `credential_offer_uri`, plus an optional `tx_code` for the pre-authorized code flow.

Responses depend on the caller. Browser navigations (a `GET` with an HTML `Accept` header, a clicked link) behave like a same-device wallet. After a presentation is submitted, the browser is redirected to the verifier's `redirect_uri` (or to the wallet UI when the verifier returns none), and after an offer is imported, to the wallet UI. Everything else (`curl`, test harnesses, the JSON APIs) receives the same JSON payloads as `POST /api/presentations` and `POST /api/offers`. A verifier or issuer configured with the wallet's URLs completes a standard browser round trip with no custom schemes (for example `keycloak-extension-oid4vp` with `walletScheme` set to the wallet's `/authorize` URL).

In interactive mode (no `--auto-accept`) the two callers also differ before consent. A browser navigation redirects to the wallet UI, which shows the pending consent request and continues the flow once approved (a presentation then navigates on to the verifier's `redirect_uri`). An API call blocks until the request is approved or denied, in the UI or via `POST /api/requests/{id}/approve`.

## HAIP 1.0 Enforcement

`--haip` on `wallet serve` or `wallet accept` checks incoming requests and offers against [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html). `--demo` turns it on by default (see [hosting a public demo](../public-demo.md)).

`--haip` and `--mode` are separate switches. `--haip` adds every check below to the ones that apply to any counterparty. `--mode` decides what happens on a finding. `--mode strict` stops the flow and `--mode debug` reports it and continues. So `--haip --mode debug` reports every profile violation and still completes the flow, which is useful for a counterparty under development.

For **presentations** (OID4VP `direct_post.jwt` and Browser API `dc_api.jwt`) the wallet checks every request against all of:

- `response_type` must be `vp_token` (§5)
- `response_mode` must be `direct_post.jwt` (§5.1) or `dc_api.jwt` (§5.2)
- A signed request must use the `x509_hash:` Client Identifier Prefix (§5), and its Request Object signature must verify against a certificate whose SHA-256 is the prefix value
- The certificate signing the request must not be self-signed, and the trust anchor must not be included in the `x5c` header (§5)
- A request arriving over redirects must carry a signed request object (JAR) delivered through `request_uri` (§5.1). An unsigned request is accepted only over the Digital Credentials API, where §5.2 requires the wallet to support one, and such a request has no `client_id`
- The query must use DCQL (§5), and every credential it asks for must be `mso_mdoc` (§5.3.1) or `dc+sd-jwt` (§5.3.2)
- The Verifier's client metadata must list both `A128GCM` and `A256GCM` in `encrypted_response_enc_values_supported` (§5)
- A signed Digital Credentials API request must list the caller origin in `expected_origins` (OpenID4VP Appendix A.2, which §5.2 incorporates)
- The request object signing algorithm must be `ES256`

In `--mode strict` a non-compliant request is refused with an HTTP 400 listing the failed checks. In `--mode debug` the same findings are logged as warnings and the flow continues.

For **issuance** the checks depend on the flow the offer uses. The received credential is checked against §6.1.1. An SD-JWT VC must carry its issuer's signing certificate and a trust chain in its `x5c` header, without the trust anchor's certificate, and its signing certificate must not be self-signed. A credential offer is rejected when the credential issuer is served over plain http (loopback excepted, as in OAuth). An offer that uses the authorization endpoint is also rejected unless the authorization server supports the authorization code flow, offers a pushed authorization request endpoint, and advertises PKCE and DPoP in line with the profile. Only metadata that is present and wrong counts. `require_pushed_authorization_requests` is optional in RFC 9126, `code_challenge_methods_supported` in RFC 8414 and `dpop_signing_alg_values_supported` in RFC 9449, and HAIP defers all three to FAPI 2.0, which constrains the server's behaviour and not its metadata. A server that publishes none of them passes. A server that lists PKCE without `S256`, or DPoP without `ES256`, is refused. Client authentication is not checked for the same reason. A pre-authorized code offer is checked only against the transport rule. HAIP 1.0 §4 requires an issuer to *support* the authorization code flow, says nothing about the pre-authorized code flow, and scopes PAR to "when using the Authorization Endpoint".

The prefix rule comes from the profile. §5 allows only `x509_hash` for signed requests, so `x509_san_dns` is refused even though OpenID4VP defines it. An unsigned request is one that arrives over the Digital Credentials API without a Request Object. Appendix A.2 of OpenID4VP says such a request carries no `client_id` and a wallet ignores one that is present. The caller is identified by the origin the platform reports. §7 requires at least ES256, and this wallet advertises ES256 in `request_object_signing_alg_values_supported`. As a client the wallet always follows the profile (PAR, PKCE S256, DPoP, wallet attestation when advertised, ES256 proofs, key attestation), so `--haip` only affects what it refuses from an issuer or a verifier.

```bash
eudi wallet serve --haip --auto-accept --pid
eudi wallet accept --haip 'openid4vp://authorize?...'
```

Every request to a given wallet uses the same validation mode, HAIP and encrypted-request settings.
