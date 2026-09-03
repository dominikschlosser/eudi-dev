[← Wallet](../wallet.md)

# Presenting from the wallet

The wallet answers an OID4VP presentation request from the CLI (`wallet accept`), from a scanned QR (`wallet scan`), or at its own `/authorize` URL, and can hold the request to HAIP 1.0. A credential offer is dispatched by the same `wallet accept` command (see [issuing into the wallet](issuing.md) for the issuance side).

## `wallet accept <uri>`

Auto-detects the URI type and dispatches to the appropriate flow:

- `openid4vp://`, `haip-vp://`, `eudi-openid4vp://` → OID4VP presentation (evaluates DCQL, shows consent UI, submits VP token)
  - Supports `response_type=vp_token id_token` (SIOPv2 + OID4VP combined flow). Generates a self-issued ID token alongside the VP token
  - Supports `response_type=id_token` (SIOPv2 only). Generates a self-issued ID token without VP token
- `openid-credential-offer://`, `haip-vci://` → OID4VCI credential issuance (fetches credential from issuer)

In interactive mode (default), OID4VP requests start a temporary consent UI server and auto-open it in the browser. With `--auto-accept`, selects and submits one credential per credential query (the most recently issued one that answers it) without asking.

When a verifier answers a presentation with a `redirect_uri`, the URL is printed and opened in a browser (OpenID4VP returns the user agent to the verifier so a same-device flow lands back on the site that asked). A scripted run, or a host without a desktop, only prints it. `--no-open` disables opening everywhere.

With DCQL, `debug` mode is forgiving to help troubleshoot verifier queries. A credential that matches the requested format and metadata and at least one requested claim is kept as a match with a warning, even when other required claim paths are missing. `strict` mode treats the same query as non-matching.

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
| `--haip`                | `false`  | Hold incoming presentations and credential offers to HAIP 1.0. What a violation does follows `--mode`: strict refuses the flow, debug reports it and carries on |

Note: pre-authorized code offers work directly with `wallet accept`. Authorization-code offers are also supported. They require a running `wallet serve` instance. The client id and redirect URI default to the wallet's own origin and its `/callback` endpoint (`--vci-client-id` and `--vci-redirect-uri` override them), and PAR and DPoP are used where the issuer's metadata advertises them. The wallet server answers with the issuer's authorization URL rather than holding the request open. `wallet accept` prints it, and opens it only when it named no page for the wallet to send there, since the request behind that URL has one use (RFC 9126 §4). The user authenticates at the issuer, the issuer redirects back to the wallet's configured callback URI, and the wallet exchanges the code. The CLI follows the flow until the credential lands or the issuance fails. This also works against a remote wallet: the callback is matched by `state`, so the sign-in can happen in any browser that can reach the wallet. With `--haip` a pre-authorized code offer is still accepted and held only to the https transport rule. The PAR, PKCE, DPoP and client authentication requirements apply to offers that drive the authorization endpoint.

## `wallet scan`

Scans a QR code from an image file or screen capture and auto-detects the content:

- `openid4vp://` → delegates to `accept` (OID4VP presentation)
- `openid-credential-offer://` → delegates to `accept` (OID4VCI issuance)
- SD-JWT / mDoc raw credential → delegates to `import`

```bash
eudi wallet scan qr-image.png
eudi wallet scan --screen              # macOS interactive screen capture
eudi wallet scan --screen --auto-accept # auto-approve if it's a presentation
```

For OID4VP requests and OID4VCI offers, `wallet scan` behaves exactly like `wallet accept` (it is the same flow with a scan step first). It routes the scanned request to a running or remote wallet when one is configured (opening that wallet's consent UI), and otherwise runs the local flow. Nothing about the offer is read here when a wallet is going to read it, so a `credential_offer_uri` an issuer serves once is left for that wallet, and its consent dialog asks for the transaction code. The local flow prompts at the terminal instead, when stdin is a terminal and no `--tx-code` was given ([ADR-0012](../adr/0012-every-entry-point-runs-the-same-flow.md)). It honors the persistent `wallet --mode` flag and takes the same `--auto-accept`, `--tx-code`, and `--haip` flags as `accept`.

## Invoking the wallet by URL

Custom URL schemes require OS-level handler registration (macOS only). Both wallet flows can instead be invoked at the wallet's own URL, wherever a verifier or issuer would otherwise emit a custom-scheme link. This works in hosted environments, automated tests, containers, and on platforms without scheme registration.

The URLs take exactly the same query parameters as their custom-scheme counterparts:

| Custom scheme | Wallet URL |
|---------------|------------|
| `openid4vp://?<params>` or `openid4vp://authorize?<params>` | `http://localhost:8085/authorize?<params>` |
| `openid-credential-offer://?<params>` | `http://localhost:8085/credential-offer?<params>` |

To convert a link, replace everything before the `?` with the wallet endpoint URL and keep the query string unchanged.

Note on the paths: in a custom-scheme URI the part between `://` and `?` carries no meaning, so `openid4vp://?...` and `openid4vp://authorize?...` are the same request (the wallet ignores the conventional `authorize`). A web URL needs a path to identify the flow. `/authorize` follows the OAuth convention (in OID4VP the wallet acts as the OAuth authorization server), and `/credential-offer` names the OID4VCI credential offer endpoint. Neither spec mandates a path.

```bash
# Presentation request: standard OID4VP authorization request parameters
curl 'http://localhost:8085/authorize?client_id=...&request_uri=...'

# Credential offer by reference
curl 'http://localhost:8085/credential-offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F123'

# Credential offer by value (url-encoded offer JSON), with a transaction code
curl 'http://localhost:8085/credential-offer?credential_offer=%7B...%7D&tx_code=1234'
```

`/credential-offer` accepts `credential_offer` or `credential_offer_uri`, plus an optional `tx_code` for the pre-authorized code flow.

Responses depend on the caller. Browser navigations (a `GET` with an HTML `Accept` header, a clicked link) behave like a same-device wallet: after a presentation is submitted, the browser is redirected to the verifier's `redirect_uri` (or to the wallet UI when the verifier returns none), and after an offer is imported, to the wallet UI. Everything else (`curl`, test harnesses, the JSON APIs) receives the same JSON payloads as `POST /api/presentations` and `POST /api/offers`. A verifier or issuer configured with the wallet's URLs therefore completes a standard browser round trip with no custom schemes (for example `keycloak-extension-oid4vp` with `walletScheme` set to the wallet's `/authorize` URL).

In interactive mode (no `--auto-accept`) the two callers also diverge before consent. A browser navigation redirects to the wallet UI, which shows the pending consent request and continues the flow once approved (a presentation then navigates on to the verifier's `redirect_uri`). An API call blocks until the request is approved or denied, in the UI or via `POST /api/requests/{id}/approve`.

## HAIP 1.0 Enforcement

Use `--haip` with `wallet serve` or `wallet accept` to enforce [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html) compliance on incoming OID4VP requests. `--demo` turns it on by default (see [hosting a public demo](../public-demo.md)).

`--haip` and `--mode` are separate switches. `--haip` decides which checks run, adding every check below on top of the ones that apply to any counterparty. `--mode` decides what a finding does, for a profile violation like for any other. `--mode strict` stops the flow and `--mode debug` reports it and carries on. So `--haip --mode debug` names every profile violation without refusing the request, useful against a counterparty still being brought into line.

Enforcement covers **presentations**: OID4VP `direct_post.jwt` and Browser API `dc_api.jwt`. When enabled, the wallet checks every request against all of:

- `response_type` must be `vp_token` (§5)
- `response_mode` must be `direct_post.jwt` (§5.1) or `dc_api.jwt` (§5.2)
- A signed request must use the `x509_hash:` Client Identifier Prefix (§5), and its Request Object signature must verify against a certificate whose SHA-256 is the prefix value
- The certificate signing the request must not be self-signed, and the trust anchor must not be included in the `x5c` header (§5)
- A request arriving over redirects must carry a signed request object (JAR) delivered through `request_uri` (§5.1). An unsigned request is accepted only over the Digital Credentials API, where §5.2 obliges the wallet to support one and it carries no `client_id` at all
- The query must use DCQL (§5), and every credential it asks for must be `mso_mdoc` (§5.3.1) or `dc+sd-jwt` (§5.3.2)
- The Verifier's client metadata must list both `A128GCM` and `A256GCM` in `encrypted_response_enc_values_supported` (§5)
- A signed Digital Credentials API request must list the caller origin in `expected_origins` (OpenID4VP Appendix A.2, which §5.2 incorporates)
- The request object signing algorithm must be `ES256`

In `--mode strict` a non-compliant request is refused with an HTTP 400 naming the failed checks. In `--mode debug` the same findings are logged as warnings and the flow continues.

Issuance is enforced too, following the flow the offer actually drives. The credential that arrives is checked against §6.1.1: an SD-JWT VC must carry its issuer's signing certificate and a trust chain in its `x5c` header, without the certificate of the trust anchor, and its signing certificate must not be self-signed. A credential offer is always rejected when the credential issuer is served over plain http. An offer that drives the authorization endpoint is additionally rejected unless the authorization server supports the authorization code flow, offers a pushed authorization request endpoint, and does not advertise PKCE or DPoP in a way that contradicts the profile. Only advertisement that is present and wrong counts. `require_pushed_authorization_requests` is optional in RFC 9126, `code_challenge_methods_supported` in RFC 8414 and `dpop_signing_alg_values_supported` in RFC 9449, and HAIP defers all three to FAPI 2.0, which puts the obligation on the server's behaviour rather than on its metadata. A server that says nothing is not refused. A server that lists PKCE without `S256`, or DPoP without `ES256`, has said it cannot do what the profile requires and is refused. Client authentication is not checked at all, for the same reason. A pre-authorized code offer is held only to the transport rule: HAIP 1.0 §4 requires an issuer to *support* the authorization code flow rather than to use it for every credential, says nothing about the pre-authorized code flow, and scopes PAR to "when using the Authorization Endpoint". Plain http on loopback is accepted, the way OAuth treats a local development host.

The prefix rule in the bullets above is the profile's: §5 names `x509_hash` and only `x509_hash` for signed requests, so `x509_san_dns` is refused even though OpenID4VP defines it. An unsigned request is recognised by how it arrived (the Digital Credentials API, with no Request Object) rather than by a `client_id` value, because Appendix A.2 of OpenID4VP says such a request must carry none and a wallet must ignore one that is present. The caller is identified by the origin the platform reports. ES256 is the floor §7 sets and what this wallet advertises in `request_object_signing_alg_values_supported`. On the client side the wallet meets the profile itself (PAR, PKCE S256, DPoP, wallet attestation when advertised, ES256 proofs, key attestation), so `--haip` is about what it refuses from an issuer or a verifier.

```bash
eudi wallet serve --haip --auto-accept --pid
eudi wallet accept --haip 'openid4vp://authorize?...'
```

Conformance is the wallet's own setting. Every request to a given wallet is held to the same validation mode, HAIP and encrypted-request settings.
