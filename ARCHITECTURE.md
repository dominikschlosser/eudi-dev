# Architecture

The package layout and how a request passes through it. The reasons are in the [decision records](#decisions).

For the vocabulary these documents use, see [CONTEXT.md](CONTEXT.md).

## Layout

```
main.go        Entry point
cmd/           CLI commands (Cobra), one file per command or command group
internal/      Everything else (ADR-0007)
e2e/           Playwright tests against a running wallet server
examples/      Keycloak and web-wallet integration examples
```

### Packages

| Package | Responsibility |
|---|---|
| `config` | Defaults (ports, timeouts) |
| `credtemplate` | Credential templates, pre-defined and user-supplied |
| `credtype` | The EUDI credential type identifiers and which type extends which |
| `dcql` | DCQL query parsing, evaluation, generation |
| `demorp` | The demo issuer and verifier the wallet hosts |
| `format` | Format detection, base64url, and the outbound fetch policy (ADR-0004) |
| `httpsec` | Browser security headers and the cross-origin guard (ADR-0002) |
| `imprint` | Operator-supplied legal notice page |
| `jsonutil` | Type-safe accessors for `map[string]any` |
| `jwe` | Compact JWE decryption (ECDH-ES, Concat KDF, AES-GCM) |
| `jws` | JWS signing (ES256) and verification (ES, RS and PS families), shared by signer and verifier (ADR-0008) |
| `keys` | PEM and JWK key loading and conversion |
| `mdoc` | mdoc parsing (CBOR) and COSE_Sign1 verification |
| `mock` | Test credential generators |
| `oid4vc` | OID4VP and OID4VCI request and offer parsing |
| `output` | Terminal output formatting |
| `proxy` | Reverse proxy, traffic classifier, dashboard |
| `qr` | QR scanning from file or screen |
| `remote` | Remote wallet control (REST client, instance discovery) |
| `sdjwt` | SD-JWT parsing, disclosure resolution, verification |
| `statuslist` | Token Status List encoding and decoding, in JWT and CWT form |
| `trustlist` | ETSI TS 119 602 trust list parsing |
| `validate` | Orchestrates verification (signature, expiry, revocation) |
| `wallet` | Wallet state, HTTP server, OID4VP and OID4VCI protocol logic |
| `web` | Decoder and validator web UI |

## Flows

**Decode and validate.** Input arrives from a file, URL, stdin or a QR scan. Format detection picks the parser. The parser produces a token or document. The result is printed or carried into verification (signature, validity period, revocation).

**Presentation (OID4VP).** An authorization request arrives as a URI, an HTTP request to the wallet, or a browser API call. Its parameters may be inside a request object, fetched by reference and possibly encrypted. A request object replaces the parameter set, so the wallet acts on what the verifier signed. The wallet validates the request (client identifier, request object, signature, required parameters) and handles findings according to the active validation mode (ADR-0001). With `--haip` it also checks the request against HAIP, and those violations are errors in either mode. It then matches the request against held credentials with DCQL. The wallet answers a request for a type with a credential of that type or of one extending it. The user consents or the wallet auto-accepts. The wallet builds a VP token (SD-JWT with a key binding JWT, or an mdoc DeviceResponse) and sends it to the verifier, encrypted when the response mode asks for it.

**Issuance (OID4VCI).** A credential offer arrives by URI or by reference. The wallet fetches issuer metadata and authorization server metadata. It then runs the pre-authorized code flow or the authorization code flow (PAR, PKCE, DPoP and client attestation as the issuer's metadata requires). At OpenID4VCI feature level 1.1, the wallet runs the interactive flow instead when the issuer publishes an authorization challenge endpoint. The wallet answers the challenge with an OpenID4VP presentation or sends the user to a browser sign-in (`auth_via_web`) and exchanges the resulting code as usual. It proves possession of its holder key, receives the credential, and imports it. An issuer that defers returns a transaction id, and the wallet collects the credential in the background.

**Proxy.** The wallet connects to a verifier or issuer through the proxy. The proxy classifies each exchange as an OID4VP or OID4VCI step and shows it on a dashboard.

## Decisions

| ADR | Decision |
|---|---|
| [0001](docs/adr/0001-debug-by-default-validation-with-opt-in-strict-mode.md) | Debug-by-default validation with an opt-in strict mode |
| [0002](docs/adr/0002-the-wallet-http-api-is-unauthenticated.md) | The wallet HTTP API is unauthenticated |
| [0003](docs/adr/0003-keys-and-credentials-are-stored-unencrypted.md) | Keys and credentials are stored unencrypted |
| [0004](docs/adr/0004-outbound-fetches-are-policed-at-dial-time.md) | Outbound fetches are policed at dial time |
| [0005](docs/adr/0005-the-server-reloads-its-store-on-every-request.md) | The server reloads its store on every request |
| [0006](docs/adr/0006-one-binary-plays-wallet-issuer-verifier-and-ca.md) | One binary plays wallet, issuer, verifier and CA |
| [0007](docs/adr/0007-everything-lives-under-internal.md) | Everything lives under `internal/` |
| [0008](docs/adr/0008-jws-verification-uses-go-jose-jwe-stays-hand-written.md) | JWS verification uses go-jose, JWE stays hand-written |
| [0009](docs/adr/0009-signatures-are-verified-but-not-anchored-to-a-pre-registered-trust-list.md) | Signatures are verified but not anchored to a pre-registered trust list |
| [0010](docs/adr/0010-spec-conformance-is-checked-before-and-after-every-change.md) | Spec conformance is checked before and after every change |
| [0011](docs/adr/0011-a-flow-belongs-to-the-browser-that-started-it.md) | A flow belongs to the browser that started it |
| [0012](docs/adr/0012-every-entry-point-runs-the-same-flow.md) | Every entry point runs the same flow |
| [0013](docs/adr/0013-only-the-eudi-stack-is-supported.md) | Only what the EUDI stack references is supported |
| [0014](docs/adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md) | Pinned draft versions stay supported alongside the latest |
| [0015](docs/adr/0015-the-web-ui-lays-out-at-phone-width.md) | The web UI lays out at phone width |

## Related

- [CONTEXT.md](CONTEXT.md) glossary
- [docs/spec-compliance.md](docs/spec-compliance.md) feature-by-feature status against the specifications
- [SECURITY.md](SECURITY.md) scope and threat model
