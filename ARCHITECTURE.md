# Architecture

Where things live and how a request moves through them. Why things are the way they are is in the [decision records](#decisions).

For the vocabulary these documents use (and the terms this project overloads), see [CONTEXT.md](CONTEXT.md).

## Layout

```
main.go        Entry point
cmd/           CLI commands (Cobra), one file per command or command group
internal/      Everything else (see ADR-0007 for why nothing is importable)
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
| `jws` | ES256 JWS signing and verification, shared so neither can drift (ADR-0008) |
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

Described in domain terms rather than function names, which go stale.

**Decode and validate.** Input arrives from a file, URL, stdin or a QR scan. Format detection picks the parser, the parser produces a token or document, and the result is either printed or carried into verification (signature, validity period, revocation).

**Presentation (OID4VP).** An authorization request arrives as a URI, an HTTP request to the wallet, or a browser API call. Its parameters may be inside a request object, which may itself be fetched by reference and encrypted. A request object replaces the parameter set rather than being merged into it, so what the verifier signed is what the wallet acts on. The request is validated (client identifier, request object, signature, required parameters) with the findings handled by the active validation mode (ADR-0001), optionally checked against HAIP, whose violations are errors either way, and then matched against held credentials with DCQL, where a requested type is answered by a credential of that type or of one extending it. The user consents or the wallet auto-accepts, a VP token is built (SD-JWT with a key binding JWT, or an mdoc DeviceResponse), and the response goes to the verifier, encrypted when the response mode asks for it.

**Issuance (OID4VCI).** A credential offer arrives by URI or by reference. The wallet fetches issuer metadata and authorization server metadata, then runs either the pre-authorized code flow or the authorization code flow (PAR, PKCE, DPoP and client attestation as the issuer's metadata demands). It proves possession of its holder key, receives the credential, and imports it. An issuer that defers hands back a transaction id, and collection continues in the background.

**Proxy.** The wallet talks to a verifier or issuer through the proxy, which classifies each exchange as an OID4VP or OID4VCI step and shows it on a dashboard.

## Decisions

| ADR | Decision |
|---|---|
| [0001](docs/adr/0001-debug-by-default-validation-with-opt-in-strict-mode.md) | Debug-by-default validation with an opt-in strict mode |
| [0002](docs/adr/0002-the-wallet-http-api-is-unauthenticated.md) | The wallet HTTP API is unauthenticated |
| [0003](docs/adr/0003-keys-and-credentials-are-stored-unencrypted.md) | Keys and credentials are stored unencrypted |
| [0004](docs/adr/0004-outbound-fetches-are-policed-at-dial-time.md) | Outbound fetches are policed at dial time, not at the URL |
| [0005](docs/adr/0005-the-server-reloads-its-store-on-every-request.md) | The server reloads its store on every request |
| [0006](docs/adr/0006-one-binary-plays-wallet-issuer-verifier-and-ca.md) | One binary plays wallet, issuer, verifier and CA |
| [0007](docs/adr/0007-everything-lives-under-internal.md) | Everything lives under `internal/` |
| [0008](docs/adr/0008-jws-verification-uses-go-jose-jwe-stays-hand-written.md) | JWS verification uses go-jose, JWE stays hand-written |
| [0009](docs/adr/0009-signatures-are-verified-but-not-anchored-to-a-pre-registered-trust-list.md) | Signatures are verified but not anchored to a pre-registered trust list |

## Related

- [CONTEXT.md](CONTEXT.md) glossary
- [docs/spec-compliance.md](docs/spec-compliance.md) feature-by-feature status against the specifications
- [SECURITY.md](SECURITY.md) what this tool does and does not protect
