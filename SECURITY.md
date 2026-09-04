# Security

## Scope

`eudi-dev` is a development and testing tool. Never use it with real credentials or real identity data.

## Key Considerations

- **Plaintext storage**: Wallet credentials and private keys are stored unencrypted on disk (`~/.eudi-dev/wallet/`). Do not store real credentials.
- **Test CA on disk**: The wallet's CA key is stored unprotected at `~/.eudi-dev/wallet-ca-key.pem` and shared by every wallet under the same base directory, so trust lists stay stable across restarts. Anyone who can read that file can issue credentials your verifiers will accept.
- **Unauthenticated HTTP**: The wallet server, web UI, and proxy expose unauthenticated HTTP endpoints. Anyone who can reach the port controls the wallet, so keep them on localhost or an isolated network. The only supported exception is the `--demo` profile for a public demo. It disables the process and filesystem endpoints, blocks server-side fetches into private networks, and resets state periodically. Everything in such a wallet is public and disposable (see [docs/public-demo.md](docs/public-demo.md)).
- **Browser pages reach localhost**: Every page a developer visits can send requests to localhost. The `/api/` endpoints therefore refuse a request carrying an `Origin` from another site. A CLI, a curl invocation, or a test harness sends no `Origin` and is unaffected. The protocol endpoints (`/authorize`, `/credential-offer`, `/callback`) are reached by browser navigation and stay open.
- **Proxy captures all traffic**: The reverse proxy logs and shows every request and response on its dashboard, tokens and credentials included.
- **Only the EUDI stack is supported**: Mechanisms the EUDI ARF and the specifications it references do not define are recognised and reported, never used to establish trust ([ADR-0013](docs/adr/0013-only-the-eudi-stack-is-supported.md)). DID-based `client_id` values are parsed without resolution, an issuer or Status Issuer key named by a DID is reported, and an `openid_federation:` client identifier is refused.
- **No pre-registered verifier or issuer trust**: A signed request object's `x5c` chain and signed Credential Issuer Metadata are checked for a valid signature and a consistent chain. They are not anchored to a pre-registered CA or trust list, because a test wallet cannot know those CAs in advance. An attacker who signs with their own certificate and sets the matching `x509_hash` or `sub` passes these checks. A valid signature proves only that the object is well-formed and self-consistent.
- **Key attestations claim what they are asked to claim**: The wallet issues its own key attestations (OpenID4VCI Appendix D). By default it states the `key_storage` and `user_authentication` levels the issuer requires, `iso_18045_high` included. Its keys are plain files, so no level is true. This lets you test issuers that require a level. `--key-attestation-level none` claims nothing, `--key-attestation-level <level>` claims that level for both, and the Conformance panel changes it at runtime on a local wallet. Every attestation carrying a claim is marked in the activity log.
- **No revocation enforcement in the wallet**: The wallet presents credentials regardless of their status list entry. Status checks in the UI and CLI are informational. The built-in demo verifier resolves the status list and rejects revoked credentials.

## Reporting

Report security issues at [github.com/dominikschlosser/eudi-dev/issues](https://github.com/dominikschlosser/eudi-dev/issues).
