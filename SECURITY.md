# Security

## Scope

`eudi-dev` is a **development and testing tool**. It is not intended for production use with real credentials or real identity data.

## Key Considerations

- **Plaintext storage**: Wallet credentials and private keys are stored unencrypted on disk (`~/.eudi-dev/wallet/`). Do not store real credentials.
- **Test CA on disk**: The wallet's CA key is persisted (`~/.eudi-dev/wallet-ca-key.pem`) and shared by every wallet under the same base directory, so trust lists stay stable across restarts. It is an unprotected test trust anchor: anyone who can read that file can issue credentials your verifiers will accept.
- **Unauthenticated HTTP**: The wallet server, web UI, and proxy expose unauthenticated HTTP endpoints. Anyone who can reach the port controls the wallet, so keep them on localhost or an isolated network. The one supported exception is the `--demo` profile for a public demo: it disables the process and filesystem endpoints, blocks server-side fetches into private networks, and resets state periodically. Everything in such a wallet is public and disposable by design (see [docs/public-demo.md](docs/public-demo.md)).
- **Localhost is not a boundary against the browser**: every page a developer visits can send requests to localhost, so "keep it local" does not by itself keep a web page out. The `/api/` endpoints therefore refuse a request carrying an `Origin` from another site. A CLI, a curl invocation, or a test harness sends no `Origin` and is unaffected. The protocol endpoints (`/authorize`, `/credential-offer`, `/callback`) are reached by browser navigation and stay open, which is what they are for.
- **Proxy captures all traffic**: The reverse proxy logs and displays all request/response data, including tokens and credentials, on its dashboard.
- **No DID resolution**: DID-based `client_id` values are parsed but not resolved against any DID registry.
- **No pre-registered verifier or issuer trust**: A signed request object's `x5c` chain and signed Credential Issuer Metadata are checked for a valid signature and a consistent chain, but not anchored to a pre-registered CA or trust list. A test wallet cannot know those CAs in advance. An attacker who signs with their own certificate and sets the matching `x509_hash` or `sub` passes these checks. A green signature means well-formed and self-consistent, not from a trusted party.
- **No revocation enforcement in the wallet**: The wallet presents credentials regardless of their status list entry. Status checks in the UI and CLI are informational. The built-in demo verifier does resolve the status list and rejects revoked credentials.

## Reporting

If you find a security issue, please open an issue at [github.com/dominikschlosser/eudi-dev/issues](https://github.com/dominikschlosser/eudi-dev/issues).
