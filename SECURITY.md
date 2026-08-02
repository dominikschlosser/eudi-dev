# Security

## Scope

`oid4vc-dev` is a **development and testing tool**. It is not intended for production use with real credentials or real identity data.

## Key Considerations

- **Plaintext storage** — Wallet credentials and private keys are stored unencrypted on disk (`~/.eudi-dev/wallet/`). Do not store real credentials.
- **Ephemeral CA keys** — The wallet's CA key and certificate chain are regenerated on each startup. They are not persisted and provide no long-term trust.
- **Unauthenticated HTTP** — The wallet server, web UI, and proxy expose unauthenticated HTTP endpoints. Never expose them to untrusted networks.
- **Proxy captures all traffic** — The reverse proxy logs and displays all request/response data, including tokens and credentials, on its dashboard.
- **No DID resolution** — DID-based `client_id` values are parsed but not resolved against any DID registry.
- **No revocation enforcement** — Status list checks are informational; the wallet does not refuse revoked credentials.

## Reporting

If you find a security issue, please open an issue at [github.com/dominikschlosser/eudi-dev/issues](https://github.com/dominikschlosser/eudi-dev/issues).
