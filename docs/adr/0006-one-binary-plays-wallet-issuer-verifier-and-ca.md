# One binary plays wallet, issuer, verifier and CA

`wallet serve` also runs a demo issuer at `/issuer` and verifier at `/verifier` (`internal/demorp`). It signs credentials, serves issuer metadata and status lists, publishes trusted lists and acts as a CA. This gives developers a complete local flow without configuring another service. External wallets, issuers and verifiers can use the same endpoints.

The verifier follows HAIP 1.0. It serves signed request objects by reference and derives its `x509_hash:` client ID from its signing certificate. It requests `direct_post.jwt` responses with a fresh encryption key for each request. It checks credential signatures, key binding JWTs and status lists.

## Consequences

The built-in issuer and verifier share a CA. A successful exchange between them tests the local flow. Use an external issuer or verifier to test interoperability.

The demo issuer and verifier keep their state in memory. Offers and verification requests expire after ten minutes, and each verification request accepts one response. Restarting clears that state. Wallet state uses the selected storage backend and survives restarts with files or Postgres.
