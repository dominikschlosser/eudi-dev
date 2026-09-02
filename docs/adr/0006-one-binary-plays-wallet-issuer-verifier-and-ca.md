# One binary plays wallet, issuer, verifier and CA

`wallet serve` runs more than a wallet. The same process runs a demo issuer at `/issuer` and a demo verifier at `/verifier` (`internal/demorp`), signs credentials with its own issuer key, serves issuer metadata and a status list, publishes a trust list and acts as its own CA. Testing an OID4VC flow needs a counterparty, and requiring one to be stood up first would put a multi-service setup between the user and the first credential. Here the flow runs end to end from a single binary with no configuration, and the same endpoints double as real protocol counterparties for external wallets, issuers and verifiers pointed at the host.

The verifier follows HAIP 1.0 (signed request objects served by reference, an `x509_hash:` client id derived from its signing certificate, `direct_post.jwt` responses with a per-request key) and cryptographically verifies what it receives, down to the key binding JWT and the status list. Otherwise it would confirm that a flow completed without confirming it was correct.

## Consequences

The roles share a trust anchor, so a presentation verified by the built-in verifier proves less than one verified by a third party. The credential was signed by a CA the verifier already trusts because both are this process. When the question is interoperability rather than plumbing, test against something external.

Both demo counterparties keep their state in memory (offers and verification requests expire after ten minutes, each verification request accepts exactly one answer) while the wallet's own state is on disk. A restart therefore clears one and not the other.
