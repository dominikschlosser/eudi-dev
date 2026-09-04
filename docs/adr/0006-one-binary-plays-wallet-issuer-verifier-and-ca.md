# One binary plays wallet, issuer, verifier and CA

`wallet serve` runs more than a wallet. The same process runs a demo issuer at `/issuer` and a demo verifier at `/verifier` (`internal/demorp`), signs credentials with its own issuer key, serves issuer metadata and a status list, publishes a trust list and acts as its own CA. Testing an OID4VC flow needs a counterparty. Here the flow runs end to end from a single binary with no configuration, and the same endpoints serve as real protocol counterparties for external wallets, issuers and verifiers pointed at the host.

The verifier follows HAIP 1.0 (signed request objects served by reference, an `x509_hash:` client id derived from its signing certificate, `direct_post.jwt` responses with a per-request key). It cryptographically verifies what it receives, down to the key binding JWT and the status list, so a completed flow is also a correct one.

## Consequences

The roles share a trust anchor. The built-in verifier trusts the CA that signed the credential because both live in this process, so a presentation it verifies proves less than one verified by a third party. For interoperability questions, test against something external.

Both demo counterparties keep their state in memory (offers and verification requests expire after ten minutes, each verification request accepts exactly one answer). The wallet's own state is on disk. A restart clears the demo state and keeps the wallet.
