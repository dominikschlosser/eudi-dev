# Signatures are verified but not anchored to a pre-registered trust list

When a verifier sends a signed request object, the wallet verifies the JWS against the leaf certificate in the `x5c` header and checks that the supplied chain is internally consistent. When an issuer serves signed Credential Issuer Metadata, the wallet verifies the signature over its `x5c` leaf and checks `typ`, `alg` and a `sub` matching the issuer identifier. In both cases the wallet stops there. It has no pre-registered certificate the chain could be required to terminate in.

## Why there is nothing to anchor to

Anchoring a request object or issuer metadata to a trust list means the wallet was provisioned, ahead of time, with the CA the real verifier or issuer registered under. A development and testing tool has no such provisioning. No registrar hands this wallet a list of production verifier CAs, and a fake one would only move the trust decision into test fixtures. So the wallet treats a well-formed, self-consistent signature as the most it can assert.

`verifySuppliedX5CChain` builds a root pool from the top certificate of the supplied chain and verifies the leaf against that. This proves the chain is consistent. It says nothing about who issued its root. `verifyIssuerMetadataChainTrust` logs "signed but unplaced" when it cannot anchor the signer, so the gap is visible.

Threat model: an attacker who signs a request object (or issuer metadata) with a certificate they generated, and sets the matching `x509_hash` or `sub`, passes every check the wallet runs. A passing signature check means "well-formed and self-consistent".

## What is still enforced

A request object for a signing-required `client_id` prefix must be signed (an `alg` of `none` is a finding, fatal in strict mode). The `x509_hash` value must be the SHA-256 of the certificate that signed the request. Under HAIP the signing certificate must not be self-signed, and the trust anchor must not be in the `x5c` header. None of these need a pre-registered CA. The wallet never decides that an unknown CA is trustworthy.

## Consequences

Request object and issuer metadata verification use no configured CA or trust list.

Docs, validation findings and log lines describe a signature check by what it proves: the request or the metadata is signed and self-consistent. They never call it an authentication or anti-impersonation boundary. `SECURITY.md` states this under "No pre-registered verifier or issuer trust", and the OID4VP JAR row and the signed-issuer-metadata row in `docs/spec-compliance.md` carry the same caveat. Strict mode ([ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md)) makes findings fatal, and a finding is only raised for something the wallet can check.
