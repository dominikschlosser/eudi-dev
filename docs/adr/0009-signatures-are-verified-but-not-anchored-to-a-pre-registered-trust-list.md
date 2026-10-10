# Signature checks have no configured trust anchors

When a verifier sends a signed request object, the wallet verifies the JWS against the leaf certificate in the `x5c` header and checks that the supplied chain is internally consistent. When an issuer serves signed Credential Issuer Metadata, the wallet verifies the signature against the leaf certificate in its `x5c` header and checks `typ`, `alg` and a `sub` matching the issuer identifier. The wallet has no configured trust anchors for either check.

## Trust anchors

Without `--arf`, this test wallet has no configured verifier or issuer CAs. It checks signature validity and chain consistency. Trusting the root certificate would need a configured anchor. `--arf` adds anchors from trusted lists for access certificates, registration certificates and received credentials ([ADR 0021](0021-arf-checks-are-a-separate-profile.md), [ADR 0023](0023-trust-anchors-come-from-trusted-lists.md)).

`verifySuppliedX5CChain` builds a root pool from the top certificate of the supplied chain and verifies the leaf against that. This proves the chain is consistent. It does not show who issued the root. `verifyIssuerMetadataChainTrust` logs "signed but unplaced" when it cannot anchor the signer.

An attacker can generate a certificate, sign a request object or issuer metadata, and supply a matching `x509_hash` or `sub`. The signature and chain checks will pass.

## Request validation

A request object for a signing-required `client_id` prefix must be signed (an `alg` of `none` is a finding, fatal in strict mode). The `x509_hash` value must be the SHA-256 of the certificate that signed the request. Under HAIP the signing certificate must not be self-signed, and the trust anchor must not be in the `x5c` header. All of these checks compare the request with the supplied certificate.

## Consequences

Documentation and findings call these results signature and chain-consistency checks. They do not prove who the signer is. `SECURITY.md` and `docs/spec-compliance.md` state this limit. Strict mode ([ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md)) makes a finding fatal only when the wallet can perform the check.
