# Signatures are verified but not anchored to a pre-registered trust list

When a verifier sends a signed request object, the wallet verifies the JWS against the leaf certificate carried in the `x5c` header and checks that the supplied chain is internally consistent. When an issuer serves signed Credential Issuer Metadata, the wallet verifies the signature over its `x5c` leaf and checks `typ`, `alg` and a `sub` matching the issuer identifier. In both cases the wallet stops there: it does not require the chain to terminate in a certificate it already trusts, because it has no such certificate.

This is the deliberate boundary, and it is the same boundary on both the verifier side and the issuer side.

## Why there is nothing to anchor to

Anchoring a request object or issuer metadata to a trust list means the wallet was provisioned, ahead of time, with the CA that the real verifier or issuer registered under. That provisioning is exactly what a development and testing tool cannot have. There is no registrar handing this wallet a list of production verifier CAs, and standing up a fake one would only move the trust decision into test fixtures without making it mean anything. So the wallet treats a well-formed, self-consistent signature as the most it can honestly assert.

`verifySuppliedX5CChain` reflects this: it builds a root pool from the top certificate of the *supplied* chain and verifies the leaf against that, which proves the chain hangs together but not that anyone vouched for its root. `verifyIssuerMetadataChainTrust` goes a step further and logs "signed but unplaced" rather than failing when it cannot anchor the signer, so a developer sees the gap instead of a green light that lies about it.

The consequence for the threat model is blunt: an attacker who signs a request object (or issuer metadata) with a certificate they generated, and sets the matching `x509_hash` or `sub`, passes every check the wallet runs. A green request-object or issuer-metadata signature means "well-formed and self-consistent", not "from a party this wallet trusts".

## What is still enforced

Not anchoring is not the same as not checking. The wallet still requires that a request object for a signing-required `client_id` prefix actually be signed (an `alg` of `none` is a finding, fatal in strict mode), that the `x509_hash` value be the SHA-256 of the certificate that signed the request, that the signing certificate not be self-signed under HAIP, and that the trust anchor not travel in the `x5c` header. None of those need a pre-registered CA, so the wallet does them; the one thing it will not pretend to do is decide that an unknown CA is trustworthy.

## Consequences

Do not "fix" this by wiring request-object or issuer-metadata verification to a configured CA or trust list. It is intentional, and the same reasoning that keeps the wallet from encrypting real data (ADR-0003) keeps it from asserting a trust decision it is not in a position to make.

When describing a signature check, in docs, in a validation finding, or in a log line, do not frame it as an authentication or anti-impersonation boundary. Say what it proves: the request or the metadata is signed and self-consistent. `SECURITY.md` states this under "No pre-registered verifier or issuer trust", and the OID4VP JAR row and the signed-issuer-metadata row in `docs/spec-compliance.md` carry the same caveat. This decision sits alongside the debug-by-default validation of [ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md): strict mode makes findings fatal, but a finding can only be raised about something the wallet is able to check.
