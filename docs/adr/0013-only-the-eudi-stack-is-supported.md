# Only what the EUDI stack references is supported

The specifications this toolkit implements are the ones the EUDI Architecture and Reference Framework builds on: OpenID4VP 1.0, OpenID4VCI 1.0, HAIP 1.0, SD-JWT and SD-JWT VC, ISO 18013-5, ETSI TS 119 602, and the Token Status List draft. `docs/spec-compliance.md` lists them and says what is implemented from each.

Everything outside that set is unsupported. Unsupported means the mechanism is never implemented and never relied on. At most the toolkit recognises it and says so.

## Why recognising is not supporting

A wallet that ignores a mechanism it does not implement reports a success it cannot back up. The counterparty is told the request went through, the developer reading the run sees no finding, and the mechanism that was supposed to establish something established nothing.

The rule has two halves:

- **Never used.** No key is resolved, no trust decision is made, and no signature is treated as verified through a route the EUDI stack does not reference. Implementing one would invent a trust model no EUDI deployment uses.
- **Always named.** When such a mechanism turns up in a counterparty's request, credential, or token, the run says which one it was and what it means, instead of reporting a failed fetch or a missing field.

## What this looks like in the code

`openid_federation:` as a Client Identifier Prefix is refused with "not supported by this wallet". OID4VP 1.0 §5.9.3 defers its processing rules to OpenID Federation, and the wallet resolves no trust chain (`internal/wallet/clientid.go`).

A key named by a DID is reported as unresolved: in the credential import warning, in the HAIP findings, in the skipped-signature note of `validate`, and in the failure of a status list check (`keys.DIDReference`). An issuer key is resolved through the `x5c` chain HAIP 1.0 §6.1.1 requires or the issuer metadata SD-JWT VC defines. `did:key` carries its key in the identifier and could be decoded in a few lines. It is left out on purpose.

The Status List Token check accepts ES256 and ES384 only (`internal/statuslist/checker.go`).

## Deviations are still processed

The toolkit still talks to a counterparty that deviates. Debug mode runs the flow anyway and collects every finding ([ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md)), because the thing under test is the issuer or the verifier. A profile deviation this toolkit can still process (a `direct_post` response mode where HAIP asks for `direct_post.jwt`, a credential format outside the profile) is a finding plus a completed flow. The rule applies to mechanisms the toolkit would have to implement before it could report anything about them. Those are refused, and the refusal is visible.

Support means the mechanism is checked. It does not mean the result is trusted: signatures are verified without being tied to a pre-registered trust list ([ADR-0009](0009-signatures-are-verified-but-not-anchored-to-a-pre-registered-trust-list.md)).

## Consequences

Support for a mechanism is added only when the EUDI ARF or a specification it references defines it. A counterparty using it is not enough. If the ARF does not define it, the right change is a clearer finding. If the ARF later adopts it, revisit this decision first.

When such a mechanism is encountered, name it. A message that says a key is missing, when the key was named in a way this toolkit does not follow, makes the reader look for a network problem. `SECURITY.md` and `docs/spec-compliance.md` state the boundary. A developer sees it in a finding or a log line.

A Request Object under a `decentralized_identifier:` or `verifier_attestation:` client identifier has its key in a place this wallet does not resolve. A request passed with no finding would look verified. So `VerifyRequestObjectSignature` reports which key it would have needed and where it would come from. It does the same for a bare `client_id`, whose key would have to be pre-registered, and this wallet registers nothing.
