# Only what the EUDI stack references is supported

The specifications this toolkit implements are the ones the EUDI Architecture and Reference Framework builds on: OpenID4VP 1.0, OpenID4VCI 1.0, HAIP 1.0, SD-JWT and SD-JWT VC, ISO 18013-5, ETSI TS 119 602, and the Token Status List draft. `docs/spec-compliance.md` lists them and says what is implemented from each.

Everything outside that set is unsupported, and unsupported means one thing here: the mechanism is never implemented and never relied on. At most the toolkit recognises it and says so.

## Why recognising is not supporting

A wallet that quietly does nothing about a mechanism it does not implement produces the most expensive kind of green light. The counterparty is told the request went through; the developer reading the run sees no finding; the mechanism that was supposed to establish something established nothing. That is worse than a refusal, because a refusal is legible.

So the rule has two halves, and both matter:

- **Never used.** No key is resolved, no trust decision is made, and no signature is treated as verified through a route the EUDI stack does not reference. Implementing one would be inventing a trust model that no EUDI deployment is going to hold anyone to.
- **Always named.** When such a mechanism turns up in a counterparty's request, credential, or token, the run says which one it was and what it means, rather than reporting the resulting absence as a fetch that went wrong or a field that happened to be missing.

## What this looks like in the code

`openid_federation:` as a Client Identifier Prefix is refused with "not supported by this wallet", because OID4VP 1.0 §5.9.3 defers its processing rules to OpenID Federation, and "accepting it without resolving the trust chain would assert a verification that never happened" (`internal/wallet/clientid.go`).

A key named by a DID is reported as one nothing here resolves, in the credential import warning, in the HAIP findings, in the skipped-signature note of `validate`, and in the failure of a status list check (`keys.DIDReference`). An issuer key is resolved through the `x5c` chain HAIP 1.0 §6.1.1 requires or the issuer metadata SD-JWT VC defines. `did:key` carries its key in the identifier and could be decoded in a few lines, which is exactly why the boundary has to be a decision rather than an accident of effort.

The Status List Token check accepts ES256 and ES384 only, "a status list token is spec-constrained, and widening it here would quietly start accepting lists this check refuses" (`internal/statuslist/checker.go`).

## What this does not mean

It does not mean refusing to talk to a counterparty that deviates. Debug mode exists to run the flow anyway and collect every finding ([ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md)), because the thing under test is the issuer or the verifier, and a wallet that hangs up at the first deviation reports nothing about it. A profile deviation this toolkit can still process (a `direct_post` response mode where HAIP asks for `direct_post.jwt`, a credential format outside the profile) is a finding plus a completed flow. The rule here is about mechanisms the toolkit would have to implement to make a *positive* statement: those are declined, and the decline is visible.

It is also not a claim that what is inside the set is anchored. Signatures are verified without being tied to a pre-registered trust list ([ADR-0009](0009-signatures-are-verified-but-not-anchored-to-a-pre-registered-trust-list.md)). Being in scope buys a check, not a trust decision.

## Consequences

Do not add support for a mechanism because a counterparty in the wild uses it. The question is whether the EUDI ARF or a specification it references defines it. If it does not, the change to make is a clearer finding, not an implementation. If the ARF later takes it up, this decision is what needs revisiting first, in the open, rather than being eroded one convenience at a time.

When such a mechanism is met, name it. A message that says a key is missing, when the truth is that the key was named in a way this toolkit does not follow, sends the reader looking for a network problem. `SECURITY.md` and `docs/spec-compliance.md` state the boundary; a finding or log line is where a developer actually meets it.

The silence is the failure mode to watch for, and it is subtle. A Request Object under a `decentralized_identifier:` or `verifier_attestation:` client identifier used to pass through `VerifyRequestObjectSignature` with no finding at all, on the reasoning that its key lives elsewhere and there was "nothing to check here". That is true and it is not an answer: the request read exactly like one whose signature had been verified. It now reports which key it would have needed and where that key lives, and so does a bare `client_id`, whose key would have been pre-registered with a wallet that registers nothing.
