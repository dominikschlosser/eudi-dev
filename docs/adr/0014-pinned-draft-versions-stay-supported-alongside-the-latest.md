# Pinned draft versions stay supported alongside the latest

The EUDI Architecture and Reference Framework is the root of this toolkit's specification graph ([ADR-0013](0013-only-the-eudi-stack-is-supported.md)). Every specification version is inferred from there. The ARF references OpenID4VCI and HAIP, and those pin draft versions of their own dependencies. This decision is about what happens when such a pinned draft falls behind the latest one: both stay supported.

The concrete case is OAuth 2.0 Attestation-Based Client Authentication. OpenID4VCI 1.0 pins draft-07, and its §14.7 says implementations should keep using the pinned versions in preference to later ones. The OpenID4VCI 1.1 editor draft pins draft-08, which removed the `iss` claim from both the Client Attestation JWT and its PoP. The latest published draft is -10, which added the `attest_jwt_client_auth_dpop` method, the proof of possession methods registry, and the `client_attestation_pop_methods_supported` metadata parameter. Real counterparties implement what OpenID4VCI pins, not what the IETF last published, so dropping a pinned draft breaks exactly the ecosystem the ARF describes. Supporting only the pinned drafts would be just as wrong: the latest draft is where the specification is going, and a development toolkit that cannot speak it reports nothing about it.

## The rule

- **Outgoing messages are version-exact.** The configured OpenID4VCI version maps to the ABCA draft it pins (`--vci-version 1.0` maps to draft-07, `1.1` to draft-08), and outgoing attestations and PoPs carry exactly that draft's claims. There is no separate version knob and no union shape that mixes drafts.
- **Incoming verification is tolerant across the supported set.** Material that violates the pinned draft while being correct under another supported draft is accepted, with a warning in the log naming both drafts. Material invalid under every supported draft is rejected.
- **Latest-only features are negotiated through metadata.** A server that offers only `attest_jwt_client_auth_dpop` or `dpop_combined` gets the combined proof, with a warning that the configured draft predates the mechanism. Additive metadata from the latest draft may always be published, because older clients ignore unknown parameters.

## Consequences

When a referenced specification publishes a new draft, the supported set is re-derived from the ARF chain and a conformance audit runs before new behavior is adopted ([ADR-0010](0010-spec-conformance-is-checked-before-and-after-every-change.md)). A shape difference between supported drafts becomes a mapping on the OpenID4VCI version (the way `VCIVersion.ABCADraft` does it), never a fork of the flow. The tolerant acceptance is what keeps a draft-08 wallet usable against this issuer configured for draft-07, and the warning is what keeps the difference visible instead of silently absorbed.
