# ARF checks are a separate profile

Strict mode covers OpenID4VP 1.0, OpenID4VCI 1.0 and HAIP 1.0. The ARF adds rules on how a relying party authenticates: an access certificate (RPA_03, RPA_04), a registration certificate (RPRC_02a, RPRC_17, RPRC_17a, RPRC_19) and the attributes it may ask for (RPRC_21). Most verifiers in tests do not follow them, and OpenID4VP makes `verifier_info` optional.

## `--arf`

`--arf` runs the ARF checks, like `--haip` runs the HAIP checks. It is separate from the validation mode, which decides what happens to a finding. Without `--arf` the wallet does not check the ARF rules. With `--arf`, debug mode reports the findings and strict mode refuses the request. The ARF lets the Wallet Provider decide whether to refuse (RPA_06a, RPRC_17, RPRC_21), and strict mode refuses. If the wallet can't read a registration certificate's status list, that is a finding too, because it can't tell whether the certificate is revoked (ARF §6.6.3.3).

`--demo` turns `--arf` on, with debug mode.

## Trust anchors

RPA_04 and RPRC_02a accept only the trust anchors of notified access certificate authorities and registrars. The ARF keeps separate trust lists for the two, and so does the wallet:

- Access certificates (RPA_04) must chain to the relying party access CA, the wallet CA (which signs the demo verifier's access certificate) or a CA from `--relying-party-ca`.
- Registration certificates (RPRC_02a) must chain to the wallet CA (which signs the registrar certificate) or a CA from `--relying-party-ca`.

The relying party access CA signs any visitor's CSR. If it also counted as a registrar, anyone could sign their own registration certificate. `--relying-party-ca` adds to both lists, because one organization often runs both roles and a test setup then needs one file. This is the only place where the wallet uses configured trust anchors. Without `--arf`, [ADR 0009](0009-signatures-are-verified-but-not-anchored-to-a-pre-registered-trust-list.md) applies.

## Consequences

A wallet with `--arf` and `--mode strict` refuses a verifier that has no registration certificate, signs with an unknown access certificate, asks for more than it registered or uses a revoked registration certificate. Conformance runs use strict mode without `--arf`.
