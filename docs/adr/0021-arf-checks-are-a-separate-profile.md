# ARF checks are a separate profile

Strict mode covers OpenID4VP 1.0, OpenID4VCI 1.0 and HAIP 1.0. The ARF adds rules on how a relying party authenticates: an access certificate (RPA_03, RPA_04), a registration certificate (RPRC_02a, RPRC_17, RPRC_17a, RPRC_19) and the attributes it may ask for (RPRC_21). Issuers authenticate the same way before the wallet requests a credential: with an access certificate that signs their metadata (ISSU_24, ISSU_34) and a registration certificate in `issuer_info` that lists what they may issue (RPRC_22a, RPRC_22b, RPRC_23, ISSU_24a, ISSU_24b, ISSU_34a, ISSU_34b). Most verifiers and issuers in tests do not follow these rules. OpenID4VP makes `verifier_info` optional. OpenID4VCI makes signed metadata optional.

## `--arf`

`--arf` runs the ARF checks, like `--haip` runs the HAIP checks. It is separate from the validation mode, which decides what happens to a finding. Without `--arf` the wallet does not check the ARF rules. With `--arf`, debug mode reports the findings. Strict mode refuses a presentation request and doesn't request a credential from the issuer. The offer's consent dialog lists the findings about an issuer, because the ARF has the wallet warn the user. The ARF lets the Wallet Provider decide whether to refuse (RPA_06a, RPRC_17, RPRC_21), and strict mode refuses. If the wallet can't read a registration certificate's status list, that is a finding too, because it can't tell whether the certificate is revoked (ARF §6.6.3.3).

`--demo` turns `--arf` on, with debug mode.

## Trust anchors

Under RPA_04, ISSU_23, ISSU_33, RPRC_02a, ISSU_23c and ISSU_33a, the wallet trusts only notified access certificate authorities and registrars. The ARF keeps separate trust lists for the two, and so does the wallet:

- Access certificates (RPA_04, ISSU_24, ISSU_34) must chain to the relying party access CA, the wallet CA (which signs the demo verifier's access certificate) or a CA from `--relying-party-ca`.
- Registration certificates (RPRC_02a, ISSU_23c, ISSU_33a) must chain to the wallet CA (which signs the registrar certificate) or a CA from `--relying-party-ca`.

The relying party access CA signs any visitor's CSR. If it also counted as a registrar, anyone could sign their own registration certificate. `--relying-party-ca` adds to both lists, because one organization often runs both roles and a test setup then needs one file. This is the only place where the wallet uses configured trust anchors. Without `--arf`, [ADR 0009](0009-signatures-are-verified-but-not-anchored-to-a-pre-registered-trust-list.md) applies.

## Consequences

A wallet with `--arf` and `--mode strict` refuses a verifier that has no registration certificate, signs with an unknown access certificate, asks for more than it registered or uses a revoked registration certificate. It doesn't request a credential when the issuer metadata is unsigned. It also doesn't when the registration certificate is missing or revoked, or doesn't list the offered type. The ARF applies the registration certificate checks for issuers 24 months after the amended CIR 2024/2982 enters into force. Strict mode applies them now, because it tests the target state. Conformance runs use strict mode without `--arf`.
