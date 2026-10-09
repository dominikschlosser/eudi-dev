# Validate

Check a credential's signature, expiry and revocation status. Use `decode` to inspect its contents.

Signature keys are resolved in this order:

1. The credential's x5c (SD-JWT/JWT) or x5chain (mdoc) certificate chain, validated against `--trust-list` when given
2. An explicitly provided `--key`
3. The embedded leaf certificate alone, when no trusted list is given. This works offline. The output notes that the chain was not validated
4. JWT VC Issuer Metadata, for credentials without an embedded certificate

SD-JWT VC §3 inserts `/.well-known/jwt-vc-issuer` between the host and path of `iss`. For example, `https://example.com/tenant/1234` resolves to `https://example.com/.well-known/jwt-vc-issuer/tenant/1234`. The metadata's `issuer` must equal `iss`, and its keys must come from either `jwks` or `jwks_uri`.

A credential with its certificate chain validates without network access. For credentials without keys or certificates, only expiry and status are checked.

```bash
# Full validation with signature verification
eudi validate --key issuer-key.pem credential.txt
eudi validate --trust-list trust-list.jwt credential.txt
eudi validate --key key.pem --allow-expired credential.txt
eudi validate --haip credential.txt

# Expiry + revocation check without signature verification
eudi validate credential.txt
```

## Flags

| Flag              | Description                                       |
|-------------------|---------------------------------------------------|
| `--key`           | Public key file (PEM or JWK), optional            |
| `--trust-list`    | ETSI trusted list JWT (file path or URL), optional   |
| `--status-list`   | Check revocation via status list when the credential contains a status reference (enabled by default) |
| `--allow-expired` | Accept expired credentials                         |
| `--haip` | Also check the credential against HAIP 1.0 and report violations |

## Revocation status

When a credential carries a status reference, `validate` fetches the Status List Token and reads the entry. It accepts both `application/statuslist+jwt` and `application/statuslist+cwt`.

The token's signature is always verified. If the check cannot complete, validation fails with an error. The signing key is trusted through `--trust-list` when the token's certificate chain ends in one of its CAs. Otherwise the key comes from the token itself (`x5c` / `x5chain`, or a header `jwk`) and the output notes that the key is unanchored. The token's `sub` must equal the `uri` in the credential's status claim. `typ`, `iat` and `exp` are checked too.

The status is reported by name (VALID, INVALID, SUSPENDED, an application specific value, or unknown) with the raw value. For multi-bit lists, the full value is reported.

## Certificate chain validation

When a trusted list is given and the credential contains an x5c (SD-JWT/JWT) or x5chain (mdoc) chain, the chain is validated against the trusted list before the signature is verified:

1. The trusted list contains **CA certificates** (trust anchors)
2. The credential's x5c/x5chain contains `[leaf, ...intermediates]`
3. The leaf certificate is verified to chain up to a trusted list CA via any intermediates
4. The leaf certificate's public key is used to verify the credential signature

Wallet-issued SD-JWT credentials follow the same model. The header contains a deterministic `kid` and an `x5c` chain with the leaf and any intermediate certificates (without the root). The wallet trusted list publishes signing certificates and their provider CAs. The wallet also publishes JWT VC issuer metadata at `/.well-known/jwt-vc-issuer`.

The web decoder (`eudi serve` and the wallet's embedded decoder) also uses the local wallet's CA as an implicit trust anchor when no key or trusted list is given. Credentials issued by the local wallet then show a verified chain.

## Catalogue trust

When the wallet's attestation catalogue has an entry for the credential type, `validate` and the web decoder also check whether one of the entry's trusted lists anchors the credential. They read the lists the entry links. For a PID or a PuB-EAA they also read the lists of that type on the wallet's list of trusted lists, as the wallet does on issuance. The decoder shows the result as the `trust` check. `validate` prints it and adds `trust` to `--json`. The exit code doesn't depend on it. A type without a catalogue entry gets no trust check.

`validate` and the decoder of `eudi serve` read the stored wallet. The lists from `wallet serve --trusted-list` and the operators from `--trust-list-ca` count only in the decoder of the running wallet.

Trusted list validation covers certificate trust and service listing. Provider class and attestation-type entitlement come from signed Credential Issuer metadata (`/.well-known/openid-credential-issuer`, `issuer_info`) and registrar data. A wallet keeps one trusted list per credential category. `/api/trustlist` serves the PID list and `/api/trustlists` lists every list. In containers, use the index entry's relative `path` instead of its advertised URL.

To let a verifier trust the wallet's local HTTPS endpoints, export the wallet CA with `eudi wallet ca-cert --out wallet-ca-cert.pem` and add it to the verifier trust store. `wallet tls-cert` exports the per-wallet HTTPS leaf certificate as a single PEM instead.

```bash
# Validate a wallet-issued credential against the wallet's trust list
eudi validate --trust-list http://localhost:8085/api/trustlist credential.txt

# Validate against the German PID provider trust list
eudi validate --trust-list https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt credential.txt
```

## HAIP 1.0

`--haip` adds the [High Assurance Interoperability Profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html) rules to the format's own checks. Section 6.1.1 requires an SD-JWT VC to carry its issuer's signing certificate and chain in the `x5c` header, without the trust anchor, and forbids a self-signed signing certificate. HAIP sets no such rule for an mdoc, so `--haip` adds nothing to its checks.

Findings are printed. The exit code depends only on the credential's own validity (signature, expiry, revocation).

## JSON output

`--json` prints one JSON document. It holds the decoded credential, the signature check under `verification`, the status list check under `status` and the HAIP findings under `haipFindings`. A check that didn't run is left out. With `--haip`, `haipFindings` is an empty list when there are no findings.
