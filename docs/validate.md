# Validate

Check a credential's signature, expiry, and revocation status. `decode` parses and displays, `validate` checks.

Signature keys are resolved in this order:

1. The credential's x5c (SD-JWT/JWT) or x5chain (mDOC) certificate chain, validated against `--trust-list` when given
2. An explicitly provided `--key`
3. The embedded leaf certificate alone, when no trust list is given. This works offline. The output notes that the chain was not validated
4. JWT VC Issuer Metadata, for credentials without an embedded certificate. SD-JWT VC §3 puts `/.well-known/jwt-vc-issuer` between the host and the path of `iss`, so `https://example.com/tenant/1234` is read from `https://example.com/.well-known/jwt-vc-issuer/tenant/1234`. The document's `issuer` must equal `iss`, and the keys come from `jwks` or `jwks_uri` (never both)

A credential with its certificate chain validates without network access. Credentials without keys or certificates get expiry and status checks only.

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
| `--trust-list`    | ETSI trust list JWT (file path or URL), optional   |
| `--status-list`   | Check revocation via status list when the credential contains a status reference (enabled by default) |
| `--allow-expired` | Accept expired credentials                         |
| `--haip` | Also check the credential against HAIP 1.0 and report what it breaks |

## Revocation status

When a credential carries a status reference, `validate` fetches the Status List Token and reads the entry. It accepts both `application/statuslist+jwt` and `application/statuslist+cwt`.

The token's signature is always verified. A check that cannot complete is an error. The signing key is trusted through `--trust-list` when the token's certificate chain ends in one of its CAs. Otherwise the key comes from the token itself (`x5c` / `x5chain`, or a header `jwk`) and the result notes the key is unanchored. The token's `sub` must equal the `uri` in the credential's status claim. `typ`, `iat` and `exp` are checked too.

The status is reported by name (VALID, INVALID, SUSPENDED, an application specific value, or unknown) with the raw value. Multi-bit lists keep their full value.

## Certificate chain validation

When a trust list is given and the credential contains an x5c (SD-JWT/JWT) or x5chain (mDOC) chain, the chain is validated against the trust list before the signature is verified:

1. The trust list contains **CA certificates** (trust anchors)
2. The credential's x5c/x5chain contains `[leaf, ...intermediates]`
3. The leaf certificate is verified to chain up to a trust list CA via any intermediates
4. The leaf certificate's public key is used to verify the credential signature

Wallet-issued SD-JWT credentials follow the same model. The header carries a deterministic `kid` and the leaf certificate in `x5c`, and the wallet trust list carries the CA. The wallet also publishes JWT VC issuer metadata at `/.well-known/jwt-vc-issuer`.

The web decoder (`eudi serve` and the wallet's embedded decoder) also uses the local wallet's CA as an implicit trust anchor when no key or trust list is given. Credentials issued by the local wallet then show a verified chain.

Trust-list validation covers certificate trust and service listing. Provider class and attestation-type entitlement come from signed Credential Issuer metadata (`/.well-known/openid-credential-issuer`, `issuer_info`) and registrar data. When a wallet exposes several trust-list profiles, `/api/trustlist` serves the PID list and `/api/trustlists` lists every profile. In containers, use the index entry's relative `path` instead of its advertised URL.

To let a verifier trust the wallet's local HTTPS endpoints, export the wallet CA with `eudi wallet ca-cert --out wallet-ca-cert.pem` and add it to the verifier trust store. `wallet tls-cert` exports the per-wallet HTTPS leaf certificate as a single PEM instead.

```bash
# Validate a wallet-issued credential against the wallet's trust list
eudi validate --trust-list http://localhost:8085/api/trustlist credential.txt

# Validate against the German PID provider trust list
eudi validate --trust-list https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt credential.txt
```

## HAIP 1.0

`--haip` adds the [High Assurance Interoperability Profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html) rules to the format's own checks. Section 6.1.1 requires an SD-JWT VC to carry its issuer's signing certificate and chain in the `x5c` header, without the trust anchor, and forbids a self-signed signing certificate.

Findings are printed. The exit code follows only the credential's own validity (signature, expiry, revocation).
