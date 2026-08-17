# Validate

Check a credential's signature, expiry, and revocation status. `decode` only parses and displays. `validate` checks correctness.

Signature keys are resolved in this order:

1. The credential's x5c (SD-JWT/JWT) or x5chain (mDOC) certificate chain, validated against `--trust-list` when given
2. An explicitly provided `--key`
3. The embedded leaf certificate alone, when no trust list is given. This works fully offline. The output notes that the chain was not validated (the signature is intact, trust is not established)
4. JWT VC Issuer Metadata, for credentials without an embedded certificate. SD-JWT VC §3 puts `/.well-known/jwt-vc-issuer` between the host and the path of `iss`, so `https://example.com/tenant/1234` is read from `https://example.com/.well-known/jwt-vc-issuer/tenant/1234`. The document's `issuer` must be identical to `iss`, and the keys come from `jwks` or `jwks_uri` (never both)

A credential that carries its certificate chain validates without network access, even when its issuer is unreachable. Credentials without keys or certificates get expiry and status checks only.

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
| `--allow-expired` | Don't fail on expired credentials                  |
| `--haip` | Also check the credential against HAIP 1.0 and report what it breaks |

## Revocation status

When a credential carries a status reference, `validate` fetches the Status List Token and reads the entry. It requests `application/statuslist+jwt` and `application/statuslist+cwt` and parses whichever comes back, so CWT lists work as well as JWT ones.

The token's signature is always verified. A check that cannot be completed is an error, not a result. The signing key is trusted via `--trust-list` when the token's chain is anchored there. Otherwise the key comes from the token itself (`x5c` / `x5chain`, or a `jwk` in its header) and the result says the key is not trust anchored. The token's `sub` must equal the `uri` in the credential's status claim. `typ`, `iat` and `exp` are checked too, so a stale list or one for a different credential is rejected.

The status is reported by name (VALID, INVALID, SUSPENDED, an application specific value, or unknown) with the raw value alongside. A two-bit or wider list is not flattened into revoked and not revoked.

## Certificate chain validation

When a trust list is given and the credential contains an x5c (SD-JWT/JWT) or x5chain (mDOC) chain, the chain is validated against the trust list before the signature is verified. This follows the real-world EUDI flow:

1. The trust list contains **CA certificates** (trust anchors)
2. The credential's x5c/x5chain contains `[leaf, ...intermediates]`
3. The leaf certificate is verified to chain up to a trust list CA via any intermediates
4. The leaf certificate's public key is used to verify the credential signature

This matches the Bundesdruckerei PID provider setup where the trust list contains CA certificates like "PIDP Preprod CA" and credentials carry a leaf certificate signed by that CA.

Wallet-generated SD-JWT credentials follow the same model. The SD-JWT header carries a deterministic `kid` plus the leaf signing certificate in `x5c`. The wallet trust list exposes the CA trust anchor separately. The wallet also publishes HTTPS JWT VC issuer metadata at `/.well-known/jwt-vc-issuer` for ecosystems that resolve issuer keys via metadata/JWKS.

The web decoder (`eudi serve` and the wallet's embedded decoder) additionally uses the local wallet's CA as an implicit trust anchor when no key or trust list is provided. Credentials issued by the local wallet then show a fully verified chain without any configuration.

Trust-list validation is intentionally limited to certificate trust and service listing. Current EUDI authorization checks (provider class, exact attestation-type entitlement) come from signed Credential Issuer metadata (`/.well-known/openid-credential-issuer`, `issuer_info`) and registrar or registration data, not from custom trust-list fields.
The trust-list parser and decoder accept current ETSI-style field names, including `ListIssueDateTime`. When a wallet exposes multiple trust-list profiles, use the legacy `/api/trustlist` endpoint for PID compatibility or resolve a specific profile from `/api/trustlists`. For containerized callers, prefer the index entry's relative `path` over its optional advertised URL.

If a verifier test environment needs to trust the wallet's local HTTPS endpoints, export the shared wallet CA with `eudi wallet ca-cert --out wallet-ca-cert.pem` and add it to the verifier trust store. Use `wallet tls-cert` only when you need the exact per-wallet HTTPS leaf certificate as a single PEM.

```bash
# Validate a wallet-issued credential against the wallet's trust list
eudi validate --trust-list http://localhost:8085/api/trustlist credential.txt

# Validate against the German PID provider trust list
eudi validate --trust-list https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt credential.txt
```

## HAIP 1.0

`--haip` adds the rules the [High Assurance Interoperability Profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html) puts on a credential, on top of what the format itself requires. Today that is section 6.1.1: a credential carrying an `x5c` chain must be bound to its issuer by the leaf certificate. The host of an https `iss` must appear as a `dNSName`, another kind of `iss` as a `uniformResourceIdentifier`, and an address as an `iPAddress`. A HAIP verifier refuses a credential where these do not match. This flag reports the mismatch before one does.

Findings are printed. The exit code follows the credential's own validity (signature, expiry, revocation), so `--haip` reports what a credential breaks whether or not it is otherwise valid.
