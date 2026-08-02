# Validate

Validate a credential by checking signatures, expiry, and revocation status. Unlike `decode` (which only parses and displays), `validate` actively checks correctness.

Signature keys are resolved in this order:

1. The credential's x5c (SD-JWT/JWT) or x5chain (mDOC) certificate chain, validated against `--trust-list` when given
2. An explicitly provided `--key`
3. The embedded leaf certificate alone, when no trust list is given. This works fully offline and the output notes that the chain was not validated (the signature is intact, trust is not established)
4. Issuer metadata from `https://<iss>/.well-known/jwt-vc-issuer`, for credentials without an embedded certificate

So a credential that carries its certificate chain validates without any network access, even when its issuer is not reachable. Credentials without keys or certificates fall back to expiry and status checks only.

```bash
# Full validation with signature verification
eudi validate --key issuer-key.pem credential.txt
eudi validate --trust-list trust-list.jwt credential.txt
eudi validate --key key.pem --allow-expired credential.txt

# Expiry + revocation check without signature verification
eudi validate credential.txt
```

## Flags

| Flag              | Description                                       |
|-------------------|---------------------------------------------------|
| `--key`           | Public key file (PEM or JWK) — optional            |
| `--trust-list`    | ETSI trust list JWT (file path or URL) — optional   |
| `--status-list`   | Check revocation via status list when the credential contains a status reference (enabled by default) |
| `--allow-expired` | Don't fail on expired credentials                  |

## Certificate chain validation

When a trust list is provided and the credential contains an x5c (SD-JWT/JWT) or x5chain (mDOC) certificate chain, the chain is validated against the trust list before verifying the signature. The validation follows the real-world EUDI flow:

1. The trust list contains **CA certificates** (trust anchors)
2. The credential's x5c/x5chain contains `[leaf, ...intermediates]`
3. The leaf certificate is verified to chain up to a trust list CA via any intermediates
4. The leaf certificate's public key is used to verify the credential signature

This matches the Bundesdruckerei PID provider setup where the trust list contains CA certificates like "PIDP Preprod CA" and credentials carry a leaf certificate signed by that CA.

Wallet-generated SD-JWT credentials follow the same model: the SD-JWT header carries a deterministic `kid` plus the leaf signing certificate in `x5c`, while the wallet trust list exposes the CA trust anchor separately. The wallet also publishes HTTPS JWT VC issuer metadata at `/.well-known/jwt-vc-issuer` for ecosystems that resolve issuer keys via metadata/JWKS.

The web decoder (`eudi serve` and the wallet's embedded decoder) additionally uses the local wallet's CA as an implicit trust anchor when no key or trust list is provided. Credentials issued by the local wallet then show a fully verified chain without any configuration.

This trust-list validation step is intentionally limited to certificate trust and service listing. Current EUDI authorization checks such as provider class and exact attestation-type entitlement come from signed Credential Issuer metadata (`/.well-known/openid-credential-issuer`, `issuer_info`) and registrar or registration data, not from custom trust-list fields.
The trust-list parser and decoder accept current ETSI-style field names, including `ListIssueDateTime`. When a wallet exposes multiple trust-list profiles, use the legacy `/api/trustlist` endpoint for PID compatibility or resolve a specific profile from `/api/trustlists`. For containerized callers, prefer the index entry's relative `path` over its optional advertised URL.

If your verifier test environment needs to trust the wallet's local HTTPS endpoints explicitly, export the shared wallet CA with `eudi wallet ca-cert --out wallet-ca-cert.pem` and add it to the verifier trust store. Use `wallet tls-cert` only when you need the exact per-wallet HTTPS leaf certificate as a single PEM.

```bash
# Validate a wallet-issued credential against the wallet's trust list
eudi validate --trust-list http://localhost:8085/api/trustlist credential.txt

# Validate against the German PID provider trust list
eudi validate --trust-list https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt credential.txt
```
