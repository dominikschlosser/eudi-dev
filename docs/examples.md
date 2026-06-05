# Examples

Runnable integration scenarios live under [`examples/`](../examples/README.md).

These examples are meant to show complete local setups around `oid4vc-dev`, including any Docker compose files, bootstrap scripts, wallet preparation steps, exact versions, flow diagrams, and the concrete parameter values each scenario uses.

## Scenarios

### Keycloak Issuer + oid4vc-dev Wallet

Folder: [`examples/keycloak-issuer-wallet`](../examples/keycloak-issuer-wallet/README.md)

Use this when you want to run Keycloak `26.6.0` as an OpenID4VCI issuer and redeem the resulting offer with an `oid4vc-dev` wallet.

It includes:

- a Keycloak compose setup
- issuer bootstrap scripts
- a helper to create a pre-authorized credential offer
- a wallet redemption helper

### Keycloak Verifier + keycloak-extension-oid4vp

Folder: [`examples/keycloak-verifier-oid4vp`](../examples/keycloak-verifier-oid4vp/README.md)

Use this when you want to run Keycloak `26.6.0` as an OpenID4VP verifier with `keycloak-extension-oid4vp` and use `oid4vc-dev` as the wallet.

It includes:

- a provider download script for the published extension jar
- wallet generation helpers
- verifier bootstrap scripts
- a headless same-device login test
- a browser-driven command-line flow that works with a registered `oid4vc-dev` wallet

### Keycloak Issuer + Verifier Demo App

Folder: [`examples/keycloak-issuer-verifier-app`](../examples/keycloak-issuer-verifier-app/README.md)

Use this when you want a more complete local integration: one Keycloak `26.6.0` instance issues a credential, the same Keycloak instance verifies it through `keycloak-extension-oid4vp` with HAIP-style verifier settings, and a sample application drives both steps.

It includes:

- a Keycloak compose setup with both OID4VCI and OID4VP pieces enabled
- a realm bootstrap script for issuance and verification together
- a custom first-broker authenticator that links the verified credential back to the existing Keycloak user by `keycloak_user_id`
- a small local demo application with issue and login actions
- HAIP verifier settings using `haip-vp://`, `direct_post.jwt`, and `x509_hash`
- local issuer metadata / JWKS trust, plus public ngrok mode with a generated Keycloak signing-certificate trust list
- a headless smoke test for the combined flow

## Notes

- The examples are intentionally self-contained and version-pinned.
- Each scenario README documents its own prerequisites, quick start, and cleanup.
- If you want to browse only the example folders, start from [`examples/README.md`](../examples/README.md).
