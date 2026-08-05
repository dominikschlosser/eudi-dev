# Examples

Runnable integration scenarios live under [`examples/`](../examples/README.md).

These examples are meant to show complete local setups around `eudi-dev`, including any Docker compose files, bootstrap scripts, wallet preparation steps, exact versions, flow diagrams, and the concrete parameter values each scenario uses.

## Scenarios

### Keycloak Issuer + eudi-dev Wallet

Folder: [`examples/keycloak-issuer-wallet`](../examples/keycloak-issuer-wallet/README.md)

Use this when you want to run Keycloak `26.6.0` as an OpenID4VCI issuer and redeem the resulting offer with an `eudi-dev` wallet.

It includes:

- a Keycloak compose setup
- issuer bootstrap scripts
- a helper to create a pre-authorized credential offer
- a wallet redemption helper

### Keycloak Verifier + keycloak-extension-oid4vp

Folder: [`examples/keycloak-verifier-oid4vp`](../examples/keycloak-verifier-oid4vp/README.md)

Use this when you want to run Keycloak `26.6.0` as an OpenID4VP verifier with `keycloak-extension-oid4vp` and use `eudi-dev` as the wallet.

It includes:

- a provider download script for the published extension jar
- wallet generation helpers
- verifier bootstrap scripts
- a headless same-device login test
- a browser-driven command-line flow that works with a registered `eudi-dev` wallet

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

### Keycloak + Web Wallet (Web URLs Instead of Custom Schemes)

Folder: [`examples/keycloak-web-wallet`](../examples/keycloak-web-wallet/README.md)

Use this when you want the full triangle in containers with no host-side wallet and no custom URL schemes at all: one Keycloak `26.7.0` instance issues and verifies (via `keycloak-extension-oid4vp`), the `eudi-dev` wallet runs as a compose service, and the verifier is *configured* with the wallet's `/authorize` URL (`walletScheme`), so verification is an ordinary browser OIDC login. The setup to copy for hosted environments, automated tests, and non-macOS platforms.

It includes:

- one compose project where all services share one network namespace, so every URL is plain `localhost` for both the host browser and the containers
- a demo UI (port 9090) with clickable localhost wallet links for issuance and a normal OIDC "Login with wallet" flow for verification
- static issuer and verifier realms reused from the two smaller examples, plus an admin-API step that points the verifier's `walletScheme` / `trustListUrl` at the wallet
- headless demos driving `GET /credential-offer` and `GET /authorize`
- automatic wallet-CA export into Keycloak's truststore for the status-list revocation check

### Keycloak + Public Demo Wallet

Folder: [`examples/keycloak-web-wallet-public`](../examples/keycloak-web-wallet-public/README.md)

Use this when you want the web wallet scenario against the shared public demo instance at `https://eudi-test.dev` (or any other `--demo` deployment) instead of a local wallet container. Keycloak and the demo UI run locally, the wallet is the public one.

It includes:

- a compose project that reuses the realms, extension jar, demo UI, and scripts of `keycloak-web-wallet` (no wallet service, no truststore mount)
- an ngrok tunnel in front of the local Keycloak, needed because the public wallet fetches the request object and calls the token endpoint server side (bring your own public URL via `KEYCLOAK_PUBLIC_URL` instead if you have one)
- the same admin-API step pointing the verifier's `walletScheme` / `trustListUrl` at the public wallet

## Notes

- The examples are intentionally self-contained and version-pinned.
- Each scenario README documents its own prerequisites, quick start, and cleanup.
- If you want to browse only the example folders, start from [`examples/README.md`](../examples/README.md).
