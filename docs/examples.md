# Examples

Runnable integration scenarios live under [`examples/`](../examples/README.md).

Each scenario is a complete local setup around `eudi-dev`: Docker compose files, bootstrap scripts, wallet preparation steps, exact versions, flow diagrams, and the concrete parameter values it uses.

## Scenarios

### Keycloak Issuer + eudi-dev Wallet

Folder: [`examples/keycloak-issuer-wallet`](../examples/keycloak-issuer-wallet/README.md)

Use this when you want to run Keycloak `26.7.2` as an OpenID4VCI issuer and redeem the resulting offer with an `eudi-dev` wallet.

It includes:

- a Keycloak compose setup
- issuer bootstrap scripts
- a helper to create a pre-authorized credential offer
- a wallet redemption helper

### Keycloak Verifier + keycloak-extension-oid4vp

Folder: [`examples/keycloak-verifier-oid4vp`](../examples/keycloak-verifier-oid4vp/README.md)

Use this when you want to run Keycloak `26.7.2` as an OpenID4VP verifier with `keycloak-extension-oid4vp` and use `eudi-dev` as the wallet.

It includes:

- a provider download script for the published extension jar
- wallet generation helpers
- verifier bootstrap scripts
- a headless same-device login test
- a browser-driven command-line flow that works with a registered `eudi-dev` wallet

### Keycloak Issuer + Verifier Demo App

Folder: [`examples/keycloak-issuer-verifier-app`](../examples/keycloak-issuer-verifier-app/README.md)

Use this for a fuller local integration: one Keycloak `26.7.2` instance signs users in with their wallet as an OpenID4VP verifier (`keycloak-extension-oid4vp`, subject-binding model) and issues them a membership credential during the first login. Later logins present the PID together with that credential and need no password. A Go relying party drives the login.

It includes:

- a Keycloak compose setup with the OID4VP provider jar, the realm import, and the wallet CA in its truststore
- a static realm with the verifier, the subject-binding first broker login flow, the membership credential scope, and the trust material
- a bootstrap script that adds a CA-issued realm signing key
- a small Go relying party with a wallet sign-in
- HAIP verifier settings using `haip-vp://`, `direct_post.jwt`, and `x509_hash`
- a headless smoke test driving the first (password plus offer) and second (passwordless) login

### Keycloak + Web Wallet (Web URLs Instead of Custom Schemes)

Folder: [`examples/keycloak-web-wallet`](../examples/keycloak-web-wallet/README.md)

Use this to run the full triangle in containers with no host-side wallet and no custom URL schemes at all. One Keycloak `26.7.2` instance issues and verifies (via `keycloak-extension-oid4vp`), the `eudi-dev` wallet runs as a compose service, and the verifier is *configured* with the wallet's `/authorize` URL (`walletScheme`). Verification is then an ordinary browser OIDC login. This is the setup to copy for hosted environments, automated tests, and non-macOS platforms.

It includes:

- one compose project where all services share one network namespace, so every URL is plain `localhost` for both the host browser and the containers
- a demo UI (port 9090) with clickable localhost wallet links for issuance and a normal OIDC "Login with wallet" flow for verification
- static issuer and verifier realms reused from the two smaller examples, plus an admin-API step that points the verifier's `walletScheme` / `trustListUrl` at the wallet
- headless demos driving `GET /credential-offer` and `GET /authorize`
- automatic wallet-CA export into Keycloak's truststore for the status-list revocation check

### Keycloak + Public Demo Wallet

Folder: [`examples/keycloak-web-wallet-public`](../examples/keycloak-web-wallet-public/README.md)

Use this to run the web wallet scenario against the shared public demo instance at `https://eudi-test.dev` (or any other `--demo` deployment) instead of a local wallet container. Keycloak and the demo UI run locally. The wallet is the public one.

It includes:

- a compose project that reuses the realms, extension jar, demo UI, and scripts of `keycloak-web-wallet` (no wallet service, no truststore mount)
- an ngrok tunnel in front of the local Keycloak, needed because the public wallet fetches the request object and calls the token endpoint server side (bring your own public URL via `KEYCLOAK_PUBLIC_URL` instead if you have one)
- the same admin-API step pointing the verifier's `walletScheme` / `trustListUrl` at the public wallet

## Notes

- The examples are intentionally self-contained and version-pinned.
- Each scenario README documents its own prerequisites, quick start, and cleanup.
- If you want to browse only the example folders, start from [`examples/README.md`](../examples/README.md).
