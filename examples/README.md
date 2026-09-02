# Examples

Runnable integration scenarios live in this directory.

For a documentation-style overview, see [docs/examples.md](../docs/examples.md).

Each example should be self-contained in its own subfolder and include:

- a short `README.md`
- any compose files, scripts, or fixtures needed to run it
- the exact versions or assumptions the scenario was tested against

The examples in this directory prefer fixed ports, fixed demo identities, and static Keycloak realm files where that keeps the flow easier to understand. Bootstrap scripts are used only where runtime-generated keys, trust lists, or provider wiring are needed.

The example scripts are written for Bash. On Windows, run them from Git Bash or WSL. The wallet flows themselves avoid macOS-only assumptions and fall back to `eudi wallet accept '<uri>'` when custom URL handlers are unavailable.

## Scenarios

| Folder | Purpose |
|--------|---------|
| `keycloak-issuer-wallet` | Smallest issuer example: one imported realm, one demo user, one credential configuration, and `eudi-dev` as the wallet |
| `keycloak-verifier-oid4vp` | Smallest verifier example: one imported realm plus `keycloak-extension-oid4vp`, using `eudi-dev` as the wallet |
| `keycloak-issuer-verifier-app` | Combined issuance and HAIP verification demo with a small Go app. Uses `haip-vp://`, `direct_post.jwt`, `x509_hash`, and runtime trust material where needed |
| `keycloak-web-wallet` | Issuer, verifier, and the wallet as a web wallet in one Docker compose project with a demo UI. Issuance and verification invoked via web URLs (`/credential-offer`, `/authorize`) instead of custom schemes |
| `keycloak-web-wallet-public` | The `keycloak-web-wallet` scenario against the shared public demo wallet (`https://eudi-test.dev`). Local Keycloak exposed through an ngrok tunnel so the public wallet can reach it |
| `public-demo` | Internet-facing shared demo deployment: Caddy with automatic TLS in front of the wallet in `--demo` mode (see [docs/public-demo.md](../docs/public-demo.md)) |
