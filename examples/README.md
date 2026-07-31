# Examples

Runnable integration scenarios live in this directory.

For a documentation-style overview, see [docs/examples.md](../docs/examples.md).

Each example should be self-contained in its own subfolder and include:

- a short `README.md`
- any compose files, scripts, or fixtures needed to run it
- the exact versions or assumptions the scenario was tested against

The examples in this directory prefer fixed ports, fixed demo identities, and static Keycloak realm files where that keeps the flow easier to understand. Dynamic bootstrap scripts are kept for cases that genuinely need runtime-generated keys, trust lists, or provider wiring.

The example scripts are written for Bash. On Windows, run them from Git Bash or WSL; the wallet flows themselves avoid macOS-only assumptions and fall back to `oid4vc-dev wallet accept '<uri>'` when custom URL handlers are unavailable.

## Scenarios

| Folder | Purpose |
|--------|---------|
| `keycloak-issuer-wallet` | Smallest issuer example: one imported realm, one demo user, one credential configuration, and `oid4vc-dev` as the wallet |
| `keycloak-verifier-oid4vp` | Smallest verifier example: one imported realm plus `keycloak-extension-oid4vp`, using `oid4vc-dev` as the wallet |
| `keycloak-issuer-verifier-app` | Combined issuance and HAIP verification demo with a small Go app; uses `haip-vp://`, `direct_post.jwt`, `x509_hash`, and runtime trust material where needed |
| `keycloak-web-wallet` | Issuer, verifier, and the wallet as a web wallet in one Docker compose project with a demo UI; issuance and verification invoked via web URLs (`/credential-offer`, `/authorize`) instead of custom schemes |
