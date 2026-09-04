# The wallet HTTP API is unauthenticated

Every wallet operation is available over HTTP with no authentication. Anyone who can reach the port controls the wallet and its credentials. That is what makes the wallet scriptable. A CI job, a Testcontainers test or a curl one-liner manages a wallet without a credential exchange first, and the CLI's own remote mode (`--remote`) is a client of the same API. Authentication would add a setup step before the use case the API exists for.

Protection comes from the deployment. The wallet runs on localhost or an isolated test network and holds only test credentials (see `SECURITY.md`). Public hosting has one supported profile, `--demo`. It closes the process and filesystem endpoints (`demoBlockedRoute` in `internal/wallet/demo.go`), blocks server-side fetches into private networks and resets state on a schedule. Everything still reachable there is public and disposable.

## Consequences

Every page a developer visits can reach localhost, so `/api/` refuses requests carrying a cross-origin `Origin` (`internal/httpsec/origin.go`). A CLI or curl sends no `Origin`, so the intended callers are unaffected. `/api/dc-api` is exempt, because a verifier's page invokes the Digital Credentials API from its own origin. That endpoint relies on the origin the request arrived with (how OpenID4VP over the Digital Credentials API identifies an unsigned request's caller) plus the consent dialog. The protocol endpoints (`/authorize`, `/credential-offer`, `/callback`) stay open to any origin.
