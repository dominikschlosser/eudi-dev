# Keycloak + Public Demo Wallet (eudi-test.dev)

This example is the [`keycloak-web-wallet`](../keycloak-web-wallet/README.md) scenario pointed at the shared public demo wallet at <https://eudi-test.dev> instead of a local wallet container. Keycloak (issuer and verifier) and the demo UI still run locally in Docker compose. Realm imports, the extension jar, the demo UI, and the helper scripts are reused from the local example, so the integration is configured exactly the same way (the verifier's `walletScheme` and `trustListUrl` point at the wallet's base URL).

One structural change follows from using a public wallet: the wallet fetches the verifier's request object and calls the issuer's token endpoint server side, so the local Keycloak must be reachable from the internet. `start.sh` starts an ngrok tunnel for that and Keycloak generates public URLs for requests that arrive through it (`--proxy-headers=xforwarded`).

## Requirements

- Docker compose (as in the local example)
- The [ngrok CLI](https://ngrok.com/download) with any account, or your own public https URL that forwards to the local Keycloak (set `KEYCLOAK_PUBLIC_URL` to skip ngrok)

With the free ngrok plan, browsers see a one-time interstitial warning page on the first visit to the tunnel URL. Click through it once per browser session. Server-to-server requests (the wallet fetching the request object, token calls) are not affected. A reserved domain (`NGROK_DOMAIN=your-domain.ngrok.app`) or a paid plan removes the interstitial.

## Quick Start

```bash
cd examples/keycloak-web-wallet-public
./start.sh
```

Then open the demo UI at <http://localhost:9090>:

- **Issuance** — creates a credential offer in Keycloak and shows a clickable `https://eudi-test.dev/credential-offer?...` link. Clicking it delivers the offer to the public wallet, which shows the consent dialog in its UI. Approving imports the membership credential.
- **Verification** — "Login with wallet" is a plain OIDC login: the browser goes to Keycloak through the tunnel, whose login page links to `https://eudi-test.dev/authorize?...`. The public wallet shows the consent request in its UI. Approving presents the PID credential, and the browser returns through Keycloak to the app's `/callback` with the ID-token claims on screen.

Stop everything with `docker compose down` and `kill $(cat .ngrok.pid)`.

## Differences to the Local Example

- **The wallet is shared.** Everything you issue lands in the one public demo wallet, is visible to every visitor of eudi-test.dev, can be deleted by anyone, and disappears with the daily reset. Do not enter personal data.
- **Shared consent.** The consent dialogs for your flows appear in the shared wallet UI, so any visitor with the wallet open can see and approve them. Approve your own requests promptly.
- **No headless demo scripts.** `demo-issuance.py` and `demo-verification.py` assume exclusive control over the wallet's consent queue, which a shared public wallet cannot provide. Use the demo UI in the browser instead.
- **No truststore or CA export.** The public wallet serves its trust list and status lists behind a publicly trusted certificate, so Keycloak's default truststore already covers it. The verifier trusts the wallet's credentials through `trustListUrl` (`https://eudi-test.dev/api/trustlist`), configured by the same script as in the local example.

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `WALLET_BASE_URL` | `https://eudi-test.dev` | Public wallet instance to run against (any `--demo` deployment works, see [docs/public-demo.md](../../docs/public-demo.md)) |
| `KEYCLOAK_PUBLIC_URL` | set by `start.sh` via ngrok | Public origin that forwards to the local Keycloak |
| `NGROK_DOMAIN` | none | Reserved ngrok domain for a stable tunnel URL |
| `KEYCLOAK_PORT` / `APP_PORT` | `9080` / `9090` | Local ports, next free port is picked automatically |

Because the wallet is a public deployment outside this compose project, restarting the example does not reset wallet state. The shared demo wallet cleans itself up with its daily reset.
