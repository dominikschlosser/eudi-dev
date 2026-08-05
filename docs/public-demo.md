# Hosting a Public Demo

The wallet server can run as a shared public demo (for example on `https://eudi-test.dev`). Visitors get the full credential flows (issue, present, decode, delete) while the endpoints that control the process or write to the host stay disabled. A working setup lives in [`examples/public-demo/`](../examples/public-demo/).

## Demo mode

```bash
eudi wallet serve --demo --base-url https://eudi-test.dev \
  --vci-client-id https://eudi-test.dev --vci-redirect-uri https://eudi-test.dev/callback \
  --status-list --imprint-file imprint.html
```

`--demo` changes the server in five ways:

1. It implies `--pid`, so the server runs headless with a known credential baseline. Consent stays interactive for browser flows (visitors clicking offer or authorize links approve in the wallet UI), while API submissions auto-accept, keeping the demo a reliable counterparty for external issuers, verifiers, and CLI clients.
   A consent dialog only opens in the browser that started the flow, never in every open tab. That is the tab a request redirected to (`/?request=<id>`), or the tab the OS scheme handler opened for a dispatched `openid4vp://` link (marked `consent=await`, valid once and for 90 seconds). Everyone else sees a "N requests are waiting for consent" bar with a Review button, so a request can still be reached without a visitor's tab being hijacked.
2. It disables the admin endpoints. `POST /api/shutdown`, `PUT/DELETE /api/templates/{name}`, `POST/DELETE /api/next-error` and `PUT /api/config/preferred-format` return 403. Saving templates through `POST /api/issue` is rejected too. `GET /api/config` stops reporting host paths and the process id.
3. It blocks outbound requests to internal networks. Visitor supplied URLs (credential offers, `request_uri`, trust lists, status lists) are still fetched from the public internet, but connections to loopback, RFC 1918, link local (including cloud metadata endpoints), CGNAT and unique local addresses are refused at dial time. The check runs on resolved IP addresses, so DNS tricks do not bypass it. The wallet's own advertised origins are exempt by exact address and port, so it can fetch a `request_uri` or post to a `response_uri` belonging to its own demo verifier. A visitor-supplied URL that merely points at loopback is still refused.
4. It enforces the EUDI profile. `--mode strict` makes request validation findings fatal instead of warnings (bad certificate chain, broken request object signature, missing nonce, unknown `client_id` prefix), and `--haip` requires HAIP 1.0 on incoming presentations: a signed request object, an `x509_hash:` / `x509_san_dns:` / `web-origin:` client id, `direct_post.jwt` or `dc_api.jwt`, DCQL, and ES256. Issuance is held to the profile as well: the issuer must support the authorization code flow, DPoP and client authentication, and an offer that drives the authorization endpoint must find PAR required and PKCE S256 supported. A pre-authorized code offer is not rejected for its grant type. **A verifier that is not HAIP-compliant gets HTTP 400, as does an offer that fails the checks applying to it.** Both settings are overridable (`--mode debug`, `--haip=false`) for a self-hosted demo that would rather be permissive, and a single call can opt out with `{"haip": false}` on `POST /api/presentations` or `POST /api/offers`. The built-in demo verifier and issuer are themselves HAIP-compliant, so the demo works out of the box under these rules. The active level is visible under **Conformance** in the wallet UI header.
5. It resets the wallet periodically. `--demo-reset` takes an interval (`24h`), a daily wall-clock time (`00:00`), or one with a timezone (`"00:00 Europe/Berlin"`). `0` disables it. A wall-clock schedule keeps the reset at the same local time every day instead of drifting with each restart, and follows DST. Resets restore the clean baseline (fresh PID credentials, empty activity log) while keys, certificates and URLs survive, so trust list and status list URLs stay stable. The UI footer shows the schedule.

## Browser hardening

A shared wallet renders one visitor's data in another visitor's browser, so the server sends `Content-Security-Policy` (scripts from this origin only, no inline script, no framing, no `<base>` rewriting), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer` on every response. The UI escapes values for attribute contexts as well as text, so a credential cannot inject markup through a status list URI, a `vct`, a claim name or a credential configuration id. The consent event stream is same-origin only.

## What stays open (accepted risk)

Every wallet server also hosts a demo issuer at `/issuer` and a demo verifier at `/verifier`. The issuer hands out a Demo Event Ticket through a real OpenID4VCI pre-authorized code flow, which HAIP permits: §4 requires an issuer to support the authorization code flow but does not require using it for every credential. It also offers the authorization code flow itself (see below), so the profile's client authentication can be exercised. The verifier requests and cryptographically verifies presentations of the ticket or the PID through OpenID4VP, following HAIP 1.0: it signs its authorization request (served by reference from `/verifier/request/{id}`), identifies itself with an `x509_hash:` client id derived from its signing certificate, and receives the response encrypted as `direct_post.jwt` with a per-request key. Together they make the public demo usable out of the box (issue, then present, all in the browser) and serve as protocol counterparties for external wallets that can reach the server. Offers and verification requests are in-memory and expire after ten minutes, and each verification request accepts exactly one answer.

The issuer page has a status list toggle. With it on, the ticket carries a reference to the wallet's own status list (one reserved index per ticket), so the credential arrives in the wallet as revocable and the demo verifier rejects the next presentation once it is revoked. With it off the ticket carries no status reference at all.

The wallet UI pages the credential list (ten per page), so a demo that accumulated hundreds of credentials between resets stays usable and does not ship the whole list to every visitor on load.

The PID credentials the demo seeds are marked protected: the UI, the API and the CLI refuse to delete or revoke them, so a visitor emptying the wallet cannot leave the demo without a baseline. Everything a visitor issues afterwards behaves normally and can be deleted. Clearing the flag needs direct access to `wallet.json`.

The demo is a shared environment by design. Anyone can issue credentials, delete them and watch the activity log. State is shared between all visitors and the periodic reset bounds the mess. The wallet also fetches visitor supplied public URLs (that is what a wallet does), so put rate limiting in front if abuse becomes a concern.

## Base URL and issuer URL

With an https base URL the issuer URL equals the base URL. Status list URIs, `iss`, the `.well-known` metadata and trust list URLs all live on the public origin, and the built-in self-signed HTTPS listener is not started (the reverse proxy owns TLS). With an http base URL the wallet keeps its second self-signed HTTPS listener on port+1 as before.

## Client identity for authorization-code issuance

A public demo should also be usable as a wallet by external issuers, and HAIP issuance runs the authorization code flow. That flow needs both `--vci-client-id` and `--vci-redirect-uri`, otherwise the wallet rejects the offer before it reaches the pushed authorization request and the issuer never sees a wallet attestation. The example deployment uses the demo origin as the client id and the wallet's own callback endpoint as the redirect URI:

```
--vci-client-id https://eudi-test.dev --vci-redirect-uri https://eudi-test.dev/callback
```

Issuers that require registration should register exactly those two values. Pre-authorized code offers work without either flag and carry no client attestation.

Both flags now default to the wallet's own origin (`--base-url`, plus `/callback`), so an authorization code offer works without configuring anything. Pass them explicitly when an issuer registered you under a different client id.

## The demo issuer as an authorization server

The demo issuer also runs the authorization code flow, with itself as the authorization server. Its metadata (`/.well-known/oauth-authorization-server/issuer`) advertises what HAIP requires: pushed authorization requests required, PKCE S256, DPoP, and `attest_jwt_client_auth`. The endpoints are `/issuer/par`, `/issuer/authorize` and `/issuer/token`.

Authentication is one hardcoded account, **alice / alice**, printed on the login page. It is a demo, not an account system: no registration, no stored user data, no session beyond the flow it belongs to.

The sign-in happens during redemption, not before it. The **Authorization code offer** button creates an offer with nobody signed in. The wallet then runs the pushed authorization request, and only at the authorization endpoint is the user asked to authenticate. That is where the authorization code flow puts it, and it means the credential is bound to whoever completed the login rather than to whoever created the offer.

The wallet never opens a browser itself. The browser that matters belongs to the user, and on a hosted wallet it is not on that machine. It hands the authorization URL to whoever is holding the user's attention: the tab that started the flow (an `authorize` event on `/api/requests/stream`), which navigates, or an API caller, which gets `202 authorization_required` with the URL and an `offer_id`. The flow stays open either way. The issuer redirects back to the wallet's `/callback`, which resumes it and returns the visitor to the wallet UI.

The callback is matched by `state` alone, so the sign-in can happen in any browser that can reach the wallet. That is what lets `eudi wallet accept` complete an authorization code offer against the hosted demo: the CLI opens the URL locally and follows the flow at `GET /api/offers/{offer_id}` until it reports `completed` or `failed`.

The pushed authorization request and the token request must both carry a wallet attestation, and the demo issuer verifies it rather than waving it through: the certificate in the `x5c` header has to chain to the wallet CA, the PoP has to be signed by the attested key, and `sub`, `iss`, `aud` and the expiry have to line up. The access token is bound to the DPoP key and the credential request has to prove that key again. The ticket then carries the name of the account that signed in, so a flow that skipped the login is visible in the result.

## What an issuer needs to verify the wallet

On the authorization-code path the wallet authenticates with attestation-based client authentication and sends both headers on the pushed authorization request and on the token request:

- `OAuth-Client-Attestation`, signed by the wallet's issuer key (`iss` is the wallet origin, `sub` is the client id, `cnf.jwk` is the wallet's holder key). Its `x5c` header carries the leaf certificate only, the self-signed root is stripped.
- `OAuth-Client-Attestation-PoP`, signed by that holder key. If the authorization server metadata advertises a `challenge_endpoint`, the wallet fetches a challenge first and includes it.

Credential proofs carry a `key-attestation+jwt` from the same signer when the credential configuration sets `key_attestations_required`.

So the leaf comes with the attestation and the trust anchor is fetched once:

| Source | URL |
| --- | --- |
| CA certificate (the anchor to pin) | `/api/certificates/ca`, JWKS form with `?format=jwks` |
| Signing key by `kid` | `/.well-known/jwt-vc-issuer` |
| ETSI trust list with the same CA | `/api/trustlists` for the index, `/api/trustlists/{id}` for a list |

Pin the CA, not the leaf or the `kid`. The CA survives restarts and the periodic reset, while a leaf is reissued whenever the wallet regenerates its signing key. The trust lists are grouped by credential profile (`pid`, `local`), but every one of them carries the same CA, so any of them works as the anchor for the attestations too. This is a self-signed development CA, so trust in it is established out of band by design.

## Imprint

Hosting a public site in the EU requires an imprint naming the operator. Pass `--imprint-file` with an HTML snippet (name, address, contact). It is served at `/imprint` (also under `/decoder/imprint`) wrapped in a page that includes the EU non-affiliation disclaimer, and the UI footer links to it. The standalone decoder (`eudi serve`) accepts the same flag.

## Deploying and updating

[`examples/public-demo/deploy.sh`](../examples/public-demo/deploy.sh) drives a host over ssh. The target is configuration, not a hardcoded value: point `DEMO_HOST` at any ssh destination (a `~/.ssh/config` alias, `user@host`, or a bare host), optionally with `DEMO_DIR` and `DEMO_URL`. Put them in the environment or in a `deploy.env` next to the script (gitignored).

```bash
cd examples/public-demo
cat > deploy.env <<'ENV'
DEMO_HOST=root@demo.example
DEMO_URL=https://demo.example
ENV

./deploy.sh setup     # first deployment: Docker, stack, volume ownership, start
./deploy.sh push      # after editing Caddyfile, compose file or imprint
./deploy.sh update    # pull the released image and restart
./deploy.sh status    # container status plus the version the site reports
./deploy.sh verify    # check that every public endpoint answers
./deploy.sh logs      # follow the wallet log
```

`setup` also fixes the wallet data volume's ownership. Docker creates named volumes owned by root while the image runs as uid 1000, which otherwise sends the wallet into a crash loop on a fresh host.

## Usage statistics

The compose example ships an optional usage report, so you can tell whether the demo is actually used. It is not analytics: Caddy writes an access log with the client address anonymized at write time (`ip_mask` zeroes the last IPv4 octet and the last 80 bits of IPv6, for both `remote_ip` and `client_ip`), [GoAccess](https://goaccess.io) turns that log into a static HTML report every five minutes, and Caddy serves it at `/stats` behind basic auth. No JavaScript is added to the pages, no cookies are set, and no third party is involved.

```bash
./deploy.sh stats-password   # writes stats.env with a bcrypt hash (gitignored)
./deploy.sh push             # applies it
./deploy.sh stats            # quick summary in the terminal
./deploy.sh stats-reset      # discard the log and start counting from zero
```

Then open `https://your-domain/stats/`. Remove the `handle_path /stats*` block from the Caddyfile (and the `stats` service) to turn the whole thing off. If your imprint claims that no access data is processed, adjust it: the log exists, even anonymized.

Read the numbers with care. Your own testing counts too, and a single browser tab produces far more requests than a visit: every page load opens an event stream and the UI reloads credentials, log and trust lists whenever anything changes. `deploy.sh stats` therefore lists page requests only (the `/api/` paths are the UI talking to itself). Distinct visitors are approximated from masked addresses, so everyone behind the same `/24` counts once.

### Log bounds

Nothing here grows without bound:

- the access log rolls at 10 MiB, keeps three files and drops anything older than 30 days (about 40 MiB worst case)
- every container caps its own log at 10 MB with three files, through the `logging` anchor in the compose file. Docker's default is unlimited, which is what actually fills a disk
- the report only reads the current access log file, so a roll also caps how far back the statistics reach

## Deployment notes

- Terminate TLS in a reverse proxy (the example uses Caddy with automatic Let's Encrypt) and forward to the wallet's HTTP port. The wallet derives all advertised URLs from `--base-url`, not from request headers.
- Persist a volume at `/home/app/.eudi-dev` (the parent directory, not just `wallet/`). The shared CA lives one level above the wallet directory and issuer keys must survive restarts, otherwise verifiers holding the old trust list fail.
- Run exactly one replica. The wallet store is a single-writer file.
- Do not set `HTTP_PROXY`/`HTTPS_PROXY` in the container. A proxy would carry the requests and bypass the dial time network checks.
- Self-fetches of the public origin (for example a pasted offer pointing at the demo itself) resolve through public DNS. On typical cloud hosts hairpin NAT makes this work. Do not add a compose network alias for the public hostname, it would resolve to a private address and be blocked.
- Consider rate limiting in the proxy. The compose example includes a commented Caddy snippet.

## Pointing the CLI at the demo

```bash
eudi wallet instances use https://eudi-test.dev
```

Management commands (list, issue, delete) then run against the hosted instance. `serve`, `scan` and `register` stay local.
