# Hosting a Public Demo

The wallet server can run as a shared public demo (for example `https://eudi-test.dev`). Visitors get the full credential flows (issue, present, decode, delete). Endpoints that control the process or write to the host stay disabled. A working setup is in [`examples/public-demo/`](../examples/public-demo/).

## Demo mode

```bash
eudi wallet serve --demo --base-url https://eudi-test.dev \
  --vci-client-id https://eudi-test.dev --vci-redirect-uri https://eudi-test.dev/callback \
  --status-list --imprint-file imprint.html
```

`--demo` changes the server in five ways. The flags it implies (`--pid`, `--mode debug`, `--haip`, `--vci-version 1.1`) are defaults, so an explicit flag overrides them. `--demo --vci-version 1.0` runs the demo at the published feature level.

1. It implies `--pid`, so the server runs headless with a known credential baseline. The baseline comes from the pre-defined PID templates through the ordinary template resolution. A user template saved under the same name (or a `--templates-dir`) decides what the demo seeds and what every reset restores. Browser flows keep interactive consent (visitors approve offer and authorize links in the wallet UI). API submissions auto-accept, so external issuers, verifiers, and CLI clients get a reliable counterparty.
   A consent request belongs to the browser it came from. The wallet recognises the browser by the `eudi_session` cookie, set on the first response to it. Clients that submit over the API (the OS scheme handler, the CLI) name the page they opened, so their request reaches that page. A request that names no page waits in the bar above the credentials, where every caller can answer it.
2. It disables the admin endpoints. `POST /api/shutdown`, `PUT/DELETE /api/templates/{name}`, `POST/DELETE /api/next-error`, `PUT /api/config/preferred-format`, `PUT /api/config/auto-accept`, `PUT/DELETE /api/config/conformance` and `DELETE /api/log` return 403. `POST /api/issue` rejects saving templates and visitor-supplied logo or background images (a template's own art still applies). `GET /api/config` omits host paths and the process id.
3. It blocks outbound requests to internal networks. Visitor-supplied URLs (credential offers, `request_uri`, trust lists, status lists) are fetched from the public internet. Connections to loopback, RFC 1918, link local (including cloud metadata endpoints), CGNAT and unique local addresses are refused at dial time. The check runs on resolved IP addresses, so a hostname that resolves to a private address is refused too. The wallet's own advertised origins are exempt by exact address and port, so it can fetch a `request_uri` or post to a `response_uri` of its own demo verifier.
4. It checks the EUDI profile in debug mode. `--haip` checks incoming presentations against HAIP 1.0: `response_type=vp_token`, a signed request object delivered through `request_uri` with an `x509_hash:` client id (the SHA-256 of the signing certificate), `direct_post.jwt` or `dc_api.jwt`, DCQL asking only for `mso_mdoc` or `dc+sd-jwt`, both `A128GCM` and `A256GCM` in the verifier's `encrypted_response_enc_values_supported`, and ES256. Over the Digital Credentials API an unsigned request is accepted. There it carries no `client_id` and the platform-reported origin identifies the caller. Issuance is checked too. An offer that uses the authorization code flow needs an authorization server that supports the authorization code flow, offers a pushed authorization request endpoint, and advertises PKCE only with `S256` and DPoP only with `ES256`. A pre-authorized code offer passes the grant type check. In debug mode a violated rule produces a warning in the activity log and the flow continues, so the demo stays usable against non-conforming issuers and verifiers. An issuer that offers only unauthenticated access at its token endpoint gets a warning and the wallet proceeds without client authentication. When self-hosting, `--mode strict` refuses violations and `--haip=false` disables the profile checks. The built-in demo verifier and issuer are HAIP-compliant. The active settings are shown read-only under **Conformance** in the wallet UI header.
5. It resets the wallet periodically. `--demo-reset` takes an interval (`24h`), a daily wall-clock time (`00:00`), or one with a timezone (`"00:00 Europe/Berlin"`). `0` disables it. A wall-clock schedule fires at the same local time every day (no drift across restarts, DST followed). A reset restores the clean baseline (fresh PID credentials, empty activity log). Keys, certificates and URLs are kept, so trust list and status list URLs stay stable. The UI footer shows the schedule.

## Browser hardening

A shared wallet renders one visitor's data in another visitor's browser. The server therefore sends `Content-Security-Policy` (scripts from this origin only, no inline script, no framing, no `<base>` rewriting), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer` on every response. The UI escapes values in attribute contexts as well as text, so a credential cannot inject markup through a status list URI, a `vct`, a claim name or a credential configuration id. The consent event stream is same-origin only.

## robots.txt and security.txt

The server serves `/robots.txt` (pages allowed, the API and the protocol endpoints excluded) and `/.well-known/security.txt` (RFC 9116, contact and policy of the project, expiry six months from the request). Every page has a meta description.

## What stays open (accepted risk)

Every wallet server also hosts a demo issuer at `/issuer` and a demo verifier at `/verifier`. The issuer hands out a Demo Event Ticket through a real OpenID4VCI pre-authorized code flow. HAIP §4 permits this, since it only requires an issuer to support the authorization code flow. The issuer offers that flow too (see below), so the client authentication HAIP requires can be tested. The verifier requests and cryptographically verifies presentations of the ticket or the PID through OpenID4VP, following HAIP 1.0. It signs its authorization request (served by reference from `/verifier/request/{id}`), identifies itself with an `x509_hash:` client id derived from its signing certificate, and receives the response encrypted as `direct_post.jwt` with a per-request key. Together they make the demo usable in the browser (issue, then present) and serve as protocol counterparties for external wallets. Offers and verification requests are in-memory and expire after ten minutes. Each verification request accepts exactly one answer.

The verifier page has a PID format toggle. By default a PID request asks for the SD-JWT VC or the mdoc and the wallet presents whichever it has. Picking one format asks for that one alone, so a format mismatch becomes visible. The ticket is always an SD-JWT VC.

The issuer page has a status list toggle. With it on, the ticket carries a reference to the wallet's own status list (one reserved index per ticket). The wallet imports the ticket as revocable and the demo verifier rejects the next presentation once it is revoked.

The wallet UI pages the credential list (ten per page), so a demo with hundreds of credentials between resets stays usable.

The demo seeds four PID credentials: the country-independent EUDI PID (`urn:eudi:pid:1`) and the German PID that extends it (`urn:eudi:pid:de:1`), each as an SD-JWT VC and an mdoc. The two carry different attributes, each following its own rulebook.

The verifier page offers both through its credential toggle. The PID request names `urn:eudi:pid:1`, which both credentials match, and the wallet presents one of them. The German PID request names `urn:eudi:pid:de:1`, which only the German credential matches. See [credential type inheritance](wallet.md#credential-type-inheritance).

`POST /verifier/api/requests` takes the type as `vct` and accepts any type in `urn:eudi:pid:` (`urn:eudi:pid:fr:1` works the same). A request naming a domestic type is SD-JWT VC only, since every PID shares the mdoc doctype `eu.europa.ec.eudi.pid.1`. A PID request can also ask for the demo ticket with `"ticket": "combined"` (one DCQL option contains PID and ticket, next to a PID-only option) or `"ticket": "optional"` (a second credential set with `required: false`). Both show the set choices in the consent dialog.

All four are marked protected. The UI, the API and the CLI refuse to delete or revoke them, so the demo always keeps its baseline. Everything a visitor issues afterwards behaves normally and can be deleted. Clearing the flag needs direct access to `wallet.json`.

State is shared between all visitors. Anyone can issue credentials, delete them and watch the activity log. The periodic reset cleans up.

The compose example rate limits per client address in Caddy, the component that sees the real address (the wallet behind it sees the proxy). The Caddy image is built from the `Dockerfile` next to the compose file because the rate-limit plugin is not in the standard image. Three zones apply, each answering `429` with `Retry-After`:

| Zone | Requests | What it covers |
|---|---|---|
| `flows_burst` | 120 per minute | The endpoints that make the wallet fetch a visitor-supplied URL or grow its state until the next reset: presentations, offers, issuance, imports, refreshes, deferred collection, demo issuer offers, verification requests |
| `flows_hour` | 2000 per hour | The same endpoints, so a script left running is capped between resets |
| `site` | 1200 per minute | Everything else, including the UI and the stats report |

These limits are far above normal use. An idle wallet page is about 14 requests (updates arrive over one long-lived event stream). A busy visitor with three tabs open, issuing and presenting, produced 36 in a minute. A browser, a test suite driving the HTTP API, and everyone behind one office address fit under the limits together. A deployment with another reverse proxy should apply the same limits there.

## Base URL and issuer URL

With an https base URL the issuer URL equals the base URL. Status list URIs, `iss`, the `.well-known` metadata and trust list URLs all use the public origin. The reverse proxy terminates TLS, so the built-in self-signed HTTPS listener stays off. With an http base URL the wallet keeps its second self-signed HTTPS listener on port+1.

## Client identity for authorization-code issuance

HAIP issuance runs the authorization code flow, which needs a client id and a redirect URI. Both default to the wallet's own origin (`--base-url`) and its `/callback` endpoint. The example deployment sets them explicitly:

```
--vci-client-id https://eudi-test.dev --vci-redirect-uri https://eudi-test.dev/callback
```

Issuers that require registration register exactly those two values. Pass different ones when an issuer registered you under another client id. Pre-authorized code offers work without either flag (an attestation is still sent where the issuer's metadata asks for one).

## The demo issuer as an authorization server

The demo issuer also runs the authorization code flow, with itself as the authorization server. Its metadata (`/.well-known/oauth-authorization-server/issuer`) advertises what HAIP requires: pushed authorization requests required, PKCE S256, DPoP, and the two client authentication methods of [OAuth 2.0 Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/) draft 10 (`attest_jwt_client_auth` and `attest_jwt_client_auth_dpop`), plus the signing algorithms and proof of possession methods that document requires with them. The endpoints are `/issuer/par`, `/issuer/authorize` and `/issuer/token`. Attestations in the shape of draft-07 (with `iss` in both JWTs), draft-08 and draft-10 (without) are all accepted, per [ADR-0014](adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md). A shape that is correct under another supported draft than the one the configured OpenID4VCI version pins is accepted with a warning in the log. The token endpoint requires this client authentication on the pre-authorized code grant too (HAIP 1.0 §4.4.1). `--demo-issuer-client-auth optional` also accepts wallets that send no attestation.

The key-proof challenge comes from the Nonce Endpoint defined in OpenID4VCI 1.0 §7. The issuer serves it at `POST /issuer/nonce` and advertises it as `nonce_endpoint` in its Credential Issuer metadata. A proof signed over a stale nonce is answered with `invalid_nonce`, which tells the wallet to fetch a fresh nonce and retry.

Authentication is one hardcoded account, **alice / alice**, printed on the login page. The issuer stores no user data and a session ends with its flow.

The sign-in happens during redemption. The **Authorization code offer** button creates an offer with nobody signed in. The wallet then runs the pushed authorization request, and the authorization endpoint asks the user to authenticate. The credential is bound to the account that completed that login.

On a hosted wallet the user's browser is on another machine, so the wallet returns the authorization URL to the caller. The tab that started the flow receives an `authorize` event on `/api/requests/stream` and navigates. An API caller gets `202 authorization_required` with the URL and an `offer_id`. The flow stays open either way until the issuer redirects back to the wallet's `/callback`, which resumes it and returns the visitor to the wallet UI.

The callback is matched by `state` alone, so the sign-in can happen in any browser that can reach the wallet. This lets `eudi wallet accept` complete an authorization code offer against the hosted demo. The CLI opens the URL locally and follows the flow at `GET /api/offers/{offer_id}` until it reports `completed` or `failed`.

The pushed authorization request and the token request must both carry a wallet attestation, and the demo issuer verifies it. The PoP must be signed by the attested key, and `sub`, `aud`, `jti` and the expiry must match. Possession of the attested key can be proven in both ways the draft allows: a dedicated `OAuth-Client-Attestation-PoP` JWT, or the DPoP proof the request already carries (`attest_jwt_client_auth_dpop`), where the issuer checks that the DPoP key is the attested key. The access token is bound to the DPoP key and the credential request must prove that key again. The ticket carries the name of the account that signed in, so a flow that skipped the login is visible in the result.

### Wallets from other providers

An attestation is signed by a wallet provider, and this issuer trusts one CA (the CA of the wallet it runs in). So that other wallets can complete the authorization code flow, an attestation whose certificate does not chain to that CA is verified against its own leaf certificate and marked. The issued ticket carries a `wallet_attestation` claim saying `trusted` (the chain reached the CA), `untrusted` (it did not) or `none` (the client authenticated with nothing). A production issuer resolves the wallet provider's trust list and pins the CA it finds there. For this wallet that list is published at `/api/trustlists/wallet-provider`.

A wallet with no attestation is refused. HAIP 1.0 §4.4.1 requires it: "Wallets MUST use, and Issuers MUST require, an OAuth2 Client authentication mechanism at OAuth2 Endpoints that support client authentication". To test such a wallet, start the server with `--demo-issuer-client-auth optional`. The authorization server then also advertises and accepts `none`. An attestation is still verified wherever one is sent, and the ticket records the outcome.

## What an issuer needs to verify the wallet

On the authorization-code path the wallet authenticates with attestation-based client authentication and sends both headers on the pushed authorization request and on the token request:

- `OAuth-Client-Attestation`, signed by the wallet's issuer key (`sub` is the client id, `cnf.jwk` is the wallet's holder key, and `iss` is the wallet origin, which draft 10 permits). Its `x5c` header carries only the leaf certificate (the self-signed root is stripped).
- `OAuth-Client-Attestation-PoP`, signed by that holder key. If the authorization server metadata advertises a `challenge_endpoint`, the wallet fetches a challenge first and includes it.

Credential proofs carry a `key-attestation+jwt` from the same signer when the credential configuration sets `key_attestations_required`, in the header of a `jwt` proof or as the `attestation` proof itself, whichever the configuration offers. The attestation claims the `key_storage` and `user_authentication` levels the issuer requires. The demo keeps its keys in plain files, so those levels are claims only (see [SECURITY.md](../SECURITY.md)).

The leaf certificate is included in the attestation. The trust anchor is fetched once:

| Source | URL |
| --- | --- |
| CA certificate (the anchor to pin) | `/api/certificates/ca`, JWKS form with `?format=jwks` |
| Signing key by `kid` | `/.well-known/jwt-vc-issuer` |
| ETSI trust list with the same CA | `/api/trustlists` for the index, `/api/trustlists/{id}` for a list |

Pin the CA. It is kept across restarts and the periodic reset, while a leaf is reissued whenever the wallet regenerates its signing key. The trust lists are grouped by trust profile (`pid`, `local`), but every one contains the same CA, so any of them works as the anchor for the attestations too. The CA is self-signed, so trust in it is established out of band.

## Imprint

Hosting a public site in the EU requires an imprint naming the operator. Pass `--imprint-file` with an HTML snippet (name, address, contact). It is served at `/imprint` (also under `/decoder/imprint`) wrapped in a page that includes the EU non-affiliation disclaimer, and the UI footer links to it. The standalone decoder (`eudi serve`) accepts the same flag.

The demo sets one cookie, `eudi_session`. It holds an opaque random value that binds a pending consent request to the browser that started it, so a visitor is only asked to approve their own flows. The activity log stays shared. It is a session cookie (gone when the browser closes), `HttpOnly`, `SameSite=Lax`, and `Secure` for a visitor reached over https. A tab opened by a URL handler or the CLI also keeps that flow's name in `sessionStorage`, which the tab discards when it closes. Under the ePrivacy Directive both are strictly necessary for a service the visitor asked for and need no consent. The demo also keeps a theme preference and a dismissed-banner flag in `localStorage`, functional storage set by the visitor's own choice (no personal data, no tracking, no third parties). Mention all of it in your imprint or privacy notice if you want to.

## Deploying and updating

[`examples/public-demo/deploy.sh`](../examples/public-demo/deploy.sh) manages a host over ssh. Point `DEMO_HOST` at any ssh destination (a `~/.ssh/config` alias, `user@host`, or a bare host), optionally with `DEMO_DIR` and `DEMO_URL`. Put them in the environment or in a `deploy.env` next to the script (gitignored).

```bash
cd examples/public-demo
cat > deploy.env <<'ENV'
DEMO_HOST=root@demo.example
DEMO_URL=https://demo.example
ENV

./deploy.sh setup     # first deployment: Docker, stack, volume ownership, start
./deploy.sh push      # after editing Caddyfile, compose file or imprint
./deploy.sh update    # pull the released image and restart
./deploy.sh rollback  # put the release that was live before that back
./deploy.sh status    # container status plus the version the site reports
./deploy.sh verify    # check that every public endpoint answers
./deploy.sh logs      # follow the wallet log
```

`push` and `update` record the release they replace, so `rollback` on its own puts that one back. `rollback v2.0.0` selects any release directly. The choice is pinned as `WALLET_TAG` in the host's `.env` (where the compose file reads the image tag), so it is kept across a restart. The image is pulled before anything is switched, so naming a release that was never published leaves the running demo unchanged. A later `update` clears the pin and returns to the newest release.

`setup` also fixes the wallet data volume's ownership. Docker creates named volumes owned by root while the image runs as uid 1000, which would put the wallet into a crash loop on a fresh host.

### Preview host

A big change can go live on a preview host first and then move to the main site. The preview is a second wallet on the same host, served by the same Caddy at its own subdomain (`preview.eudi-test.dev` in the example), with its own data volume and its own release. Point the subdomain's DNS at the same host (a CNAME to the main domain is enough) and add its URL to `deploy.env`.

```bash
# in deploy.env, alongside DEMO_HOST and DEMO_URL:
PREVIEW_URL=https://preview.demo.example

./deploy.sh preview v2.1.0   # run v2.1.0 on the preview host, main site untouched
./deploy.sh verify           # checks the main site and the preview host
./deploy.sh promote          # move the main site to the release the preview runs
./deploy.sh logs preview     # follow the preview wallet log
```

`preview` copies the stack (the Caddy preview block and the `wallet-preview` service), prepares the preview data volume, pins its release as `PREVIEW_TAG` in the host's `.env`, starts the preview wallet, and reloads Caddy gracefully so the main site stays up. Without a tag it runs `latest`, so the preview mirrors the newest release until a change is pinned. `promote` reads the version the preview reports and moves the main site to exactly that image, recording the release it replaces so `rollback` still works.

### Strict conformance host

The certification target for the OIDF wallet plans is a third wallet on the same host, served at its own subdomain (`strict.eudi-test.dev` in the example). It runs in strict mode with HAIP enforced, auto-accept, and the default PID baseline. The Caddy block allows only GET and HEAD. The public origin serves what the conformance suite and other counterparties consume (issuer metadata, status list, CRL, trust lists, the CA certificate, GET `/authorize` requests) and nobody on the internet can change settings or state. The conformance harness reaches the management API through an SSH tunnel to the wallet's loopback-published port (`127.0.0.1:18086` on the host). Its release is pinned independently with `STRICT_TAG`, and its OID4VCI redirect URI points at the fixed suite alias `oid4vc-dev-vci-strict` on the production conformance service.

```bash
# in deploy.env, alongside DEMO_HOST and DEMO_URL:
STRICT_URL=https://strict.demo.example

./deploy.sh strict v2.3.0    # run v2.3.0 on the strict host, main site untouched
./deploy.sh logs strict      # follow the strict wallet log
```

[The conformance runbook](./conformance-run.md) describes the run against it.

## Usage statistics

The compose example includes an optional usage report. Caddy writes an access log with the client address anonymized at write time (`ip_mask` zeroes the last IPv4 octet and the last 80 bits of IPv6, for both `remote_ip` and `client_ip`). [GoAccess](https://goaccess.io) turns that log into a static HTML report every two minutes, and Caddy serves it at `/stats` behind basic auth. The pages get no extra JavaScript, the report sets no cookies, and no third party is involved.

```bash
./deploy.sh stats-password   # writes stats.env with a bcrypt hash (gitignored)
./deploy.sh push             # applies it
./deploy.sh stats            # quick summary in the terminal
./deploy.sh stats-reset      # discard the log and start counting from zero
```

Then open `https://your-domain/stats/`. To turn it off, remove the `handle_path /stats*` block from the Caddyfile and the `stats` service. The anonymized log still counts as processed access data, so word your imprint accordingly.

Interpret the numbers with care. Your own testing counts too, and one page load is about a dozen requests (the assets, the state the UI reads, and the event stream it keeps open). `deploy.sh stats` lists pages and API calls separately, and repeats the API calls that changed something (`POST`, `PUT`, `PATCH`, `DELETE`). Those are the interesting numbers. A write is a visitor issuing, presenting, importing or deleting a credential, from the UI, an external wallet, or a test suite. Distinct visitors are approximated from masked addresses, so everyone behind the same `/24` counts once.

### Log bounds

- the access log rotates at 10 MiB, keeps three files and drops anything older than 30 days (about 40 MiB worst case)
- every container caps its own log at 10 MB with three files, through the `logging` anchor in the compose file (Docker's default is unlimited)
- the report only reads the current access log file, so a rotation also caps how far back the statistics reach

## Deployment notes

- Terminate TLS in a reverse proxy (the example uses Caddy with automatic Let's Encrypt) and forward to the wallet's HTTP port. The wallet derives all advertised URLs from `--base-url`.
- Persist a volume at `/home/app/.eudi-dev` (the parent of `wallet/`). The shared CA is stored one level above the wallet directory, and issuer keys must persist across restarts, otherwise verifiers holding the old trust list fail.
- Run exactly one replica. The wallet store is a single-writer file.
- Leave `HTTP_PROXY` and `HTTPS_PROXY` unset in the container. A proxy would bypass the dial time network checks.
- Self-fetches of the public origin (for example a pasted offer pointing at the demo itself) resolve through public DNS. On typical cloud hosts hairpin NAT makes this work. A compose network alias for the public hostname would resolve to a private address and be blocked.
- Keep the rate limiting in the proxy. The compose example's Caddyfile ships active `rate_limit` zones (described above).

## Pointing the CLI at the demo

```bash
eudi wallet use https://eudi-test.dev
```

Management commands (list, issue, delete) then run against the hosted instance. `serve`, `scan` and `register` stay local.
