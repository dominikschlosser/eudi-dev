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
4. It checks the EUDI profile in debug mode. `--haip` holds incoming presentations to HAIP 1.0: `response_type=vp_token`, a signed request object delivered through `request_uri` with an `x509_hash:` client id whose value is the SHA-256 of the signing certificate, `direct_post.jwt` or `dc_api.jwt`, DCQL asking only for `mso_mdoc` or `dc+sd-jwt`, both `A128GCM` and `A256GCM` in the verifier's `encrypted_response_enc_values_supported`, and ES256. An unsigned request is accepted over the Digital Credentials API alone, where it carries no `client_id` at all and the platform-reported origin identifies the caller. Issuance is held to the profile as well: an offer that drives the authorization endpoint must find an authorization server that supports the authorization code flow and offers a pushed authorization request endpoint, and that does not advertise PKCE without `S256` or DPoP without `ES256`. A pre-authorized code offer is not rejected for its grant type. **In debug mode a counterparty that breaks a rule produces a warning in the activity log and the flow continues**, rather than being refused, so the demo stays usable against issuers and verifiers still being brought into line. That includes an issuer that requires HAIP of the wallet but offers only unauthenticated access at its token endpoint: the wallet notes the violation and proceeds without client authentication. Both settings are overridable when self-hosting (`--mode strict` to refuse violations, `--haip=false` to drop the profile checks). The built-in demo verifier and issuer are themselves HAIP-compliant. The active settings are visible, read-only, under **Conformance** in the wallet UI header. Only a locally-hosted wallet can change them.
5. It resets the wallet periodically. `--demo-reset` takes an interval (`24h`), a daily wall-clock time (`00:00`), or one with a timezone (`"00:00 Europe/Berlin"`). `0` disables it. A wall-clock schedule keeps the reset at the same local time every day instead of drifting with each restart, and follows DST. Resets restore the clean baseline (fresh PID credentials, empty activity log) while keys, certificates and URLs survive, so trust list and status list URLs stay stable. The UI footer shows the schedule.

## Browser hardening

A shared wallet renders one visitor's data in another visitor's browser, so the server sends `Content-Security-Policy` (scripts from this origin only, no inline script, no framing, no `<base>` rewriting), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer` on every response. The UI escapes values for attribute contexts as well as text, so a credential cannot inject markup through a status list URI, a `vct`, a claim name or a credential configuration id. The consent event stream is same-origin only.

## What stays open (accepted risk)

Every wallet server also hosts a demo issuer at `/issuer` and a demo verifier at `/verifier`. The issuer hands out a Demo Event Ticket through a real OpenID4VCI pre-authorized code flow, which HAIP permits: §4 requires an issuer to support the authorization code flow but does not require using it for every credential. It also offers the authorization code flow itself (see below), so the profile's client authentication can be exercised. The verifier requests and cryptographically verifies presentations of the ticket or the PID through OpenID4VP, following HAIP 1.0: it signs its authorization request (served by reference from `/verifier/request/{id}`), identifies itself with an `x509_hash:` client id derived from its signing certificate, and receives the response encrypted as `direct_post.jwt` with a per-request key. Together they make the public demo usable out of the box (issue, then present, all in the browser) and serve as protocol counterparties for external wallets that can reach the server. Offers and verification requests are in-memory and expire after ten minutes, and each verification request accepts exactly one answer.

The verifier page has a PID format toggle. By default a PID request asks for the SD-JWT VC or the mdoc and the wallet answers with whichever it holds. Picking one format asks for that one alone, so a wallet that cannot answer says so (which is what makes a format mismatch visible at all). The ticket takes no format because the demo issuer only issues it as an SD-JWT VC.

The issuer page has a status list toggle. With it on, the ticket carries a reference to the wallet's own status list (one reserved index per ticket), so the credential arrives in the wallet as revocable and the demo verifier rejects the next presentation once it is revoked. With it off the ticket carries no status reference at all.

The wallet UI pages the credential list (ten per page), so a demo that accumulated hundreds of credentials between resets stays usable and does not ship the whole list to every visitor on load.

The demo seeds four PID credentials: the country-independent EUDI PID (`urn:eudi:pid:1`) and the German PID that extends it (`urn:eudi:pid:de:1`), each as an SD-JWT VC and an mdoc. The two carry different attributes, each following its own rulebook.

The verifier page has a button for each. The PID request (`#request-pid`) names `urn:eudi:pid:1`, which both credentials answer, and the wallet presents one of them. The German PID request (`#request-pid-de`) names `urn:eudi:pid:de:1`, which the German credential answers. This is [credential type inheritance](wallet.md#credential-type-inheritance) in both directions.

`POST /verifier/api/requests` takes the type as `vct`, and accepts any type in `urn:eudi:pid:` (`urn:eudi:pid:fr:1` works the same). A request naming a domestic type is SD-JWT VC only, since every PID shares the mdoc doctype `eu.europa.ec.eudi.pid.1`.

All four are marked protected: the UI, the API and the CLI refuse to delete or revoke them, so a visitor emptying the wallet cannot leave the demo without a baseline. Everything a visitor issues afterwards behaves normally and can be deleted. Clearing the flag needs direct access to `wallet.json`.

The demo is a shared environment by design. Anyone can issue credentials, delete them and watch the activity log. State is shared between all visitors and the periodic reset bounds the mess.

The compose example rate limits per client address in Caddy, which is the component that sees the real address (the wallet behind it sees the proxy). Its image is built from the `Dockerfile` next to the compose file, because the plugin that does this is not in the standard Caddy image. Three zones apply, each answering `429` with `Retry-After`:

| Zone | Requests | What it covers |
|---|---|---|
| `flows_burst` | 120 per minute | The endpoints that make the wallet fetch a URL somebody handed it or grow state until the next reset: presentations, offers, issuance, imports, refreshes, deferred collection, demo issuer offers, verification requests |
| `flows_hour` | 2000 per hour | The same endpoints, so a loop left running stays bounded between resets |
| `site` | 1200 per minute | Everything else, including the UI and the stats report |

They are ceilings against abuse rather than traffic shaping. An idle wallet page is about 14 requests (updates arrive over one long-lived event stream) and a busy visitor with three tabs open, issuing and presenting, produced 36 in a minute, so a browser, a test suite driving the HTTP API, and everyone behind a single office address fit under them together. A deployment that puts something other than this Caddy in front should carry the same limits there.

## Base URL and issuer URL

With an https base URL the issuer URL equals the base URL. Status list URIs, `iss`, the `.well-known` metadata and trust list URLs all live on the public origin, and the built-in self-signed HTTPS listener is not started (the reverse proxy owns TLS). With an http base URL the wallet keeps its second self-signed HTTPS listener on port+1 as before.

## Client identity for authorization-code issuance

A public demo should also be usable as a wallet by external issuers, and HAIP issuance runs the authorization code flow. That flow needs both `--vci-client-id` and `--vci-redirect-uri`, otherwise the wallet rejects the offer before it reaches the pushed authorization request and the issuer never sees a wallet attestation. The example deployment uses the demo origin as the client id and the wallet's own callback endpoint as the redirect URI:

```
--vci-client-id https://eudi-test.dev --vci-redirect-uri https://eudi-test.dev/callback
```

Issuers that require registration should register exactly those two values. Pre-authorized code offers work without either flag and carry no client attestation.

Both flags default to the wallet's own origin (`--base-url`, plus `/callback`), so an authorization code offer works without configuring anything. Pass them explicitly when an issuer registered you under a different client id.

## The demo issuer as an authorization server

The demo issuer also runs the authorization code flow, with itself as the authorization server. Its metadata (`/.well-known/oauth-authorization-server/issuer`) advertises what HAIP requires: pushed authorization requests required, PKCE S256, DPoP, and the two client authentication methods of [OAuth 2.0 Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/) draft 10 (`attest_jwt_client_auth` and `attest_jwt_client_auth_dpop`), together with the signing algorithms and proof of possession methods that document requires alongside them. The endpoints are `/issuer/par`, `/issuer/authorize` and `/issuer/token`.

The key-proof challenge comes from the Nonce Endpoint that OpenID4VCI 1.0 §7 defines. The issuer serves it at `POST /issuer/nonce` and advertises it as `nonce_endpoint` in its Credential Issuer metadata, and its token responses carry no `c_nonce`, which is a draft-era parameter the final specification does not define. A proof signed over a stale nonce is answered with `invalid_nonce`, which tells a wallet to fetch a fresh one and retry rather than to give up.

Authentication is one hardcoded account, **alice / alice**, printed on the login page. It is a demo, not an account system: no registration, no stored user data, no session beyond the flow it belongs to.

The sign-in happens during redemption, not before it. The **Authorization code offer** button creates an offer with nobody signed in. The wallet then runs the pushed authorization request, and only at the authorization endpoint is the user asked to authenticate. That is where the authorization code flow puts it, and it means the credential is bound to whoever completed the login rather than to whoever created the offer.

The wallet never opens a browser itself. The browser that matters belongs to the user, and on a hosted wallet it is not on that machine. It hands the authorization URL to whoever is holding the user's attention: the tab that started the flow (an `authorize` event on `/api/requests/stream`), which navigates, or an API caller, which gets `202 authorization_required` with the URL and an `offer_id`. The flow stays open either way. The issuer redirects back to the wallet's `/callback`, which resumes it and returns the visitor to the wallet UI.

The callback is matched by `state` alone, so the sign-in can happen in any browser that can reach the wallet. That is what lets `eudi wallet accept` complete an authorization code offer against the hosted demo: the CLI opens the URL locally and follows the flow at `GET /api/offers/{offer_id}` until it reports `completed` or `failed`.

The pushed authorization request and the token request must both carry a wallet attestation, and the demo issuer verifies it rather than waving it through: the PoP has to be signed by the attested key, and `sub`, `aud`, `jti` and the expiry have to line up. Possession of the attested key can be proven either way the draft allows, with a dedicated `OAuth-Client-Attestation-PoP` JWT or with the DPoP proof the request already carries (`attest_jwt_client_auth_dpop`), where the issuer checks that the DPoP key is the one the attestation attests. The access token is bound to the DPoP key and the credential request has to prove that key again. The ticket then carries the name of the account that signed in, so a flow that skipped the login is visible in the result.

### Wallets from other providers

An attestation is signed by a wallet provider, and this issuer was given exactly one CA, the wallet it is mounted on. Refusing every other attester would mean the authorization code flow can only ever be completed by this project's own wallet, which is no use to anybody testing their own. So an attestation whose certificate does not chain to that CA is accepted on its own leaf and marked instead: the issued ticket carries a `wallet_attestation` claim saying `trusted` (the chain reached the CA), `untrusted` (it did not) or `none` (the client authenticated with nothing). A production issuer resolves the wallet provider's trust list and pins the CA it finds there, which is what `/api/trustlists/wallet-provider` publishes for this wallet.

A wallet that has no attestation to send at all is still refused, because HAIP 1.0 §4.4.1 says it must be ("Wallets MUST use, and Issuers MUST require, an OAuth2 Client authentication mechanism at OAuth2 Endpoints that support client authentication"), and demonstrating that is most of the point of this issuer. To test such a wallet, start the server with `--demo-issuer-client-auth optional`. The authorization server then also advertises and accepts `none`, an attestation is still verified wherever one is sent, and the ticket says how the flow actually went.

## What an issuer needs to verify the wallet

On the authorization-code path the wallet authenticates with attestation-based client authentication and sends both headers on the pushed authorization request and on the token request:

- `OAuth-Client-Attestation`, signed by the wallet's issuer key (`sub` is the client id, `cnf.jwk` is the wallet's holder key, and `iss` names the wallet origin, which draft 10 no longer requires but does not forbid). Its `x5c` header carries the leaf certificate only, the self-signed root is stripped.
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

The demo sets no cookies. It keeps a theme preference and a dismissed-banner flag in the browser's `localStorage` (no personal data, no tracking, no third parties). Under the ePrivacy Directive that is strictly-functional device storage, so it needs no consent, but you may still mention it in your imprint or privacy notice.

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
./deploy.sh rollback  # put the release that was live before that back
./deploy.sh status    # container status plus the version the site reports
./deploy.sh verify    # check that every public endpoint answers
./deploy.sh logs      # follow the wallet log
```

`rollback` covers the case where a release turns out to be wrong once it is in front of people. `push` and `update` record the release they replace, so `rollback` on its own puts that one back, and `rollback v1.19.16` names any release directly. It pins `WALLET_TAG` in the host's `.env`, which is where the compose file reads the image tag from, so the choice survives a restart. The image is pulled before anything is switched, so naming a release that was never published leaves the running demo alone. A later `update` clears the pin and returns to the newest release.

`setup` also fixes the wallet data volume's ownership. Docker creates named volumes owned by root while the image runs as uid 1000, which otherwise sends the wallet into a crash loop on a fresh host.

## Usage statistics

The compose example ships an optional usage report, so you can tell whether the demo is actually used. It is not analytics: Caddy writes an access log with the client address anonymized at write time (`ip_mask` zeroes the last IPv4 octet and the last 80 bits of IPv6, for both `remote_ip` and `client_ip`), [GoAccess](https://goaccess.io) turns that log into a static HTML report every five minutes, and Caddy serves it at `/stats` behind basic auth. No JavaScript is added to the pages, the usage report itself sets no cookies, and no third party is involved.

```bash
./deploy.sh stats-password   # writes stats.env with a bcrypt hash (gitignored)
./deploy.sh push             # applies it
./deploy.sh stats            # quick summary in the terminal
./deploy.sh stats-reset      # discard the log and start counting from zero
```

Then open `https://your-domain/stats/`. Remove the `handle_path /stats*` block from the Caddyfile (and the `stats` service) to turn the whole thing off. If your imprint claims that no access data is processed, adjust it: the log exists, even anonymized.

Read the numbers with care. Your own testing counts too, and one page load is about a dozen requests (the assets, the state the UI reads, and the event stream it keeps open for updates). `deploy.sh stats` therefore lists pages and API calls separately, and among the API calls it repeats the ones that changed something (`POST`, `PUT`, `PATCH`, `DELETE`). Those are the interesting number: a write is somebody issuing, presenting, importing or deleting a credential, whether from the UI, an external wallet, or a test suite. Distinct visitors are approximated from masked addresses, so everyone behind the same `/24` counts once.

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
