# Hosting a Public Demo

The wallet server can run as a shared public demo (for example on `https://eudi-test.dev`). Visitors get the full sandbox (issue, present, decode, delete) while the endpoints that control the process or write to the host stay disabled. A working setup lives in [`examples/public-demo/`](../examples/public-demo/).

## Demo mode

```bash
eudi wallet serve --demo --base-url https://eudi-test.dev --status-list --imprint-file imprint.html
```

`--demo` changes the server in four ways:

1. It implies `--auto-accept` and `--pid`. The server runs headless with a known credential baseline.
2. It disables the admin endpoints. `POST /api/shutdown`, `PUT/DELETE /api/templates/{name}`, `POST/DELETE /api/next-error` and `PUT /api/config/preferred-format` return 403. Saving templates through `POST /api/issue` is rejected too. `GET /api/config` stops reporting host paths and the process id.
3. It blocks outbound requests to internal networks. Visitor supplied URLs (credential offers, `request_uri`, trust lists, status lists) are still fetched from the public internet, but connections to loopback, RFC 1918, link local (including cloud metadata endpoints), CGNAT and unique local addresses are refused at dial time. The check runs on resolved IP addresses, so DNS tricks do not bypass it.
4. It resets the wallet periodically. `--demo-reset` (default `1h`, `0` disables) restores the clean baseline (fresh PID credentials, empty activity log). Keys, certificates and URLs survive resets, so trust list and status list URLs stay stable. The UI shows the reset interval in the footer.

## What stays open (accepted risk)

The demo is a shared sandbox by design. Anyone can issue credentials, delete them and watch the activity log. State is shared between all visitors and the periodic reset bounds the mess. The wallet also fetches visitor supplied public URLs (that is what a wallet does), so put rate limiting in front if abuse becomes a concern.

## Base URL and issuer URL

With an https base URL the issuer URL equals the base URL. Status list URIs, `iss`, the `.well-known` metadata and trust list URLs all live on the public origin, and the built-in self-signed HTTPS listener is not started (the reverse proxy owns TLS). With an http base URL the wallet keeps its second self-signed HTTPS listener on port+1 as before.

## Imprint

Hosting a public site in the EU requires an imprint naming the operator. Pass `--imprint-file` with an HTML snippet (name, address, contact). It is served at `/imprint` (also under `/decoder/imprint`) wrapped in a page that includes the EU non-affiliation disclaimer, and the UI footer links to it. The standalone decoder (`eudi serve`) accepts the same flag.

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
