# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.18.2] - 2026-08-03

### Added

- An original project logo (an open wallet holding an ID credential, with a terminal prompt on the pocket, drawn from scratch in the project palette, no relation to EU emblems): shown in the README, in every UI header (wallet, decoder, demo issuer, demo verifier), and served as the favicon by all of them
- All open wallet UI tabs now update live: the server broadcasts a state event on the SSE stream after every persisted change, and each UI refreshes credentials, status badges, and the activity log immediately (bursts are coalesced). Consent dialogs stay scoped to the browser that started the flow

## [1.18.1] - 2026-08-03

### Fixed

- Consent dialogs are scoped to the browser that started the flow. The browser redirect now carries the consent request id (`/?request=<id>`) and the UI auto-opens exactly that request. In demo mode, other visitors' requests no longer pop up in every open tab (they could previously be triggered and approved from any browser); outside demo mode the previous auto-open behavior remains for requests arriving via schemes or the API
- The decoder no longer renders short digest values (`sd_hash` and other 32-byte digests) as clickable embedded mDOC links. Their random first byte often happened to look like a CBOR type marker, so the embedded-credential detection now requires at least 64 decoded bytes

## [1.18.0] - 2026-08-03

### Changed

- Consent semantics are now per channel. `--auto-accept` still forces auto-accept everywhere. Without it, programmatic submissions (`POST /api/offers`, `POST /api/presentations`) auto-accept too, because the API call itself is the caller's consent, while interactive channels keep the consent dialog: the web invocation URLs (`GET /credential-offer`, `GET /authorize`), scheme dispatches (`openid4vp://`, `openid-credential-offer://` and synonyms, unless registered with `wallet register --auto-accept`), and browser DC-API flows. Both API endpoints accept `"interactive": true` to opt a submission back into the consent dialog (the macOS URL handler uses this)
- The public demo no longer forces auto-accept: visitors clicking offer or authorize links now see the wallet's real consent dialog, while the demo stays a reliable auto-accepting counterparty for external issuers, verifiers, and CLI clients using the API
- Demo mode serves only the newest 50 activity log entries via `GET /api/log`, since a shared wallet accumulates entries from every visitor between resets. Local instances stay unbounded

## [1.17.1] - 2026-08-03

### Fixed

- Links inside dialogs (How to use, Get the CLI) and other unstyled containers in both web UIs fell back to the browser default dark blue, which is unreadable on the dark theme. Both stylesheets now set a base link color from the theme palette
- Deleting a credential or changing its status in the wallet UI refreshes the activity log immediately (the new management entries only appeared after a page reload)
- UI static assets are served with `Cache-Control: no-cache`. Embedded files carry no modtime, so responses had no cache validators at all and browsers could keep stale JavaScript across releases (for example a "Get the CLI" link from a new page with the old script, doing nothing). A hard reload fixes affected browsers once, the header prevents it from recurring

## [1.17.0] - 2026-08-03

### Added

- Built-in demo issuer and demo verifier, mounted on every wallet server under `/issuer` and `/verifier` (so the public demo works out of the box). The issuer is a minimal OpenID4VCI issuer (pre-authorized code flow) handing out a Demo Event Ticket SD-JWT VC, holder bound to the wallet's proof key and signed under a leaf certificate from the wallet CA, so the wallet's own trust list covers it. The verifier creates plain-parameter OpenID4VP requests (`dcql_query`, `direct_post`) for the ticket or the PID and cryptographically verifies the response (issuer chain against the wallet CA, key binding signature, `sd_hash`, nonce, audience), showing each check and the verified claims. Both have small UI pages and also work with external OID4VCI/OID4VP clients that can reach the server
- `examples/keycloak-web-wallet-public`: the `keycloak-web-wallet` scenario against the shared public demo wallet (`https://eudi-test.dev` by default, any `--demo` deployment via `WALLET_BASE_URL`). Local Keycloak is exposed through an ngrok tunnel (or a URL supplied via `KEYCLOAK_PUBLIC_URL`) because the public wallet fetches the request object and calls the token endpoint server side. Realms, extension jar, demo UI, and scripts are reused from the local example

- Credential management actions now always appear in the wallet activity log with a `management` action: issuing (including PID regeneration), deleting one or all credentials, and revoking or activating a credential's status entry
- Demo mode shows a prominent dismissible banner in the wallet UI: the instance is shared, anyone can change or delete credentials, it is for demonstration only, and isolated testing should use your own instance. The dismissal is remembered per browser
- The wallet UI header gained a "How to use" dialog. It states that the wallet is fully OID4VC compliant, lists the protocol endpoints with the wallet's own origin filled in (`/credential-offer`, `/authorize`, `/api/trustlist`), and shows how custom-scheme links map onto them (CLI `wallet accept` on any platform, `wallet register` system handlers on macOS)

### Changed

- The decoder's "Get the CLI" header link opens the same install dialog as the wallet UI (Homebrew, Go, Docker, binaries) instead of navigating to GitHub
- The wallet UI hides the TLS certificate downloads when an external TLS terminator serves the issuer origin (as on the public demo). The built-in HTTPS listener is disabled in that mode, so the exported self-signed leaf is never presented on the wire and downloading it would only mislead. `/api/config` gains a `tls_listener` field, and the CA downloads stay (they are the credential trust anchor, independent of TLS termination)

## [1.16.4] - 2026-08-03

### Changed

- The demo footer note now says "Public demo" instead of "Public sandbox", and the docs follow. "Sandbox" is the name of the official German EUDI test ecosystem, so the public demo no longer uses the term for itself
- Improved text contrast in both web UIs. Dimmed text (subtitles, pane headers, hints, placeholders) was well below WCAG AA in both themes (2.4 to 2.8 to 1) and is now at least 4.5 to 1, and the light theme accent color was darkened to pass as well

## [1.16.3] - 2026-08-03

### Changed

- Demo mode (`wallet serve --demo`) hides the Templates button in the wallet UI. The dialog was read only there anyway (template writes are rejected with 403), so it only added clutter for visitors
- The embedded decoder page shows a disclaimer in demo mode that pasted input is sent to the server for decoding (decoding happens server side, so visitors should not paste credentials containing real personal data)

## [1.16.0] - 2026-08-03

### Added

- `wallet serve --demo`: hardened profile for hosting a shared public demo. Implies `--auto-accept` and `--pid`, disables the process and filesystem endpoints (`/api/shutdown`, template writes including `save_as_template`, `/api/next-error`, preferred-format changes) with 403, redacts host paths and the pid from `/api/config` and `/api/version`, caps request bodies, and blocks server-side fetches to internal networks (loopback, RFC 1918, link local including cloud metadata, CGNAT, unique local) at dial time so visitor supplied URLs cannot reach the host's private network
- `wallet serve --demo-reset <duration>` (default `1h`): periodically restores the clean demo baseline (fresh PID credentials, empty activity log) while keeping keys, certificates, and serving URLs stable. The UI footer shows the reset interval
- `wallet serve --imprint-file <path>` and `serve --imprint-file <path>`: serve an operator supplied legal notice at `/imprint` (EU hosting requirement), wrapped in a page that includes the EU non-affiliation disclaimer. The wallet and decoder UI footers link to it when configured
- Both web UIs link to GitHub and CLI install instructions in the header, and show the release version (plus the imprint link when configured) in a footer. The wallet UI shows trust list URLs (with copy buttons) above the certificate downloads, since verifiers need the trust list to trust self-issued credentials
- Deployment recipe for public hosting: `docs/public-demo.md` and `examples/public-demo/` (Caddy with automatic TLS in front of the wallet)

### Changed

- An https `--base-url` now becomes the issuer URL directly: status list URIs, `iss`, `.well-known` metadata, and trust list URLs all live on the public origin, and the built-in self-signed HTTPS listener is skipped (an external TLS terminator is assumed). Http base URLs keep the previous port+1 behavior

### Fixed

- The decoder's `/api/validate` no longer reads server-side files when `trustListURL` is a local path, and remote fetches are capped at 10 MB
- `scripts/build.sh` stamped the version into the pre-rename module path, so builds made with it always reported `dev`. It now builds the `eudi` binary with the correct ldflags path and installs completions under that name
- Documentation screenshots and the flow diagrams were refreshed for the current UI and the `eudi-dev` name
- Issue dialog: switching between templates without issuing no longer submits a merge of all previously selected templates (stale VCT, doc type, and expiry are cleared when the new template omits them), and selecting `(none)` resets the form

## [1.15.5] - 2026-08-03

### Fixed

- Local and remote wallet management now share one code path. Every management command (`wallet list|show|import|remove|logs|ca-cert|tls-cert|info`, `issue ... --wallet`, and all `templates` commands) operates on a single wallet service with a local store backend and a REST backend, so the output is identical no matter where the wallet lives. Previously each command had two separate implementations that could and did drift
- `issue ... --wallet` against the local store resolves templates and claims through the same request contract as the server's `POST /api/issue`, removing a duplicated resolution path that could behave differently from issuance on a running instance
- `wallet scan` imported a scanned credential by writing the store files directly, even while a running server owned the wallet directory. It now routes through the managed wallet like every other command, keeping one writer per wallet directory
- The `ACTIVE` column of `wallet instances list` now marks the instance the CLI actually manages. Previously only an explicitly selected remote target got the mark, while an auto-routed instance (a running server serving the local wallet directory) showed as inactive despite handling every command. The `--json` output gains an `active` field with the same information
- Remote commands no longer print `Managing remote wallet <url>` on stderr for every invocation, so command output can be scripted without filtering. Check the managed target with `wallet instances use` (without arguments), `wallet info`, or the `ACTIVE` column of `wallet instances list`. The `Routing through the running wallet instance ...` notice for auto-routing remains
- Certificate export with `--out` prints the written file path to stdout for remote wallets too (previously a different message went to stderr), and template save and delete messages read the same in both modes

## [1.15.4] - 2026-08-03

### Fixed

- The macOS URL scheme handler works with a remote wallet target. Clicked links are submitted to the active remote instance, and the handler opens the remote consent UI on this desktop before submitting (a wallet in a container cannot open a browser here, and the submit blocks until the request is decided). A failed remote submit no longer falls back to processing the link locally, which would have handled the offer a second time
- `wallet instances list` includes the active remote target even when it is not locally discoverable (for example a wallet in a Docker container). It is health checked and listed with source `active`, with pid, build id, and wallet directory taken from its introspection endpoint
- `wallet.json` is written atomically (write then rename), so a crash or a concurrent writer never leaves a truncated or interleaved file behind

## [1.15.3] - 2026-08-02

### Fixed

- One writer per wallet directory: when a running wallet server serves the same wallet directory, CLI commands now route through its REST API automatically (with a `Routing through the running wallet instance ...` notice on stderr) instead of writing the store files directly. Previously a CLI issuance next to a running server silently rewrote the persisted serving URLs and produced credentials pointing at endpoints the server does not serve. `--remote local` or an explicit `--templates-dir` still forces direct file access
- Issuance no longer rewrites persisted serving config: `wallet generate-pid` and `issue ... --wallet` keep existing `base_url` and `issuer_url` values unless `--base-url` or `--docker` is passed explicitly, and only derive defaults for a fresh wallet. When no server is running they print a note that the embedded URLs resolve once `wallet serve` runs. A registered URL scheme listener no longer rewrites Docker issuer URLs to localhost
- Offline validation via embedded certificates: `validate` and `decode` verify signatures against the credential's x5c (SD-JWT/JWT) or x5chain (mDOC) leaf certificate when no trust list is given, instead of failing on an unreachable `/.well-known/jwt-vc-issuer` endpoint. The output notes that the chain was not validated. With a trust list the chain validation behaves as before and is never downgraded to a leaf-only pass
- The web decoder uses the local wallet's CA as an implicit trust anchor, so credentials issued by the local wallet show a fully verified chain without configuration
- `wallet serve` warns at startup about serving config that cannot work: a persisted Docker hostname outside Docker, and stored credentials whose embedded issuer or status list URLs this server does not serve
- `wallet info` warns when a running instance and the wallet file disagree on serving URLs (the instance keeps its startup config until restarted)
- The wallet UI screenshots in the documentation show a realistic session with an imported credential plus full OID4VCI issuance and OID4VP presentation activity, instead of an empty activity log

## [1.15.2] - 2026-08-02

### Fixed

- Homebrew tap publishing now runs automatically on tagged releases (the repository token is configured). The 1.15.1 formula was published manually, from this release on the workflow keeps the tap current

## [1.15.1] - 2026-08-02

### Added

- Homebrew installation: `brew install dominikschlosser/tap/eudi-dev` installs the `eudi` command with shell completion and the `oid4vc-dev` legacy alias. The release workflow updates the tap formula automatically on each tagged release

### Fixed

- CI test failures on clean environments: the default wallet directory test asserted the legacy `.oid4vc-dev` path, which only held on machines where the legacy state directory exists. The test now verifies both the fresh `.eudi-dev` default and the legacy fallback with a controlled home directory
- Documentation screenshots refreshed for the renamed EUDI Dev Wallet and EUDI Dev Decoder UIs

## [1.15.0] - 2026-08-02

### Changed

- The project is renamed from oid4vc-dev to **eudi-dev** and the CLI command is now **`eudi`**. The Go module moved to `github.com/dominikschlosser/eudi-dev`, releases ship `eudi` binaries, the Docker image is `ghcr.io/dominikschlosser/eudi-dev`, and the state directory is `~/.eudi-dev` (`EUDI_DEV_HOME` overrides it). The wallet and decoder UIs are titled EUDI Dev Wallet and EUDI Dev Decoder
- The old name keeps working for the time being: a binary named `oid4vc-dev` behaves identically (help and shell completion adapt to the invoked name, and the Docker image contains it as a second name), an existing `~/.oid4vc-dev` state directory keeps being used when `~/.eudi-dev` does not exist, `OID4VC_DEV_HOME` is still honored, instance discovery finds wallets running under either name, and `ghcr.io/dominikschlosser/oid4vc-dev` keeps receiving releases. Note that `go install` of new versions requires the new module path

## [1.14.1] - 2026-08-02

### Added

- Shell completion for bash, zsh, fish, and powershell, including dynamic completion of known values: template names (local or active remote), credential IDs (with their type as description), running wallet instances for `wallet instances use|kill` and `--remote`, plus static value flags (`--format`, `--trust-profile`, `--mode`). `completion install [bash|zsh|fish]` wires it into the shell init (source line in `.bashrc` or `.zshrc`, completion file for fish) and detects the shell from `$SHELL`

### Changed

- The instance lifecycle commands moved under one command group: `wallet instances list` (also reachable as plain `wallet instances`), `wallet instances use <url|local>`, and `wallet instances kill <pid|port|url>`. The previous top level `wallet use` and `wallet kill` commands are gone. This keeps credential commands (`wallet list`) clearly separated from instance commands

## [1.14.0] - 2026-08-02

### Added

- Remote control for the CLI: the management commands can operate on a running oid4vc-dev wallet server over its REST API instead of the local store. `wallet use <url>` switches management to a remote instance (persisted until `wallet use local`), `--remote <url>` targets one for a single invocation, and remote commands print the target to stderr. Remote mode covers `wallet list|show|import|remove|generate-pid|logs|accept|ca-cert|tls-cert|info`, `issue ... --wallet`, and all `templates` commands (templates resolve against the remote instance's template directory)
- Wallet instance discovery and lifecycle: `wallet instances` scans the local system for running wallet servers (instance registry plus process scan, health checked via `GET /api/version`), `wallet kill <pid|port|url>` (or `--all`) stops instances via the new `POST /api/shutdown` endpoint with a SIGTERM fallback, and `wallet use` switches management to any of them. Every `wallet serve` registers itself in `~/.oid4vc-dev/instances/` and deregisters on shutdown
- Instance introspection: `GET /api/config` now returns the full instance document (pid, port, build id, wallet and template directories, base, issuer, and status list URLs, preferred format, validation mode, auto accept, session transcript, HAIP and encryption toggles, credential count), and the new `wallet info` command prints it for the managed wallet
- Status list visualization and handling in the wallet UI: credential cards show a status badge when a credential carries a status list reference. Credentials on the wallet's own status list get a live Active or Revoked badge plus Revoke and Activate buttons. Credentials referencing an external status list get a Check status action that fetches and resolves the current value. The issue dialog gained a status list selector (wallet list, none, or custom URI and index). New API surface: credential summaries include a `status` object (`uri`, `idx`, `managed`, `status`) and `GET /api/credentials/{id}/status` resolves the live status (from the wallet's list or by fetching the external one)
- The wallet UI is fully automatable with browser testing frameworks: every interactive control has a stable element id and credential cards expose `data-credential-id`, `data-format`, `data-vct`, `data-doctype`, and `data-status` selection attributes. Template manager rows and consent dialog elements carry equivalent ids and data attributes
- Credential templates: named, reusable claim sets with per-format defaults (VCT or doc type, namespace, expiry) usable across the CLI, the HTTP API, and the wallet UI. New `templates list|show|save|import|delete` commands manage them, `issue sdjwt|jwt|mdoc --template <name>` issues from one (with `--claims` overriding individual claims), `--save-template <name>` saves the issued parameters as a template, and templates are shareable as single JSON documents (`templates show` to export, `templates import` for a file, JSON string, or stdin). The wallet server exposes the same store via `GET/PUT/DELETE /api/templates[/{name}]` plus `template` and `save_as_template` fields on `POST /api/issue`, and the wallet UI adds a template dropdown in the issue dialog and a Templates manager for editing, importing (paste JSON), and deleting. User templates live in the wallet directory's `templates/` subdirectory (pre-defined templates are compiled in) and a user template saved under a pre-defined template's name overrides it. `--templates-dir` on the wallet, issue, and templates commands points them at any directory instead, so a project folder or container mount of template files works as a self-contained setup
- The hardcoded EUDI PID claim sets moved into pre-defined credential templates (`german-pid-sdjwt`, `german-pid-mdoc`). `issue --pid`, `wallet generate-pid`, and `POST /api/generate-pid` all resolve through the template system now, so overriding those templates changes what every PID path issues
- SD-JWT claims can be issued without selective disclosure: `--always-disclosed` on `issue sdjwt` (or `always_disclosed` in templates and `POST /api/issue`) embeds the named claims plainly in the signed payload so they are always visible and cannot be withheld during presentation. Nested subclaims use dotted paths (`address.country`), which keep the parent selectively disclosable while pinning the subclaim inside its disclosure. The default is unchanged (every claim selectively disclosable). The wallet UI exposes this as a per-claim SD checkbox in the claim builder (JSON mode shows the same list as an "Always visible" field that also accepts dotted paths). mdoc rejects the option (every element is selectively disclosable in ISO 18013-5) and JWT VC ignores it

### Removed

- The issue dialog's "Fill with EUDI PID defaults" preset button and its `GET /api/issue/defaults` endpoint: the template dropdown with the pre-defined `german-pid-sdjwt` and `german-pid-mdoc` templates replaces both (`GET /api/templates` serves the same data)
- The `trust_anchor` element from the pre-defined mDoc PID claims: it was an artifact copied from real issuer samples and is meaningless for self-issued test credentials

### Deprecated

- `wallet generate-pid` and `POST /api/generate-pid`: issue from the pre-defined PID templates instead (`issue sdjwt --wallet --template german-pid-sdjwt`, `issue mdoc --wallet --template german-pid-mdoc`, or `POST /api/issue` with `template`). Both still work but will be removed in a future release. The CLI prints the equivalent template commands and the API responds with a `Deprecation: true` header

### Fixed

- Status checks and other local fetches against `host.docker.internal` URLs now fall back to `localhost` when the Docker alias does not resolve on the host. Credentials issued by Docker-facing wallets (whose status list URI points at `host.docker.internal`) previously failed the status check in the decode UI and `validate` when inspected on the host itself
- `wallet generate-pid` and `wallet serve --pid` skipped the status list reference when only an issuer URL (and no explicit base URL) was configured, while `POST /api/issue` embedded it. Both now use the same status list resolution, so default PID generation produces revocable credentials out of the box
- Flaky e2e runs in CI: docker.spec.js mapped its container to host port 18925, which the wallet spec's server binds as its HTTPS port (port+1), and spec files run in parallel workers. The docker spec now uses a free port. The issue-dialog tests also raced against the wallet UI's error overlay left behind by earlier negative API tests. The issuing tests now clear the last error and pending consent requests before each test

## [1.13.0] - 2026-08-01

### Added

- Wallet UI: credentials can now be issued from the web UI. The Issue Credential dialog shows format specific fields (VCT for SD-JWT and JWT VC, doc type and a per-attribute namespace column for mDoc), a claim builder kept in two-way sync with an alternative raw JSON mode, expiry, and not-before. Switching the format resets the other fields. A preset button fills all fields with the EUDI PID defaults so they can be reviewed and edited before issuing. A Certificates row links to the CA and TLS certificate exports (PEM or JWKS). Every control has a stable element id so the UI is easy to automate with browser testing frameworks
- mDoc issuance supports multiple namespaces: claim keys of the form `namespace:element` place single attributes in their own namespace (CLI `--claims`, `POST /api/issue`, and the wallet UI claim builder)
- Wallet management HTTP API: every wallet CLI operation is now also available on a running `wallet serve` instance. This lets automated tests manage and drive a hosted or containerized wallet entirely over HTTP. New endpoints: `GET /api/credentials/{id}` (show), `DELETE /api/credentials` (remove all), `POST /api/issue` (issue a credential with the wallet's issuer key and import it, mirroring `issue sdjwt|jwt|mdoc --wallet` including claims and PID presets, expiry, not-before, status-list references, and trust metadata), `POST /api/generate-pid` (regenerate the default PID pair), and `GET /api/certificates/ca` and `GET /api/certificates/tls` (export the wallet CA or HTTPS leaf certificate as PEM or JWKS). Listing, import, and delete-by-ID already existed. The API intentionally has no authentication (the wallet is a testing tool) and the docs now state this explicitly

## [1.12.3] - 2026-08-01

### Added

- Wallet credential offer endpoint (`GET /credential-offer`): accepts `credential_offer` / `credential_offer_uri` (and optional `tx_code`) query parameters, making offers deliverable to the wallet's own URL instead of the `openid-credential-offer://` custom scheme — together with the existing `/authorize` endpoint, both wallet flows are now fully invocable by plain web URL in hosted environments, automated tests, and on platforms without URL scheme registration
- Browser invocations of `/authorize` and `/credential-offer` (GET with an HTML Accept header) now complete like a same-device wallet: after a presentation the browser is redirected to the verifier's `redirect_uri`, after an offer import to the wallet UI — so a verifier configured with the wallet's URL (e.g. `keycloak-extension-oid4vp` `walletScheme`) runs a standard OIDC round trip end to end; API callers keep receiving JSON. Without `--auto-accept` the navigation redirects to the wallet UI immediately with the consent request pending — the flow finishes in the background once it is approved there (presentations continue to the verifier's `redirect_uri` via the approve response) instead of the browser tab blocking until consent
- Example `keycloak-web-wallet`: Keycloak 26.7.0 issuer, `keycloak-extension-oid4vp` verifier, the wallet, and a demo UI in one Docker compose project sharing one network namespace, so every URL is plain `localhost` for both the host browser and the containers — issuance delivers offers to the wallet's `/credential-offer` URL, and verification is an ordinary OIDC login whose Keycloak login page links straight to the wallet's `/authorize` URL (requires `keycloak-extension-oid4vp` > 0.6.4 for wallet web URLs in `walletScheme`)

### Fixed

- The wallet's credential request advertises `Accept: application/jwt` only when credential response encryption is negotiated; sending it unconditionally made Keycloak 26.6's credential endpoint fail with an internal error (it returns signed issuer metadata when it sees `application/jwt` in the Accept header)

## [1.12.2] - 2026-07-30

### Added

- Wallet batch credential issuance (OID4VCI `batch_credential_issuance`): when an issuer advertises a `batch_size` of 2 or more, the wallet sends multiple proofs with distinct, freshly generated keys, matches the returned credentials to their binding keys regardless of response order, and imports the holder-key-bound credential

### Changed

- Wallet and decoder web UIs unified to a shared look and layout
- Wallet activity log verbosity increased with more detailed per-step entries

### Fixed

- The wallet strips the issuer's terminating `/` when building the `/.well-known/oauth-authorization-server` metadata URL per RFC 8414 §3.1, while continuing to preserve the Credential Issuer Identifier path verbatim for `/.well-known/openid-credential-issuer` per OID4VCI 1.0 §12.2.2
- The wallet ignores verifier `client_metadata.jwks` encryption keys it cannot use (unsupported `kty`/curve or signing-only keys) per RFC 7517 §5 and encrypts to the first usable key, so verifiers can advertise e.g. post-quantum keys ahead of wallet support
- Conformance harness updated to conformance-suite release-v5.2.1: runs the new batch-issuance and unusable-encryption-key wallet modules, and documents the release-v5.2.1 suite-side `invalid-client-id-prefix` module regression as an exclusion

## [1.12.1] - 2026-07-30

### Fixed

- Wallet UI shows stored credentials and allows clearing the activity log

## [1.12.0] - 2026-07-30

### Added

- The macOS URL-handler script detects stale `wallet serve` processes and auto-restarts them

## [1.11.1] - 2026-07-30

### Fixed

- Send `Accept` header on the credential request

## [1.11.0] - 2026-07-26

### Added

- `wallet ca-cert --jwks` and `wallet tls-cert --jwks` export the certificate as a JWKS document (public key with `x5c` chain) instead of PEM, e.g. for pasting into Keycloak trust configuration

### Removed

- removed the dedicated HAIP Keycloak example now that the combined issuer+verifier app covers the HAIP verifier flow

## [1.10.11] - 2026-06-05

### Fixed

- Proxy log output simplified

## [1.10.10] - 2026-06-05

### Fixed

- Do not truncate URLs in the proxy for debugging
- Exclude non-applicable conformance variants, update docs

## [1.10.9] - 2026-06-05

### Fixed

- Some edge cases with multiple wallet instances

## [1.10.8] - 2026-06-05

### Fixed

- Various bugfixes

## [1.10.7] - 2026-06-05

### Fixed

- Local scan

## [1.10.6] - 2026-06-05

### Fixed

- Scan bug

## [1.10.5] - 2026-06-05

### Fixed

- Proxy behavior

## [1.10.4] - 2026-06-05

### Fixed

- Wallet log contents

## [1.10.3] - 2026-06-05

### Fixed

- Wallet logs more fine-grained

## [1.10.2] - 2026-06-05

### Fixed

- Wallet logs expanded/fixed

## [1.10.1] - 2026-06-05

### Fixed

- Wallet store reuse between instances

## [1.10.0] - 2026-06-05

### Added

- `wallet logs` command

### Fixed

- Demo QR code size

## [1.9.5] - 2026-06-05

### Fixed

- Conformance tests / debug mode behavior
- Add local wallet mode to the Keycloak demo

## [1.9.4] - 2026-04-18

### Fixed

- Do not truncate tokens in the proxy

## [1.9.3] - 2026-04-18

### Fixed

- Show POST headers / body in the proxy

## [1.9.2] - 2026-04-18

### Fixed 

- Do not print traffic classified as "unknown" in the proxy by default

## [1.9.1] - 2026-04-18

### Fixed 

- Proxy grouping fixed/improved

## [1.9.0] - 2026-04-18

### Changed 

- Proxy now learns dynamic endpoints as the flow is going on, calls classified as 'unknown' are not logged by default

## [1.8.10] - 2026-04-12

### Fixed

- malformed custom-scheme credential offer links in the Keycloak demo apps by preserving the original `openid-credential-offer://` and `haip-vci://` URIs after scheme validation instead of normalizing them through `url.Parse(...).String()`
- wallet UI manual URI detection so `haip-vci://...` offers are routed to issuance instead of the presentation parser

## [1.8.9] - 2026-04-12

### Fixed

- lint and security issues in the wallet presentation port probing logic by binding temporary listeners to `127.0.0.1` and handling listener close errors explicitly
- Keycloak example offer-link rendering by validating allowed wallet URI schemes before passing them through to the HTML templates

## [1.8.8] - 2026-04-12

### Fixed

- interactive wallet issuance now defers `credential_offer_uri` fetches until after user consent instead of dereferencing remote offers just to render the modal
- interactive wallet issuance now shows imported credentials immediately after approval and surfaces issuance errors in the wallet UI instead of failing silently

## [1.8.7] - 2026-04-12

### Fixed

- interactive wallet issuance after UI approval now reuses the parsed credential offer instead of refetching one-shot `credential_offer_uri` endpoints
- wallet UI issuance approvals now surface errors correctly and refresh imported credentials immediately on success
- Keycloak example offer links now render as the correct custom wallet schemes instead of broken sanitized browser URLs

## [1.8.6] - 2026-04-12

### Changed

- aligned the dedicated HAIP Keycloak example structure and docs with the baseline issuer+verifier example so both are easier to compare as reference setups

### Fixed

- `wallet accept --auto-accept` now reuses an already running wallet server instead of conflicting on the local port
- `wallet accept` without an explicit port now probes the standard wallet port before falling back to a one-shot server
- HAIP example helper layout and related scripts/build wiring were cleaned up

## [1.8.5] - 2026-04-11

### Added

- a new dedicated HAIP Keycloak example covering HAIP-style authorization-code issuance and x509-based verifier authentication
- wallet support for interactive authorization-code issuance callbacks via the local `/callback` endpoint

### Changed

- simplified and cleaned up the Keycloak example set so the demo apps and bootstrap flows are easier to follow as reference implementations
- expanded the OIDF conformance runner coverage for Browser API and HAIP flows

### Fixed

- Browser API handling for multisigned OpenID4VP request objects
- mdoc Browser API session transcript generation for `dc_api` / `dc_api.jwt`
- multiple issuance and verification issues in the combined Keycloak demo flows

## [1.8.4] - 2026-04-11

### Added

- `wallet remove --all` for clearing the stored wallet more easily

### Fixed

- example setup and bootstrap issues in the combined Keycloak issuer/verifier demo
- interactive wallet issuance behavior so headed mode no longer behaves like silent auto-accept
- Keycloak demo support files so generated trust-list and signing material are handled correctly

## [1.8.3] - 2026-04-11

### Changed

- macOS wallet URL-handler behavior now distinguishes between interactive mode and explicit `--auto-accept` background import

### Fixed

- headed issuance flows now surface the wallet instead of silently importing like auto-accept mode
- the combined Keycloak demo app now logs out through Keycloak instead of only clearing the local session

## [1.8.2] - 2026-04-11

### Added

- Keycloak-based example setups for issuer-only, verifier-only, and combined issuance + verification flows
- a combined Keycloak demo app with smoke tests and bootstrap scripts for end-to-end issuance and wallet login flows

### Fixed

- credential-offer and issuer-metadata parsing for the new Keycloak issuance example flows

## [1.8.1] - 2026-04-09

### Fixed

- SIOPv2 only mode and require-encrypted-request was not enforced

## [1.8.0] - 2026-04-09

### Added

- Browser API presentation support at `/api/dc-api` for OpenID4VP `dc_api` and `dc_api.jwt` response modes, including `web-origin:` client binding and wallet-side Browser API result handling
- HAIP wallet conformance coverage for the current OID4VP 1.0 Final and OID4VCI 1.0 Final HAIP plans, including `dc_api.jwt` VP scenarios

### Changed

- the OIDF wallet conformance runner now targets the current OID4VP 1.0 Final, OID4VCI 1.0 Final, and HAIP wallet plans by default
- the wallet now requests `credential_response_encryption` when issuers advertise it and accepts encrypted JWE credential responses in the authorization code flow

### Fixed

- wallet-generated ETSI trust lists now use the required top-level `LoTE` JSON binding wrapper instead of the previously emitted unwrapped payload
- trust-list parsing and format detection now reject the old non-conformant unwrapped trust-list shape
- proxy JWE tests now match the current `EncryptJWE` API so the full suite builds cleanly again

## [1.7.4] - 2026-04-09

### Changed

- updated the conformance runner to target the current OpenID4VP / OID4VCI 1.0 variant names

## [1.7.3] - 2026-04-08

### Fixed

- compatibility with the then-current wallet conformance test suite

## [1.7.2] - 2026-04-08

### Fixed

- authorization errors are now returned to the verifier instead of being dropped locally
- `direct_post.jwt` responses now preserve `state`

## [1.7.1] - 2026-03-22

### Fixed

- trust-list parsing and decoded output now preserve and expose `ListAndSchemeInformation.NextUpdate`

## [1.7.0] - 2026-03-22

### Changed

- `/api/trustlists` now exposes a container-friendly relative `path` for each trust-list profile entry
- `/api/trustlists` now publishes `advertised_url` for the configured issuer URL and keeps `url` as a backward-compatible alias

### Documentation

- clarified that `/api/trustlists` is a local discovery endpoint while `/api/trustlists/{id}` serves the ETSI trust-list JWT
- documented how Docker and Testcontainers callers should resolve trust-list `path` values against the URL they actually used

## [1.6.0] - 2026-03-22

### Added

- multiple wallet trust-list profiles with `/api/trustlists`, `/api/trustlists/{id}`, and CLI selection via `wallet trust-list --id|--vct|--doctype`
- signed OpenID Credential Issuer metadata and registrar-style authorization responses for wallet-issued credential types
- trust-profile-specific credential-signing leaf certificates under the shared wallet CA

### Changed

- `issue --wallet` now issues with the wallet issuer context instead of generating externally and importing afterward
- wallet issuer and status-list URLs are now persisted and reused across commands so generated credentials, `wallet serve`, trust lists, and status lists stay aligned
- wallet trust lists remain ETSI-shaped and certificate-centric while issuer authorization data is published through issuer metadata and registrar responses

### Fixed

- `issue --wallet` credentials now validate against the wallet trust list and use wallet-managed status-list entries by default
- `wallet generate-pid`, `wallet serve`, `wallet trust-list`, `wallet ca-cert`, `wallet tls-cert`, and `validate --trust-list` now work coherently against the same persisted wallet issuer state
- trust-list parsing accepts current ETSI-style `ListIssueDateTime` payloads

### Documentation

- documented trust-list creation, profile IDs such as `pid` and `local`, wallet-native `issue --wallet` behavior, and the shared-CA/per-profile-leaf certificate model

## [1.5.3] - 2026-03-20

### Fixed

- `wallet tls-cert` now prints exactly one leaf PEM certificate; `wallet ca-cert` prints exactly one CA PEM certificate

## [1.5.2] - 2026-03-20

### Added

- `wallet ca-cert` to print or export the shared wallet CA certificate

### Changed

- wallets under the same wallet base directory now share one persisted CA
- the shared CA now anchors wallet trust lists, status-list `x5c` chains, issuer-metadata `x5c` chains, and HTTPS wallet certificates
- HTTPS wallet certificates are now signed by the shared CA instead of being self-signed
- no wallet API endpoint paths or response formats changed; only the trust model and certificate material changed

## [1.5.1] - 2026-03-20

### Changed

- wallet-generated PID credentials now use the HTTPS wallet status list endpoint on `port+1`
- `wallet issuer-tls-cert` was renamed to `wallet tls-cert` to reflect that the exported certificate covers all HTTPS wallet endpoints
- persisted HTTPS wallet certificate files were renamed to `wallet-tls-cert.pem` / `wallet-tls-key.pem` with legacy migration from the old issuer-prefixed names
- `wallet serve` now prints both HTTP and HTTPS endpoint URLs where both are available

### Documentation

- clarified that `/api/trustlist` and `/api/statuslist` are also exposed via HTTPS
- updated wallet, validate, docker, and README docs for `wallet tls-cert` and HTTPS status-list resolution

## [1.5.0] - 2026-03-20

### Added

- persistent wallet issuer HTTPS certificate files in the wallet directory
- `wallet issuer-tls-cert` to print or export the HTTPS issuer certificate used by `/.well-known/jwt-vc-issuer`

### Changed

- validate UI banner now prefers the status-list validation result when a status check ran

### Fixed

- local validation fetches now bypass proxies and correctly trust the wallet's self-signed local HTTPS endpoints for issuer metadata and status-list resolution

## [1.4.5] - 2026-03-20

### Fixed

- statuslist entries for generate-pid/validate checks statuslist

## [1.4.4] - 2026-03-20

### Fixed

- kid-based verification in validate ui

## [1.4.3] - 2026-03-20

### Fixed

- validate ui does kid-based resolution

## [1.4.2] - 2026-03-20

### Fixed

- `wallet generate-pid` now uses the correct local issuer `iss` instead of `https://issuer.example`

## [1.4.1] - 2026-03-20

### Fixed

- kid-based issuer metadata resolution issues

## [1.4.0] - 2026-03-20

### Added

- HTTPS issuer metadata endpoint for wallet-issued SD-JWT credentials
- kid-based issuer metadata resolution for SD-JWT verification

## [1.3.8] - 2026-03-19

### Fixed

- disclosure of nested values in SD-JWT credentials

## [1.3.7] - 2026-03-19

### Fixed

- further mock PID structural fixes
- multi-credential decoding in proxy

## [1.3.6] - 2026-03-19

### Fixed

- default mdoc PID `birth_place` claim shape
- render one decode link per credential for multi-credential proxy results

## [1.3.5] - 2026-03-19

### Fixed

- debug-mode wallet allows non-matching claims

## [1.3.4] - 2026-03-19

### Fixed

- update default pid mock credentials to better match reality

## [1.3.3] - 2026-03-18

### Fixed

- support browser back in decode ui and nested cred drilldown

## [1.3.2] - 2026-03-11

### Fixed

- enforce spec-compliant request object claims/values

## [1.3.1] - 2026-03-10

### Added

- add aki trusted_authorities support

## [1.3.0] - 2026-03-10

### Added

- add aki trusted_authorities support

## [1.2.1] - 2026-03-09

### Fixed

- include sub and ttl in statuslists

## [1.2.0] - 2026-03-07

### Changed

- Default OIDF runner to signed strict plan

## [1.1.0] - 2026-03-05

### Added

- `wallet show <id>` subcommand to inspect stored credentials (raw by default, `--decoded` for human-readable output)

## [1.0.4] - 2026-03-04

### Fixed

- `trusted_authorities` trust list fetch: fall back to `localhost` when `host.docker.internal` is unreachable (wallet running on host, verifier in Docker)

## [1.0.3] - 2026-03-04

### Added

- Display version in `wallet serve` and `proxy` startup banners

## [1.0.2] - 2026-03-04

### Fixed

- DCQL `trusted_authorities` now reads `values` (array) per OID4VP 1.0 spec instead of `value` (string)
- Codecov ignore patterns use regex syntax to match Go coverage paths

## [1.0.1] - 2026-03-04

### Added

- Version auto-detection from Go module info for `go install` builds (falls back to ldflags, then `dev`)

## [1.0.0] - 2026-03-04

First stable release of oid4vc-dev, a developer toolkit for debugging and testing
OID4VP, OID4VCI, SD-JWT, mDoc, and related SSI/eIDAS 2.0 protocols.

### Features

- **Credential Decoding** - Auto-detect and decode SD-JWT VC, JWT VC, and mDoc/mdoc credentials with selective disclosure resolution
- **Credential Validation** - Signature verification (ES256/384/512, RS256/384/512, PS256), certificate chain validation against ETSI trust lists, token status list (RFC 9596) checking
- **Credential Issuance** - Generate test SD-JWT, JWT VC, and mDoc credentials with configurable claims, key types, and certificate chains
- **DCQL Evaluation** - Parse and evaluate Digital Credentials Query Language queries with credential matching, claim_sets, and credential_sets support
- **Wallet** - Full OID4VP 1.0 wallet with consent UI, supporting:
  - All client_id schemes (x509_san_dns, x509_hash, redirect_uri, verifier_attestation, decentralized_identifier)
  - Response modes: direct_post, direct_post.jwt (JARM), fragment
  - Encrypted request objects (JWE with ECDH-ES)
  - HAIP 1.0 enforcement mode
  - SIOPv2 self-issued ID token (response_type "vp_token id_token")
  - OID4VCI pre-authorized code flow with tx_code support
  - DCQL `trusted_authorities` (`etsi_tl`) filtering
  - Session transcript generation (OID4VP and ISO 18013-7 modes)
- **Proxy** - Debugging reverse proxy that intercepts, classifies, and decodes OID4VP/VCI traffic with:
  - Live web dashboard with SSE streaming
  - HAR export
  - Automatic JWE decryption (key extraction from subprocess stdout)
  - Subprocess management for proxied services
- **Web UI** - Browser-based credential decoder and validator
- **QR Code** - Screen capture and decode support (macOS)
- **Docker** - Multi-arch Docker image with HTTP API for integration testing (Testcontainers support)
### Spec Compliance

- OID4VP 1.0 (Draft 28) - Authorization request parsing, DCQL, JAR, all response modes
- OID4VCI 1.0 - Pre-authorized code grant, credential endpoint, proof of possession
- HAIP 1.0 - Full enforcement of mandatory parameters and algorithms
- SD-JWT (RFC 9809) - Parsing, disclosure resolution, key binding JWT, SHA-256/384/512
- mDoc (ISO 18013-5) - CBOR parsing, COSE_Sign1 verification, MSO validation
- ETSI TS 119 612 - Trust list generation and certificate chain validation
- RFC 9596 - Token status list generation and checking
- SIOPv2 - Self-issued ID token with JWK thumbprint subject

## [0.22.0] - 2026-03-04

### Fixed

- build/linting

## [0.21.2] - 2026-03-04

### Fixed

- build

## [0.21.1] - 2026-03-04

### Fixed

- improve maintainability, tests, remaining spec deviations

## [0.21.0] - 2026-03-04

### Fixed

- improve maintainability, tests, remaining spec deviations

## [0.20.2] - 2026-03-03

### Fixed

- generate trust list correctly signed

## [0.20.1] - 2026-03-03

### Fixed

- build

## [0.20.0] - 2026-03-03

### Added

- add optional request obj enc

## [0.19.0] - 2026-03-03

### Fixed

- use cert chain to sign creds/trust list

## [0.18.5] - 2026-03-02

### Added

- add --docker shortcut

## [0.18.4] - 2026-03-02

### Fixed

- claim matching

## [0.18.3] - 2026-03-02

### Added

- warn if sig algorithm doesnt match header cert

## [0.18.2] - 2026-03-02

### Fixed

- clickable links in proxy

## [0.18.1] - 2026-03-02

### Fixed

- proxy credential detection and decryption

## [0.18.0] - 2026-03-02

### Fixed

- proxy credential scanning improved

## [0.17.2] - 2026-03-02

### Fixed

- wallet enforces OID4VP 1.0 enc args and dismisses invalid requests

## [0.17.1] - 2026-03-02

### Fixed

- windows build

## [0.17.0] - 2026-03-02

### Fixed

- use OID4VP 1.0 spec client_metadata scheme for enc alg/enc

## [0.16.1] - 2026-02-28

### Fixed

- flaky tests

## [0.16.0] - 2026-02-28

### Added

- add --nbf to add not-before claim to issued credentials

## [0.15.0] - 2026-02-28

### Added

- proxy detects credentials / keys from proxied service

## [0.14.2] - 2026-02-28

### Fixed

- use go 1.26.0 in dockerfile

## [0.14.1] - 2026-02-28

### Changed

- apply code review findings / improvements

## [0.14.0] - 2026-02-28

### Changed

- add issue jwt documentation and wallet tx-code/pre-auth notes

## [0.13.4] - 2026-02-28

### Changed

- apply code review findings / improvements

## [0.13.3] - 2026-02-27

### Fixed

- spec violation when building vp response with multiple creds

## [0.13.2] - 2026-02-27

### Fixed

- support JWT VC throughout the codebase

## [0.13.1] - 2026-02-27

### Fixed

- wallet now supports jwt_vc_json (plain jwt credentials)

## [0.13.0] - 2026-02-27

### Added

- add next-response manipulation and preferred format

## [0.12.1] - 2026-02-27

### Fixed

- missed renames

## [0.12.0] - 2026-02-27

### Changed

- rename to oid4vc-dev

## [0.11.1] - 2026-02-27

### Added

- build docker image, update docs

## [0.11.0] - 2026-02-27

### Added

- add mock wallet

## [0.10.0] - 2026-02-27

### Added

- allow to decode tokens from token response in proxy ui

## [0.9.1] - 2026-02-27

### Fixed

- decoder ui created errors when used with the proxy

## [0.9.0] - 2026-02-27

### Added

- merge openid into decode command

## [0.8.2] - 2026-02-26

### Fixed

- fix issue command issues

## [0.8.1] - 2026-02-26

### Fixed

- output mdoc as b64 encoded

## [0.8.0] - 2026-02-26

### Added

- issue mock credentials

## [0.7.1] - 2026-02-26

### Added

- add proxy features

## [0.7.0] - 2026-02-26

### Added

- add proxy features

## [0.6.3] - 2026-02-26

### Fixed

- proxy request classification, docs

## [0.6.2] - 2026-02-26

### Fixed

- proxy respect forwarded-for header

## [0.6.1] - 2026-02-26

### Fixed

- proxy filters out irrelevant requests

## [0.6.0] - 2026-02-26

### Added

- add proxy mode

## [0.5.0] - 2026-02-26

### Added

- add qr screen capture support for macos

## [0.4.1] - 2026-02-26

### Fixed

- fix web ui bugs

## [0.4.0] - 2026-02-26

### Added

- add validation to web ui

## [0.3.0] - 2026-02-26

### Added

- improve web ui highlighting and structure

## [0.2.0] - 2026-02-26

### Added

- add web ui

## [0.1.0] - 2026-02-26

### Fixed

- add Apache 2.0 license

[1.12.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.12.3
[1.12.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.12.2
[1.12.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.12.1
[1.12.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.12.0
[1.11.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.11.1
[1.11.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.11.0
[1.10.11]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.11
[1.10.10]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.10
[1.10.9]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.9
[1.10.8]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.8
[1.10.7]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.7
[1.10.6]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.6
[1.10.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.5
[1.10.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.4
[1.10.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.3
[1.10.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.2
[1.10.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.1
[1.10.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.0
[1.9.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.5
[1.9.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.4
[1.9.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.3
[1.9.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.2
[1.9.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.1
[1.9.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.0
[1.8.10]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.10
[1.8.9]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.9
[1.8.8]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.8
[1.8.7]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.7
[1.8.6]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.6
[1.8.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.5
[1.8.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.4
[1.8.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.3
[1.8.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.2
[1.8.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.1
[1.8.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.0
[1.7.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.4
[1.7.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.3
[1.7.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.2
[1.7.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.1
[1.7.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.0
[1.6.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.6.0
[1.5.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.3
[1.5.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.2
[1.5.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.1
[1.5.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.0
[1.4.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.5
[1.4.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.4
[1.4.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.3
[1.4.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.2
[1.4.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.1
[1.4.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.0
[1.3.8]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.8
[1.3.7]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.7
[1.3.6]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.6
[1.3.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.5
[1.3.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.4
[1.3.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.3
[1.3.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.2
[1.3.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.1
[1.3.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.0
[1.2.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.2.1
[1.2.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.2.0
[1.1.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.1.0
[1.0.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.4
[1.0.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.3
[1.0.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.2
[1.0.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.1
[1.0.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.0
[0.22.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.22.0
[0.21.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.21.2
[0.21.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.21.1
[0.21.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.21.0
[0.20.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.20.2
[0.20.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.20.1
[0.20.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.20.0
[0.19.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.19.0
[0.18.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.5
[0.18.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.4
[0.18.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.3
[0.18.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.2
[0.18.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.1
[0.18.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.0
[0.17.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.17.2
[0.17.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.17.1
[0.17.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.17.0
[0.16.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.16.1
[0.16.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.16.0
[0.15.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.15.0
[0.14.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.14.2
[0.14.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.14.1
[0.14.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.14.0
[0.13.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.4
[0.13.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.3
[0.13.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.2
[0.13.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.1
[0.13.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.0
[0.12.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.12.1
[0.12.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.12.0
[0.11.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.11.1
[0.11.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.11.0
[0.10.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.10.0
[0.9.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.9.1
[0.9.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.9.0
[0.8.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.8.2
[0.8.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.8.1
[0.8.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.8.0
[0.7.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.7.1
[0.7.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.7.0
[0.6.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.3
[0.6.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.2
[0.6.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.1
[0.6.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.0
[0.5.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.5.0
[0.4.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.4.1
[0.4.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.4.0
[0.3.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.3.0
[0.2.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.2.0
[0.1.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.1.0
