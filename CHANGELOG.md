# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.19.6] - 2026-08-05

### Added

- **`wallet trust-list --list` shows which trust list profiles a wallet serves.** The ids were only discoverable by reading `/api/trustlists`, so picking one from the CLI meant guessing. Every profile carries the same certificate (the wallet has one CA) and differs in what it declares that CA to be, so the listing names the category to pick by. `--json` emits the `/api/trustlists` body unchanged

### Fixed

- **`wallet serve` tried to open a browser on headless hosts.** An incoming interactive request printed "Opening wallet UI" and spawned a browser on the serving machine, which reaches nobody over SSH or in a container while claiming otherwise. The CLI now opens a browser only where there is a desktop to open it on, and names the consent URL instead when there is not
- **`wallet trust-list` ignored the remote target and printed the local wallet's CA.** It read the local store directly instead of routing through the active remote, so with a remote wallet selected it handed out an anchor that validates nothing that wallet issues, silently. It now fetches from the wallet it is pointed at, and `--url` prints that wallet's URL rather than a localhost one

- **`wallet accept` did nothing with an authorization code offer against a hosted wallet.** The offer needs the user to sign in at the issuer, so the wallet handed the URL to an open UI tab, and with no tab attached it fell back to opening a browser on its own machine. On a hosted wallet that reaches nobody, and it then blocked five minutes waiting for a callback nobody could produce while the caller timed out with nothing to act on. The wallet no longer opens browsers at all: it answers `HTTP 202` with the authorization URL and an `offer_id`, keeps the flow running, and `GET /api/offers/{offer_id}` reports how it ended. `wallet accept` opens the URL on the machine the user is at (and prints it), then follows the offer to the credential. The callback is matched by `state`, so any browser that can reach the wallet completes the flow

### Security

- **The decoder web UI and the proxy dashboard sent no browser security headers.** Only the wallet server set them, so `eudi serve` and the proxy dashboard ran without a content security policy, without `nosniff`, and framable. Both render content someone else supplied (a credential from a `?credential=` link, traffic from whatever the proxy is pointed at), which is exactly where escaping failing turns into code execution. All three UIs now share one policy: scripts from the page origin only and no inline script, so an injected handler does not run, plus no plugins, no base tag rewriting, no framing, and forms and fetches confined to the origin. The public demo already had this through the wallet server and is unaffected
- Two values in the wallet UI were interpolated into markup without escaping (a deferred issuance attempt count, a transaction code length). Both are numbers rather than anything a caller controls, so neither was exploitable, but it is the pattern that produced the stored XSS fixed in 1.19.2

## [1.19.5] - 2026-08-05

### Added

- **The decoder explains the mdoc format instead of dumping it.** An SD-JWT arrives as text whose parts can be coloured, an mdoc arrives as one binary blob, and the decoder showed little more than the MSO and the claim values. It now follows the container: `issuerSigned.nameSpaces`, `issuerSigned.issuerAuth` broken into its COSE_Sign1 parts, the MSO as that signature's payload, the device key, and `deviceSigned.deviceAuth`. Each element shows its salt and digest id next to the value, and whether the digest recomputes to the one the issuer signed, which is what mdoc selective disclosure actually is. COSE integer labels are named (`alg`, `kid`, `x5chain`, `kty`, `crv`), certificate chains are shown as subject, issuer and expiry, and each section says in a line what it is for

### Fixed

- **The mdoc decoder did not show the holder binding.** An mdoc is bound to a device key the holder proves possession of when presenting, which is the same fact `cnf` carries in an SD-JWT and is shown there by default. In mdoc it was reachable only as a raw COSE_Key behind `-v`, and not at all in the decoder UI, so a bound credential looked like an unbound one. Both now show it next to the MSO, as the curve and a thumbprint rather than integer-labelled bytes, and say so plainly when a credential carries no device key at all. A presentation also reports whether it carries a `deviceSignature` or a `deviceMac`

- **The wallet published a signing key expiry that was almost always in the past.** The `exp` in `/.well-known/jwt-vc-issuer` and in the signed issuer metadata was computed once when the server started, as that moment plus a day, and never moved. Any wallet running for more than a day advertised an expired key, and a hosted one advertised a key that expired on its first day. It now follows the signing certificate, so it says what is actually true
- **A long-running wallet renews its certificates.** Leaves are valid for a year and nothing about an expired one announces itself: the wallet keeps issuing credentials that quietly stop verifying, and keeps serving HTTPS that clients quietly stop trusting. Both the signing leaf and the HTTPS leaf are re-issued from the same CA within a month of expiry. The HTTPS listener resolves its certificate per handshake, so a renewal reaches clients without a restart (it used to hold the one it started with). The CA is untouched, so a party that pinned it keeps working

## [1.19.4] - 2026-08-05

### Added

- **The conformance harness runs the pre-authorized code grant.** All four VCI scenarios pinned `authorization_code`, so the grant most wallets actually meet (scan a QR, no sign-in) went untested, which is where every issuance bug of the 1.19.3 cycle turned out to live. Two scenarios now run it in SD-JWT and mDoc. HAIP is deliberately not among them: the suite refuses that combination outright, and pre-authorized offers are outside the profile anyway
- The demo reset re-issues the wallet's signing leaf from its own CA. Leaves are valid for a year, so a long-running demo would eventually sign with an expired one, noticed only by whatever stopped verifying. The CA is untouched, so anything that pinned it keeps working

### Fixed

- **A credential proof carried an empty nonce claim when the issuer had given none.** An absent `c_nonce` still produced `"nonce": ""`, which an issuer reads as a nonce that does not match rather than as no nonce at all. The OIDF client attestation challenge module rejected it (`expected_nonce = null, actual_nonce = ""`), and with the claim omitted all four VCI plans pass, pre-authorized ones included
- **A deferred issuance no longer holds up whoever started it.** 1.19.3 waited out a short deferral before answering, which left the consent dialog spinning for the issuer's interval, showed nothing under "Awaiting issuance" while it did, and then produced the credential out of nowhere. The transaction is recorded and reported immediately, and the poller collects on the issuer's own schedule
- **Two protected PIDs after a change of credential type.** The baseline was replaced by matching the type it was generated with, so the 1.19.3 move to `urn:eudi:pid:1` left the `urn:eudi:pid:de:1` one in place beside it. The whole protected set is replaced now, whatever it was generated as

### Changed

- **Trust & certificates is laid out rather than listed.** The dialog put trust lists and five certificate links in one block with the explanation trailing after, which had to be read start to finish. Trust lists and certificates are now separate sections, and each certificate is a labelled row (trust anchor, signing key, TLS) with a line saying what it is for

## [1.19.3] - 2026-08-05

### Added

- **The demo verifier asks for the PID in either format.** A PID exists as SD-JWT VC and as mdoc, and a verifier that names only one turns the wallet's format choice into a failure. The request now carries both credential queries and one DCQL `credential_sets` option pair, so either satisfies it, and the verifier verifies whichever comes back
- **mdoc presentations are verified, not just parsed.** `mdoc.VerifyValueDigests` checks the disclosed elements against the digests the issuer signed (the issuer signature only covers the MSO, so without it a holder could return any value it liked), and `mdoc.VerifyDeviceAuth` checks the holder signature over the session transcript, which is what binds a response to one request. The demo verifier runs both, plus the doctype, the issuer certificate chain and the validity period
- **Demo issuer: one button, one toggle.** "Create credential offer" and "Authorization code offer" sat side by side with the first always highlighted, so the grant looked like a state and the highlight like a selection. The grant is now a toggle (pre-authorized / authorization code) above a single **Create offer** button, with the explanation changing to match the selected grant
- **Trust lists are grouped by what they anchor** in the wallet's Trust & certificates dialog, under "Credential providers" and "Wallet providers", sorted within each group. They were an unordered flat list, so an issuer looking for the wallet attestation anchor had to read past the credential ones. `GET /api/trustlists` entries carry the group as `category`
- The demo issuer and demo verifier link the imprint in their footer when the wallet serves one, which public EU hosting requires and only the wallet UI did
- `eudi wallet list` includes deferred credentials with a `deferred` status, and `eudi wallet show <id>` on one reports where it stands (issuer, transaction, retry interval, next attempt) instead of "not found". A deferred issuance is on its way, and leaving it out of the list made it look like nothing had happened
- **A deferred credential is collected in the background, on the schedule the issuer asked for.** An issuer that defers by an hour used to end the flow with a red "Credential issuance failed" dialog. Nothing had failed, and the transaction id that would have collected the credential lived only inside that error message, so the credential could never arrive. The transaction is now persisted with everything the deferred request needs (including the ephemeral batch proof keys, which exist nowhere else), and `wallet serve` polls for it on the issuer's own interval. Accepting such an offer answers `HTTP 202` with `pending`, the wallet UI lists it under **Awaiting issuance**, and the credential appears by itself once collected. Pending issuances survive a restart, and are dropped when the credential arrives, when the issuer answers something that will not improve by asking again (a rejected token, an unknown transaction), or after 24 hours. Collecting is also driveable by hand, for when the credential is known to be ready or the exchange is what you want to watch
- **`eudi wallet deferred`** lists what an issuer has deferred, with the retry interval and the next attempt. `eudi wallet deferred check [id]` makes one request straight away instead of waiting for the scheduled attempt, and reports what came back; `eudi wallet deferred abandon <id>` stops collecting one, leaving the transaction valid at the issuer. The wallet UI carries the same two actions on each entry. Over `GET /api/deferred`, `POST /api/deferred/{id}/collect` and `DELETE /api/deferred/{id}`; the listing never returns the access token
- **The consent dialog asks for a transaction code.** An offer whose pre-authorized grant carries `tx_code` cannot be redeemed without one, and the issuer delivers it out of band (the Animo playground prints it beside the QR code, a bank would text it). The dialog only reported that a code was required and then offered no way to supply it, so such an offer could not be accepted from the UI at all. It now shows an input sized and typed from the offer's own `input_mode`, `length` and `description`, refuses an empty approval in the dialog rather than spending the offer on a request that cannot succeed, and sends the code with the approval
- `wallet accept` asks for the transaction code when the offer requires one and none was passed. `--tx-code` still wins, and nothing is asked when no terminal is attached, so scripts and containers keep their current behavior and get the issuer's own error instead of a hanging prompt
- **`wallet serve --client-attestation`** sends the wallet attestation on OID4VCI token requests even when the authorization server does not advertise `attest_jwt_client_auth`. The default stays metadata-driven, which is what draft-ietf-oauth-attestation-based-client-auth §8 asks a client to do and what §10.1 wants for privacy (this wallet reuses one attestation and one `cnf` key, and §10.1 warns that reusing them across authorization servers lets those servers correlate the user). Advertising the method is only a SHOULD, though, so an issuer can check an attestation without announcing it, and against one of those a correct wallet gets `invalid_client` and no credential. The flag is the operator overriding that, which is a decision for a person rather than something the wallet infers from an error message. `GET /api/config` reports it as `force_client_attestation`

### Fixed

- **`wallet accept --tx-code` did nothing against a wallet server.** The flag reached the local store but the remote path dropped it, so the same command worked locally and failed with "Missing required 'tx_code'" against `--remote` (which is how the CLI drives a container or a hosted wallet, and how it auto-routes to a running instance). The code now travels in the `POST /api/offers` body, which the server already accepted
- **The pre-authorized code flow ignored every protection the issuer asked for.** It was a separate path from the authorization code flow and never gained what that one has: no DPoP proof, no `OAuth-Client-Attestation` headers, no key attestation in the credential proof. The wallet even read `key_attestations_required` out of the issuer metadata and then did nothing with it. An issuer that requires any of the three refused to issue, so testing against one (the Animo playground requires all three) meant turning the requirements off first. Each is now driven by the issuer's own metadata, so an issuer that asks for none of them sees exactly the request it saw before. Both flows share one transport now, and the duplicated HTTP code on the pre-authorized path is gone
- **Deferred issuance did not work on the pre-authorized code flow, and its polling watched for the wrong thing on the other one.** An issuer that cannot produce the credential yet answers with a `transaction_id`, and the pre-authorized path had no handling for that at all: it read the ticket as a credential response and gave up with "no credential in response". Both flows share one deferred step now. The polling itself was also wrong: it waited only while the issuer echoed a `transaction_id` back in a success-shaped body, but OID4VCI 1.0 §9.3 reports "not ready" as the `issuance_pending` *error*, which arrives as an HTTP 400 and ended the flow instead of extending it. Both shapes are accepted now, and the issuer's `interval` is honored. This was invisible to the conformance run, which never has to wait
- **A deferred issuance stops blocking after 90 seconds and is collected in the background instead.** The poll loop had no bound, so an issuer deferring by a day would have held the request open for a day. A short deferral is still waited out, so a quick one comes back from the call that started it; a longer one is recorded and collected on the interval the issuer asked for (see Added). The wallet server's write timeout, the remote CLI client and the consent approval wait were each below that bound (60s, 30s and 30s) and would have cut off a deferral the others were still waiting for, so all three now derive from it
- **A key attestation says what it protects.** OID4VCI 1.0 Appendix D has the attestation state how well the key storage and the user authentication resist attack, and an issuer that names required values in `key_attestations_required` checks them. The attestation carried neither, so an issuer asking for `iso_18045_high` rejected it as insufficient. The attestation now mirrors the values the credential configuration requires
- **Key attestation and batch issuance no longer collide.** A jwt proof carrying an attestation stands for the single key that signed it, so an issuer advertising `batch_credential_issuance` got a batch of proofs that all claimed the same attestation and refused them. A configuration that requires key attestation now sends one proof, and batch issuance is unchanged everywhere else
- The authorization scheme for an access token comes from `token_type` in the token response instead of being assumed. RFC 9449 has an authorization server return `DPoP` for a key-bound token, so an issuer that accepts a proof and still hands back a plain bearer token is now addressed as one
- A credential request advertises `application/jwt` in `Accept` only when the wallet asked for an encrypted response. The authorization code flow claimed it unconditionally, which describes something the request does not accept

### Changed

- **The default PID is the country-independent EUDI PID.** It used the German type and rulebook namespace (`urn:eudi:pid:de:1`, with national additions under `eu.europa.ec.eudi.pid.de.1`), which is where the ecosystem started rather than where it is going. The type is now `urn:eudi:pid:1` and every mdoc element sits in `eu.europa.ec.eudi.pid.1`, with no national namespace. The sample identity is unchanged (ERIKA MUSTERMANN), so only the identifiers move. Anything matching on the old vct (a DCQL `vct_values`, a verifier config) has to be updated

## [1.19.2] - 2026-08-05

### Security

- **Stored cross-site scripting in the wallet UI.** The escaping helper round-tripped values through `textContent`, which escapes `&`, `<` and `>` but leaves `"` and `'` alone. Several values land inside quoted HTML attributes (a credential's status list URI, its `vct` and `doctype`, a claim name, a credential configuration id from an offer), so a crafted value closed the attribute and added an event handler. On a shared wallet those values come from whoever imported the credential or sent the offer, and the script then ran in every other visitor's browser on the wallet's origin. Confirmed with a credential whose status list URI carried an `onmouseover` handler that fired in a second browser. All four UIs (wallet, decoder, proxy dashboard, demo verifier) now escape quotes as well, and an end-to-end test drives the original payload
- **Browser hardening headers.** Every wallet response now carries `Content-Security-Policy` (`script-src 'self'`, no inline script, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`. With no `'unsafe-inline'`, an injected handler does not execute even if escaping fails somewhere. The demo issuer and verifier pages moved their inline scripts into `issuer.js` and `verifier.js` so the policy needs no exception
- **The consent event stream is no longer readable cross-origin.** `GET /api/requests/stream` sent `Access-Control-Allow-Origin: *`, so any page a user visited could subscribe to it and read incoming consent requests, including the claims a verifier asked for. The wallet's own UI is same-origin and never needed the header; non-browser clients do not enforce CORS and are unaffected
- **A verifier could execute script in the wallet through its `redirect_uri`.** After a presentation the wallet navigates the browser to the `redirect_uri` (or `Location`) the verifier returns, and it only checked that the URI was absolute. `url.Parse` calls `javascript:` and `data:` absolute, so a verifier answering with `{"redirect_uri":"javascript:..."}` got script execution on the wallet's own origin. Both are now restricted to http and https, server-side and again in the UI before it navigates
- A wallet attestation with no `exp` claim was accepted by the demo issuer, because the expiry was only checked when present, and a DPoP proof was accepted at any age. `exp` is now required and a proof's `iat` has to fall inside a five-minute window, so a captured proof stops working

### Fixed

- **The login in the demo issuer's authorization code flow happened before redemption instead of during it.** The offer was created only after signing in, and the wallet then completed the flow without the user ever meeting the authorization endpoint. Now the offer is created signed-out and the user authenticates at `/issuer/authorize`, between the pushed authorization request and the token exchange, which is where the flow puts it: the credential is bound to whoever completed the login, not to whoever created the offer
- **A hosted wallet can complete an authorization code flow at all.** The wallet only knew how to open a browser on the machine it runs on, which does nothing on a demo host. It now offers the authorization URL to the open UI (an `authorize` event on the consent stream) and that tab navigates; `/callback` resumes the flow already in progress and returns the visitor to the wallet. A wallet running locally with no UI attached still opens a local browser
- `wallet serve` defaults `--vci-client-id` to its own origin and `--vci-redirect-uri` to that origin's `/callback`, so an authorization code offer no longer fails with "requires configured wallet client_id and redirect_uri" on a wallet that never set them. Explicit flags still win
- **A credential issued by a long-running flow could be lost.** Every request reloads the wallet from its store, replacing the in-memory credential list. An authorization code flow stays open across the user's login, and the UI's burst of requests when it returns landed between the import and the save: issuance reported success and stored nothing. The credential is now put back if a reload dropped it, and the restore and the save happen under the lock the reload takes
- Only the tab that started an issuance follows the issuer's login page. The authorization event went to every open UI, so on a shared wallet a visitor who did nothing would have been navigated to some issuer's login, which is exactly what the consent dialog already avoids
- Two tests wrote to variables from a request goroutine and read them from the test goroutine, which `go test -race` flags. The whole repository is race-clean now

## [1.19.1] - 2026-08-04

### Added

- **Instances report which release they run, and the CLI checks it before managing one.** A wallet instance can live anywhere (a container, a VPS, the public demo), so the CLI driving it is not necessarily the same release. `GET /api/version` already carried `version`; discovery now keeps it, so `wallet instances list` has a `VERSION` column (`version` in `--json`), selecting a target prints the release it runs, and the automatic routing notice names it too. The version comes from the health check rather than the registry file, so it describes the process that is actually answering
- `wallet instances use <url>` compares that release with the CLI's own, the way semantic versioning defines compatibility: a differing major release is refused (that is where breaking changes live) and `--force` overrides it, while minor and patch differences are compatible in both directions and pass without comment. A development build on either side is not comparable, so nothing is claimed. `wallet instances list` marks an incompatible instance with `(!)`, and an auto-routed instance a major release apart from the CLI is reported the same way

### Added

- **The demo issuer runs the authorization code flow, as its own authorization server.** It previously only had the pre-authorized code grant, so nothing in the box exercised the part of HAIP that matters most for a wallet: attestation-based client authentication. It now serves `/issuer/par`, `/issuer/authorize` and `/issuer/token` with pushed authorization requests required, PKCE S256, DPoP and `attest_jwt_client_auth`, advertised at `/.well-known/oauth-authorization-server/issuer`. Authentication is one hardcoded demo account (alice / alice) printed on the login page, with no registration, no stored user data and no session beyond the flow. An issuer-initiated offer carries the `issuer_state` of a completed browser login, which is what lets a headless wallet finish the flow, and a wallet that opens the authorization endpoint itself gets the same login page
- The demo issuer verifies the wallet attestation instead of accepting it: the `x5c` certificate has to chain to the wallet CA, the PoP has to be signed by the attested key, and `sub`, `iss`, `aud` and expiry have to match. The access token is DPoP-bound and the credential request has to prove the same key. The issued ticket carries the name of the account that signed in, so a flow that skipped the login shows up in the result
- **A dedicated `wallet-provider` trust list.** The wallet attestation and the credentials share one CA, but they are checked by different parties, and a list called `pid` gave an issuer no reason to think it was the anchor it needed. `/api/trustlists/wallet-provider` is now always served, with the ETSI TS 119 602 Wallet Provider profile (`EUWalletProvidersList`, `SvcType/WalletSolution/*`), carrying the same CA certificate. It is never the default that `/api/trustlist` returns, and `/api/trustlists` entries gained a `description` saying who each list is for

### Fixed

- **The public demo can serve as a wallet for external HAIP issuers.** Its deployment passed neither `--vci-client-id` nor `--vci-redirect-uri`, and without both the wallet refuses an authorization-code offer before the pushed authorization request. HAIP issuance runs exactly that flow, so an issuer testing against the demo never reached the point where the wallet sends its attestation. The example compose file now passes the demo origin as the client id and the wallet's own `/callback` as the redirect URI, which are the two values an issuer would register

### Changed

- **Trust & certificates** in the wallet UI covers both counterparties instead of verifiers alone. An issuer verifying the wallet attestation (`OAuth-Client-Attestation`) or the key attestation in credential proofs needs the same anchor a verifier needs, which the dialog never said. It now names both directions, links the signing key JWKS (`/.well-known/jwt-vc-issuer`) next to the CA and TLS downloads, and states that the attestations carry only the leaf in `x5c`, so the CA is what to configure. Each trust list is listed with the provider profile it describes and a line saying who it is for
- UI copy across the wallet, the demo issuer and the demo verifier is shorter and plainer. Same facts, fewer words

## [1.19.0] - 2026-08-04

### Added

- The issuance consent dialog says what is actually being issued. It showed the issuer's origin and a raw configuration id; it now shows the issuer's own name with the origin beneath it, the flow the offer uses, whether a transaction code will be required, and per credential the format, type, display name, description and the claims the issuer declares. Everything past the offer comes from the issuer metadata, which is optional, so each part appears only when it is known and an issuer without readable metadata still yields a usable dialog. An offer delivered as a `credential_offer_uri` is resolved for the dialog as well, and fetched again after approval, which the specification permits and which is what lets a visitor see the credential rather than a bare hostname; an offer that cannot be retrieved still produces a dialog naming its issuer
- A **Conformance** dialog in the wallet UI header reports what incoming requests are actually held to: validation mode, HAIP 1.0 for presentations and for issuance, encrypted requests, session transcript and preferred format, with an explanation of what the active level rejects. Only what is enforced is highlighted, so "not enforced" cannot be mistaken for a pass. `GET /api/config` gained `require_haip_issuance` alongside the fields it already reported
- `eudi wallet config` as an alias of `wallet info`, and the local backend now reports `require_haip`, `require_haip_issuance`, `auto_accept`, `session_transcript` and `require_encrypted_request`. Local and remote wallets described the same thing differently before, and the conformance-relevant settings were missing from the local view entirely

### Changed

- **Demo mode enforces the EUDI profile.** `--demo` now implies `--mode strict` and `--haip`, so a publicly hosted wallet holds callers to the rules a real EUDI wallet applies instead of accepting anything and teaching verifiers that they pass. A verifier that is not HAIP-compliant gets `HTTP 400` from the public demo, and so does an offer from an issuer that fails the checks applying to it. Both are overridable (`--mode debug`, `--haip=false`) for a self-hosted demo that would rather be permissive, and nothing changes outside demo mode: a plain `wallet serve` keeps `debug` and no HAIP, which is what the OIDF conformance runner relies on
- The built-in demo verifier is HAIP-compliant, which is what makes the above possible: it signs its authorization request object (ES256, `x5c`) and serves it by reference from `/verifier/request/{id}`, identifies itself with an `x509_hash:` client id derived from its signing certificate, requests `response_mode=direct_post.jwt`, publishes a per-request P-256 encryption key in `client_metadata`, and decrypts the response. It previously failed three of the five HAIP checks
- **HAIP is enforced for issuance, not only for presentations.** `ValidateHAIPIssuanceCompliance` follows the flow an offer actually drives: every offer must come from an https issuer, and an offer that drives the authorization endpoint must additionally find pushed authorization requests required and the authorization code flow, PKCE S256, DPoP and client authentication supported. A pre-authorized code offer is held only to the transport rule, because HAIP 1.0 §4 requires an issuer to *support* the authorization code flow rather than to use it everywhere, says nothing about the pre-authorized code flow, and scopes PAR to "when using the Authorization Endpoint". The wallet's own client already satisfied all of it; nothing rejected an issuer that did not. Plain http on loopback is still accepted, the way OAuth treats a local development host, so a demo instance on localhost is not refused for being local
- The built-in demo issuer describes itself properly in its metadata: proof requirements (`cryptographic_binding_methods_supported`, `proof_types_supported`), the claims the ticket contains, and a description, so a wallet can show a visitor what they are accepting. It keeps the pre-authorized code flow, which the profile permits
- `POST /api/offers` accepts `haip` and `mode`, the same per-request overrides presentations already had. It also fixes a silent bug: the endpoint decoded neither field, so the `mode` the conformance runner has always sent was discarded and issuance ran on whatever the server was started with
- The per-request HAIP override works in both directions. `{"haip": false}` on `POST /api/presentations` (or `X-OID4VC-Dev-HAIP: false`) now switches enforcement off for one request, where before a request could only ever turn it on. Without this there was no way to test a non-HAIP verifier against a wallet that enforces HAIP, and the conformance suite's non-HAIP modules would have been rejected outright. An absent field or header still inherits the server setting
- A demo instance may fetch its own advertised origins. `--demo` blocks connections to internal addresses, which also blocked the wallet from reaching its own demo verifier, so on localhost the built-in flows could not complete at all. The exemption is by exact resolved address and port for the configured base and issuer URLs; a visitor-supplied URL pointing at loopback is still refused
- `--demo` no longer claims to imply `--auto-accept` in its flag help and startup banner. It never did — consent stays interactive on purpose

### Fixed

- The status list token publishes the signing key as a `jwk` header alongside `x5c`. Relying parties that resolve keys from the token itself had no route to verify it: Token Status List leaves key resolution to the deployment (§11.3) and requires only `typ` in the header (§5.1), so both mechanisms are permitted, and `jwk` is a registered JOSE header (RFC 7515 §4.1.3). It is derived from the signing key rather than configured, so it cannot disagree with the certificate in `x5c`, which remains the route that anchors the key in a trust anchor
- The status list token no longer ships the trust anchor inside its `x5c` chain. A relying party holds the anchor out of band, and a chain that carries its own self-signed root proves nothing, so HAIP 6.1 rejects it: the OIDF suite failed every HAIP sd_jwt_vc module with "Trust anchor certificate must not be included in x5c chain". Every other JWS this wallet signs already stripped it; the status list path was the one that did not
- A credential imported during a request that carried a profile override is no longer lost. Those requests run on a per-request clone of the wallet, which holds its own credential slice, so an issuance would have reported success and stored nothing. Imports on a clone are now forwarded to the wallet it was cloned from
- `docs/spec-compliance.md` listed batch credential issuance as not implemented; it has been implemented since `internal/wallet/issuance_batch.go`. The HAIP section of `docs/wallet.md` described enforcement as covering OID4VCI when every enforced check is a presentation check

## [1.18.11] - 2026-08-04

### Fixed

- The wallet refreshes its own protected baseline again. Protecting the default PIDs stopped `GenerateDefaultCredentials` from replacing them, which was the point, but it also stopped the server's own baseline generation, so a demo instance kept serving the PID claim set of whichever release first created it: after updating to 1.18.10 the shared demo still showed `personal_administrative_number` and the other claims the German PID does not have. Startup and the periodic reset now replace the baseline they created earlier, protection included. Nothing reachable from a request can: `POST /api/generate-pid`, the CLI and every other request-driven path still leave a protected credential alone

## [1.18.10] - 2026-08-04

### Changed

- The German PID templates and the default PIDs carry the claims the [German PID Rulebook](https://demo.pid-provider.bundesdruckerei.de/credential-claims) defines, with the values of the provider's ERIKA MUSTERMANN test identity. SD-JWT gained `birth_name`, `title`, `also_known_as`, `date_of_expiry`, `source_document_type`, `address.region`, `place_of_birth.no_place_info` and all six age thresholds (only 18 was there before); mdoc gained the same plus `resident_state`. Claims the rulebook lists as unused because the German eID does not supply them are gone (portrait, sex, email, phone number, document number, personal administrative number, issuing jurisdiction, `issuance_date`, `age_in_years`, `age_birth_year`, birth given and family name, `resident_address`, `resident_house_number`, `address.formatted`, `address.house_number`), so a presentation from this wallet exercises the claim set a verifier meets in production. A user template saved under either PID name still overrides all of it
- The mdoc PID puts the national additions of the German rulebook in the `eu.europa.ec.eudi.pid.de.1` namespace, where verifiers following that rulebook look for them: `birth_name`, `academic_title`, `also_known_as`, `no_place_info`, `source_document_type` and the age thresholds. Any mdoc claim key can now carry a `namespace:element` prefix, which `GenerateMDOC` routes for every issuance path (the CLI, the API, templates and the default PIDs), not just the wallet's issue endpoint
- mdoc dates are CBOR tagged the way ISO 18013-5 defines them: a calendar day becomes full-date (tag 1004) and a timestamp becomes tdate (tag 0), matching real PIDs. Previously every date went out as a plain text string, which a verifier that type-checks the element rejects. Parsing unwraps the tags again, so claim matching and presentation are unaffected. A tagged tdate also decodes to the same RFC 3339 string as every other date now instead of surfacing as a Go timestamp

### Fixed

- Regenerating the default PIDs no longer deletes protected credentials. `wallet generate-pid`, `POST /api/generate-pid` and every other path through `GenerateDefaultCredentials` removed the existing PIDs before writing new ones, without checking the protection flag, so a single call replaced a shared instance's protected baseline with unprotected copies. It now keeps a protected PID and skips generating a replacement for it, which is what "only direct file access can remove these" has to mean to be worth anything
- `go test ./cmd` runs against a throwaway config directory. Commands resolve the active wallet through `remote.json`, so on a machine where `wallet instances use <url>` points at a hosted wallet, running that package issued and deleted credentials on the live instance. It has now happened twice against the public demo, so it is prevented rather than remembered
- Clicking an `openid4vp://` or `openid-credential-offer://` link opens the consent dialog again instead of only the "1 request is waiting for consent" bar. The OS handler opens the wallet UI itself and submits right after, so that tab is the one that started the flow, but it cannot carry a request id (the id does not exist yet, and the submit blocks until consent is resolved). It looked exactly like an uninvolved visitor's tab, which demo mode deliberately does not interrupt. The handler now marks the tab it opens with `consent=await` and that tab takes the next consent request directly. The claim is single use, expires after 90 seconds and is stripped from the URL, so a stale or shared link cannot collect somebody else's consent, and every other tab keeps getting the bar

- The demo verifier stops reporting `pending` for a request nobody answered. Its status endpoint ignored the ten minute TTL, so an abandoned verifier page polled a dead request every 1.5 seconds indefinitely. On the public demo two such tabs produced 38% of all traffic in the access log. The endpoint now reports `expired` once the window has passed (a request that was answered keeps its result, so returning through the wallet redirect still shows it), and the page stops polling on any settled status
- The verifier page also backs off between polls (1.5s growing to 8s) and pauses entirely while the tab is hidden, resuming immediately when it becomes visible again. An unattended tab now costs a handful of requests instead of thousands
- The wallet's event stream sends a keepalive comment every 25 seconds. An idle stream sent nothing at all, so proxies dropped the connection and the browser reconnected, which turned a single open tab into a new request every couple of minutes (318 reconnects from one visitor in 11 hours on the public demo)

### Changed

- The public demo example bounds every log it writes. The container logs of all three services are capped at 10 MB with three files each (Docker's default keeps them forever, which is the one thing in the stack that could fill the disk), and the Caddy access log rolls at 10 MiB keeping three files for at most 30 days
- `deploy.sh push` pulls the image before recreating the containers and reports the version it ended up with. The compose file and the image move together (a wall-clock `--demo-reset` in the compose file crash-looped a wallet still running the previous release), so pushing files without pulling was the one way this script could take the demo down
- `deploy.sh stats-reset` discards the access log and rebuilds the report from zero, for when the numbers are mostly your own testing. `deploy.sh stats` now lists top pages only, since the API paths in the log are the UI polling itself and say nothing about visitors

## [1.18.9] - 2026-08-04

### Added

- `GET /api/credentials` takes optional `limit` and `offset` parameters and returns the full count in `X-Total-Count`. Without them the response is unchanged, so the CLI and existing clients keep working. The wallet UI pages the credential list ten at a time, which a shared demo needs once visitors have issued a few hundred credentials between resets
- Protected credentials: a credential marked `"protected": true` in the wallet file cannot be deleted or revoked through the UI, the HTTP API, or the CLI, and `DELETE /api/credentials` keeps it while removing the rest. Demo mode marks the PID credentials it seeds, so a visitor can no longer leave the shared demo without a baseline (freshly issued credentials, including new PIDs, are never protected). Setting or clearing the flag is only possible with direct access to `wallet.json`. The UI shows a "Protected" badge explaining this and hides the Delete and Revoke buttons for those credentials, and `wallet list` gained a STATUS column showing revocation state and protection

### Changed

- The demo banner states the configured reset schedule instead of claiming "state resets daily" regardless of it. With the default `--demo-reset 1h` that sentence was simply wrong, and it would have kept saying "daily" for any interval. Banner and footer now derive their text from the same description, so they cannot disagree
- `--demo-reset` accepts a daily wall-clock time, not just an interval: `00:00`, or `"00:00 Europe/Berlin"` with an explicit zone (durations like `24h` still work, `0` still disables). An interval restarts its countdown with the process, so on a demo that gets redeployed the reset wanders through the day. A wall-clock schedule lands at the same local time every day and follows DST, since the next occurrence is recomputed in the target location after each run. The timezone database is embedded in the binary so named zones resolve in the release image, the startup banner and the UI footer show the schedule ("resets daily at 00:00 CET"), and the public demo example now resets at midnight Berlin time

## [1.18.8] - 2026-08-04

### Added

- `e2e/demo.spec.js` covers demo-mode behavior that two changes have already broken in opposite directions: a scheme-dispatched presentation or credential offer must surface as a reviewable pending request, a browser-initiated request must open its dialog in that tab only, a bystander's tab must never be hijacked, and the hardened endpoints and hidden UI elements must stay that way

### Fixed

- A consent request that reaches a demo instance without a browser redirect is now visible. Scheme dispatches (`openid4vp://` handled by the OS, which submits through the API) create a pending consent, but the wallet UI opens without a request id, and demo mode deliberately does not pop dialogs in every tab. The request stayed invisible and the flow hung until it timed out. The UI now shows an unobtrusive "N requests are waiting for consent" bar with a Review button, instead of either hijacking every open tab or hiding the request

## [1.18.7] - 2026-08-04

### Changed

- The macOS URL handler bundle is named `EUDI-Dev-Wallet.app` (was `OID4VC-Dev-Wallet.app`), so the system dialog that asks which app may open an `openid4vp://` link shows the current name. `wallet register` and `wallet unregister` remove and deregister the old bundle, otherwise Launch Services would keep two handlers for the same schemes. The bundle identifier is now `dev.eudi.wallet` and the handler logs live in `/tmp/eudi-dev-wallet*.log`
- The security notes no longer contradict the hosted demo. They said to never expose the wallet to untrusted networks while eudi-test.dev does exactly that, so they now describe the actual rule: no authentication by default, keep it local, and `--demo` as the one supported profile for public hosting. `SECURITY.md` also stopped claiming the CA key is ephemeral (it is persisted and shared, which is what keeps trust lists stable) and now notes that the demo verifier does enforce revocation
- The custom-scheme URIs on the demo issuer and verifier pages are clickable links, so a wallet that registered `openid4vp://` or `openid-credential-offer://` opens straight from the page instead of requiring copy and paste

## [1.18.6] - 2026-08-04

### Changed

- The wallet UI points at the built-in demo issuer and verifier from the action bar ("No offer at hand?"), where someone stands when they want to run a flow but have no offer or request URI. They were only reachable from the bottom of the How to use dialog
- Header links are ordered by the sequence they are needed (How to use, Get the CLI, Trust & certificates, GitHub) with more space between them, and the decoder header follows the same order and spacing
- Trust list URLs and certificate downloads moved from two permanent rows under the action bar into a "Trust & certificates" dialog. They matter to whoever wires up a verifier, not to everyone looking at the wallet

### Fixed

- The demo verifier accepted revoked credentials. It verified the issuer signature, key binding, `sd_hash`, nonce and audience, but never resolved the credential's status list, so a credential revoked in the wallet still showed every check green. It now fetches the referenced status list, validates its signature against the wallet CA (a forged list cannot un-revoke anything), and fails the presentation when the entry is set. Credentials without a status list reference say so explicitly
- The demo verifier also reports whether the credential is within its validity period. `exp` and `nbf` were evaluated during signature verification but the result was never shown
- The demo verifier enforces the credential type it asked for. The wallet picks what to send, so a PID could answer a request for the demo ticket and still verify
- A demo verification request is now single use. The nonce is fixed per request, so a captured response could be replayed to the response endpoint and verify again. Later responses are rejected with 409 and cannot overwrite the first result
- The demo verifier rejects presentations carrying a disclosure that no digest in the issuer-signed payload references, or the same disclosure twice. A tampered presentation was previously accepted as verified: the unreferenced claim was dropped when resolving claims, but SD-JWT requires rejecting the presentation outright, and a holder can re-sign the key binding over their own additions
- The demo verifier checks that the claims it requested were actually disclosed, and that the key binding JWT carries `typ: kb+jwt`

## [1.18.5] - 2026-08-04

- Optional usage statistics for a hosted demo, entirely in the deployment: Caddy writes an access log with the client address anonymized at write time, GoAccess renders it into a static HTML report, and Caddy serves that at `/stats` behind basic auth (`./deploy.sh stats-password`). `./deploy.sh stats` prints a summary in the terminal. Nothing is added to the pages: no scripts, no cookies, no third party

### Changed

- The wallet UI header no longer shows the credential count badge. The credential list right below it already answers the question

### Added

- Every UI footer (wallet, decoder, demo issuer, demo verifier) carries a short non-affiliation notice: unofficial, independent open source project, not affiliated with or endorsed by the European Commission or the European Union

### Fixed

- The wallet UI footer (version and imprint link) is reachable on phones. The wallet had no responsive rules at all, so `height: 100vh` with `overflow: hidden` pushed the footer below the visible area, which on mobile is shorter than `100vh` because the URL bar counts into it. The layout now uses `dvh` and scrolls as one document below 768px, matching the decoder
- The favicon appears again in the wallet UI and on the demo issuer and verifier pages. All three link to `/favicon.svg`, which 404'd for one release (see 1.18.3), and browsers cache a missing icon per URL without refetching it. The icon now ships under a versioned URL so those pages pick it up. The decoder was unaffected, since it serves its own copy under `/decoder/`

## [1.18.4] - 2026-08-03

### Changed

- Header polish across all UIs: the logo is larger and drawn at its own aspect ratio instead of a square box that letterboxed it, and header items are centered rather than baseline aligned (the mark used to sit visibly high next to the title). The demo issuer and verifier pages get the same treatment with a roomier header
- The decoder header dropped the "Decode SD-JWT, JWT & mDOC credentials" subtitle. In the same size and color as the neighboring links, it read like another nav item

- The decoder footer no longer advertises keyboard shortcuts. All three bindings collided with browser defaults (`Ctrl`/`Cmd+L` and `+K` focus the address bar, `Ctrl+Shift+C` opens developer tools), so they never reached the page. The hints and the dead handler are gone, leaving the version and imprint links

### Fixed

- Timestamp tooltips now work where people actually read timestamps. Claim and disclosure lists render through a helper that never received the claim name, so only the raw payload block showed the human-readable date on hover. A non-numeric claim value could also have produced an invalid date, which is now guarded
- The decoder header no longer collapses on narrow viewports. Below 768px the responsive rule stacked everything in `.header-left`, which since the logo was added pushed the title underneath it and out of the header. Title and links now stack inside their own container with the logo beside them

## [1.18.3] - 2026-08-03

### Added

- `examples/public-demo/deploy.sh`: deploy and operate a public demo host over ssh (`setup`, `push`, `update`, `status`, `verify`, `logs`). The target host, directory, and public URL come from the environment or a gitignored `deploy.env`, so nothing is hardcoded. `setup` also chowns the wallet data volume, which otherwise crash-loops a fresh host

### Fixed

- The logo and favicon 404'd on every wallet server: `internal/wallet/embed.go` listed the embedded UI assets file by file, so the newly added SVGs were never compiled into the binary. The wallet now embeds the whole `static/` directory (as the decoder already did), and a test asserts every asset the UI references is served

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
