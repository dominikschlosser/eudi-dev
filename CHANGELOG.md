# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - Unreleased 

### Added

- **The demo issuer and demo verifier are conformance tested.** `scripts/oidf-demorp-conformance.sh` runs the official OIDF issuer plans (`oid4vci-1_0-issuer-test-plan`, `oid4vci-1_0-issuer-haip-test-plan`) and verifier plans (`oid4vp-1final-verifier-test-plan`, `oid4vp-1final-verifier-haip-test-plan`) against the demo pair, with the suite playing the wallet. The harness delivers credential offers to the suite, signs in at the demo issuer's authorization page, hands each verifier module a fresh demo request, fills the screenshot placeholders those plans end on, and additionally checks the demo verifier's own verdict per module (a tampered presentation has to fail, everything else has to verify), which the suite itself cannot observe. See [the runbook](docs/conformance-run-demorp.md).
- **`wallet serve --serve-tls` serves an https base URL locally.** With an https `--base-url` naming an explicit port, the wallet binds that origin itself with its own TLS certificate instead of expecting an external TLS terminator. The conformance run needs it because the OIDF suite requires https endpoints from the party under test.
- **`wallet serve --demo-verifier-trust-anchor` adds CAs the demo verifier trusts.** The demo verifier accepts issuer chains under the wallet's own CA. The repeatable flag adds anchors for presentations issued elsewhere, such as the ones the OIDF suite signs under its own CAs.

- **Warnings for undefined parameters.** The wallet now warns about request parameters that OID4VP 1.0 does not define (for example the dropped `presentation_definition`) and about fields other than `redirect_uri` in the verifier's response to a posted presentation (§8.2). These stay warnings in every mode because RFC 6749 §3.1 requires ignoring unrecognized parameters.

### Changed

- **Specification findings name their source in one uniform prefix.** Every warning that reports a broken rule starts with the specification and rule it cites, for example "OID4VP 1.0 §5.2: nonce is required" or "ARF RPRC_19: ...". Grouped summaries name the cited specifications instead of "the profile", rules that HAIP only incorporates are cited from the specification that defines them, and under `--haip` the incorporated checks are reported once instead of twice.
- **`wallet instances` is split into `wallet ps`, `wallet use`, and `wallet kill`.** `wallet ps` lists running instances, `wallet use <url|local>` switches which wallet the CLI manages, and `wallet kill <pid|port|url>` stops one. The old `wallet instances list|use|kill` spellings keep working as hidden deprecated aliases.

### Fixed

- **The demo issuer accepts a pushed authorization request without a DPoP proof.** RFC 9449 §10 makes binding the authorization code to a DPoP key the client's choice (`dpop_jkt` is OPTIONAL, and §10.1 offers the DPoP header at the PAR endpoint as one way a client MAY do it), but the demo issuer required the header and refused a conformant wallet that omitted it. A proof that is sent is still verified, and the token endpoint still requires one for the authorization code exchange.
- **The demo issuer's token endpoint accepts an authenticated client that omits `client_id`.** RFC 6749 §4.1.3 has the parameter "REQUIRED, if the client is not authenticating with the authorization server", but the demo compared the absent parameter against the authorization request and refused the exchange with `invalid_grant`. The client the attestation names in its `sub` now stands in, and the code check runs against it, which is the "issued to the authenticated confidential client" rule of the same section. The OIDF suite's wallet authenticates exactly this way.
- **The demo verifier checks the Key Binding JWT's creation time.** RFC 9901 §7.3 has the verifier "check that the creation time of the Key Binding JWT, as determined by the iat claim, is within an acceptable window", and the demo accepted a binding created a year away from now. The window is the same one the demo issuer applies to key proofs. The OIDF verifier plans present exactly such presentations and expect the refusal.
- **The wallet's local TLS listener only offers the TLS 1.2 ciphers RFC 9325 (BCP 195) recommends.** The Go defaults also accept non-recommended suites, which the OIDF suite's TLS checks flag on the credential endpoint.
- **The demo ticket's issuance instant is rounded to the hour.** RFC 9901 §10.1 asks issuers to keep credentials unlinkable, and a ticket carrying the precise issuance second in `iat` (and the `exp` derived from it) lets colluding verifiers correlate the copies of a batch, and two sequentially issued tickets through their inter-issuance gap. The OIDF suite's batch issuance module fails an issuer over the former and warns over the latter.
- **The demo e2e wallet's log survives a CI failure.** The spawned demo wallet's output went to a discarded pipe, so a CI-only failure left nothing saying what the server was doing. It now lands in `e2e/test-results/`, which CI already uploads on failure.

## [2.1.2] - 2026-08-31

### Changed

- **A credential on the transitional `vc+sd-jwt` typ follows the wallet mode.** draft-ietf-oauth-sd-jwt-vc-18 §2.2.1 replaced the `vc+sd-jwt` media type with `dc+sd-jwt` for the SD-JWT VC issuer-signed JWT. On import, debug mode keeps a credential still on `vc+sd-jwt` and records the deviation as a warning, strict mode refuses it, and the decoder flags the typ as a violation rather than passing it as valid with a superseded note. This is the same split the wallet already uses for credentials that break RFC 9901.

### Fixed

- **Fetch clients are reused so connections pool instead of opening a new socket per fetch.** The wallet built a fresh HTTP client (and its own connection pool) for every request object, status list, and presentation response it fetched, so no connection was ever reused and a burst of many rapid local fetches could exhaust ephemeral ports. The clients are shared now, which pools and reuses connections.

## [2.1.1] - 2026-08-30

### Fixed

- **Wallet warnings that can stand alone read as sentences.** Several presentation request findings (a missing or unreadable relying party registration certificate, the ARF content, validity and over-asking checks, and the vp_token query requirement) started with a lowercase letter, which looked wrong when the finding was shown on its own rather than grouped into one activity log entry. They now start with a capital letter.

## [2.1.0] - 2026-08-30

### Added

- **The demo verifier can build a presentation request by hand.** Next to the demo ticket and PID presets, a Custom option assembles a DCQL query one credential at a time (format, type and claim paths, where a path ending in [*] selects every array element and [n] one by index, per OpenID4VP 1.0 §7.1). The request runs under a chosen client identifier scheme (x509_hash, x509_san_dns, redirect_uri or pre-registered, the last with a settable client id) and takes an optional request object signing key and verifier_info, so a wallet can be tested against requests the presets do not cover (such as the empty-array disclosure below).
- **In debug mode the wallet can present a credential whose issuer the request's trusted_authorities do not match.** A verifier can limit a request to specific issuers (DCQL trusted_authorities). Strict mode offers only the credentials that match. Debug mode also offers the ones that do not, flagged in the consent dialog, so a verifier can be tested against a wallet that ignores the restriction. A matching credential stays the wallet's default pick.
- **The wallet checks the relying party registration certificate against the ARF content rules.** A presentation request should carry a registration certificate (an rc-wrp+jwt in verifier_info) that the ARF requires of every request (RPRC_19). The wallet now warns when it is absent, and when present it validates the certificate against the mandatory content of ETSI TS 119 475 V1.2.1 §5.2.4 (trade name, relying party identifier, service description, entitlements, privacy policy, data deletion contact, supervisory authority, registered credentials) and a validity window no longer than 12 months, and it runs the ARF RPRC_21 over-asking check (every claim the request asks for has to be one the certificate registered). Each finding is a warning in every mode, since validation mode is OpenID4VP and HAIP strict and the ARF rules are not part of it. The demo verifier and demo issuer now present a fully conformant registration certificate.

### Changed

- **A request or credential that fails several checks is one activity log entry, not a long line or an entry per finding.** The HAIP profile findings on an offer or credential, the OpenID4VP profile findings on a presentation request, and the registration certificate findings used to be joined into the entry's main line or logged one entry each. Each now records a single warning naming the count, with the full list in the entry details for the UI to expand.
- **The wallet always sends a Request Object encryption key in `wallet_metadata`.** Before, the encryption JWK was in the `request_uri` POST only under `--require-encrypted-request`. It is always sent now (OID4VP 1.0 §10), so a Verifier can encrypt the Request Object. `--require-encrypted-request` now only rejects a `request_uri` response that is not a JWE, so a Verifier that signs the Request Object without encrypting it still works without the flag. The metadata also lists the Authorization Response encryption algorithms (`authorization_encryption_alg_values_supported`, `authorization_encryption_enc_values_supported`), and lists `request_object_signing_alg_values_supported` only when the Client Identifier Prefix allows a signed Request Object (not under `redirect_uri`, which forbids one).
- **Keeping a non-standard credential follows the wallet mode.** During issuance and import, debug mode keeps a credential that breaks a spec rule in a way that still resolves (an SD-JWT that breaks RFC 9901, an mDoc with a part the parser could not read) and records each break as a warning. Strict mode refuses it. A `status` that is not a Token Status List is a HAIP finding (a warning in debug, a refusal in strict), since §6.1 is where that rule lives and SD-JWT VC §2.2.2.3 leaves the mechanism open. This is the same split the wallet uses for authorization server deviations.

### Fixed

- **The decoder shows a credential that breaks a spec rule in a recoverable way instead of a blank page.** An SD-JWT that a strict parser refuses (a nested `_sd_alg`, a digest that repeats because the claims are mirrored into a `credentialSubject`, a disclosure that redefines a signed claim, an unreadable disclosure, an `_sd_alg` this build cannot compute) now resolves as far as it can, with each break shown as a deviation (a real credential can hit several at once). An mDoc that drops a malformed namespace or a repeated element records it rather than dropping it silently, and a plain JWT VC shows the same deviations. The decode only fails when there is no JWT to read at all.
- **A `status` claim that is not a Token Status List is a warning, not a silent gap.** HAIP 1.0 §6.1 asks the `status` claim to hold `status_list` (the IETF Token Status List). A credential whose `status` uses a W3C `StatusList2021Entry` used to read as having no status at all. The decoder now warns and names the format, and under `--haip` the credential gets a §6.1 finding.
- **A W3C JWT VC (jwt_vc_json) shows its credential type, not its format.** The wallet read the display type only from a vct claim, which a W3C Verifiable Credential does not carry, so the listing fell back to the format and showed jwt_vc_json for the type. It now reads the type from the VC type array (in the vc claim or at the payload root), so a credential like NFEmployeeCredential shows its type.
- **The wallet metadata sent in the request_uri POST carries response_types_supported.** OpenID4VP 1.0 §10 makes the wallet metadata an RFC 8414 Authorization Server Metadata document, where response_types_supported is REQUIRED, and the wallet omitted it, so a verifier that parses the metadata (such as the EUDI reference verifier) rejected the request_uri_method=post request. It now carries response_types_supported (vp_token, per §5.6 and the §13.1.2 example). It also states response_modes_supported (direct_post, direct_post.jwt, dc_api, dc_api.jwt), which RFC 8414 leaves optional but whose default of query and fragment does not describe this wallet.
- **A DCQL path onto an array of selectively disclosable elements discloses an empty array, not the elements.** OpenID4VP 1.0 §7.1 selects array elements with a null or an index, so a whole path like nationalities selects only the array. The wallet used to disclose the array with its elements, which §6.4 forbids (a claim the path did not select). It now discloses the array without those elements, and the consent dialog and the activity log warn that the verifier has to end the path with null or an index to receive the values. An array whose elements are not selectively disclosable is unaffected.
- **The consent dialog shows what each requested claim actually discloses.** A claim that discloses an empty array now shows [] with a short note beside it, rather than the credential's value next to a block of warning text. A requested claim the selected credential cannot satisfy (a claim it does not carry, or an array index out of range) is shown as not disclosed with a note, in debug mode, instead of being dropped silently. When more than one credential answers a query, one that satisfies every requested claim is preferred, so a fully answerable request draws no such note. Every note groups into one activity log entry. Strict mode still refuses a request it cannot fully satisfy.

## [2.0.7] - 2026-08-27

### Fixed

- **The wallet records the nonce request and handles a nonce endpoint that does not answer.** The key proof challenge comes from the Nonce Endpoint (OpenID4VCI 1.0 §7.1, an HTTP POST). The pre-authorized flow fetched it without recording the call, so a nonce endpoint that failed left no trace and surfaced only later as a rejected proof. The nonce request and its response are now in the activity log for both issuance flows. When an advertised nonce endpoint returns no c_nonce, strict mode refuses the issuance naming the endpoint, and debug mode warns and sends the proof without a c_nonce so the issuer's rejection is the finding. When the endpoint answers the POST with 405 and serves the c_nonce only over GET (a §7.1 deviation), debug mode fetches it over GET with a warning.

## [2.0.6] - 2026-08-27

### Added

- **The demo issuer's sign-in page has a debug panel showing the wallet's client authentication.** During the authorization code flow the page now carries a collapsible panel with the client_id, the OAuth-Client-Attestation and the OAuth-Client-Attestation-PoP the wallet sent at the PAR endpoint (or a note when the client authenticated with nothing), so a wallet developer can inspect what their client presented.

### Fixed

- **A deviating `iss` or `state` in the authorization response is reported, not silently accepted in debug.** RFC 9207 `iss` and RFC 6749 §4.1.2 `state` were checked only in strict mode, so in debug a mismatched value (or, when the server advertised iss support, a missing one) passed with no warning. Each is now worked around in debug with a warning and refused in strict. A missing `iss` is a deviation only when the server advertises `authorization_response_iss_parameter_supported`.
- **The pre-authorized flow fails clearly when the token response carries no access_token.** RFC 6749 §5.1 makes access_token REQUIRED; the pre-authorized code flow read it without checking (unlike the authorization code and refresh flows), so a response omitting it sent the credential request unauthenticated and surfaced a confusing HTTP 401. It now fails naming the missing access_token.
- **A signed OpenID4VP request can no longer redirect its response to another host.** For an `x509_san_dns` client_id the wallet matched the request signer's certificate to the client_id but never checked where the response went, so a verifier with a valid certificate for its own domain could set `response_uri` to a different host and receive the presented credentials. The wallet now binds the response destination's FQDN to the client_id (OpenID4VP 1.0 §5.9.1): debug warns and strict refuses. The Digital Credentials API is origin-bound and unaffected.

- **`validate --haip` reports HAIP findings for mdoc and JWT credentials, not only SD-JWT.** The flag advertised a HAIP check on the credential but ran it only on the SD-JWT path. An mdoc's certificate chain and a JWT credential are now checked too.
- **A missing or empty required endpoint in issuer metadata is reported, not silently worked around.** `credential_endpoint` (OpenID4VCI 1.0) and `token_endpoint` (RFC 8414) are required. When one was missing or an empty string, the wallet fell back to the conventional path (`<issuer>/credential`, `<issuer>/token`) without a word, and an empty string even produced a broken empty URL. Strict mode now refuses such metadata, and debug mode warns and works around it with the conventional path.
- **A data race reading the holder key in the deferred-issuance poller is fixed.** The poller read the key field directly while a per-request reload could reassign it. It now goes through the locked accessor.
- **A token response that omits or misnames `token_type` is reported, not silently assumed.** RFC 6749 §5.1 makes `token_type` REQUIRED, and RFC 9449 returns `DPoP` for a DPoP-bound token. The wallet picked the authorization scheme from it but never flagged its absence, so a server omitting it (or returning something other than Bearer or DPoP) drew no attention. Strict now refuses such a response, and debug warns and proceeds on the assumed scheme (DPoP when a proof was sent, otherwise Bearer).
- **The KB-JWT `sd_hash` follows the credential's `_sd_alg` instead of assuming SHA-256.** RFC 9901 §4.3 computes `sd_hash` with the hash the credential's disclosures use, but both the wallet (creating the KB-JWT) and the demo verifier (checking it) hashed with SHA-256 unconditionally. A credential issued under SHA-384 or SHA-512 then produced or failed against a hash under the wrong algorithm. Both sides now read `_sd_alg` and hash with it, defaulting to SHA-256 only when the credential states none.
- **The demo verifier reports an SD-JWT VC whose issuer-signed JWT does not declare the `dc+sd-jwt` typ.** SD-JWT VC requires the issuer-signed JWT to carry `typ` `dc+sd-jwt` (or `vc+sd-jwt` during the transition), but the demo verifier never checked it. It now warns when the typ is missing or something else, without refusing the presentation.
- **An SD-JWT missing the tilde after its last disclosure is reported, not silently accepted.** RFC 9901 §4 requires the trailing tilde (the empty slot after it, where a Key Binding JWT would go, must not be omitted). The parser already read such a credential by treating the final component as a disclosure, but said nothing. It now records a warning, which the CLI validator and the demo verifier surface.
- **A verified mdoc that omits the MSO `digestAlgorithm` is reported, not silently defaulted.** ISO 18013-5 requires `digestAlgorithm`, but verification fell back to SHA-256 without a word when it was absent, so an issuer leaving it out drew no attention. The value digests still verify under SHA-256, but the omission is now surfaced as a warning by the CLI validator and the demo verifier.
- **The demo verifier no longer reports an mdoc with no stated validity as being within its validity period.** ISO 18013-5 makes the MSO `validityInfo` (with `validUntil`) required, but an mdoc that omits it has no expiry to check. The verifier still ran its "within its validity period" check, which read the absent `validUntil` as no expiry and passed, affirming a validity it never verified. It now warns that the period cannot be checked instead of claiming the credential is current.
- **A presented mdoc verifies against a session transcript that is not canonically encoded.** The device signature covers the session transcript, and the verifier rebuilt it by decoding and re-encoding the bytes, which reproduces the original only for a transcript that round-trips canonically. A transcript carrying a map or a tag (an ISO 18013-7 handover) then verified as a different value and the signature was rejected. The verifier now embeds the transcript bytes verbatim, as the holder signed them.
- **The HAIP check that a credential's signer is not self-signed now catches a self-signed leaf.** HAIP 1.0 §6.1.1 says the certificate signing a credential must not be self-signed. The check asked the certificate to verify its own signature through a path that rejects a non-CA certificate on its constraints before ever checking the signature, so a self-signed end-entity certificate, the exact case the rule is about, passed unflagged. It is now detected.
- **A presented mdoc carries the element that was selected, not the one at its position.** The presentation copied each disclosed data element from the raw namespace array by the parsed item's index, but the parser skips unparseable items and drops repeated element identifiers, so that array can be shorter or reordered. A selection could then disclose the wrong element or a broken digest. Each element is now taken from its own parsed bytes, so it always matches what was asked for.
- **A presented SD-JWT VC no longer drops a claim nested under a cleartext parent.** When a verifier asked for a claim like `address.street_address` and the credential carried `address` as a plain object with its members selectively disclosable (a common SD-JWT VC shape), the wallet resolved the request only through the credential's top-level `_sd`, found no `address` disclosure, and left the claim out of the presentation even though the consent dialog listed it. The wallet now walks the requested path from the payload root, descending a cleartext parent to reach its selectively disclosable children.
- **A visitor's credential import, deletion or status change is no longer dropped on a busy shared instance.** These management actions changed the wallet in memory and then saved, but the save was not fenced against the per-request reload a shared demo runs on every request. A reload landing in between reverted the change on disk, so an import, delete or revoke could silently not take. The change and its save now hold the store lock together, so a reload cannot interleave.

- **The demo's Issue Credential form no longer offers logo alt text with the logo field gone.** A shared demo takes no visitor-supplied image, so the form hides the logo and background image inputs. The "Logo alt text" field stayed behind, asking for a description of a logo that could not be set. It is now hidden with the logo field.
- **The issuer's logo shows in the credential offer dialog.** OpenID4VCI lets a Credential Issuer publish a logo in its metadata (`display[].logo`), and the wallet read it but never showed it: when the card art moved to the fetched-and-embedded image path, the issuer logo was left behind as a bare metadata URL the dialog could not render under its image policy. The logo is now fetched through the same policed path as the card art and embedded, so the offer dialog shows it beside the issuer's name. It is embedded even under `--adhoc-display-images`, since it is shown once at consent time and never stored.
- **The demo issuer tells the wallet which PID it will accept during issuance.** Before it issues a ticket, the demo issuer asks the wallet to present a PID, and it accepts only a PID that chains to its own CA. The request named no trusted authority, so the wallet could present a PID from another issuer, which the demo then rejected a step later during verification. The request now names that CA as an `aki` trusted authority (the CA key identifier a wallet reads from a credential's `AuthorityKeyIdentifier`), on both the SD-JWT and mdoc alternatives, so the wallet presents only a PID that would pass, or reports it holds none. The demo issuer page notes this when presentation during issuance is selected.

## [2.0.5] - 2026-08-26

### Fixed

- **The demo issuer's authorization code flow works with an external wallet again.** The sign-in page the issuer shows during the authorization code flow carried the toolkit's global `form-action 'self'` Content-Security-Policy. A browser enforces `form-action` across the redirect a form submission triggers, so after signing in, the redirect back to the wallet's `redirect_uri` was silently blocked whenever that URI was cross-origin or a custom scheme (every real mobile wallet). The sign-in button appeared to do nothing, the wallet never received the code, and no token request was made. Only the wallet's own same-origin redirect got through, which is why the flow worked with this wallet but not others. The sign-in page now widens `form-action` to the request's own redirect target, keeping every other restriction. The pre-authorized code flow was never affected (it uses no browser redirect).
- **The JWT key proof names the client as `iss` when the wallet has one.** OpenID4VCI 1.0 Appendix F.1 defines the proof's `iss` claim as the `client_id` of the client making the credential request. The wallet left it out entirely, so an issuer that binds the access token to a registered OAuth client and checks the proof against it (many do) rejected the credential request with `invalid_proof`. The proof now carries `iss` when the wallet obtained the token as an identified client (the authorization code flow, or a pre-authorized flow that authenticated the client), and still omits it for an anonymous pre-authorized flow, where naming a client the token is not bound to would fail that same check. Thanks to Massimiliano Perrone for the detailed report (#13).
- **A long claim name in the offer preview no longer breaks mid-word.** The credential offer's "you will receive" list gave each claim name the same narrow column the presentation dialog splits for a value, so a long mdoc claim path (its namespace prepended, like `eu.europa.ec.eudi.loyalty_mdoc.given_name`) was squeezed into part of the row and wrapped in the middle of a word. The name now spans the whole row in the offer preview (there is no value beside it), and a path too long for one line breaks at its dots.
- **The credential card's front face no longer shows through the flip on iOS.** Opening a card's description flips it on a phone. iOS WebKit only culls a hidden backface on an element that is itself 3D-transformed. The back face rotates and was culled, but the front face carried no transform, so its mirrored name and logo showed through the whole turn on iOS browsers. The front face now carries an identity rotation, the same 3D layer the back has, so it is culled through the flip too.

## [2.0.4] - 2026-08-25

### Added

- **`--adhoc-display-images` fetches display art on demand instead of storing it.** An issuer's metadata can name a card logo or background as an http(s) URL, which the wallet fetches once through the policed client and stores. The flag keeps an https URL instead, so the card fetches it on demand and nothing is stored (the issuer then sees each render; a data URI, a template's own art, and http URLs are still stored). `GET /api/config` reports it as `adhoc_display_images`.

### Changed

- **Display images are stored beside wallet.json, not inside it.** A credential's card art (logo, background) was embedded in `wallet.json` as a base64 data URI, so a wallet holding image-heavy credentials grew the file to megabytes and a hosted instance that reparses it on every request crawled. The images now live as content-addressed files in an `assets/` directory beside `wallet.json`, referenced by `asset:<hash>.<ext>`, so the file stays small. The same image is stored once, and an image a wallet embedded before this change is still served and moves to `assets/` on the next save. Assets a demo reset leaves unreferenced are pruned.

## [2.0.3] - 2026-08-25

### Fixed

- **A busy demo no longer queues up behind store reloads.** The wallet reloads its store on every request so visitors of a shared demo see each other's changes, but reparsing a wallet.json that carries embedded card art runs to megabytes, and doing it on every poll (serialized) made a busy instance lag for seconds before a click even registered. The reload now skips the reparse when the file has not changed since the last load, so unchanged requests return at once. A reparse still runs at least every couple of seconds, so a change a coarse-resolution filesystem reports with the same size and time is not missed.
- **A credential listing is small again.** The overview embedded each card's display images (logo, background) in `/api/credentials` as base64 data URIs and carried the full claim values and the raw credential too, so a wallet holding a dozen styled credentials returned several megabytes and the cards appeared only once the whole list had loaded. The listing now references each image by URL (`/api/credentials/{id}/display/{logo|background}`, served on its own and cached hard with an ETag) and leaves out the claim values and the raw credential, which an overview card does not render (the per-credential GET and the decoder still carry them). Cards render at once and the browser fetches the art in parallel.
- **A deferred credential recovers a display that did not resolve at offer time.** Display is resolved when the offer is accepted and carried on the deferred record. When that came back empty the collected credential was left blank (its card showing the raw type and a generic glyph). The poller now resolves the display again from the metadata it fetches for the collection, so the card is styled once the credential arrives.
- **The credential card hides its front face through the flip on iOS.** Opening a description flips the card on a phone. iOS WebKit stops honoring `backface-visibility` on an element that also clips its overflow, so the front face (its name and logo, mirrored) showed through the turn on iOS browsers. The overflow clip moved to the card art itself, which the earlier faces did not need, so the front face stays hidden through the flip on iOS as it already was elsewhere.

## [2.0.2] - 2026-08-25

### Fixed

- **A verifier that encrypts with RSA-OAEP is answered.** OID4VP 1.0 makes ECDH-ES mandatory to implement but permits other JWE algorithms, so a verifier may put an RSA encryption key in `client_metadata.jwks`. The wallet accepted only EC P-256 keys and refused the response (no encryption key found). It now encrypts a `direct_post.jwt` or `dc_api.jwt` response with RSA-OAEP to an RSA verifier key, and prefers an EC key (ECDH-ES) when the verifier offers both. Under `--haip` an RSA key is a §5 violation (debug warns and proceeds, strict refuses). A verifier that publishes only a signing-marked key is a misconfiguration (debug warns and encrypts to it anyway, strict refuses).
- **A deferred issuance is collected on the public demo.** The demo reloads the wallet from its store on every request (its state is shared), and that reload replaced the deferred issuances the poller works from. A credential the issuer deferred (a transaction id in place of the credential, §9) was recorded and then wiped moments later by the next poll of the page, so the poller never collected it. The poller and the offer that records a deferral now own that list in memory (persisted whenever it changes), so a per-request reload no longer clears it and the credential arrives once the issuer has it ready.
- **A partial batch is accepted and every copy stays presentable.** A batch-capable issuer may issue fewer credentials than the proofs the wallet sent, and it binds each key to at most one credential, so it need not bind any of them to the holder key. The wallet now imports whatever comes back (one credential, or several fewer than advertised, whichever proof keys they name) and records each copy's binding key, so every copy signs its key binding (RFC 9901) with the key its cnf names. A copy the issuer bound to the holder key still uses the holder key.
- **An issuance that cannot finish says so in the activity log.** After the credential response arrives the flow can still fail (an unusable credential, a deferred response the wallet cannot act on, an import error), and until now the activity log stopped at the last step that succeeded. Any error that ends the flow after the offer was received is now recorded, naming the issuer and the reason, so a failed issuance is visible rather than silent.
- **The credential card flips cleanly on a phone.** Opening a credential's description flips the card to its back. The 3D perspective is now held steady through the flip, so the front face (its name and logo, mirrored) no longer shows until the animation ends.

## [2.0.1] - 2026-08-25

### Fixed

- **A batch-capable issuer that issues a single credential is accepted.** An issuer that advertises `batch_credential_issuance` makes the wallet request a batch (several key proofs), but the issuer may hand back a single credential, which OpenID4VCI 1.0 allows ("unless the Issuer decides to issue fewer Credentials"). The wallet now imports that one credential rather than refusing one that is not bound to its holder key (a credential bound elsewhere reads as bound to another key on its card).

## [2.0.0] - 2026-08-24

### Summary

2.0.0 is a wallet redesign around the credential card. A card now wears the appearance its issuer declared (name, description, logo, colors and background image) and reads its own trust state, and the consent and offer dialogs render that same card. The wallet gained batch issuance (it holds many copies of a credential and presents an unused one each time, so two presentations cannot be linked), deferred issuance, and the option to issue a credential unbound. Credentials carry a short hex id, the activity log moved into a collapsible drawer so the list owns the scroll, and a credential's description opens behind an About control. The country-independent PID now carries the EUDI PID Rulebook's own Jan Wijnand example instead of borrowing the German specimen.

### Added

- **Credential cards show the appearance the issuer declared (§12.2.4).** The name, description, logo, colors and background image travel with the credential and render on its card. The display name is the headline (or the technical type when the issuer declared no name), and the type otherwise sits in the meta line with the other facts (a DCQL query matches on the vct). The background image and color are the card face as one slot (the image over the color, or a solid color, or a plain tile with a monogram), and the color stays in the face. The card lays out from its width, a dense row on a wide list (a fixed card-art thumbnail beside the facts) and a wallet-style card on a phone (the art a full-width hero with the name on it). In the consent and offer dialogs the card is narrow, so its meta line keeps the facts that help pick a credential (id, iat, type) and drops the issuer and claim count. The first display entry is used whatever its locale.
- **Card images are fetched safely and once.** An image is fetched at issuance through the policed client (up to 4MB, bounded to 32 megapixels, cached at 256KB and downscaled when larger) and embedded as a data URI, so a card never calls the issuer again. An SVG logo is kept as it was served (a browser renders it inertly in the card), bounded to the same 256KB and refused when it carries a script. The offer preview fetches under the same internal-address policy, since anyone can issue on a shared demo. An out-of-range color or a pair below 3:1 contrast is warned about, never fatal (`credential_display_invalid`, `credential_display_low_contrast`, `credential_display_image_rejected`).
- **The credential card reads its own trust state.** Each card shows its status, validity, a signature checked only against the key material the credential carries (self-consistent, never issuer trust), its holder binding, the issuer as the format names it, the count of its subject attributes (the protocol members like iss and cnf left out) and when it was issued. Two same-type credentials are told apart by that issued time and a short id.
- **The consent and credential-offer dialogs render the same card.** The consent dialog names who is asking (the verifier client_id or the issuer, with a self-asserted client_name when the request carries one) and, for a presentation, whether the request object was signed and self-consistent or not authenticated. A credential with no declared appearance shows its monogram or a generic glyph there too, never a blank tile. The disclosed fields are toggles that can withhold even a requested claim.
- **The demo issuer and the generated credentials wear the eudi-dev look.** The demo issuer and its event ticket carry the eudi-dev logo (served at `/issuer/logo.svg`) and the brand blue, and the generated PID credentials do too, so a fresh wallet shows styled cards. The generated German PID (`urn:eudi:pid:de:1`) is told apart from the country-independent one by its name and the public German ID specimen (the Personalausweis "MUSTER") as its card art.

- **The wallet holds a batch and presents an unused copy each time.** When an issuer issues a batch (one credential per key proof, §8.3), the wallet keeps every copy, each bound to its own key, and presents a copy chosen at random among those used the fewest times, so it shows each once before reusing any and two presentations of the same credential cannot be linked (EUDI ARF method C, ISSU_52). A batch reads as one credential everywhere: a small stacked card in the list and the consent dialog (a plain card on a phone, and no count on the art, since a batch cycles and reuses), and presenting, deleting or revoking it acts on the whole batch. Every copy sits on its own status index so a shared one cannot link them, and revoking flips them all. The wallet can also mint a batch itself (`issue ... --wallet --batch N`, a Copies field in the Issue dialog).
- **The demo issuer offers a batch of a chosen size and defers issuance.** It advertises `batch_credential_issuance` and, when an offer asks for a batch (a Copies selector, Single to five copies), signs one copy per key proof. An offer created with the Deferred option returns a transaction id from the credential endpoint and hands the credential over at a new deferred credential endpoint once it is ready (§9). The wallet shows the credential awaiting issuance, drawn with the card face the offer declared, and collects it a few seconds later.
- **A credential template carries the display of the credentials issued from it.** The pre-defined PID templates hold the eudi-dev appearance (the brand blue, the logo, and the German ID specimen for the German PID), which the wallet resolves from its bundled assets by an `embedded:<file>` reference read by base name, so a template reaches only the wallet's own read-only assets. Choosing a template in the Issue dialog fills the name, description and colors from it and shows that it provides its own logo and background image. The issued credential wears that art: the template's embedded logo and background image cannot travel in a form field, so its name travels instead and the server applies its display, with any explicit field laid over it (setting a name keeps the art). The generated PID appearance now comes from its template.
- **Issuing can leave a credential unbound.** The Issue dialog (a Holder binding choice) and the CLI issue commands (`--unbound`) issue a credential with no holder key. An SD-JWT VC then names no cnf, which SD-JWT VC (§3.2.2.2) allows, so it is a bearer credential anyone holding it can present. An mdoc names no MSO deviceKey, which ISO 18013-5 (§9.1.2.4) makes mandatory, so an unbound mdoc is a deliberately malformed document for testing verifier rejection rather than a presentable bearer credential. A presented unbound SD-JWT carries no key binding (RFC 9901 §3.3), and an unbound mdoc presentation warns that its device key is missing. The default binds the credential to the wallet. An unbound credential cannot be a batch (a batch needs a distinct holder key per copy).
- **Issuing a credential can set its display.** The Issue-Credential dialog and the CLI issue commands (`--display-name`, `--display-description`, `--background-color`, `--text-color`, `--logo`, `--logo-alt`, `--background-image`) set the name, description, colors, logo (and its alt text) and background image the card shows. Colors are held to the §12.2.4 value space (a bad one is dropped with a warning) and images run through the policed, size-capped cache, the same as an issuer's display metadata. The logo and background image take a file path, a data URI or an https URL. A public demo takes no visitor-supplied image (the logo and background-image fields are gone there), while a template's own art still applies.
- **The card reveals the issuer's description behind an About control.** A credential that carries a `description` shows an About button beside its actions (an info glyph). A credential with none shows no control, so its presence is the cue there is one. On a wide list the button opens a bounded pane below the row (indented under the art, the text held to a readable measure). On a phone the card flips to read the description on its back. The pane clamps its height and scrolls with the wallet's one themed scrollbar. The pre-defined PID templates carry a default description, so a fresh wallet shows the control.
- **Display text is bounded for safety.** Every text a display can carry (name, description, locale and logo alt text) is capped when it is issued or read from an issuer, a form or a template, since a shared demo takes any of them from anyone. Images stay byte-capped in the cache.

### Changed

- **The country-independent PID carries the rulebook's own example identity.** The `pid-*` templates (`urn:eudi:pid:1`) now hold the EUDI PID Rulebook v1.7 worked example, the Dutch Jan Wijnand ('t Hart) of Leiden, instead of borrowing the German specimen. The `german-pid-*` templates keep the German Erika Mustermann, so the two PIDs describe different people (which also tells them apart when both answer a `urn:eudi:pid:1` query).
- **`wallet list` and `wallet show` report the issuer-declared display.** The list carries a NAME column with the credential's display name, and `wallet show -v` prints its description, so the appearance a card shows is legible from the terminal too.
- **A credential's id is a short hex handle that resolves from a prefix.** New credentials get a git-style hex id instead of a UUID, and a command names one by the short id the card shows (`wallet show`, `wallet remove`, `wallet refresh` and the decoder `?id=` link all resolve an unambiguous prefix to the full id). An exact id still wins, and a prefix that matches more than one credential names none.
- **The credentials own the main scroll and the activity log moved into a drawer.** With many credentials the one long scroll buried the log and made the two fight for the same bar, so the credential list now owns the main scroll and the activity log is a collapsible drawer pinned at the bottom with its own scroll (its state is remembered per viewer). Every scroll region (the list, the drawer, the dialogs, the decoder) uses one thin theme-aware scrollbar instead of the platform default, and the list reserves the scrollbar's width so its content does not shift sideways when it grows past a screen.
- **EC key coordinates are read and written through the crypto/ecdsa encode and decode calls.** Go 1.26 deprecated direct access to the big.Int coordinate fields, so the JWK, COSE key and thumbprint code now uses `PublicKey.Bytes`, `ParseUncompressedPublicKey` and the private-scalar `Bytes` call. The bytes are identical to before (an equivalence test pins this across P-256, P-384 and P-521), and rebuilding a key from its coordinates now rejects a point that is not on the curve. The debug reverse proxy moves from the deprecated `ReverseProxy.Director` to `Rewrite`.

### Fixed

- **A dialog answered in one tab closes in the others.** Two tabs of the same browser both show the dialog for a pending request. Resolving it in one (approve, deny or a timeout) now closes the others too, which used to keep asking about a flow that had already ended. Every resolution notifies the open event streams, and a tab whose dialog names a request that is no longer pending closes it.

## [1.26.2] - 2026-08-22

### Fixed

- **Credential cards lay out at phone width.** On a narrow screen the action buttons kept their row and squeezed the credential body into a sliver a few characters wide: a long type name broke into one vertical column and the badges broke inside their labels ("Ext ern al sta tus"). The actions now wrap onto their own row below the content, the type name breaks only where its line ends, and a badge wraps as a whole. Checked at 375px and 320px, with the desktop layout unchanged. [ADR-0015](docs/adr/0015-the-web-ui-lays-out-at-phone-width.md) records the rule: every view lays out down to 320px, and narrow width is part of checking a layout change

- **An offer naming an authorization server that states it cannot take the grant now falls back to an advertised one that can.** The EUDIPLO playground names its presentation-during-issuance authorization server in a pre-authorized code offer. That server lists only `authorization_code` and `refresh_token` in `grant_types_supported`, so the token exchange failed with `Invalid grant_type`. In debug mode the wallet now reads the metadata of the other advertised `authorization_servers` entries (however many the issuer lists) and continues with the first that lists the grant, logged as a warning (`authorization_server_fallback`). When none states support, a warning says so (`authorization_server_fallback_unavailable`) and the flow stays at the named server. The move happens only between explicit statements on both sides, and a server that omits `grant_types_supported` has said nothing. Strict mode still refuses before the code is spent. §4.1.1 makes the offer's `authorization_server` a value the wallet "can use" and §12.2.4 has the wallet read `grant_types_supported` to pick the server for its grant

## [1.26.1] - 2026-08-22

### Fixed

- **The decoder shows a credential without waiting for the issuer.** Decoding ran one request that verified the signature and the revocation status before anything reached the screen, so the output waited on a round trip to whatever host the credential names. A driving licence issued in Thailand took 0.8s to decode from a local server and 2.8s from the public demo, all of it the status list fetch. The decode and every check answerable from the credential itself (type, expiry, integrity, a signature covered by an embedded certificate) now run in their own pass and render right away, typically in 30ms. The status list and an issuer key named by metadata are fetched alongside it, and the banner reads **Checking** with those rows marked until they answer. `POST /api/validate` takes an `offline` flag for that first pass, and a check it leaves open is marked `needsNetwork`
- **Pasting a credential decodes it once instead of twice.** A paste raises a paste event and an input event, and each scheduled its own decode, so every paste fetched the status list twice and the second answer was what the reader waited for
- **A claim value of a few kilobytes no longer runs off the side of the output.** A `portrait` claim carries an image as a base64 data URL, and the disclosure and resolved claim lists put all of it on one line (70,000 pixels wide for a 9KB portrait), which pushed the rest of the section out of view. Long values now show their first 300 characters with the rest one click away, and an image claim is shown as a thumbnail
- **The wallet attestation is accepted again by issuers that verify it against draft-07.** Version 1.26.0 made the outgoing attestation version-exact per the configured OpenID4VCI version, which dropped `iss` from both JWTs under `--vci-version 1.1` and `nbf` and `exp` from the PoP under every version. Issuance against the Animo playground then failed at the token exchange with `Error during verification of client attestation jwt`, and the public demo profile (which selects `--vci-version 1.1`) hit it on every offer. The attestation and its PoP now carry the union of the claims the supported drafts define, which is the draft-07 shape, whatever version is configured. The later drafts only stopped requiring those claims, and each of them lets a JWT carry claims it does not define (§5.1 and §5.2 rule 1), so one shape verifies under all three. [ADR-0014](docs/adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md) records the revised rule

## [1.26.0] - 2026-08-21

### Added

- **Three drafts of OAuth 2.0 Attestation-Based Client Authentication are supported: draft-07, draft-08 and draft-10.** [ADR-0014](docs/adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md) records the rule: the EUDI ARF is the root of the specification graph, every draft a referenced specification pins stays supported, and the latest published draft is always supported alongside them. OpenID4VCI 1.0 pins draft-07 (its §14.7 says to prefer the pinned version), the OpenID4VCI 1.1 editor draft pins draft-08, and draft-10 is the latest. Outgoing attestations are version-exact: `--vci-version 1.0` emits the draft-07 shape (`iss` in both the attestation and its PoP, which that draft requires), `--vci-version 1.1` emits the draft-08 shape (neither, and the PoP drops the `exp`/`nbf` no draft defines). The draft the authentication was resolved under travels with the stored credential, so a later refresh emits what the issuance did
- **The wallet speaks the combined DPoP proof of possession of draft-10.** A server that offers only `attest_jwt_client_auth_dpop`, or whose `client_attestation_pop_methods_supported` names `dpop_combined` without `attestation_pop_jwt`, gets the attestation with the DPoP proof as its possession proof and no dedicated PoP header (draft-10 §5.2). Using a mechanism the configured draft predates is warned about and done, per ADR-0014. Such a server used to be refused as an unsupported token endpoint auth method
- **The wallet follows the header-based challenge conversation.** A challenge served in the `OAuth-Client-Attestation-Challenge` response header is carried in the next PoP, and a request refused with `use_attestation_challenge` or `use_fresh_attestation` is retried once with the served challenge or a fresh attestation (§6.2 of every supported draft). Only the `challenge_endpoint` route worked before, so a server using header-based challenges failed the exchange permanently
- **The demo issuer accepts every supported draft's attestation shape and says which one it saw.** A shape that deviates from the draft the configured OpenID4VCI version pins, while being correct under another supported draft (an attestation without `iss` at a draft-07 configuration, a combined DPoP proof below draft-10), is accepted with a warning in the log naming both drafts. Under `--demo-issuer-client-auth optional` the metadata now also advertises the `none` proof of possession method, which is how draft-10 spells "the client MAY omit the attestation"

### Fixed

- **The demo issuer's pre-authorized code exchange authenticates the client.** The token endpoint advertised attestation-based client authentication as its only methods and then issued tokens on the pre-authorized grant to anybody, which contradicted both the metadata and HAIP 1.0 §4.4.1. The exchange now runs the same client authentication as the authorization code grant (the grant carries no `client_id`, so the attestation's `sub` stands on its own), verifies a DPoP proof where the wallet sends one and binds the issued token to it
- **A client attestation whose `cnf.jwk` carries private key material is refused.** Every supported ABCA draft requires the confirmation key to be a public key, and the JWK parser silently used the public half of a private key. The same check now guards the `jwk` header of a DPoP proof (RFC 9449 §4.3)
- **The demo issuer's pre-authorized code is single-use.** The exchange now binds the offer to the redeeming client (its DPoP key and its attestation), so a second redemption of the same code is refused with `invalid_grant`, the way a spent authorization code is (RFC 6749 §4.1.2). Redeeming twice used to rebind the first access token to the second redeemer's key, or strip its DPoP binding entirely
- **A request carrying more than one `OAuth-Client-Attestation` or `OAuth-Client-Attestation-PoP` header field is refused.** The validation checklist starts with "precisely one" of each, and only the first was read, so a second attestation could ride along unverified. The `alg` header of both JWTs is also checked against the advertised algorithms before the signature, so a mismatch is named as such instead of as a signature failure

## [1.25.5] - 2026-08-21

### Fixed

- **The badge on a credential bound to a key this wallet does not hold names the binding as the wrong one.** It read **No holder key**, which describes something else: a credential without holder binding at all (an SD-JWT with no `cnf`, an mdoc whose MSO names no `deviceKey`). Those are presented without key binding, they are not a finding, and they never carried the badge. The badge always meant the opposite (the credential names a holder key, and it is not this wallet's), so it now reads **Wrong holder binding**

## [1.25.4] - 2026-08-21

### Added

- **A presentation the wallet cannot sign key binding for is reported before it goes out.** The wallet signs a KB-JWT (RFC 9901 §4.3) and a DeviceSigned (ISO 18013-5 §9.1.3) with the one holder key it has, so a credential bound to another key produces a signature no verifier accepts. It used to be sent anyway and the first sign of trouble was the verifier's refusal, which names the signature and not the credential that could never carry a valid one. Strict mode now stops while the nonce is unspent, debug mode sends it and records the reason next to the response, so a run against a verifier still shows what that verifier does with it
- **A Request Object signed by a key this wallet cannot resolve is reported as unverified.** The x509 prefixes carry the signing certificate in `x5c` and are checked against it. The others resolve their key elsewhere: `decentralized_identifier:` through a DID, `verifier_attestation:` through the `cnf` claim of the attestation JWT, a bare `client_id` through a pre-registration this wallet has none of. Each of those left `VerifyRequestObjectSignature` with nothing to check, and it said so by returning no finding, which made a request nobody had authenticated read exactly like one whose signature verified. Each now names the key it would have needed and where that key lives. The signature is still not treated as fatal outside strict mode, so the flow runs and the finding is what the developer takes away, and a multisigned Digital Credentials API request now prefers a signature that actually verified over one that never could
- **A key named by a DID is reported as one nothing here resolves.** This toolkit finds an issuer key through the x5c chain HAIP 1.0 §6.1.1 requires or the issuer metadata SD-JWT VC defines, and the EUDI ecosystem uses no DIDs, so a credential or a Status List Token naming its key by a `did:` is one whose signature is never checked. That was visible only as an absence: the credential import said nothing, `validate` reported a skipped signature as if a `--key` would have fixed it, and a status list check failed with "no key to verify the status list token with", which reads as a fetch that went wrong. All four now name the DID. The import logs a warning naming it (and `wallet import` and `wallet scan` print it), the HAIP findings carry it next to the missing x5c, and a failing status list check both names it and lands in the activity log, where the reason survives the page reload that clears the badge's tooltip. Seen against `issuer.zenithcomp.co.th`, whose credentials and status lists are both signed by a `did:key`. [ADR-0013](docs/adr/0013-only-the-eudi-stack-is-supported.md) records the general rule: what the EUDI ARF and the specifications it references do not define is recognised and reported, never used
- **A credential bound to a holder key this wallet does not hold is reported when it arrives.** Key binding is signed with the wallet's own holder key, and the key that counts is the one the credential names: `cnf` for an SD-JWT (RFC 9901 §4.3), the MSO's `deviceKey` for an mdoc (ISO 18013-5 §9.1.3). A credential issued to another wallet can be stored, listed and decoded, but every presentation of it carries a key binding signature from the wrong key, which the verifier refuses (seen against `verifier.zenithcomp.co.th`, which answered `invalid_kb_jwt_signature` for a credential a wallet had imported rather than been issued). The import now says so, with both key thumbprints in the activity log entry, a warning from `wallet import` and `wallet scan`, a **No holder key** badge on the credential card, and `key_binding_not_held` in the credential summary. The check runs wherever a credential enters the store, so an issuer that ignores the wallet's proof key and binds the credential to something else is named at issuance too

### Fixed

- **A refused token request reports what the server said, not the status phrase it said it in.** The refusal's headline is read from the two fields RFC 6749 §5.2 defines, and a server answering outside that format puts the HTTP status phrase in `error` and its reason somewhere else: eudiplo answers `{"error":"Bad Request","message":"Invalid grant_type, must be \"authorization_code\" or \"refresh_token\""}`, so the CLI ended a run on `token exchange: Bad Request` while the sentence that explains it stayed in the log details. A `message` beside the code is now read the way an `error_description` is, as one string or as the list of things that were wrong with the request, and the rest of the body still travels in the entry's details

## [1.25.3] - 2026-08-20

### Fixed

- **An issuer sign-in opens in one browser tab, not two.** `wallet accept` and `wallet scan` open a tab for the wallet UI and name it on the call they make, so when the issuer asks the user to sign in the wallet sends that tab to the authorization URL. The CLI opened the same URL as well, which RFC 9126 §4 does not allow ("the client MUST only use a `request_uri` value once"), so one of the two tabs landed on the issuer's error for a request that had already been spent. A client that named a page now leaves the navigating to it and only prints the URL. One that named none (headless, `--no-open`, a plain API caller) still opens it, because nothing else will. The same was true of the verifier's `redirect_uri` after a local presentation: the consent tab receives the result and goes there, and the CLI opened a second tab at the same URL, where OpenID4VP 1.0 §13.3 has the verifier consume the session on the first arrival. Both now ask the one question (is a browser already holding this flow?) and every place that sends a browser somewhere is listed with the reason it is the only arrival, with a test that fails when a new one appears
- **A test that failed roughly one run in a hundred now builds the key it means to.** `TestEcdsaPublicKeyFromJWK` took the EC coordinates from `big.Int.Bytes()`, which drops leading zeros, so a generated key whose coordinate started with a zero produced a JWK narrower than RFC 7518 §6.2.1.2 allows and strict mode correctly refused it. The wallet was right and the test was wrong. Every place the tool emits a JWK already pads
- **A DPoP proof no longer carries the query of the endpoint it is for.** RFC 9449 §4.2 defines `htu` as the target URI "without query and fragment parts", and the wallet stripped only the fragment. An issuer that publishes an endpoint carrying a query (a tenant, an API version) and compares `htu` against its own target URI refused every proof the wallet sent, which reads as a rejected token rather than a malformed proof
- **A credential the issuer refused to be notified about is kept.** The Notification Endpoint is called once the credential is stored, and a call the issuer answered with an error ended the issuance instead: the flow reported `Failed: sending notification`, so nothing saved the wallet and a credential that had already been issued, imported and logged was thrown away. OpenID4VCI 1.0 §11 makes the endpoint optional and its use "not mandatory for the Wallet", and it says nothing about the credential, which the issuer has already handed over. The refusal is reported as a warning naming the endpoint and the credential is kept, which is what the deferred collector already did. The warning also says what the answer was against §11.3, which defines two: an Authorization Error Response (RFC 6750 §3) for a token the endpoint will not take, and a 400 whose JSON error SHOULD name `invalid_notification_id` or `invalid_notification_request`. An issuer answering outside those is named as doing so, because a bare status leaves a developer unable to tell a refusal from a wiring mistake. Seen against eudiplo, whose notification handler looks the session up by the access token's `sub` and answers `404 Could not find any entity of type "Session"` when a chained authorization server puts the client id there
- **`wallet scan` and `wallet accept` leave the credential offer for the wallet to read.** Both prompted for a transaction code when the offer required one, and finding out whether it did meant reading the `credential_offer_uri` here first. The wallet then read it again, and an issuer that serves it once (eudiplo consumes it unless `ISSUER_MULTI_CONSUMPTION` is set) answered the wallet with `404 Credential offer not found` for an offer the user was holding in front of them. Nothing is read here when a wallet is going to read it: that wallet's consent dialog asks for the code when it is asked interactively, which is how a scheme-dispatched link has always worked, so a scan now behaves exactly like a clicked link. The local headless flow has no dialog to ask in, so it still prompts, and hands the offer it read to the issuance, which falls back to it when the issuer will not serve the read a second time. An offer that names a `tx_code` and reaches an issuance with none (an auto-accepting wallet, or an API caller that left it out) is refused before the pre-authorized code is spent, naming the length and input mode to supply, rather than sending a token request the Authorization Server was always going to reject. [ADR-0012](docs/adr/0012-every-entry-point-runs-the-same-flow.md) records the rule: a door recognises a URI and hands it over, and never reads what the flow will read

## [1.25.2] - 2026-08-20

### Added

- **An offer naming an authorization server that cannot take its grant is reported before the grant is spent.** The wallet compares the server's `grant_types_supported` with the grant the issuance uses, which is the reading OpenID4VCI 1.0 §12.2.4 describes ("the Wallet can filter the server to use based on the grant type it plans to use"). Strict mode refuses while the offer is still redeemable elsewhere, debug mode warns and runs into the refusal as before. A server that states no grant types has said nothing, and is not a finding

### Fixed

- **The HAIP credential check holds a credential to what §6.1.1 requires.** It asked for the credential's `iss` to be named by a subject alternative name of the signing certificate, which HAIP 1.0 does not say: it defers credential key resolution to SD-JWT VC, where that rule was dropped after draft-08 and `iss` is now optional for a credential carrying `x5c`. Strict mode was refusing conformant credentials. §6.1.1 is checked in its place: the issuer's signing certificate and its trust chain travel in `x5c`, the trust anchor is not among them, and the signing certificate is not self-signed. Leaves this wallet signs with still name the issuer, for the verifiers that ask
- **A pending consent request is shown only to the browser that started it.** On a wallet several people reach, every visitor was told about every pending request, and one visitor's failure or issuer sign-in could land in another's tab. The consent request, the error report and the sign-in prompt now each belong to the browser whose flow raised them, recognised by an `eudi_session` cookie the wallet sets when it first serves that browser. It replaces a client-side rule that decided by timing: a tab claimed the next prompt or error for two minutes after it submitted something, so two visitors starting flows in the same window could be handed each other's. Anything a client submitted without naming a browser stays visible and answerable to every caller, which is what keeps the CLI, API clients and every handler installed before this working, and every client this project ships now names itself with `X-Eudi-Client` so a submission from one that cannot is reported once per run in the activity log. The browser the wallet redirects is also handed the request id, so one that keeps no cookie still reaches the request it was sent for. The same rule runs on every wallet, local or shared, because a local wallet is a shared one with a single visitor. The bar above the credentials holds what is waiting off screen, since one dialog fits on screen and a second request replaces the first; closing the dialog puts back what is left. A request nobody answers in five minutes is `expired` rather than denied, so a stale dialog is told it ran out of time instead of that somebody else answered it. The cookie identifies a browser and authenticates nobody, as [ADR-0002](docs/adr/0002-the-wallet-http-api-is-unauthenticated.md) says of this API generally, and [ADR-0011](docs/adr/0011-a-flow-belongs-to-the-browser-that-started-it.md) records the model
- **A refused token, PAR or authorization challenge request keeps what the server said.** The entry reported the refusal's code alone, which for a server answering outside the OAuth 2.0 error format (RFC 6749 §5.2) is the HTTP status text, so an issuance ended on "Bad Request" while the sentence naming the reason went with the body. The headline stays the code, and the status and the response body travel in the entry's details
- **An answer given after a long think still reaches the caller.** The server's write timeout is two minutes and a request waiting for consent runs for five, so a decision taken later was written to a connection Go had already closed: the caller saw a dropped connection instead of the result, and the URL handler took that for a failure and dispatched the same offer a second time. The handlers that wait for consent now hold the response open past every wait that can follow, including the presentation an issuer asks for once an offer is approved
- **The consent dialog's Edit view renders each candidate like the wallet overview.** A candidate showed its format and its type, which is what every credential matching one DCQL query has in common, so two PIDs that differ in their data appeared as the same row twice. Each one is now the card the credential list renders (the status, expiry and protected badges, and the claim names grouped by mdoc namespace), next to a **Decode** link that opens it in the decoder in a new tab

## [1.25.1] - 2026-08-19

### Fixed

- **The demo issuer spends a pushed `request_uri` on one authorization request.** RFC 9126 §4 gives a client one use of it, so a second request is refused rather than served. The login form still posts the same value back, as the issuer's own step, and an end-to-end test now signs in at that page, which is the branch the OIDF suite never drives
- **An authorization code offer no longer spends its pushed request before the browser gets there.** The wallet requested the authorization endpoint itself first, to see whether a code came straight back, and then sent the browser to the same URL. RFC 9126 §4 says "the client MUST only use a `request_uri` value once", so an issuer that enforces it answered the browser with an error and the issuance waited for a callback that never came. Whichever of the two can perform the sign-in now makes the single request
- **The warning about a `credential_offer_uri` that could not be read again fits on a line.** The issuer's whole error body was part of the headline. It now stays in the entry's details, where the full response already was

## [1.25.0] - 2026-08-18

### Added

- **`eudi proxy logs` prints the traffic of a proxy that is already running.** A proxy in a container, in the background, or on another machine prints to a terminal you do not have, so the command reads its dashboard instead: `eudi proxy logs [dashboard-url]`, with the same output the proxy prints itself and decode links pointing at that dashboard. `--follow` keeps printing as traffic arrives and keeps reattaching until it is interrupted, re-reading the recorded traffic after each reattachment so nothing recorded while the stream was down is missed, including after a proxy restart
- **The demo verifier can ask for the demo ticket next to the PID.** `POST /verifier/api/requests` takes `"ticket": "combined"` (one DCQL option holds PID and ticket, next to a PID-only option) or `"ticket": "optional"` (a second credential set with `required: false`). The verifier verifies both presentations of the vp_token, reports the ticket claims under `claims.ticket`, and accepts an answer that leaves the ticket out

- **The consent dialog lets the user change which credentials are presented** (#8). The wallet still auto-selects the answer and the dialog opens on it unchanged. When a request has alternatives, a row above the credential cards names how many and offers Edit: pick the DCQL credential-set option to answer with, and per credential query the credential that answers it. Changes apply immediately, Done returns to the summary, reset to auto restores the wallet's choice, and Deny/Approve keep meaning the presentation itself on both screens. The consent request carries the alternatives as `credential_options`, the approval names the selection as `picks` and `set_choices`, and a selection the request did not offer is refused with 400 while the request stays pending. Auto-accept wallets are untouched and submit the auto-selection as before

## [1.24.3] - 2026-08-18

### Fixed

- **The token request log entry names the client authentication it sends.** The wallet attestation pair and the DPoP proof travel as HTTP headers, so `token_request` entries now carry `client_attestation` and `dpop` flags next to the form, and the activity log shows what the issuer was given to check
- **The demo ticket signs under its own trust profile.** The ticket's leaf certificate now names the local trust profile issuer instead of the PID provider, and issuing one registers the ticket type as an issued attestation, so the trust list carries it under the profile the signature chain actually uses
- **A credential offer that changes between the consent dialog and the approval no longer redirects the issuance.** The offer is read again when the user approves, and an issuer that answers with a different `credential_issuer` or different credentials would have replaced what the dialog described. The issuance continues with the offer that was approved and records a warning naming what the second read offered instead
- **An issuer that serves a `credential_offer_uri` once no longer breaks the issuance.** An interactive issuance reads the offer twice: once so the consent dialog can say what is being offered, once when the user approves. OpenID4VCI 1.0 §4.1.3 allows both ("unless it is already cached"), but issuers that consume the offer on the first read answer the second with an error, which ended a flow the user had already approved. The approval now continues with the offer the dialog resolved and records a warning naming the read that failed
- **Event streams are no longer cut off by the server's write timeout.** The proxy dashboard stopped delivering after 60 seconds and the wallet's consent stream after two minutes, because the write deadline covers a streaming response as much as any other. Both clear it for the duration of the stream, the proxy dashboard sends keepalives so nothing in between drops an idle connection, and the dashboard page re-reads the entry list whenever it reconnects, so traffic recorded while the stream was down still appears
- **The proxy dashboard lists the newest traffic first**, like the wallet's activity log, in the entry list and in the flow timeline
- **Several mdocs in one ISO-mode response are signed over the same generated nonce.** ISO 18013-7 Annex B carries one `mdoc_generated_nonce` per response, in the `apu` of the encrypted response, and every document's session transcript hashes it. The wallet generated one per document and reported only the last, so a verifier rebuilding the transcript could verify the last presentation and none of the others. The nonce is now settled once per response (`--session-transcript iso`, a response answering more than one mdoc credential query)
- **Concurrent visitors on a shared wallet stay out of each other's flows.** The transaction code travels with the offer flow it belongs to instead of through one shared field, so two visitors approving offers at the same time each send their own code. The consent registry marshals requests under its lock, approvals write into their own copy of the matches, resolved requests are pruned instead of accumulating for the life of the process, and the offer consent timeout honors a decision that arrives as the timer fires, like the presentation consents already did. The demo issuer and verifier read the wallet CA under its lock, so the periodic demo reset can no longer tear the chain out from under an in-flight verification
- **The media type of a fetched request object follows the validation mode.** A `request_uri` response without `application/oauth-authz-req+jwt` is now a finding like any other: strict mode refuses it, debug mode records a profile warning in the activity log and reads the request object anyway. Before, a GET response passed without a word in every mode and a POST response was refused even in debug, so a verifier serving `text/plain` was silently tolerated on one path and hard-rejected on the other

## [1.24.2] - 2026-08-17

### Fixed

- **The wallet advertises request object encryption under its proper name.** The `wallet_metadata` sent with `request_uri_method=post` announced the encryption algorithms as `authorization_encryption_*_values_supported`, which is the pair for encrypting the authorization response. A verifier looking for the request object pair found nothing next to the `jwks`. The algorithms now travel as `request_object_encryption_alg_values_supported` and `request_object_encryption_enc_values_supported`

- **Every demo default yields to its explicit flag.** `--demo --pid=false` starts the demo without seeding a baseline, completing the rule the other implied settings already followed (`--mode`, `--haip`, `--vci-version`). The docs now also say that the baseline follows the pre-defined PID templates, so a template override decides what the demo seeds and what every reset restores

## [1.24.1] - 2026-08-17

### Added

- **The consent dialog shows the purpose the verifier registered for its request.** The wallet reads it from the wallet-relying-party registration certificate (typ `rc-wrp+jwt`, ETSI TS 119 475) in the request's `verifier_info` (format `registration_cert`, ETSI TS 119 472-2), which OpenID4VP 1.0 §5.1 defines for exactly this ("enrich the End-User consent dialog"). A plain purpose string and the localized `{lang, value}` form are both read (English preferred). A certificate whose signature fails against its own x5c leaf is not shown and leaves a warning in the activity log. The chain is not anchored to a trust list, like every other x5c this wallet checks, and the certificate's `sub` is the registered legal entity rather than the request's `client_id`, so it is not matched against one
- **The wallet header shows and toggles auto-accept.** An auto-accept wallet approves every presentation and offer without asking, so its consent dialogs never appear, which read as a broken flow. The header now names the mode and, on a locally-hosted wallet, flips it at runtime (`PUT /api/config/auto-accept`). The demo refuses the change like its other fixed settings. The Docker image's default command runs with `--auto-accept`, so its UI is where the silence was most confusing
- **The demo verifier and the demo issuer present registration certificates.** Every demo verifier request and the demo issuer's presentation-during-issuance request now carry `verifier_info` with an `rc-wrp+jwt` signed under the wallet CA, naming the party and its purpose, so the consent dialog on the demo shows why a request is made

### Fixed

- **A credential can no longer vanish after being issued.** Saving the wallet snapshots it and then replaces wallet.json, and the writers were not ordered with each other: the activity-log sink and the demo issuer save through their own callbacks, outside the server's lock. A save that snapshotted before an import could replace the file after the import's own save, and the next store reload made the loss permanent, so a flow logged "Received credential" and stored nothing. All saves now serialize inside the store, which also closes the window the earlier issuance and renewal write-backs still left open
- **A wallet started without --base-url completes the browser sign-in.** The redirect flow refused its own `/callback` ("redirect_uri is not handled by the running wallet server") because the callback check required a configured base URL, while the default client id and redirect URI are derived from the serving port precisely when there is none. The serve command now records the origin it answers on and the check falls back to it. The Docker image's default command was the common victim
- **The Docker guide shows the demo profile.** A single `docker run` with `wallet serve --demo` gives the public demo's setup locally, and the guide now says so, including where the full deployment with TLS and rate limiting lives
- **The conformance docs name the v5.2.2 suite baseline.** The runbook and status page still said `release-v5.2.1` while the recorded results run on `release-v5.2.2`
- **The demo issuer accepts the auth_session its auth_via_web answer hands out.** The session id was never stored, so a wallet returning with it (OpenID4VCI 1.1 §6.2.1 has it sent on every further request) was refused with `invalid_grant`. The session is stored now and the wallet gets the interaction again with a fresh pushed request
- **The challenge endpoint caps its pushed requests like PAR.** The browser sign-in answers (`redirect_to_web` and auth_via_web) stored pushed authorization requests without the 500-entry cap the PAR endpoint enforces. A full map answers 429
- **A purpose from an unverifiable registration certificate is not shown.** A certificate without a readable x5c skipped the signature check and its purpose was displayed anyway. It now leaves a warning in the activity log and stays out of the dialog, like a certificate whose signature fails
- **A purpose also shows for a request sent as plain parameters.** `verifier_info` was only read from a request's payload document, which a bare query-parameter request does not have. The raw parameter is now kept and read. Outer parameters of a signed request stay ignored (OpenID4VP 1.0 §5.10.1)
- **The demo reads its signing key and certificate chain in one step.** The chain was fetched under the wallet lock but the key in a separate read, so a reload or demo reset in between produced signatures the embedded x5c leaf cannot verify. Both now come from one locked read
- **A renewal is no longer lost to a concurrent store reload.** The refresh flow replaced the credential in memory and then saved. A request reloading the store in between reverted the renewal, including the rotated refresh token, while the API reported success. The renewed copy is now written back under the same lock the reload takes, like the issuance flow

## [1.24.0] - 2026-08-17

### Added

- **The browser interaction of interactive authorization (OpenID4VCI 1.1 §6.2.1.2).** The wallet now advertises `urn:openid:dcp:ia:auth_via_web` next to the presentation interaction, when a redirect URI is configured and the authorization server publishes an `authorization_endpoint` (it advertises only what it can complete, since §6.2.1 makes it abort on an unsupported interaction). A server answering the challenge with that interaction hands over a `request_uri`, which the wallet turns into an authorization request (RFC 9126 §4) and gives to the user's browser, as in the redirect flow. The redirect back to the wallet finishes the exchange with the authorization code, or continues it at the challenge endpoint when it carries an `auth_session` instead. The demo issuer asks for this interaction on a "Browser sign-in" offer redeemed by a wallet that advertises it, and keeps answering `redirect_to_web` (first-party-apps Section 5.2.2.1.1) for one that does not, so both kinds of wallet still reach the sign-in

### Fixed

- **A credential from the demo issuer no longer shows "External status" on the wallet that serves its status list.** The status entry adopted when the credential was imported could be wiped by a concurrent request reloading the wallet from disk mid-flow. The save already put a wiped credential back, but not its status entry, so the credential looked externally governed and nothing could revoke it. On the public demo, whose UI polls while a flow runs, this happened almost every time. The entry is now re-adopted at save time, under the same lock the reload takes

### Changed

- **The documentation is shorter and plainer.** The README and the prose documents under docs/ were rewritten for brevity and clarity. No commands, flags or behaviors changed
- **The demo verifier's trust check says what it checks.** Its checklist read "issuer certificate chains to the wallet CA", which sounded like issuers were expected to chain to a holder's wallet. It now reads "issuer certificate chains to a trusted CA". The trusted CA is unchanged: the root of the wallet's signing chain, which the built-in issuer signs under
- **Client authentication at the Authorization Challenge Endpoint is documented and pinned by tests.** The wallet has always sent its wallet attestation (the `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers) there, exactly as at the PAR and token endpoints, and the demo issuer has required it there in its default `required` mode. The wallet docs now say so, and a regression test holds the endpoint to it

## [1.23.2] - 2026-08-16

### Fixed

- **The presentation an issuer asks for mid-issuance now opens where it belongs.** A wallet UI submitting such an offer appeared to hang: the flow reached "Issuer asked for a presentation before issuing" and stopped there, because the tab's consent claim is single use and the issuance consent had already spent it, so the second consent of the same flow landed in the pending banner instead of a dialog. Approving an issuance now also claims the presentation that may follow it
- **A presentation asked for during someone else's issuance is no longer shown to every visitor.** On a shared wallet it reached every open UI, where answering it would have finished a stranger's flow with the shared wallet's PID. It has its own consent type now (`issuance_presentation`), which the browser that started the issuance opens and no other browser is offered, in a dialog or in the banner
- **The presentation consent named nobody.** An unsigned request carries no `client_id` (OpenID4VP Appendix A.2), so the dialog read "Verifier:" and nothing else. It names the Authorization Challenge Endpoint's origin, which is the party the presentation is bound to and goes back to
- **The demo verifier applies the PID format to the German PID too.** The format toggle was hidden for it and silently forced to SD-JWT. Both PID requests take a format now, and asking for the national type as an mdoc is answered with the reason it cannot exist

## [1.23.1] - 2026-08-16

### Fixed 

- **The demo issuer asks how an authorization code offer should be authorized.** Its page now offers "Browser sign-in" or "Presentation during issuance" next to the grant, and the offer carries that choice. Until now a wallet using interactive authorization always got the presentation, which left the sign-in unreachable from the demo. An offer that wants the browser tells such a wallet so with `redirect_to_web` (Section 5.2.2.1.1 of the OAuth 2.0 for First-Party Applications specification), handing back a pushed authorization request for it to continue with, and the wallet falls back to the redirect flow instead of failing. A wallet that does not use interactive authorization sees the sign-in either way
- **The specification versions this toolkit implements are shown as README badges**, each linking to its section of the [spec compliance](docs/spec-compliance.md) document
- **An offer submitted through the API hung until it timed out when the issuer asked for a presentation.** A programmatic submission is the caller's consent, which is how the offer and presentation endpoints have always treated one, but the consent for a presentation asked for mid-flow (OpenID4VCI 1.1 §6) was put to a user who was not there. It bit any wallet not running with `--auto-accept`, the public demo profile among them

### Changed

- **The demo verifier picks what to request with a toggle.** Three buttons asked for the ticket, the PID and the German PID while a blue border sat permanently on the first one, so nothing showed what was selected. It is now a Credential toggle in the style of the demo issuer, with one "Create request" button, and the PID format toggle appears only for the request it applies to. The paragraph explaining PID type inheritance is gone: what it described is visible in the request itself

## [1.23.0] - 2026-08-16

### Fixed

- **HAIP 1.0 was applied to a channel it does not describe.** A presentation made during interactive authorization was held to the profile's rules for an OpenID4VP Authorization Request: `response_mode` had to be `direct_post.jwt` or `dc_api.jwt`, and a request without a signed Request Object under an `x509_hash:` client identifier was a violation. HAIP profiles the two channels a verifier sends a request over, and OpenID4VCI 1.1 §6.2.1.1 is neither: it fixes the response mode, the delivery and the binding itself. A wallet run with `--haip --mode strict` could not use the feature at all, and the public demo (HAIP in debug) logged four violations per presentation that no specification supports. The same applied on the issuance side, where an authorization server offering the challenge endpoint was reported for having no pushed authorization request endpoint, which §4 scopes to "when using the Authorization Endpoint". What the profile says about the query, the credential formats and the token exchange still applies

### Added

- **The wallet has an OpenID4VCI feature level, selected with `--vci-version`.** It speaks OpenID4VCI 1.0, the published final version, and `1.0` stays the default, so an existing setup behaves exactly as it did. `1.1` says the wallet is willing to use what the [1.1 draft](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-1_1-wg-draft.html) adds on top of it. Every one of those features is negotiated in the issuer's metadata, so the level is what the wallet is willing to use rather than what it demands, and against an issuer that publishes none of them the two levels are indistinguishable. That is what makes it safe on a wallet that also talks to 1.0 issuers. The level sits with the other conformance settings: `GET /api/config` reports it as `vci_version`, `PUT /api/config/conformance` changes it on a locally-hosted wallet, the Conformance panel has a control for it, and `--demo` selects `1.1` (overridable, like the validation mode and HAIP defaults it already implied). Which features `1.1` selects is listed in [spec compliance](docs/spec-compliance.md)
- **Interactive Authorization (OpenID4VCI 1.1 §6), so an issuer can ask for a credential before it issues one.** At `--vci-version 1.1`, an authorization server that publishes `authorization_challenge_endpoint` is talked to there instead of through a browser redirect: the wallet sends the challenge request, is answered `403 insufficient_authorization` naming the interaction it must perform, presents a credential it holds, and gets an authorization code back for the ordinary token exchange. The presentation is consented to separately from the issuance, because agreeing to receive a credential is not agreeing to disclose one. It is bound to the challenge endpoint the wallet called and to nothing else: an SD-JWT key binding JWT carries `ia:<endpoint>` as its `aud` (Appendix A.3.5) and an mdoc signs the `OpenID4VCIIAEHandover` session transcript (Appendix A.2.5, checked against the worked example in the draft), and an `expected_origins` that names anything but that endpoint's origin is refused, which is what stops one authorization server forwarding another's request (§6.2.1.5). The wallet advertises the presentation interaction alone, so a server never selects one it would then have to be refused for (§6.2.1). This flow needs no `--vci-redirect-uri`, since nothing is redirected anywhere, and it is the only way to use an issuer that sets `require_interactive_authorization`
- **The built-in demo issuer asks for a PID before it issues its ticket.** It implements the other half of §6: a `POST /issuer/authorize-challenge` endpoint that answers the first request with `insufficient_authorization` and an OpenID4VP request for a PID in either format, verifies the presentation that comes back as a verifier would (signature, the nonce it handed out, the binding to its own challenge endpoint, revocation), and only then issues the authorization code. The endpoint is published in its authorization server metadata at `--vci-version 1.1` alone, so one setting decides both halves of what an installation does, and `require_interactive_authorization` is never published because the redirect flow still works there. An ordinary authorization code offer is what drives it: nothing about the offer says how the code is obtained, so the same offer is redeemed interactively by a 1.1 wallet and through the browser sign-in by a 1.0 one. The ticket it issues names the holder of the PID that was presented, since that presentation is the only thing that authorized the issuance
- **An issuer offering interactive authorization is no longer declined without a word.** An authorization server publishes `authorization_challenge_endpoint` to say it supports Interactive Authorization (OpenID4VCI 1.1 §6, §13.3: "the presence of authorization_challenge_endpoint is sufficient for a Wallet to determine that it can use Interactive Authorization"). A wallet at feature level 1.0 takes the redirect flow the server also published, which is correct but silent, and silence is the wrong answer from a tool people use to find out why a flow went the way it did. The activity log now records the offer, and at 1.0 the entry names the flag that would use it. An authorization server that sets `require_interactive_authorization` says so in the entry too, since the redirect flow it is about to attempt is likely to be refused

## [1.22.2] - 2026-08-15

### Fixed

- **Credentials this wallet issued were refused by verifiers that resolve the issuer key from the x5c header.** The signing leaf carried no subject alternative name, so nothing in it named the issuer, while the credentials it signs carry the wallet's issuer URL as `iss`. HAIP 1.0 section 6.1.1 binds the two ("the iss value MUST be an URL with a FQDN matching a dNSName Subject Alternative Name (SAN) entry in the leaf certificate"), and the Animo playground refuses a credential where they do not match. The leaf now names the issuer URL as a `dNSName` and as a `uniformResourceIdentifier`, or as an `iPAddress` when the wallet is reached by address

## [1.22.1] - 2026-08-14

### Changed

- **The namespace label on an mdoc credential card reads as a group divider.** It was a filled chip in the accent colour, which made it the loudest element on the page. It is now the card's own text colour with a thin rule to its left, so it separates one namespace's elements from the next without competing with the credential type above it

## [1.22.0] - 2026-08-14

### Added

- **Credential types inherit.** A national PID extends the country-independent one (ARF v3.0.0 Annex 2, PID_14: the vct "SHALL be `urn:eudi:pid:1` for the type defined in this document or a domestic type that extends it"), so a verifier asking for `urn:eudi:pid:1` is now answered by a `urn:eudi:pid:de:1` credential. That is applied as the rule it is, not as a list of known types: any type in `urn:eudi:pid:` whose next segment is a country or region rather than a version extends the country-independent PID, so `urn:eudi:pid:fr:1` works without anything here knowing about France. The wallet matches a DCQL `vct_values` entry against the credential's own type, the type it extends, and the types its `aka_vcts` claim names (SD-JWT VC §2.2.2.2, new in draft-18), which is the general mechanism for types outside that namespace. Inheritance runs one way only (a request for the German PID is not answered by the country-independent one) and is never a trust decision: who may issue a type is still decided by the signature and trust list checks (§6.6). The demo verifier accepts an extending type for the same reason. Type Metadata's `extends` is not used: the EUDI PID types are URNs, so nothing resolves them, and the ARF only asks a Scheme Provider to "consider defining" a Type Metadata Document (ARB_31)
- **The German PID is a credential type of its own.** New pre-defined templates `german-pid-sdjwt` (vct `urn:eudi:pid:de:1`, carrying `aka_vcts`) and `german-pid-mdoc`, which keeps the doctype `eu.europa.ec.eudi.pid.1` and puts its national elements in `eu.europa.ec.eudi.pid.de.1`, as ISO 18013-5 has no inheritance between document types. `wallet generate-pid --vct`, `issue --pid --vct` and `POST /api/generate-pid` select the type, and with it the claim set
- **The public demo example rate limits per client address.** Its Caddy image is built with the caddy-ratelimit plugin and caps the endpoints that fetch a visitor-supplied URL or grow state until the next reset (presentations, offers, issuance, imports, refreshes, deferred collection, demo issuer offers, verification requests) at 120 per minute and 2000 per hour, with everything else at 1200 per minute. Exceeding a limit answers `429` with `Retry-After`. The limits are ceilings against abuse: a busy visitor with three tabs open, issuing and presenting, produces about 36 requests a minute
- **`deploy.sh stats` reports API calls.** The public-demo helper listed pages only, and dropped every `/api/` path as UI noise, which hid what the demo is actually used for. It now lists the top API calls and, separately, the ones that changed something (`POST`, `PUT`, `PATCH`, `DELETE`): a credential issued, presented, imported or deleted, whoever drove it
- **The credential list names the namespaces an mdoc credential uses.** Its elements were listed as a flat set of names, so the two mdoc PIDs (which share the doctype `eu.europa.ec.eudi.pid.1` and differ only in whether they also use `eu.europa.ec.eudi.pid.de.1`) looked identical on the card. Each namespace is now named with a few of its elements as examples. SD-JWT claims have no namespace and stay a plain list
- **The demo seeds both PIDs.** Its protected baseline is now four credentials, the country-independent PID and the German one in each format. The demo verifier's PID request takes the type to ask for (`{"type":"pid","vct":"urn:eudi:pid:de:1"}`, any type in `urn:eudi:pid:`), and the verifier page has a button for the German one. A request naming the country-independent type is answered by either credential. One naming a domestic type is answered by that type alone, and in SD-JWT VC alone, since every PID carries the same mdoc doctype

### Fixed

- **`wallet generate-pid` could leave a second mdoc PID behind.** The credential it replaces is recognized by the namespaces its elements sit in, which it read from the stored claim keys. A wallet file written before those keys carried the namespace stores them bare, so the credential looked like it had no namespaces, survived, and the wallet ended up holding two PIDs of the same doctype. The namespaces now come from the credential itself, which is rebuilt from it on every load
- **`issue jwt --pid` refused to run**, reporting `template "pid-sdjwt" is for format sdjwt, not jwt`. The template the flag picks for the caller was held to the same format rule as one they named themselves, though a JWT VC carries the same PID claim set plainly. The rule now applies only to a template the caller named
- **A long-running wallet dated every PID it issued to the day it started.** The dated claims (`date_of_issuance`, `date_of_expiry`, and their mdoc names) were computed once when the process loaded its claim sets, so a server up for a month issued PIDs issued a month ago, expiring five years after that day. They are recomputed whenever a PID template is materialized

### Changed

- **The default PID follows the EU rulebook, not the German one.** The claim set behind `urn:eudi:pid:1` was the German provider's all along, which made every default PID claim a rulebook it did not follow. `pid-sdjwt` and `pid-mdoc` (new names for the pre-defined country-independent templates, which `--pid` and `generate-pid` use by default) now follow the EUDI PID Rulebook attribute for attribute: `birth_family_name` and `sex` and `personal_administrative_number` and `document_number` and `date_of_issuance` are in, the national additions (`birth_name`, `title`, `also_known_as`, `source_document_type`, `no_place_info`) are out, and so are all age attributes, which that rulebook removed in version 1.1 following CIR 2024/2977. The SD-JWT address gained `address.house_number`, the mdoc place of birth is now the `place_of_birth` element the rulebook names (it was `birth_place`, a data identifier of the encoding-independent table), and the mdoc elements all sit in `eu.europa.ec.eudi.pid.1`. The German claim set is unchanged, and now issued under the German type. The sample identity stays ERIKA MUSTERMANN. Anything asserting on the old default claim set, or issuing from `german-pid-sdjwt` and expecting `urn:eudi:pid:1`, has to be updated

## [1.21.7] - 2026-08-13

### Fixed

- **A signed request object without an x5c header was wrongly flagged for every client_id.** The request-object signature check demanded an x5c header from any signed request, so a `verifier_attestation:` or `decentralized_identifier:` request (which take the signing key from the attestation JWT or the DID, not from a certificate) drew a spurious "Request Object signature verification requires an x5c header" warning, and in strict mode failed outright. The x5c requirement is now scoped to the x509 prefixes (`x509_san_dns:`, `x509_hash:`), where the certificate really does travel in the x5c header. HAIP is unaffected (it mandates an x509 prefix, so x5c stays required there).
- **Restarting the demo silently dropped a visitor's PID credential.** On startup (and on the periodic reset) the demo refreshes its protected baseline, and that refresh removed every credential of the baseline's type before recreating it. A PID a visitor issued from the demo issuer carries the same type (vct `urn:eudi:pid:1` or doctype `eu.europa.ec.eudi.pid.1`), so it was indistinguishable from the old baseline and got swept away, with no deletion in the activity log. The baseline refresh now drops only its own previous protected baseline and keeps whatever visitors issued, so a restart no longer loses their credentials (the scheduled reset still clears all visitor state, as before). Credentials of other types were never affected.
- **`wallet scan` ignored a configured running or remote wallet for scanned requests.** A scanned `openid4vp://` request or `openid-credential-offer://` offer always ran the local flow, even when a running wallet on the same directory (or a `wallet instances use` remote) was configured, so it never reached that wallet or opened its consent UI. Scanning a raw credential already routed correctly. A scanned request now behaves exactly like `wallet accept` (it routes to the running or remote wallet when one is configured), and `wallet scan` gained the matching `--tx-code` and `--haip` flags.

## [1.21.6] - 2026-08-12

### Fixed

- **`wallet accept` auto-accepted silently when routed to a running or remote wallet.** When the command routed the request through a running wallet server (same wallet directory) or a `wallet instances use` remote, it submitted to that wallet's API without asking for consent, so the wallet treated the CLI call as the consent and accepted the request without showing its dialog. It now submits interactively (unless `--auto-accept`) and opens the wallet UI at that request, so the presentation or offer is reviewed there, the same as this command's own local flow and the macOS URL handler already do.

## [1.21.5] - 2026-08-12

### Fixed

- **The Conformance popup was wordy and its read-only demo controls were hard to read.** The trailing explainer and note lines are gone (the intro carries the one line that matters, and says when the settings are fixed on the demo). The HAIP and encrypted-request checkboxes dropped the `checked` and `required` words that read oddly next to a disabled, unticked box, and the controls now use an accent colour so a fixed demo setting stays legible.

## [1.21.4] - 2026-08-12

### Fixed

- **The Process button did not ask for consent.** Pasting an offer or request and pressing Process submitted it as an auto-accepted API call, so the flow completed without a chance to review it. Because pasting the request is this tab's own action, it now submits interactively and opens the consent dialog here, the same as a scanned or clicked request.
- **Importing a credential left no activity-log entry.** Pasting a credential into Import Credential added it silently. It now records an entry, the same as issuing or deleting one.

## [1.21.3] - 2026-08-12

### Fixed

- **A presentation's profile-violation warnings were logged twice.** A request submitted through `/api/presentations` was validated once for the API response and again in the shared flow handler, so every profile warning appeared twice for a single flow. The API path no longer logs them, and the flow handler logs each once.
- **A long activity-log message is readable on hover.** Log entries are truncated to one line with an ellipsis. Hovering over one now shows the full text as a tooltip.

## [1.21.2] - 2026-08-12

### Fixed

- **The demo could not issue from an issuer that requires client attestation without advertising it.** 1.21.0 made the wallet skip client attestation under HAIP + debug whenever the authorization server did not advertise `attest_jwt_client_auth`. That was too broad. It correctly skips for an issuer that explicitly offers only unauthenticated access (Procivis One), but it also skipped for an issuer that requires an attestation without advertising the method (the Animo playground, since draft-ietf-oauth-attestation-based-client-auth §10.1 makes advertising a SHOULD not a MUST), so the token exchange failed with `invalid_client`. The wallet now attests a silent issuer, and warns that the method was not advertised, while still taking an explicit `none` at its word.

## [1.21.1] - 2026-08-11

### Fixed

- **A demo tab could briefly show a stranger's request as a consent dialog while it was still loading.** The dialog-versus-banner decision depends on whether the wallet is a demo, which is only known once `/api/config` has resolved. A request that arrived in that window was treated as this tab's own and opened directly. The decision now waits for config: a request arriving first is offered in the banner (unless the tab explicitly claimed it through a scheme dispatch) and re-evaluated once the wallet knows whether it is a demo. A local wallet still opens its dialog.

## [1.21.0] - 2026-08-11

### Changed

- **The public demo is graceful against non-conformant counterparties.** It runs HAIP in debug mode now, not strict: a request or issuer that breaks a profile rule produces a warning in the activity log and the flow continues, rather than being refused. In particular, an issuer that requires HAIP of the wallet but offers only unauthenticated access at its token endpoint (as the Procivis One and Animo trial issuers do) no longer fails issuance. The wallet notes the violation and proceeds without client authentication. Under strict mode it still attests and the exchange fails, the honest result for a wallet asserting HAIP.
- **Conformance settings are the wallet's own, changed only on a locally-hosted wallet.** Validation mode, HAIP and encrypted requests are process-level state set through the local Conformance panel (`PUT`/`DELETE /api/config/conformance`). The public demo shows them read-only. There is no longer a per-request override, which removes the confusion of a browser setting that a CLI or system-handler flow could not see.
- **The activity log marks spec violations as warnings.** A HAIP or profile violation the wallet noted without failing on is a distinct warning state (a `⚠ WARN` badge), separate from OK and FAIL.

### Removed

- **The per-request conformance override.** The `eudi_conformance` cookie, the `X-Eudi-Dev-*` request headers, the `wallet conformance` CLI command (and its `conformance.json`), and the `haip`/`mode` body fields on the flow endpoints are gone. The demo therefore sets no cookies. The OIDF conformance harness sets the wallet's conformance through `PUT /api/config/conformance` before each submission instead.

## [1.20.4] - 2026-08-11

### Fixed

- **A freshly issued credential could disappear despite a successful issuance.** When a conformance override put the offer on a per-request wallet clone (which the public demo always does), the save ran against the clone's own wallet and its own copy of the store lock rather than the wallet the server serves and reloads. A store reload landing between the import and the save (every poll on the demo triggers one) dropped the new credential, so the flow reported success and left nothing behind. Saving now delegates to the real server, so the credential lands in the served wallet under the same lock the reload takes.

## [1.20.3] - 2026-08-11

### Fixed

- **The decoder header stacks cleanly on a narrow screen.** The wordmark and buttons sat at the left edge while the title and links were indented under the logo, so the rows did not line up. The header stacks into left-aligned rows (brand, then links, then buttons) that share one edge.
- **The macOS URL-scheme handler survives a Homebrew upgrade.** Registration baked the resolved binary path (`…/Cellar/eudi-dev/<version>/bin/eudi`) into the handler, so `brew upgrade` deleted that file and a clicked `openid4vp` or credential-offer link did nothing until the wallet was registered again. It bakes the stable symlink (`/opt/homebrew/bin/eudi`) instead, so an upgrade swaps the target underneath it and registering once is enough.
- **The demo conformance warning now names the links a browser override cannot reach.** It called out the CLI but not the `openid4vp` and credential-offer links the macOS handler opens, which run through the same header path rather than the browser cookie. Both are named now.

## [1.20.2] - 2026-08-11

### Fixed

- **The demo Conformance panel did not say its override is browser-only.** A visitor who relaxed HAIP or the validation mode there had no sign that a CLI offer sent to the same demo ignores the change, because the override rides a per-browser cookie the CLI never sends. The panel now shows a short warning on the demo. The same ordering bug had also rendered the local note text on the demo, which is corrected.
- **`wallet conformance` could not turn HAIP or encrypted requests off.** `--haip` and `--encrypted` were bare boolean flags, so they only ever set the override on, while `--mode` took a value. They take `true` or `false` now, matching `--mode`, so a CLI override can relax a remote wallet as well as tighten it. A flag left unset still inherits the remote wallet's own setting.

## [1.20.1] - 2026-08-10

### Fixed

- **The Conformance panel's note overstated what a local change reaches, and its text ran long.** It read as though a local change also governed the `openid4vp://` and credential-offer links the CLI or the macOS handler sends, which only holds when the same override is set on the local wallet too. The note now says a local change affects this wallet's own settings, and the panel's copy throughout is shorter.
- **The decoder page's logo sat on top of its title on a narrow screen.** The mobile header placed the logo and the titles in one column and they overlapped. The logo aligns to the top of that column now and the title clears it.

## [1.20.0] - 2026-08-10

### Added

- **The wallet's conformance settings can be changed from the UI, not just read.** The Conformance panel showed the validation mode, HAIP and encrypted-request settings a request is held to, but only the startup flags could set them. The panel is editable now, and where a change lands follows the wallet. A local wallet changes its own settings through `PUT /api/config/conformance` (`DELETE` restores the startup values), so every flow that reaches it honors the change: the UI, a scanned QR, and `openid4vp://` or credential-offer links routed there by the CLI or the macOS handler. The public demo keeps the change per visitor in the `eudi_conformance` cookie, applied per request (including the `/authorize` navigation a verifier link triggers), so one visitor never affects another. There the shared setting is fixed and the endpoint returns 403. A remote wallet driven from the CLI cannot be reconfigured, so `wallet conformance` records an override the CLI and the macOS handler send as `X-Eudi-Dev-*` headers, which the remote honors per request. Every flow endpoint reads those headers. Precedence on one request is an explicit header or body first, then the cookie, then the wallet's own setting. The three surfaces (a wallet's own setting, a demo visitor's cookie, and the CLI/handler `conformance.json`) are independent and do not sync

### Changed

- **The per-request override headers are named `X-Eudi-Dev-*`.** They were `X-OID4VC-Dev-*`, from before the tool was renamed, and the old names are no longer accepted: a caller that set `X-OID4VC-Dev-HAIP` or `X-OID4VC-Dev-Mode` must use `X-Eudi-Dev-HAIP` / `X-Eudi-Dev-Mode`. They are also read on every flow endpoint now, not only the Browser API, and `X-Eudi-Dev-Encrypted` is read alongside them

## [1.19.22] - 2026-08-07

### Added

- **The demo issuer can be told to serve a wallet that authenticates with nothing.** Its authorization server required attestation-based client authentication at the pushed authorization request and the token endpoint, which is what HAIP 1.0 §4.4.1 asks of an issuer and what the public demo is there to show. It also meant that a wallet built to OpenID4VCI alone, where §6.1 leaves client authentication to the client type and the deployment, could not complete the authorization code flow against it at all, and got a bare `invalid_client` for its trouble. `--demo-issuer-client-auth optional` additionally advertises and accepts `none`, the registered method of a client that does not authenticate. An attestation is still verified wherever one is presented, and the issued ticket records which of the two happened, so the relaxed mode cannot be mistaken for the profile. The default is unchanged at `required`

### Changed

- **An attestation from a wallet provider the demo issuer was never given is accepted and marked, rather than refused.** The certificate in the `x5c` header had to chain to the wallet CA of the wallet this issuer runs on, which is the only attester it has been handed. Every other wallet in the world signs with a provider nobody gave it, so the check reserved the authorization code flow for this project's own wallet and answered every other one with a chain failure. The attestation is verified against the certificate it carries now, and whether that certificate reached the known CA becomes a property of the exchange rather than the end of it. The issued ticket carries a `wallet_attestation` claim of `trusted`, `untrusted` or `none`, so what the issuer could not establish travels with the credential instead of being lost. This is a demo issuer making itself available as a counterparty. A production issuer resolves the wallet provider's trust list and pins the CA it finds there, which is what this wallet publishes at `/api/trustlists/wallet-provider`
- **The demo authorization server follows draft 10 of attestation-based client authentication.** It was written against an earlier revision, which cost it interoperability in three places. It required `iss` in the Client Attestation and in its proof of possession, both of which the draft has since dropped (`iss` left the attestation in draft 08, and the proof is identified by the attestation it belongs to), so a client built to the current text was refused for omitting claims it is right to omit. It required `exp` on the proof of possession, which is not among the claims §5.1 lists, and took freshness from it alone, where the required `iat` is what bounds a proof now. And it knew only the method that carries a separate proof of possession JWT, so `attest_jwt_client_auth_dpop`, where "a request using the mechanism carries only one PoP, the DPoP proof, instead of two separate PoP JWTs", was answered as though no proof had been sent. All three are fixed, and the metadata advertises both methods, the signing algorithms §10.1 requires of a server that supports them, and the proof of possession methods it accepts. A failure that concerns an attestation somebody did present is reported as `invalid_client_attestation` (§6.2), which tells a wallet its attestation was read and rejected. A client that presented none still gets `invalid_client`, because there is nothing to fault

### Fixed

- **The wallet presented itself as a client claiming less than it can.** Where an authorization server accepted both a wallet attestation and a client that authenticates with nothing, 1.19.21 took the second, on the grounds that no deployment has been given this wallet's self-signed attester and the attestation would be refused. That refusal is the accurate answer to a wallet nobody registered, and skipping it makes every exchange that follows a test of something the wallet is not. Signing the attestation is within its own means, so it sends one wherever the server takes it and leaves the counterparty to judge it. What it cannot do without anchors it was never given, such as placing somebody else's attester or metadata signer, is still reported rather than enforced. A server offering only methods that ask nothing of the client is still usable, which is what 1.19.21 fixed and this keeps
- **A finding about somebody else's certificate chain claimed more than the wallet could see.** A signed request whose `x5c` carried a self-signed certificate was refused with "the trust anchor MUST NOT be included in the x5c header", though which certificate is a trust anchor depends on what the party checking the chain was configured to trust, and this wallet has been given no such list. What it can see is a certificate that signed itself, so that is what the finding reports now, with its position in the chain and its subject, alongside the requirement it runs into (HAIP 1.0 §5: "The X.509 certificate of the trust anchor MUST NOT be included in the x5c JOSE header of the signed request"). The check is unchanged and still refuses the request in strict mode, because a root in the chain is the shape the requirement is aimed at. A Verifier told which certificate was objected to can act on it
- **How long the wallet waits for a counterparty can be set.** The wait was fixed at 15 seconds, which is short on purpose: a developer pointed at an issuer or verifier that does not answer learns more from a prompt failure than from a long one. It is the wrong number when the counterparty shares a machine with the wallet, which is what running the OpenID Foundation suite locally does, because a request that would normally be served at once can take tens of seconds under load. Giving up there ends the exchange, and nothing resumes it, so a conformance run that was measuring the wallet ends up measuring the machine. `EUDI_REMOTE_TIMEOUT` takes a Go duration (`45s`, `2m`) and the default is unchanged at 15 seconds. A value that cannot be read is reported and ignored rather than applied, because a mistyped duration should not quietly turn every remote read into one that never times out. The conformance wrapper sets 120s

## [1.19.21] - 2026-08-07

### Fixed

- **The wallet authenticated with an attestation no issuer can trust, where the issuer would have taken it unauthenticated.** An authorization server offering both an unauthenticated client and `attest_jwt_client_auth` was always answered with the attestation, and the exchange then failed with the server reporting that no trusted attester matched. It cannot match: this wallet signs its attestation with a certificate authority it generated for itself, and no deployment has been given that authority, so the attestation is only ever accepted by a counterparty configured with it (the conformance suite, the demo issuer). The method that can complete the exchange is preferred now, and attestation is still used where the server offers nothing else, where `--haip` requires it, and where the override asks for it. An `attest_jwt_client_auth`-only server, which is what the conformance suite advertises, is unaffected
- **A token endpoint authentication method outside the registry is reported rather than read past.** RFC 8414 takes the values of `token_endpoint_auth_methods_supported` from the IANA "OAuth Token Endpoint Authentication Methods" registry, where a client that does not authenticate is `none`. Deployments publishing `public` for the same thing are naming something no client is obliged to understand, so the wallet records the deviation, refuses it in strict mode, and in debug mode names it and proceeds on what it evidently means
- **An earlier failure reopened over every later request.** The wallet page showed the previous flow's error dialog for a moment whenever a new issuance request arrived, then swapped it for the consent screen. The stored error outlives the flow it came from, because the endpoint the page reads it from peeks rather than pops, and only the Dismiss button cleared it: an error the user navigated away from instead of dismissing stayed on the wallet and was presented again against whatever request happened to be on screen next. A new request now clears the previous failure, since a request that is only just arriving cannot have caused it, and an error reaching the page while a consent dialog is open no longer takes that dialog over

## [1.19.20] - 2026-08-07

### Fixed

- **A credential request under key attestation carried more proofs than the specification gives a reading for.** Where the credential configuration required key attestations, the request held one proof per batch key, each with an attestation covering every key. OpenID4VCI 1.0 Appendix F.1 and F.3 both put the count on the attestation rather than the proofs: the issuer "SHOULD issue a Credential for each cryptographic public key specified in the `attested_keys` claim within the `key_attestation` parameter". Several such proofs would have the issuer issue for the same keys once per proof, so an issuer applying that sentence answers `invalid_proof`. The request stays at a single proof wherever an attestation is required, and batch issuance applies where it is not
- **An issuer whose metadata signer the wallet could not place was unreachable.** Signed Credential Issuer Metadata was refused whenever its `x5c` chain did not end in a root the host already trusts, which ended the flow. An ecosystem's issuer CA is not a WebPKI root, so this rejected the EUDI reference issuer outright, on a document it had signed correctly. OpenID4VCI 1.0 §12.2.3 does say "When requesting signed metadata, the Wallet MUST establish trust in the signer of the metadata. Otherwise, the Wallet MUST reject the signed metadata", but establishing that trust needs anchors a wallet has to be provisioned with, and this one has no way to be given any. A check nothing can satisfy is not enforcement, so the signer that anchors nowhere is named in the log and the metadata is read. That is no weaker than the unsigned form the same issuer serves on request, which carries no signature at all. What the wallet can check without being given anything is still enforced: the `typ`, an asymmetric `alg`, a `sub` matching the Credential Issuer Identifier, and the signature itself. Registering issuer trust anchors is tracked as a future addition, and the check becomes meaningful once they can be supplied
- **The demo issuer left a wallet to guess where its Authorization Server metadata was.** Its Credential Issuer Metadata named no `authorization_servers` and carried a top-level `token_endpoint` instead. OpenID4VCI 1.0 §12.2.4 defines no token endpoint among those parameters, and a wallet reading it there has no reason to look further for what that endpoint accepts, so the `attest_jwt_client_auth` this issuer requires, along with its PAR endpoint and DPoP algorithms, went unseen and the flow was refused as though attestation-based client authentication were not offered. The section does allow the server to be inferred ("If this parameter is omitted, the entity providing the Credential Issuer is also acting as the Authorization Server"), but only a wallet that implements the inference ever reaches the document. The issuer names itself in `authorization_servers` now and publishes no `token_endpoint` of its own, so the Authorization Server metadata is what describes the token endpoint

## [1.19.19] - 2026-08-07

### Fixed

- **A refused Digital Credentials API request looked like an answered one.** Under `dc_api.jwt` the wallet encrypted its error the way it encrypts a presentation, so a Verifier that had just been refused received a JWE where OpenID4VP 1.0 Appendix A.4 puts the error: "Protocol error responses are returned as an object within the data property. This object has a single property with the name `error` and a value containing the error response code as defined in Section 8.5." A Verifier reading that saw a response rather than a refusal. Where the wallet does answer with an error over this API it is that single-member object now, carried plainly under both response modes. A request that fails validation is answered differently again: it gets no protocol response at all, over this API as anywhere else, because §8.5 says the error response "follows the rules as defined in [RFC6749]" and RFC 6749 §4.1.2.1 has a server facing a request it could not validate inform the user rather than answer it
- **The wallet could only collect from an issuer that offered both PAR and DPoP.** The authorization code flow refused to start unless the Authorization Server published a `pushed_authorization_request_endpoint` and advertised DPoP signing algorithms, so an ordinary OAuth server was answered with "authorization server metadata did not include pushed_authorization_request_endpoint" and the credential could not be collected at all. OpenID4VCI requires neither. RFC 9126 §2 makes the endpoint the signal that a server takes pushed requests ("Authorization servers supporting PAR SHOULD include the URL of their pushed authorization request endpoint in their authorization server metadata document"), and RFC 9449 leaves the DPoP metadata optional. Both are used where they are offered and skipped where they are not: without a PAR endpoint the same parameters travel in the authorization request query string as RFC 6749 §4.1.1 describes, and without advertised DPoP the token is a bearer token. Three places downstream had the assumption baked in as a constant and now follow what the server actually offers: the Authorization scheme derived from the token response, the key used for the Credential Endpoint request, and the DPoP flag recorded for later renewal. HAIP still asks for both, and `--haip` still checks for them
- **A remote read that got no answer ended the flow.** Fetching a `request_uri`, a credential offer held by reference or a trust list asked once, so a connection that timed out took the flow with it, and a presentation request whose Request Object could not be retrieved failed as though the Verifier had refused. A read that produced no response at all is retried now. One that produced a response is not, whatever it said, because OpenID4VP 1.0 §5.10.2 is explicit for the `request_uri` case: "If the Verifier responds with any HTTP error response, the Wallet MUST terminate the process"
- **One slow metadata read ended the whole flow.** Issuer and authorization server metadata is fetched from somebody else's server at the start of every issuance, and the wallet asked once. A single answer that did not arrive inside the timeout left the metadata empty, and the flow then stopped reporting what the metadata did not contain (typically a missing `pushed_authorization_request_endpoint`), which points at the issuer's configuration rather than at the read that never completed. Metadata reads are attempted three times now, spaced out, and only where waiting can help: a transport failure or the 5xx range. A 404 is the server saying it publishes nothing there, which is an answer, so it is taken at face value and the well-known probes that are expected to miss still cost one request each
- **Batch issuance was switched off by the very issuers most likely to offer it.** A credential configuration requiring key attestations collapsed the request to one proof, on the reasoning that a key attestation stands for the single key that signed its proof. OpenID4VCI 1.0 Appendix F.1 says the opposite: the proof carries an OPTIONAL `key_attestation` header, and "The Credential Issuer SHOULD issue a Credential for each cryptographic public key specified in the `attested_keys` claim within the `key_attestation` parameter". One proof per key is the shape, each carrying an attestation whose `attested_keys` covers every key proven in the request, which is what the wallet already built and then threw away. A configuration requiring key attestations batches like any other now, so the two features combine rather than cancel. Against the conformance suite this was visible as every mdoc batch module skipping with "the wallet only sent one proof in the credential request" while the SD-JWT ones passed, because the mdoc plans request a configuration that requires key attestations
- **A credential collected through a pre-authorized code was never acknowledged.** The Notification Endpoint was called only on the authorization code path, so the same issuer offering the same endpoint heard nothing back for a pre-authorized code flow. OpenID4VCI 1.0 §11.1 leaves the call to the wallet ("If the Wallet supports the Notification Endpoint, the Wallet MAY send one or more Notification Requests per `notification_id` value received"), which makes this a matter of the wallet being consistent about what it supports rather than a violation, and a developer watching one flow report `credential_accepted` and the other stay silent has no way to tell which of the two is the bug. Both paths send it now, wherever the issuer publishes the endpoint and the Credential Response carries a `notification_id`. A deferred credential is acknowledged too, once the poller collects it: §8.3 lets the Deferred Credential Response carry a `notification_id` of its own, and the flow that started the issuance is long gone by then. That one cannot fail the issuance, because the credential is already stored, so an unanswered notification is reported and the credential kept

- **A HAIP violation refused the request even in debug mode.** The two switches had grown into one: `--haip` decided both that the profile checks run and that anything they found was fatal, so the mode meant for watching a counterparty misbehave could not be used with the profile that finds the most to watch. They are separate again. `--haip` decides how many checks run, adding what the profile asks of a counterparty on top of what the base specifications ask of any, and the validation mode decides what a finding does, the same for a profile violation as for anything else. `--haip --mode strict` refuses the request, `--haip --mode debug` names every violation and carries on. This also matters for testing against the OpenID Foundation conformance suite, whose Verifier lists one content encryption algorithm where HAIP §5 requires both, which a debug run can now report without the exchange failing

### Added

- **`./deploy.sh rollback` puts the previous release back on a demo host.** A release that turns out to be wrong once it is in front of people had no way back other than editing the compose file by hand. `push` and `update` record the release they replace, so `rollback` with no argument restores that one, and `rollback v1.19.16` names any release directly. It pins the image tag in the host's `.env`, so the choice survives a restart, and the image is pulled before anything is switched, so naming a release that was never published leaves the running demo alone. A later `update` clears the pin and returns to the newest release

## [1.19.18] - 2026-08-06

### Fixed

- **The wallet answered a request it could only half satisfy.** A DCQL query listing two credentials with no `credential_sets` asks for both, and a wallet holding one of them sent that one, disclosing a credential the Verifier had no use for on its own. OpenID4VP 1.0 §6.4.2 is explicit: "If the Wallet cannot deliver all non-optional Credentials requested by the Verifier according to these rules, it MUST NOT return any Credential(s)." Every entry in `credentials` is required when no `credential_sets` is present, and the sets decide when one is, so the wallet returns everything the query asks for or nothing at all. `credential_sets` had the mirror-image bug: when the sets were present but no option of any of them could be satisfied, the filter fell through to a branch meant for queries with no sets and returned every credential that happened to match
- **A Verifier's `values` restriction was read and ignored.** The claim selector looked only at `path`, so a request for `given_name` with `"values": ["MAX"]` disclosed the holder's actual given name instead of nothing. §6.3 says the Wallet "SHOULD return the claim only if the type and value of the claim both match exactly for at least one of the elements in the array", and §6.4.1 adds that a claim that does not match "should be treated the same as if it did not exist in the Credential", so a mismatch withholds the claim and, since every requested claim is required, the credential with it. Matching is exact in type as well as value, so a string never answers a number and a boolean never answers the integer 1. mdoc data elements are converted to JSON first as §6.3 requires, so a byte string is matched as base64url and a CBOR integer as a JSON number
- **Three things the wallet made up about DCQL are gone.** A `required: false` on a Claims Query let a Verifier mark a claim optional, but §6.3 defines `id`, `path` and `values` and nothing else. An mdoc query for `place_of_birth` was quietly served the `birth_place` element, though §7.2.1 says to select the data element the second path component names and to error out when it does not exist, so the wallet was disclosing something the request did not cover. And `format`, `meta` and the syntax of a credential query `id` were never checked, all three of which §6.1 makes normative. A structural validator reports them, as errors in strict mode and warnings in debug
- **The wallet tells the Verifier when it has nothing to present.** A query nothing matched was reported only to the local caller, leaving a conformant Verifier waiting on its `response_uri` until it timed out with no idea why. That refusal goes back over the request's Response Mode as an OpenID4VP 1.0 §8.5 Authorization Error Response now, with the code the section calls for (`access_denied` when the wallet holds nothing that satisfies the query, `vp_formats_not_supported` when the query names only formats it cannot present). A request that fails validation is treated differently and deliberately: §8.5 says the error response "follows the rules as defined in [RFC6749]", and RFC 6749 §4.1.2.1 requires that a server facing a missing or invalid client identifier or redirection URI "SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI". A request whose signature does not verify, whose `client_id` does not match, or which is malformed names an endpoint the wallet has no reason to trust, so nothing is sent there and the caller is told instead
- **Digital Credentials API error objects match Appendix A.4.** An error returned through the DC API carried `error_description` and `state` alongside the code, where the appendix allows a single `error` property. It carries the code alone now. A `redirect_uri` that already had a fragment is also merged into rather than given a second `#`, which buried the response parameters where no Verifier could read them
- **The wallet page scrolls as one column again.** Giving the credentials and the activity log a scrollbar each (1.19.17) made both panels share the height below the actions bar, and on the public demo that left the activity entries too small to read with no scrollbar to recover the space. The panels are gone and the page scrolls as a whole, which is what it did before

- **The wallet gets its key-proof challenge where OpenID4VCI 1.0 says it lives.** It read `c_nonce` out of the token response, a parameter the final specification does not define, and where there was none it spent a credential request to harvest one from an error body. It asks the Nonce Endpoint now, retries once on `invalid_nonce` with rebuilt proofs as §8.3.1.2 asks ("The wallet should retrieve a new c_nonce value"), and refuses a token response `c_nonce` in strict mode while debug mode uses it and names the issuer as pre-1.0, so a developer pointed at one still sees how far the flow gets
- **Credential renewal could not work against a 1.0 issuer.** A renewal sent a key proof with no nonce and had no way to obtain one: it looked only at the refresh token response, and the issuer metadata that names the Nonce Endpoint was never read on that path. Every renewal was refused. It reads the metadata back from the Credential Issuer Identifier now (§12.2.2 makes the identifier the address of that document), takes its challenge from the Nonce Endpoint, applies whatever request and response encryption the issuer requires, and names the credential the way §8.2 allows rather than always sending `credential_configuration_id`
- **Issuer metadata was used without being checked.** A metadata document was trusted whatever identifier it declared, though §12.2.4 says that if the `credential_issuer` value is not identical to the one the URL was built from "the data contained in the response MUST NOT be used". Signed metadata was worse: it was accepted with no trust established in the signer, and a document carrying no certificate chain at all was treated as verified. Metadata whose `credential_issuer` does not match is refused now, and signed metadata is held to its `typ`, an asymmetric algorithm, a `sub` matching the issuer, and a chain ending in a trusted anchor, because §12.2.3 requires the wallet to "establish trust in the signer of the metadata" or reject it
- **The demo issuer accepted key proofs it should refuse.** It checked a proof's signature and its nonce and nothing else, so a proof issued for a different Credential Issuer was accepted, which is the cross-issuer replay §13.8 warns about. It ignored which credential was being requested and issued its ticket for anything, and it answered a stale nonce with `invalid_proof`, a code that tells a wallet to give up rather than fetch a fresh nonce and retry. Appendix F.4 is applied in full now (`typ`, `alg`, `aud`, an `iat` inside a window, exactly one of `jwk`, `x5c` or `kid`), the request must name a credential this issuer publishes, and a stale nonce comes back as `invalid_nonce`. The draft-era shapes are gone with it: no `c_nonce` in token responses, no singular `proof` member, and no `credentials` entries that are bare strings rather than the objects §8.3 requires
- **A status list could be swapped for any other and the wallet accepted it.** The Status List Token's `sub` was never compared to the `uri` in the credential's own status claim, which draft-ietf-oauth-status-list §8.3 requires ("The subject claim (sub or 2) of the Status List Token MUST be equal to the uri claim in the status_list object of the Referenced Token"), so any list signed by a key already trusted answered for any credential: one list whose index N was zero un-revoked every credential sitting at index N. Signature verification was opt-in, so a caller with no trust list (the wallet's own status endpoint was one) got an unverified status back with the validity flag left unset, and every caller rendered unset as a pass. `exp` was never looked at, so a copy of the list captured before a credential was revoked kept answering for it forever. All three together made a captured pre-revocation list a working un-revoke. Verification is mandatory now and fails closed, `sub`, `iat`, `exp` and `typ` are all checked, and any failure comes back as an error rather than a flag a caller has to remember to read, because §8.3 is explicit that a check that fails supports no statement about the credential at all
- **A credential could crash whoever checked whether it was revoked.** The status list index comes from the credential's own status claim, and `idx * bits` overflowed to a negative number for a large one, which passed a bounds check written on the byte offset and then indexed the bitstring negatively. Depending on the width it either panicked with "index out of range" or returned a status read from nowhere. The range is checked against the index itself before any multiplication now. `bits` also silently defaulted to 1 and `idx` to 0 when absent, although §4.2 and §6.2 make both REQUIRED, so a wider list was read at the wrong offsets and a credential with no index was told the status of whoever held index 0. Both are refused. Responses are accepted across the whole 2xx range as §8.2 says, the response `Content-Type` and a missing ZLIB header are reported as conformance warnings rather than passed over, and a status is named (VALID, INVALID, SUSPENDED, application specific, unknown) instead of everything non-zero being called revoked
- **The wallet published a different status than its own API reported.** Statuses were stored as arbitrary values but the list was always one bit wide, so a credential set to SUSPENDED (0x02) reached every external verifier as INVALID (0x01). §7 puts the choice of width on the issuer ("The issuer of the Status List MUST choose an adequate bits value"), so the published list is now 1, 2, 4 or 8 bits wide depending on the largest status it holds, and carries the real value. Values outside the 0 to 255 range §7 allows are refused on the way in. Status List Tokens in CWT format (§5.2) are implemented end to end, parsed when checking and served under `application/statuslist+cwt` through content negotiation, so an mdoc ecosystem that serves CWT lists is resolvable at all. The endpoint sends CORS headers as §8.1 recommends and answers 501 to the `time` query parameter as §8.4 says a server without historical resolution should. The specification's own Appendix C test vectors, at 1, 2, 4 and 8 bits, are now a table test
- **`--haip` asserted a profile it did not check.** It required the `x509_hash:` Client Identifier Prefix and then never verified the signature that prefix names: the value is a hash of the certificate signing the request, and checking the string while accepting an unverifiable signature is enforcement in name only. Those checks lived behind `--mode strict`, a separate flag, so `--haip` alone proved nothing about them. The signature, the `x509_hash` binding, and the two certificate rules of §5 (the signing certificate must not be self-signed, the trust anchor must not travel in the `x5c` header) are all checked now, and a violation is an error whenever `--haip` is on. Four mandates the profile states and the wallet never looked at are enforced as well: `response_type` must be `vp_token`, the credential formats must be `mso_mdoc` or `dc+sd-jwt` (§5.3.1, §5.3.2), and a Verifier must list both `A128GCM` and `A256GCM` in `encrypted_response_enc_values_supported`. The demo verifier listed only `A128GCM` and was not HAIP-compliant itself, which is how the new check found it
- **`web-origin:` is not a Client Identifier Prefix and never was.** The string appears nowhere in OpenID4VP 1.0 or in HAIP 1.0, and the wallet both invented it for unsigned Digital Credentials API requests and required it under `--haip`, so every conformant unsigned request was refused three separate ways: for not carrying the invented prefix, for having no signed Request Object, and for having no `client_id` at all. What the specification actually says is that such a request has none: "The `client_id` parameter MUST be omitted in unsigned requests defined in Appendix A.3.1. The Wallet MUST ignore any `client_id` parameter that is present in an unsigned request" (Appendix A.2). An unsigned request is now recognised by how it arrived rather than by a value it is not allowed to carry, and `client_id` and `expected_origins` are discarded from one before anything reads them. The reserved `origin:` prefix, which §5.9.3 says the wallet "MUST NOT accept ... in requests", is refused rather than silently accepted, and `openid_federation:` is refused rather than accepted without the trust chain resolution it requires
- **Validation findings were collected only in strict mode.** Debug mode ran the checks and threw the results away, so the mode meant for watching what a counterparty does wrong reported nothing at all. Findings are gathered in every mode now, and the mode decides what happens to them: strict stops the flow, debug reports each one and carries on. The checks themselves also cover more of what OpenID4VP 1.0 requires, including the missing `nonce` (§5.2 REQUIRED), a request carrying both `dcql_query` and `scope` or neither (§5.1), `transaction_data` this wallet cannot process (§5 obliges a wallet that does not support it to reject the request rather than answer without the hashes), and `expected_origins` that excludes the caller on a signed Digital Credentials API request
- **A disclosure could overwrite a signed claim and the wallet took it.** `sdjwt.Parse` implemented the resolution half of RFC 9901 §7.1 and none of its MUST-reject conditions, and it is the only gate on the wallet's import path. A disclosure named `vct` was inserted over the `vct` the issuer signed, so whoever read the resolved claims and whoever read the payload were told two different credential types by one credential. A disclosure could also be named `_sd` or `...`, the same digest could appear twice, a disclosure could arrive that nothing in the credential referred to, and an array element whose disclosure was withheld stayed in the output as `{"...": digest}` rather than being removed, which handed a hash to anything that read the claim. Parsing now runs the whole of §7.1 (steps 3 to 5) and refuses the credential on every condition the specification says MUST be rejected, naming the rule that failed. `_sd_alg` is matched case-sensitively as §4.1.1 requires, refused inside nested objects, and salts, claim names and `_sd` arrays are type-checked
- **The credential generator emitted SD-JWTs that a conformant verifier must reject.** Issuing with every claim always disclosed produced `"_sd": null` and a serialization ending in `jwt~~`, and neither is allowed (SD-JWT VC §2.2.2.5 requires the `_sd` claim to be absent when there are no disclosures, and the RFC 9901 §4 grammar permits no empty component). Any claim could also be made selectively disclosable, including the ones §2.2.2.3 says cannot be (`iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts`, `status`), which is how a credential ended up with a disclosed `vct` shadowing the signed one. Those claims are embedded plainly now, `_sd`, `_sd_alg` and `...` are refused as claim names, and the `_sd` array is sorted rather than left in Go map order, because §4.2.4.1 obliges the issuer to hide the order the claims came in
- **A tenant-scoped issuer's key was fetched from the wrong URL.** The JWT VC Issuer Metadata location was built by appending `/.well-known/jwt-vc-issuer` to `iss`, but SD-JWT VC §3 forms it by inserting that string between the host and the path, so `https://example.com/tenant/1234` is published at `https://example.com/.well-known/jwt-vc-issuer/tenant/1234` and every issuer with a path in its identifier failed to resolve. The lookup now inserts, drops a terminating slash as §3.1 requires, and refuses an `iss` that is not https or that carries a query or fragment. The document itself is read as §3.2 and §3.3 define it: `issuer` is required and must be identical to `iss` (it was optional before and compared with trailing slashes trimmed), and the keys come from `jwks` or from `jwks_uri`, which was unsupported until now, with a document carrying both refused
- **The decoder refused to show a credential that broke the rules.** Enforcing RFC 9901 §7.1 on the import path is right for a wallet deciding whether to hold a credential, but the decoder is asked the opposite question: the credential is already suspected of being wrong and the point is to see it. `eudi decode` now reports the rule that makes a credential invalid and still prints its header, payload and disclosures, so the thing being diagnosed remains visible. Nothing that decides trust uses that path
- **A query parameter could override what a Verifier signed.** The wallet merged the claims of a signed Request Object into the parameters it had already read from the invocation URL, so a parameter the Request Object omitted kept its outer value, and `dcql_query` was read from the URL after the object had been applied and replaced it outright. OpenID4VP 1.0 §5.10.1 is unambiguous: "The Wallet MUST extract the set of Authorization Request parameters from the Request Object. The Wallet MUST only use the parameters in this Request Object, even if the same parameter was provided in an Authorization Request query parameter." Anyone able to append to the URL a wallet is handed could therefore choose which credentials and which claims were disclosed, and where the response was sent, while the Verifier's signature still verified over something else. A Request Object now replaces the parameter set rather than being merged into it, so a parameter it leaves out is absent instead of inherited, and a Request Object whose `client_id` does not match the outer one is refused

- **The demo issuer refused every wallet built to OpenID4VCI 1.0.** It served no Nonce Endpoint and advertised no `nonce_endpoint`, while still requiring the key proof to carry the `c_nonce` it returned with the access token. That field belongs to the earlier drafts. The final specification moved the challenge to a dedicated endpoint (§7), so a wallet built to 1.0 never reads the token response for one and sends a proof with no nonce at all, which the issuer then rejected with "proof JWT nonce does not match the issued c_nonce" on every attempt. Nothing the wallet could do would fix it: the nonce it needed was in a field it had no reason to read. A real wallet tested against the public demo issuer hit exactly this. The issuer now serves `POST /issuer/nonce` and advertises it, and accepts a proof carrying either that nonce or the token response `c_nonce`, so wallets on both the drafts and the final specification are served
- **The wallet preferred a token response `c_nonce` over the nonce endpoint.** Both issuance flows only asked the Nonce Endpoint for a challenge when the token response carried none. Against an issuer that advertises the endpoint and also returns the draft-era field, the wallet signed its proof over the field, which the issuer need not accept and which may already be stale. The endpoint is the source OpenID4VCI 1.0 defines, so an issuer that names one is asked first, and the token response `c_nonce` is left as the fallback for issuers that offer no endpoint

- **A wallet holding two credentials of one type presented an arbitrary one.** A DCQL credential query asks for one credential, and a wallet may answer with more than one only when the query sets `multiple`, which this wallet does not implement. It matched every credential that fit anyway, signed a presentation for each, and wrote them all to the same key of the `vp_token` object, so all but the last were built and discarded and the one that reached the verifier was decided by map assignment order rather than by anything considered. The consent dialog and the activity log listed the whole set, including credentials that were never sent. The wallet now picks one credential per credential query, the most recently issued one that answers it, which is the order the credential list already uses and the behaviour a renewed credential calls for. A verifier asking for several different credentials still receives one for each. The OIDF conformance suite is what surfaced it, once an issuance plan had left a second PID in the wallet
- **The cross-origin guard refused the Digital Credentials API.** The guard added in 1.19.13 covers every endpoint under `/api/`, and `/api/dc-api` is the one that is cross-origin by contract rather than by accident: a verifier's web page invokes it from that page's own origin, which is the whole mechanism of the browser API. Guarding it by origin refused the only kind of caller it has, and the wallet answered `403` with "cross-origin API requests are not allowed" to a request it was built to serve. The OIDF conformance suite caught it, where every `dc_api` plan failed. That endpoint is now exempt, and what protects it is the origin the platform reports the request arrived with, which is what OpenID4VP over the Digital Credentials API authenticates an unsigned request by, plus the consent dialog. The exemption names that one path, so the rest of `/api/` is guarded as before

## [1.19.17] - 2026-08-06

### Fixed

- **HAIP enforcement rejected a conformant issuer over pushed authorization requests.** `--haip` required the authorization server to advertise `require_pushed_authorization_requests`, and reported "the authorization server must require pushed authorization requests" when it did not. No specification asks for that parameter. It is optional in RFC 9126 and defaults to false, HAIP 1.0 §4 scopes PAR to "when using the Authorization Endpoint" and otherwise defers to FAPI 2.0, and FAPI 2.0 obliges the server to reject authorization requests sent without PAR rather than to declare anything in its metadata. The EUDI reference issuer at `issuer.eudiw.dev` is one of the servers this refused: it publishes a `pushed_authorization_request_endpoint` and no flag. The check now asks for the endpoint, which is the part a wallet can see, and the behavioural half needs no check because this wallet sends the authorization request through PAR or not at all
- **Three more HAIP checks asked for more than the profile does.** The same audit found the rest. PKCE and DPoP were required to be advertised, but `code_challenge_methods_supported` is optional in RFC 8414 and `dpop_signing_alg_values_supported` in RFC 9449, and HAIP defers both to FAPI 2.0, which obliges behaviour rather than metadata. Silence is no longer read as a violation, while a server that lists PKCE without `S256`, or DPoP without `ES256`, has stated it cannot do what the profile requires and still is one. The presentation side went the other way: the audit found `--haip` accepting things the profile does not allow, which for a flag whose only job is to validate is the worse failure. §5.1 names `x509_hash` and only `x509_hash` for signed requests, so `x509_san_dns` is no longer accepted, and an unsigned request is accepted only over the Digital Credentials API, where §5.2 permits one and the caller is identified by the origin the platform reports. §5.1 also requires the signed request object to arrive "with the request_uri parameter", so one passed inline is now refused, which needed the request URI carried through parsing to notice. The ES256 rule on request objects stays: §7 sets it as the floor and this wallet advertises exactly that, so a verifier signing with anything else has ignored what the wallet told it

### Changed

- **Credentials and the activity log each scroll on their own.** Everything sat in one scrolling column, so paging through credentials pushed the activity log out of view and reading the log pushed the credentials away. Both are panels now, sharing the height below the actions bar and keeping their own scrollbar, so the page itself no longer scrolls. Phones are left alone: two short scrolling panels stacked in a small viewport is harder to use than scrolling the page, so below 768 pixels the whole page scrolls as before

## [1.19.16] - 2026-08-06

### Added

- **Credentials are listed newest first.** The order was the order they arrived, so a freshly issued credential went to the bottom of a list the UI pages ten at a time, which put it out of sight on a wallet holding more than ten. Both the API and `wallet list` now order by the issuance time the credential itself states, `iat` for an SD-JWT or JWT VC and the MSO signed time for an mdoc. Sorting happens before paging, so a page is a page of the sorted list rather than a sorted page. A credential that states no issuance time sorts last, and credentials issued in the same second keep the order they arrived in rather than being separated by anything arbitrary

### Documentation

- **Token Status List is no longer cited as RFC 9596.** RFC 9596 is the COSE `typ` header parameter and has nothing to do with status lists. Token Status List is still `draft-ietf-oauth-status-list`, in the RFC Editor queue with no number assigned, so nothing claims one now. The same comments also justified a 16 byte floor on the published bitstring as a requirement of that document. It sets no minimum size at all: the floor is this wallet's own choice, so that a fresh wallet does not publish a list short enough to identify the one credential reading it

## [1.19.15] - 2026-08-06

### Added

- **The wallet and the decoder link to each other.** Both are served by `wallet serve` and there was no way between them but the address bar. The wallet header carries a Decoder link, and the decoder header links back, reading "Demo wallet" on a shared instance and "Wallet" on somebody's own. A decoder running on its own through `eudi serve` has no wallet behind it and shows no link

### Removed

- **Bearer secrets are no longer redacted from a demo instance's activity log.** 1.19.14 replaced `access_token` and friends with `[redacted]` there. It covered a fixed list of field names and one level of nesting, so a token carried inside a logged response body went straight through, which a demo issuance still demonstrates. A redaction that misses cases is worse than none: it suggests the log is safe to read when it is not. A public demo is public, its credentials are disposable, and it was never meant to be pointed at a production issuer. The log records what went over the wire again, everywhere

### Documentation

- **The README compares this toolkit with the rest of the EUDI tooling.** Most of that tooling is an issuer or a verifier you point a wallet at, so the thing under test is the wallet. This is the wallet, and the table near the top of the README says so in one line per tool, along with what each one tests, whether it runs locally, and whether it can be scripted. It also says when to reach for something else: the OpenID Foundation suite for certification, the Animo or EUDI services when the wallet is what you are testing, an SDK for shipping a product, Multipaz when the flow is proximity rather than remote (this speaks OID4VP over HTTP and has no BLE or NFC transport), a hosted decoder for one quick look

## [1.19.14] - 2026-08-06

### Changed

- **The activity log keeps a bounded history, and a demo instance will not let a visitor clear it.** The log had no cap. It is persisted with the wallet and re-read at every request boundary, so an unbounded one grows the wallet file and the parse that each of those reloads does, which a shared demo can be driven to do by anyone. It now keeps the most recent thousand entries. The demo already capped what `GET /api/log` returns, which bounded the response and not the log behind it. With growth handled, clearing the shared history is no longer something a visitor needs: `DELETE /api/log` and `DELETE /api/error` join the endpoints the demo profile refuses, and the UI drops its Clear button there rather than offering an action that can only fail. A local wallet still clears its own

### Fixed

- **A status list could exhaust the memory of whoever resolved it.** The list is fetched from a URL in the credential's own status claim and inflated before anything is read out of it, and neither the download nor the inflate had a limit. Deflate turns half a megabyte into half a gigabyte without effort (measured at 1028 to 1), so a credential decided how much memory the party checking it allocated. The demo verifier resolves this for every presentation it is shown, unauthenticated. The download now holds to the same cap as every other remote fetch and the decompressed list is capped at 16 MiB, which is over a billion entries at one bit each. The other eleven places that read a peer's response without a limit were bounded at the same time
- **The activity log handed demo visitors somebody else's access token.** A demo wallet will redeem a credential offer from whatever issuer a visitor points it at, and `GET /api/log` is open there, so the bearer token from that exchange was readable by everyone else. The deferred issuance API already withheld the same token on the grounds that nothing outside the wallet needs it. Bearer secrets are now redacted from the log on a demo instance, with the field kept so a reader still sees one was sent. A local wallet is unchanged: the log is the operator's own there, and reading what went over the wire is what a protocol debugger is for

## [1.19.13] - 2026-08-06

### Changed

- **A COSE_Key is read by go-cose rather than by its integer labels.** The device key an mdoc issuer binds a credential to was decoded by reaching into the parsed map for labels 1, -1, -2 and -3, which meant carrying an opinion about which curves count and rebuilding the point from its coordinates. The parser now keeps the key's CBOR (the decoded map turns those integer labels into decimal strings for display, which no COSE library can read back) and `DeviceKey` hands it to go-cose, which was already a dependency. Unpadded coordinates are still accepted, because real issuers emit them whenever a coordinate's leading byte is zero
- **Strict mode refuses a JWK the specification does not allow.** RFC 7518 6.2.1.2 requires EC coordinates at the full curve width, and a peer that encodes a coordinate whose leading byte is zero sends one byte short. Repairing that silently would have made strict mode lenient about a spec violation, which is the one thing strict mode exists to prevent. Both peer encryption keys the wallet reads (a verifier's response encryption key and an issuer's credential request encryption key) are now refused under `--mode strict` when they are short. The rule applies to public keys only: a private JWK is the operator's own key file rather than a peer's document, so a short scalar there is padded and loaded, because refusing somebody their own key answers no conformance question. The debug path still reads them, and says so: the repair is written to the activity log on the presentation side and to the issuance log on the other, because a repair nobody is told about leaves the two modes disagreeing with nothing to explain why
- **JWKs are parsed by go-jose, in one place instead of five.** `keys` had four parsers split by key type and visibility, and `proxy` and `jwe` had one each, every one of them rebuilding big integers by hand with its own idea of which curves counted. All six now go through `keys.ParseJWK` and `keys.ParseJWKPrivate`, which are go-jose underneath, and the EC-and-RSA-only contract is kept by a type switch (go-jose also reads OKP and symmetric keys, which nothing here is written for). Short coordinates are left padded before the library sees them: RFC 7518 wants full width and go-jose enforces it, but peers get this wrong often enough that refusing would mean failing to decode a credential exactly when someone needs to find out what is wrong with it
- **JWS signatures are verified by go-jose, in one place instead of four.** `sdjwt`, `statuslist`, `wallet` and `demorp` each carried their own verifier: split the compact form, hash the signing input per algorithm, slice the raw `r||s` signature at the curve size, call `ecdsa.Verify`. Every copy had to get the fixed-width encoding and the algorithm mapping right by itself, and they had already drifted to different algorithm sets. They now share `jws.Verify`, which is go-jose underneath, with the accepted algorithms passed in at every parse rather than read from the token. The status list check keeps its narrower ES256/ES384 rule, so nothing it used to refuse starts verifying. JWE is deliberately left alone (see the decision record: go-jose cannot set `apu` and `apv` when encrypting, which ISO 18013-7 mdoc presentations require)
- **A deferred issuance is called that everywhere.** The CLI and the HTTP API said `deferred` while the types, the fields and the stored file said `PendingIssuance`, which is one concept wearing two names and a reliable way to search for half the code. Everything now says deferred. The stored field is `deferred_issuances`, and a wallet written before this still has its in-flight collections read from `pending_issuances` (dropping them would abandon an issuance an issuer had already accepted), so the first save after upgrading migrates the file
- **The two metadata fetches in a credential offer log themselves through one helper.** Each wrote out the same three log calls inline, with the details map spelled out separately per branch, which is how a field ends up recorded on one fetch and not the other. They now describe what they are fetching and share the logging. The entries a wallet writes are unchanged, which an issuance flow through the demo issuer confirms field by field
- **`wallet serve` runs from a function rather than from inside its flag builder.** Twenty-two flags were declared in a var block that the `RunE` closure read straight out of, so the builder was 466 lines of which the closure was 370, and every other command in the package (`runValidate`, `runDecode`, `runProxy`) already reads the other way round. The flags are a struct now and the work is `runWalletServe`, leaving the builder at 52 lines. It also removes a shadowing that was easy to miss: `--pid` and the local process id were both called `pid` in the same closure, the second one hiding the first from its declaration onward
- **Build output is no longer tracked.** Two Python bytecode caches under `examples/` and a Playwright run summary had been committed, because the ignore rules named one directory each (`scripts/__pycache__/`, `e2e/test-results/`) while the tools write them wherever they happen to run. Both rules now match at any depth

### Documentation

- **The decisions behind this toolkit are written down.** Seven decision records in `docs/adr/` cover the ones that are hard to reverse and surprising without context: debug-by-default validation, the unauthenticated API, unencrypted storage, the dial-time fetch policy, the per-request store reload, one binary playing every role, and why everything sits under `internal/`. An eighth records why JWS verification moved to a library and JWE did not
- **A glossary pins the terms this project overloads.** `CONTEXT.md` covers the vocabulary that carries more than one meaning here: attestation (client, verifier, and issued are three unrelated things), profile (trust, demo, and HAIP likewise), deferred versus pending issuance, renewal versus refresh token, and PID meaning both Person Identification Data and a process id. Specification terms used unchanged are deliberately left out
- **The architecture overview is a third shorter and points at the decision records.** It carried a per-file tree of `cmd/` and a table of key types, both of which drift, plus a data-flow section naming functions of which five no longer existed. Flows are described in domain terms now, and why anything is the way it is lives in the decision records rather than being re-explained here
- Agent guidance moved into `AGENTS.md` and `docs/agents/`, recording where issues live and how the domain docs are meant to be read
- The architecture overview lists the packages and command files that were added since it was written. Five packages were missing from it (`demorp`, `jws`, `jwe`, `httpsec`, `imprint`), and `web/` was described as embedded static assets when it is a server with its own handlers. Both trees now match what is on disk
- The wallet's HTTP API reference covers deferred issuance, the activity log and the last error, which back `wallet deferred` and `wallet logs` and were the endpoints missing from a page that says everything the CLI does is available over HTTP

### Fixed

- **The template endpoint would read any JSON file on the server.** `GET /api/templates/{name}` passed the URL segment to a loader that takes a name *or a path*, because the CLI documents `templates show ./some-template.json`. Over HTTP that became a file read: any JSON the process could open came back with whatever fields looked like a template, and the status code alone (404 against 200) located files whose contents did not survive the decode. The demo profile blocks writes to templates but not reads, so this was reachable by anyone on a public instance. The endpoint now takes a bare name, the same rule the write and delete handlers already applied, and the CLI keeps its path form
- **A credential could panic whoever checked whether it was revoked, and whoever served the status list.** The status list index comes out of the credential's own status claim, and a negative one reached a shift and raised "negative shift amount" before any bounds check ran. Anything resolving that credential's status hit it: the demo verifier does so on every presentation it checks, so a crafted credential took down the request handling it. Importing such a credential was worse: the index is adopted when it points at this wallet's own list, and once stored it panicked every build of the bitstring, which is every request for the status list. On a demo instance both importing and reading the list are open to anyone. Negative indexes are now refused on the way in and skipped on the way out. The bits-per-entry value from the fetched status list was unchecked too, and a nonsense width produced a mask that read the whole byte and reported it as a status. Both are now refused, and the four widths the specification allows are covered by tests
- **Preferred-format sorting reordered credentials it should have left alone.** With `--preferred-format` set, matches were sorted by asking whether the left one carried the preferred format, which claims i before j and j before i when both do. That is not an ordering `sort` can work with, and it reversed equally preferred matches rather than leaving them in place, so which credential a caller took first came down to how the sort happened to run. It now compares both sides, and the input order within each group is kept
- **Only a demo wallet capped the size of a request it would read.** Everywhere else the server read whatever it was sent fully into memory, so how much of it a caller could occupy was the caller's choice. The same one megabyte cap now applies to every wallet server, which every legitimate payload (credentials, offers, presentations, templates) is far below
- **The mdoc verifier was the one entry point that would panic on a nil document.** Everything else in that package reports it and returns, and callers reach all of them from the same parse results, so the odd one out was a crash waiting for whichever caller passed a parse that produced nothing. It now reports it like its neighbours
- **The imprint page's back link did nothing.** It was written as a scripted URL, and every server that mounts the page sends `script-src 'self'` without `'unsafe-inline'`, which blocks exactly that. The link rendered normally and swallowed the click, so nothing about the page said it was broken (this is live on the public demo). It is now a link to the site root, and the page is checked for carrying no script at all
- **The mdoc digest comparison was a hand-written one that could not say no.** It walked only the computed digest and compared byte by byte, so a signed digest shorter than the hash matched on its prefix and a shorter one still would have read past the end of it. A length check at the one call site kept it correct, which is the wrong place for it: the helper is what the next caller reaches for. It is now `bytes.Equal`, and the cases the hand-written version could not tell apart (a truncated digest, an empty one, one with bytes appended) are covered
- **A web page could have the wallet hand its credentials to a site of its choosing.** The API has no authentication on purpose and the answer to that has been to keep the wallet on localhost, which does not cover the browser: every page a developer visits can reach localhost too. Nothing was preflighted either, because a POST carrying `text/plain` is a CORS simple request, so a page could post a presentation request to `/api/presentations` with `auto_accept` set and the wallet would build a presentation and submit it to the `response_uri` the page named, with nobody asked and nothing shown. CORS stops the page reading the reply, and this never needed to read it. An `/api/` request arriving with an `Origin` from another site is now refused. A CLI, a curl invocation or a test harness sends no `Origin` and is unaffected, the wallet's own UI is on the same origin, and behind a reverse proxy `--base-url` counts as this wallet's own origin too. The protocol endpoints stay open, which is what they are for

## [1.19.12] - 2026-08-06

### Fixed

- **`wallet refresh` did not complete credential ids.** It takes the same argument as `wallet show` and `wallet remove`, which both complete it. `wallet deferred check` and `wallet deferred abandon` now complete the ids of the credentials still being collected
- **A refused token request read as a raw response body.** An issuer that turns down a token request (a refresh included) says why in the two fields RFC 6749 §5.2 defines for it, and the wallet handed back the whole body with the status code repeated after it: `HTTP 400: {"error":"invalid_grant","error_description":"Invalid authorization code"} (HTTP 400)`. It now reports `invalid_grant: Invalid authorization code`. A refusal that carries no OAuth error document is still reported in full

## [1.19.11] - 2026-08-06

### Changed

- **The wallet UI shows how long a credential is good for, and no longer offers to renew it.** The Renew button was a third way to do something that already happens twice on its own (a background task shortly before expiry, and again on the way to a verifier) and that `wallet refresh <id>` covers when it has to be now. What the UI was missing is the question behind it, so every credential card now carries its remaining validity, marked when it is inside a day and when it has lapsed. `wallet list` gained a `VALID` column and `wallet show --decoded` a validity line, because the decoded payload states the expiry as a Unix timestamp

### Added

- **The demo verifier links the presentation it received to the decoder.** The result showed a claims table and a list of checks, which says nothing about the key binding JWT or the device auth the wallet signed. The verification result now carries the presentation exactly as it arrived (SD-JWT with its key binding, mdoc DeviceResponse with its device auth) and the page offers it to the decoder. It is offered whether the presentation verified or not, because one that failed is the one worth opening
- **A decoder link can name a credential instead of carrying it.** `?credential=` puts the whole credential in the URL, which for an SD-JWT with disclosures is kilobytes of base64url and a link nothing will keep intact. The decoder mounted on a wallet now also takes `?id=<credential id>` and resolves it against that wallet, and the wallet UI's decoder links use it. The share button keeps whichever form the shown credential came from. A decoder with no wallet behind it says so rather than reporting the id as undecodable input
- **The demo verifier asks for the PID in the format you pick.** A PID request offered both formats and left the choice to the wallet, which is the right default but hides half the behaviour: a wallet that only holds one format, or picks the other one, looks the same from here. A toggle now asks for the SD-JWT VC only, the mdoc only, or either (the default). A one-format request carries exactly that credential and no credential set, so a wallet that cannot answer it says so instead of substituting the format it has. The ticket takes no format (the demo issuer only issues it as an SD-JWT VC) and a request that asks for one is refused
- **The demo issuer can hand out a revocable ticket.** A toggle on its page issues the Demo Event Ticket with a reference to the wallet's own status list, on an index reserved for that credential alone. A wallet importing a credential that points at the status list it serves now adopts the entry, so the ticket arrives with a working Revoke button and the demo verifier rejects the next presentation once it is revoked. Without the toggle nothing changes: the ticket carries no status reference and the verifier reports that there is none to resolve

### Fixed

- **A refresh token request carried no client authentication.** A refresh is a token request at the same endpoint as the one that obtained the credential (`grant_type=refresh_token`), so an issuer that required a wallet attestation or a `private_key_jwt` assertion then requires one now. The wallet sent neither, because the flow that discovered the requirement is gone by the time a credential nears expiry. It now keeps how it authenticated with the credential (and with a deferred issuance, whose access token renewal has the same shape) and rebuilds it per request, fetching a fresh attestation challenge each time rather than replaying the one from issuance
- **`wallet list --remote local` reported a revoked credential as governed by a foreign status list.** Both backends build the same document, but one travels through JSON (where every number is a float64) and the other is handed over in this process with its Go types intact, and the renderer only read float64. So the status value was invisible to it and it fell back to "external", on exactly the credentials the wallet governs itself. The number is now read in either shape, which also fixes the attempt count on a locally read deferred issuance

### Documentation

- The wallet documentation says where credential validity is reported, and what a refresh token request carries

## [1.19.10] - 2026-08-05

### Changed

- **The wallet's own work runs on one loop that reports what it does.** Deferred collection and certificate renewal each carried their own schedule inside their own body, one of them throttling itself with a field on the server. They are now tasks on a single background loop, off the request path, each declaring how often it is worth running. A task that fails is retried on the next tick rather than waiting out its interval, and is dropped with a reason after five failures in a row instead of repeating forever. A panic is caught and counted as a failure, so one broken job cannot stop the rest of the wallet's own work
- **Both wallet backends are compared method by method.** Every management command runs against either a local store or a remote instance, and each backend builds its documents separately, so a field only one of them fills is invisible until a column shows the wrong thing. A table now runs all fifteen `walletService` methods through both and compares what a caller can read, and a completeness check fails when a new method arrives without a case

### Added

- **A credential about to expire is renewed on the way to a verifier.** The background task only runs on a wallet server, so a credential lapsing between two presentations would otherwise be sent for the verifier to reject. A renewal that fails is not fatal: the credential in hand may still be accepted, and refusing to present it is not better
- **The wallet UI has a Renew button.** It appears on credentials whose issuer handed over a refresh token and nowhere else, so it never offers something the wallet cannot do
- **`wallet refresh <id>` renews a credential from the CLI.** It asks now rather than waiting for the background task, against a local store or a remote instance alike
- **Credentials are renewed shortly before they expire.** A task on the background loop renews what is within a minute of expiring and can be renewed, so a credential a verifier would reject is replaced before anyone tries to use it. One credential failing does not stop the sweep, and a credential whose renewal failed is held off for ten minutes rather than retried every half minute until it expires
- **A credential can be renewed from its issuer.** When an issuer hands over a refresh token at issuance, the wallet keeps what re-requesting the credential needs and `POST /api/credentials/{id}/refresh` asks for a fresh copy. The credential keeps its id: a verifier query, a UI selection and the activity log all refer to credentials by id, so a new entry would read as the old one being deleted and an unrelated one appearing. A rotated refresh token replaces the stored one. A credential whose issuer gave no refresh token is refused rather than silently left alone
- **Credentials report when they expire.** An SD-JWT states it in `exp` and an mdoc in the MSO its issuer signed, so a caller deciding what to do about it had to know which format it was holding. One function reads both, credential listings carry `expires_at`, and a credential that states no lifetime is never treated as expiring. This is what renewal will key off

### Documentation

- The storage section says plainly that the wallet keeps keys and issuer tokens unencrypted, because it is a development and test wallet whose store is meant to be readable

### Fixed

- **The deferred credential type still did not reach a local wallet.** 1.19.9 fixed the API response. The local store listing is built separately and was missed, so `wallet list` against a local store kept naming a waiting credential by the issuer's configuration id
- **A deferred credential can now outlive its access token.** The token is issued for the credential request and expires in minutes, while an issuer may ask the wallet back in an hour, so a long deferral used to fail on an authorization the issuer had already expired. The wallet keeps the refresh token and the expiry the token response carried, renews before an attempt that would be refused, and renews once and retries when an issuer refuses anyway (some expire earlier than they said). A rotated refresh token replaces the stored one. Without a refresh token nothing changes: the collection stops and says why
- **A deferred credential whose token had expired was retried hourly for a day.** The access token is issued for the credential request and expires in minutes, while an issuer may ask the wallet back in an hour, so a long deferral collects with a token the issuer has already refused. A rejected authorization (401, 403) was classed as worth another attempt, so the wallet kept asking until the 24 hour cap with no chance of succeeding. It now stops and says why. Getting a fresh token instead needs refresh token support, which the wallet does not have yet

## [1.19.9] - 2026-08-05

### Fixed

- **An error from an issuer sign-in reached no tab, and then surfaced on the next unrelated action.** The tab that starts an authorization code flow navigates away to the issuer, so the claim that says "this failure is mine" was gone by the time the flow failed. Nothing showed the error, it stayed stored, and the next issuance picked it up instead: a working flow reporting the previous one's failure. The tab coming back from the sign-in now claims that outcome, and starting something new drops any error still stored from before
- **The credential type added in 1.19.8 never reached the UI.** The deferred record carried it, but `GET /api/deferred` builds its response field by field and the two new ones were not in the list, so the wallet still listed a waiting credential by the issuer's configuration id. The endpoint now returns them

## [1.19.8] - 2026-08-05

### Fixed

- **A deferred credential was listed by the issuer's configuration id instead of its type.** A credential offer names configurations (`eudi-pid-sd-jwt-bdr-key-attestations`), never credential types, so a credential still being collected read as an issuer's internal name while the same credential became `urn:eudi:pid:1` the moment it arrived. The type is in the issuer's metadata all along, so the wallet now records it with the deferred credential and the UI, `wallet list` and `wallet deferred` show it, falling back to the configuration id for an issuer whose metadata declares neither

## [1.19.7] - 2026-08-05

### Changed

- **JWS signing and JWE decryption each have one implementation now.** ES256 signing was written out six times (credentials, presentations, trust lists, status lists, issuer metadata, client attestations) and ECDH-ES decryption twice, key derivation and all. Every copy was correct, which is the problem: a fix to one of six reaches one of six, and the r||s padding and the Concat KDF are both easy to get subtly wrong in ways that fail as "bad signature" somewhere else. They now live in `internal/jws` and `internal/jwe`, with tests. No behaviour changes
- **The wallet server is split by concern.** `server.go` had grown to 1819 lines holding about forty handlers, so finding the code behind an endpoint meant scrolling past everything else. It keeps the type, construction, routing and lifecycle, and the handlers move to files named for what they serve (TLS, presentations, offers, credentials, consent requests, deferred issuance, published metadata, control). Pure code motion, verified declaration by declaration

### Fixed

- **A deferred credential was never collected when the offer set a profile override.** `POST /api/offers` with `haip` or `mode` runs on a per-request clone of the wallet, and the clone was thrown away with the deferred record still on it. The background poller only reads the server's own wallet, so nothing ever asked the issuer again: the wallet reported the credential as on its way and then dropped it, where OpenID4VCI 1.0 section 9.3 has it retry after the interval. Found by the conformance suite, whose deferred module waits for a request that never came
- **The demo's certificate renewal raced with live requests.** The daily reset re-issues the signing leaf, and it replaced the CA key and the certificate chain without holding the wallet lock while requests were reading both. A slice header is not written atomically, so a credential could be signed against a half-swapped chain. The swap and the reads that matter now take the lock, and `go test -race` is clean across the tree
- **An error in one visitor's flow raised a dialog in every open tab.** A shared wallet broadcast every failure to all connected browsers, so someone who did nothing was shown an error another visitor ran into, including its detail text. Errors now reach the tab that started the flow and no other, on the event stream and on the stored error a tab picks up when it loads. The three separate claim mechanisms the UI had grown for this (consent, issuer sign-in, errors) are now one

## [1.19.6] - 2026-08-05

### Added

- **`wallet trust-list --list` shows which trust list profiles a wallet serves.** The ids were only discoverable by reading `/api/trustlists`, so picking one from the CLI meant guessing. Every profile carries the same certificate (the wallet has one CA) and differs in what it declares that CA to be, so the listing names the category to pick by. `--json` emits the `/api/trustlists` body unchanged

### Fixed

- **A verifier's redirect after a presentation was buried in the JSON output.** OpenID4VP 1.0 section 8.2 has the wallet send the user agent to the `redirect_uri` a verifier answers with, which is how a same-device flow returns to the site that asked. The CLI now prints it and, when a person is running the command, opens it. A scripted run only prints it, and `--no-open` turns it off everywhere
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
- **`eudi wallet deferred`** lists what an issuer has deferred, with the retry interval and the next attempt. `eudi wallet deferred check [id]` makes one request straight away instead of waiting for the scheduled attempt, and reports what came back. `eudi wallet deferred abandon <id>` stops collecting one, leaving the transaction valid at the issuer. The wallet UI carries the same two actions on each entry. Over `GET /api/deferred`, `POST /api/deferred/{id}/collect` and `DELETE /api/deferred/{id}`. The listing never returns the access token
- **The consent dialog asks for a transaction code.** An offer whose pre-authorized grant carries `tx_code` cannot be redeemed without one, and the issuer delivers it out of band (the Animo playground prints it beside the QR code, a bank would text it). The dialog only reported that a code was required and then offered no way to supply it, so such an offer could not be accepted from the UI at all. It now shows an input sized and typed from the offer's own `input_mode`, `length` and `description`, refuses an empty approval in the dialog rather than spending the offer on a request that cannot succeed, and sends the code with the approval
- `wallet accept` asks for the transaction code when the offer requires one and none was passed. `--tx-code` still wins, and nothing is asked when no terminal is attached, so scripts and containers keep their current behavior and get the issuer's own error instead of a hanging prompt
- **`wallet serve --client-attestation`** sends the wallet attestation on OID4VCI token requests even when the authorization server does not advertise `attest_jwt_client_auth`. The default stays metadata-driven, which is what draft-ietf-oauth-attestation-based-client-auth §8 asks a client to do and what §10.1 wants for privacy (this wallet reuses one attestation and one `cnf` key, and §10.1 warns that reusing them across authorization servers lets those servers correlate the user). Advertising the method is only a SHOULD, though, so an issuer can check an attestation without announcing it, and against one of those a correct wallet gets `invalid_client` and no credential. The flag is the operator overriding that, which is a decision for a person rather than something the wallet infers from an error message. `GET /api/config` reports it as `force_client_attestation`

### Fixed

- **`wallet accept --tx-code` did nothing against a wallet server.** The flag reached the local store but the remote path dropped it, so the same command worked locally and failed with "Missing required 'tx_code'" against `--remote` (which is how the CLI drives a container or a hosted wallet, and how it auto-routes to a running instance). The code now travels in the `POST /api/offers` body, which the server already accepted
- **The pre-authorized code flow ignored every protection the issuer asked for.** It was a separate path from the authorization code flow and never gained what that one has: no DPoP proof, no `OAuth-Client-Attestation` headers, no key attestation in the credential proof. The wallet even read `key_attestations_required` out of the issuer metadata and then did nothing with it. An issuer that requires any of the three refused to issue, so testing against one (the Animo playground requires all three) meant turning the requirements off first. Each is now driven by the issuer's own metadata, so an issuer that asks for none of them sees exactly the request it saw before. Both flows share one transport now, and the duplicated HTTP code on the pre-authorized path is gone
- **Deferred issuance did not work on the pre-authorized code flow, and its polling watched for the wrong thing on the other one.** An issuer that cannot produce the credential yet answers with a `transaction_id`, and the pre-authorized path had no handling for that at all: it read the ticket as a credential response and gave up with "no credential in response". Both flows share one deferred step now. The polling itself was also wrong: it waited only while the issuer echoed a `transaction_id` back in a success-shaped body, but OID4VCI 1.0 §9.3 reports "not ready" as the `issuance_pending` *error*, which arrives as an HTTP 400 and ended the flow instead of extending it. Both shapes are accepted now, and the issuer's `interval` is honored. This was invisible to the conformance run, which never has to wait
- **A deferred issuance stops blocking after 90 seconds and is collected in the background instead.** The poll loop had no bound, so an issuer deferring by a day would have held the request open for a day. A short deferral is still waited out, so a quick one comes back from the call that started it. A longer one is recorded and collected on the interval the issuer asked for (see Added). The wallet server's write timeout, the remote CLI client and the consent approval wait were each below that bound (60s, 30s and 30s) and would have cut off a deferral the others were still waiting for, so all three now derive from it
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
- **The consent event stream is no longer readable cross-origin.** `GET /api/requests/stream` sent `Access-Control-Allow-Origin: *`, so any page a user visited could subscribe to it and read incoming consent requests, including the claims a verifier asked for. The wallet's own UI is same-origin and never needed the header. Non-browser clients do not enforce CORS and are unaffected
- **A verifier could execute script in the wallet through its `redirect_uri`.** After a presentation the wallet navigates the browser to the `redirect_uri` (or `Location`) the verifier returns, and it only checked that the URI was absolute. `url.Parse` calls `javascript:` and `data:` absolute, so a verifier answering with `{"redirect_uri":"javascript:..."}` got script execution on the wallet's own origin. Both are now restricted to http and https, server-side and again in the UI before it navigates
- A wallet attestation with no `exp` claim was accepted by the demo issuer, because the expiry was only checked when present, and a DPoP proof was accepted at any age. `exp` is now required and a proof's `iat` has to fall inside a five-minute window, so a captured proof stops working

### Fixed

- **The login in the demo issuer's authorization code flow happened before redemption instead of during it.** The offer was created only after signing in, and the wallet then completed the flow without the user ever meeting the authorization endpoint. Now the offer is created signed-out and the user authenticates at `/issuer/authorize`, between the pushed authorization request and the token exchange, which is where the flow puts it: the credential is bound to whoever completed the login, not to whoever created the offer
- **A hosted wallet can complete an authorization code flow at all.** The wallet only knew how to open a browser on the machine it runs on, which does nothing on a demo host. It now offers the authorization URL to the open UI (an `authorize` event on the consent stream) and that tab navigates. `/callback` resumes the flow already in progress and returns the visitor to the wallet. A wallet running locally with no UI attached still opens a local browser
- `wallet serve` defaults `--vci-client-id` to its own origin and `--vci-redirect-uri` to that origin's `/callback`, so an authorization code offer no longer fails with "requires configured wallet client_id and redirect_uri" on a wallet that never set them. Explicit flags still win
- **A credential issued by a long-running flow could be lost.** Every request reloads the wallet from its store, replacing the in-memory credential list. An authorization code flow stays open across the user's login, and the UI's burst of requests when it returns landed between the import and the save: issuance reported success and stored nothing. The credential is now put back if a reload dropped it, and the restore and the save happen under the lock the reload takes
- Only the tab that started an issuance follows the issuer's login page. The authorization event went to every open UI, so on a shared wallet a visitor who did nothing would have been navigated to some issuer's login, which is exactly what the consent dialog already avoids
- Two tests wrote to variables from a request goroutine and read them from the test goroutine, which `go test -race` flags. The whole repository is race-clean now

## [1.19.1] - 2026-08-04

### Added

- **Instances report which release they run, and the CLI checks it before managing one.** A wallet instance can live anywhere (a container, a VPS, the public demo), so the CLI driving it is not necessarily the same release. `GET /api/version` already carried `version`. Discovery now keeps it, so `wallet instances list` has a `VERSION` column (`version` in `--json`), selecting a target prints the release it runs, and the automatic routing notice names it too. The version comes from the health check rather than the registry file, so it describes the process that is actually answering
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

- The issuance consent dialog says what is actually being issued. It showed the issuer's origin and a raw configuration id. It now shows the issuer's own name with the origin beneath it, the flow the offer uses, whether a transaction code will be required, and per credential the format, type, display name, description and the claims the issuer declares. Everything past the offer comes from the issuer metadata, which is optional, so each part appears only when it is known and an issuer without readable metadata still yields a usable dialog. An offer delivered as a `credential_offer_uri` is resolved for the dialog as well, and fetched again after approval, which the specification permits and which is what lets a visitor see the credential rather than a bare hostname. An offer that cannot be retrieved still produces a dialog naming its issuer
- A **Conformance** dialog in the wallet UI header reports what incoming requests are actually held to: validation mode, HAIP 1.0 for presentations and for issuance, encrypted requests, session transcript and preferred format, with an explanation of what the active level rejects. Only what is enforced is highlighted, so "not enforced" cannot be mistaken for a pass. `GET /api/config` gained `require_haip_issuance` alongside the fields it already reported
- `eudi wallet config` as an alias of `wallet info`, and the local backend now reports `require_haip`, `require_haip_issuance`, `auto_accept`, `session_transcript` and `require_encrypted_request`. Local and remote wallets described the same thing differently before, and the conformance-relevant settings were missing from the local view entirely

### Changed

- **Demo mode enforces the EUDI profile.** `--demo` now implies `--mode strict` and `--haip`, so a publicly hosted wallet holds callers to the rules a real EUDI wallet applies instead of accepting anything and teaching verifiers that they pass. A verifier that is not HAIP-compliant gets `HTTP 400` from the public demo, and so does an offer from an issuer that fails the checks applying to it. Both are overridable (`--mode debug`, `--haip=false`) for a self-hosted demo that would rather be permissive, and nothing changes outside demo mode: a plain `wallet serve` keeps `debug` and no HAIP, which is what the OIDF conformance runner relies on
- The built-in demo verifier is HAIP-compliant, which is what makes the above possible: it signs its authorization request object (ES256, `x5c`) and serves it by reference from `/verifier/request/{id}`, identifies itself with an `x509_hash:` client id derived from its signing certificate, requests `response_mode=direct_post.jwt`, publishes a per-request P-256 encryption key in `client_metadata`, and decrypts the response. It previously failed three of the five HAIP checks
- **HAIP is enforced for issuance, not only for presentations.** `ValidateHAIPIssuanceCompliance` follows the flow an offer actually drives: every offer must come from an https issuer, and an offer that drives the authorization endpoint must additionally find pushed authorization requests required and the authorization code flow, PKCE S256, DPoP and client authentication supported. A pre-authorized code offer is held only to the transport rule, because HAIP 1.0 §4 requires an issuer to *support* the authorization code flow rather than to use it everywhere, says nothing about the pre-authorized code flow, and scopes PAR to "when using the Authorization Endpoint". The wallet's own client already satisfied all of it. Nothing rejected an issuer that did not. Plain http on loopback is still accepted, the way OAuth treats a local development host, so a demo instance on localhost is not refused for being local
- The built-in demo issuer describes itself properly in its metadata: proof requirements (`cryptographic_binding_methods_supported`, `proof_types_supported`), the claims the ticket contains, and a description, so a wallet can show a visitor what they are accepting. It keeps the pre-authorized code flow, which the profile permits
- `POST /api/offers` accepts `haip` and `mode`, the same per-request overrides presentations already had. It also fixes a silent bug: the endpoint decoded neither field, so the `mode` the conformance runner has always sent was discarded and issuance ran on whatever the server was started with
- The per-request HAIP override works in both directions. `{"haip": false}` on `POST /api/presentations` (or `X-OID4VC-Dev-HAIP: false`) now switches enforcement off for one request, where before a request could only ever turn it on. Without this there was no way to test a non-HAIP verifier against a wallet that enforces HAIP, and the conformance suite's non-HAIP modules would have been rejected outright. An absent field or header still inherits the server setting
- A demo instance may fetch its own advertised origins. `--demo` blocks connections to internal addresses, which also blocked the wallet from reaching its own demo verifier, so on localhost the built-in flows could not complete at all. The exemption is by exact resolved address and port for the configured base and issuer URLs. A visitor-supplied URL pointing at loopback is still refused
- `--demo` no longer claims to imply `--auto-accept` in its flag help and startup banner. It never did. Consent stays interactive on purpose

### Fixed

- The status list token publishes the signing key as a `jwk` header alongside `x5c`. Relying parties that resolve keys from the token itself had no route to verify it: Token Status List leaves key resolution to the deployment (§11.3) and requires only `typ` in the header (§5.1), so both mechanisms are permitted, and `jwk` is a registered JOSE header (RFC 7515 §4.1.3). It is derived from the signing key rather than configured, so it cannot disagree with the certificate in `x5c`, which remains the route that anchors the key in a trust anchor
- The status list token no longer ships the trust anchor inside its `x5c` chain. A relying party holds the anchor out of band, and a chain that carries its own self-signed root proves nothing, so HAIP 6.1 rejects it: the OIDF suite failed every HAIP sd_jwt_vc module with "Trust anchor certificate must not be included in x5c chain". Every other JWS this wallet signs already stripped it. The status list path was the one that did not
- A credential imported during a request that carried a profile override is no longer lost. Those requests run on a per-request clone of the wallet, which holds its own credential slice, so an issuance would have reported success and stored nothing. Imports on a clone are now forwarded to the wallet it was cloned from
- `docs/spec-compliance.md` listed batch credential issuance as not implemented. It has been implemented since `internal/wallet/issuance_batch.go`. The HAIP section of `docs/wallet.md` described enforcement as covering OID4VCI when every enforced check is a presentation check

## [1.18.11] - 2026-08-04

### Fixed

- The wallet refreshes its own protected baseline again. Protecting the default PIDs stopped `GenerateDefaultCredentials` from replacing them, which was the point, but it also stopped the server's own baseline generation, so a demo instance kept serving the PID claim set of whichever release first created it: after updating to 1.18.10 the shared demo still showed `personal_administrative_number` and the other claims the German PID does not have. Startup and the periodic reset now replace the baseline they created earlier, protection included. Nothing reachable from a request can: `POST /api/generate-pid`, the CLI and every other request-driven path still leave a protected credential alone

## [1.18.10] - 2026-08-04

### Changed

- The German PID templates and the default PIDs carry the claims the [German PID Rulebook](https://demo.pid-provider.bundesdruckerei.de/credential-claims) defines, with the values of the provider's ERIKA MUSTERMANN test identity. SD-JWT gained `birth_name`, `title`, `also_known_as`, `date_of_expiry`, `source_document_type`, `address.region`, `place_of_birth.no_place_info` and all six age thresholds (only 18 was there before), and mdoc gained the same plus `resident_state`. Claims the rulebook lists as unused because the German eID does not supply them are gone (portrait, sex, email, phone number, document number, personal administrative number, issuing jurisdiction, `issuance_date`, `age_in_years`, `age_birth_year`, birth given and family name, `resident_address`, `resident_house_number`, `address.formatted`, `address.house_number`), so a presentation from this wallet exercises the claim set a verifier meets in production. A user template saved under either PID name still overrides all of it
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

- Consent dialogs are scoped to the browser that started the flow. The browser redirect now carries the consent request id (`/?request=<id>`) and the UI auto-opens exactly that request. In demo mode, other visitors' requests no longer pop up in every open tab (they could previously be triggered and approved from any browser). Outside demo mode the previous auto-open behavior remains for requests arriving via schemes or the API
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

- Wallet credential offer endpoint (`GET /credential-offer`): accepts `credential_offer` / `credential_offer_uri` (and optional `tx_code`) query parameters, making offers deliverable to the wallet's own URL instead of the `openid-credential-offer://` custom scheme. Together with the existing `/authorize` endpoint, both wallet flows are now fully invocable by plain web URL in hosted environments, automated tests, and on platforms without URL scheme registration
- Browser invocations of `/authorize` and `/credential-offer` (GET with an HTML Accept header) now complete like a same-device wallet: after a presentation the browser is redirected to the verifier's `redirect_uri`, after an offer import to the wallet UI, so a verifier configured with the wallet's URL (e.g. `keycloak-extension-oid4vp` `walletScheme`) runs a standard OIDC round trip end to end. API callers keep receiving JSON. Without `--auto-accept` the navigation redirects to the wallet UI immediately with the consent request pending. The flow finishes in the background once it is approved there (presentations continue to the verifier's `redirect_uri` via the approve response) instead of the browser tab blocking until consent
- Example `keycloak-web-wallet`: Keycloak 26.7.0 issuer, `keycloak-extension-oid4vp` verifier, the wallet, and a demo UI in one Docker compose project sharing one network namespace, so every URL is plain `localhost` for both the host browser and the containers. Issuance delivers offers to the wallet's `/credential-offer` URL, and verification is an ordinary OIDC login whose Keycloak login page links straight to the wallet's `/authorize` URL (requires `keycloak-extension-oid4vp` > 0.6.4 for wallet web URLs in `walletScheme`)

### Fixed

- The wallet's credential request advertises `Accept: application/jwt` only when credential response encryption is negotiated. Sending it unconditionally made Keycloak 26.6's credential endpoint fail with an internal error (it returns signed issuer metadata when it sees `application/jwt` in the Accept header)

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

- `wallet tls-cert` now prints exactly one leaf PEM certificate. `wallet ca-cert` prints exactly one CA PEM certificate

## [1.5.2] - 2026-03-20

### Added

- `wallet ca-cert` to print or export the shared wallet CA certificate

### Changed

- wallets under the same wallet base directory now share one persisted CA
- the shared CA now anchors wallet trust lists, status-list `x5c` chains, issuer-metadata `x5c` chains, and HTTPS wallet certificates
- HTTPS wallet certificates are now signed by the shared CA instead of being self-signed
- no wallet API endpoint paths or response formats changed. Only the trust model and certificate material changed

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
