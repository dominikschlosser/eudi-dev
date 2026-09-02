# Current OIDF Wallet Conformance Results

These are the current local wallet conformance results for `eudi-dev`. Use [Running OIDF Wallet Conformance](./conformance-run.md) to reproduce or update them.

## Demo Issuer and Verifier (2026-08-31)

The demo issuer and demo verifier are tested with the suite playing the wallet. Use [the demo runbook](./conformance-run-demorp.md) to reproduce. Suite `release-v5.2.4` (revision `ab35a8d`), 9 plans (4 issuer, 5 verifier), 101 modules: **61 `PASSED`, 36 `REVIEW`, 4 `WARNING`, 0 `FAILED`, 0 `SKIPPED`**, 7645 condition successes against 0 condition failures.

The 36 `REVIEW` are every verifier module. The suite cannot observe whether the verifier under test verified, so its verifier modules end in `REVIEW` behind an uploaded screenshot. The harness reads the demo verifier's own verdict per module instead: 36 of 36 as expected, every tampered presentation refused, every clean one verified.

The 4 `WARNING` are one condition, four times: `CheckForUnexpectedParametersInServerMetadata` flags `client_attestation_pop_methods_supported` in the demo issuer's authorization server metadata as unknown. The parameter comes from the proof of possession methods registry of draft-ietf-oauth-attestation-based-client-auth-10, which the suite's RFC 8414 schema does not know (it knows the two signing algorithm parameters from the same document).

Suite defect in `release-v5.2.4`: under the pre-authorized code grant the client attestation negative modules keep running after their expected token refusal and interrupt themselves ("This is a bug in the test module"). Those six modules are excluded there and covered by the authorization code scenarios.

## Run of 2026-09-02 (expanded matrix and production certification)

Two records from the same day, both on suite `release-v5.2.4` (revision `ab35a8d`), after the ISO 18013-5 certificate profile work, the RFC 3986 request URI parsing, and the derived `response_uri` of the 2.3.0 release.

### Production certification run

The certifiable HAIP plans ran on `https://www.certification.openid.net/` against the hosted strict wallet at `https://strict.eudi-test.dev` (see [the runbook](./conformance-run.md)). 8 plans (4 VP HAIP, 4 VCI HAIP including `by_reference` offer delivery), 192 modules, complete and unfiltered: **zero wallet condition failures and zero warnings**. The only non passing entries:

- 2 modules `INTERRUPTED` by a suite defect: `oid4vp-1final-wallet-negative-test-invalid-client-id-prefix` under `request_uri_multisigned` throws a NullPointerException in the suite's own request construction (`AddInvalidClientIdPrefixToRequestObject` reads a `client_id` the multisigned sequence deliberately never puts into the shared payload). It dies before contacting the wallet, the identical configuration passes the same module in the signed entry, and it reproduces on a local suite build. Reported upstream.
- the negative modules end `REVIEW` behind an uploaded screenshot of the wallet's error, as designed.
- the deliberate mdoc `batch-credential-issuance` skips (single-proof rule of the key attestation appendices).

### Local full matrix

The expanded local matrix (76 plans: the full supported cross product of the alpha Final plans plus the HAIP plans) ran in one pass: 768 modules, 69411 condition successes against 4 condition failures and 26 warnings. Every one of the non clean entries is accounted for:

- the 4 condition failures are the two occurrences of the multisigned suite NullPointerException above
- the 26 warnings are the pre-fix IACA subject key identifier (this run's wallet binary was built minutes before the SHA-1 fix landed, the deployed build and the production run above are clean)
- one VCI module ended `INTERRUPTED` after a machine-load stall (the harness cancelled it so the run could continue, the same module passes in the neighbouring plans)
- 18 mdoc VCI plans carry the deliberate batch skips

New variants exercised for the first time in this matrix: `url_query`, `x509_san_dns`, `web-origin`, multisigned requests and the Browser API response modes in the Final plan, plus grant, offer delivery, issuance mode and encryption cross products in VCI. Two real wallet gaps surfaced and were fixed on the way: request URIs are now read with RFC 3986 semantics (an unencoded `+` in `dc+sd-jwt` survived as a plus), and an omitted `response_uri` is derived from a `redirect_uri` client id (OID4VP 1.0 §5.9.3).

## Baseline

- date: 2026-08-09 (previous: 2026-08-08 and 2026-08-07 on suite release-v5.2.1, 2026-08-05 and 2026-08-04 across 12 plans. And 2026-07-30, which did not exercise credential status. See below)
- wallet mode: strict
- suite server: local `https://localhost:8443/`
- suite baseline: `release-v5.2.2`, version `5.2.2`, revision `321bc5bc5`
- full run directory: `/tmp/oidf-wallet-conformance-local-strict`
- full runner log: `/tmp/oidf-wallet-conformance-local-strict/runner.log`
- full exported result archives: `/tmp/oidf-wallet-conformance-local-strict/results/`
- plan-detail screenshots: [`docs/conformance-results/2026-07-30/`](./conformance-results/2026-07-30/)

Command used:

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.2.2 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-local-strict \
  scripts/oidf-wallet-conformance.sh
```

The full matrix runs in one pass: 14 plans, 160 modules, 111 `PASSED`, 44 negative modules `REVIEW`, 5 `SKIPPED`, 0 `FAILED`, 16,305 condition successes against 1 condition failure. The skips and the condition failure are both accounted for below. The 2026-07-30 run reported comparable totals, but its credentials carried no status list, so the status-list conditions were skipped rather than passed.

## Run of 2026-08-27

First run on suite `release-v5.2.4` (version `5.2.4`, revision `ab35a8d`), strict mode, after the strict array disclosure and demo custom-request-builder work of the 2.1.0 release. The scenario set exported 12 plans and 116 modules: **49 `PASSED`, 43 negative modules `REVIEW`, 21 `WARNING`, 2 `SKIPPED`, 1 `FAILED`**. The SD-JWT VC flows (happy path, request_uri, request_uri_method=post, fewer claims, optional set, no claims) are clean. The warnings, the skip and the one failure are all mdoc, and are accounted for below.

The 21 `WARNING` modules all carry the same two conditions, both new in 5.2.4 (neither existed in 5.2.2), which validate the wallet's mdoc certificates against the ISO 18013-5 Annex B profile:

- `ValidateMdocDsCertificateProfile` on the document signer certificate (CN=EUDI Dev Wallet PID Provider): no countryName in the subject, no subject key identifier extension, no extended key usage extension (which must be present, critical, and name the document signing purpose), no CRL distribution points extension, no issuer alternative name extension.
- `ValidateMdocTrustAnchorIacaCertificateProfile` on the IACA trust anchor (CN=OID4VC Dev Wallet CA): no countryName in the subject, a subject key identifier that is not the SHA-1 of the subject public key, a basicConstraints pathLenConstraint of 1 where Table B.1 requires 0, no issuer alternative name extension.

These are real profile gaps in the wallet's mdoc certificate generation, surfaced (not caused) by the suite bump, and unrelated to the 2.1.0 disclosure change. They are advisory (`WARNING`, never `FAILURE`), so no module fails on them. The SD-JWT VC profile has no equivalent certificate profile, so its flows stay clean.

The 1 `FAILED` module is `oid4vp-1final-wallet-negative-test-unknown-transaction-data-type` in the HAIP mdoc direct_post.jwt plan. Its own assertion passed first: the wallet refused the unknown transaction_data type (the response carried `invalid_transaction_data`) and the module's `ExpectUnknownTransactionDataTypeErrorPage` resolved to `REVIEW`. The `FAILED` came after, from an unrelated second request_uri hitting the shared wallet, which the module counted as unexpected. Re-running that one plan returned the module to `REVIEW` with 0 condition failures, confirming the artifact. This is the shared-wallet sequencing family (the same negative module also `REVIEW`s in the plain plan). The 2 `SKIPPED` are the deliberate mdoc `batch-credential-issuance` skips described below.

On the question the metadata fix in this release answered: 5.2.4 still does not validate `wallet_metadata.response_types_supported`. The `request_uri_method=post` module parses the posted wallet metadata for JSON validity and to read the wallet nonce (`ExtractWalletMetadataAndNonceFromRequestUriPost`), stores it as `received_wallet_metadata`, and never reads it again, so the module `PASSED` without checking the field. The reference verifier that caught the omission checks what the suite does not.

The runner needed one fix for the current wallet: the `/api/credentials` listing now carries a `claim_count` rather than the claims, so `fetch_wallet_materials` reads the holder `cnf.jwk` from the per-credential detail (`/api/credentials/{id}`) instead.

## Run of 2026-08-24

Full matrix on suite `release-v5.2.2` (version `5.2.2`, revision `321bc5b`), strict mode, after the batch-issuance, deferred-issuance and credential-display UI work of the 2.0.0 release: **111 modules `PASSED`, 44 negative modules `REVIEW`, 5 `SKIPPED`, 0 `FAILED`**, 0 condition failures and 0 warnings across all 14 plans. The 5 skips are the same deliberate mdoc `batch-credential-issuance` skips described below, so the run exits non-zero on the expected skip artifact.

The batch change of this release (the wallet now requests the advertised batch, up to a ceiling of 8 proofs, rather than a fixed 2) is conformant: every SD-JWT `batch-credential-issuance` module still `PASSED` (plans 5, 7, 13), and the deferred-issuance modules pass. Run directory `/tmp/oidf-wallet-conformance-local-strict`.

## Run of 2026-08-04

Re-run against the same suite baseline (`release-v5.2.1`), with the server running on the host per [the runbook](./conformance-run.md):

**106 modules PASSED, 38 negative modules REVIEW, 0 FAILED**, across all 12 plans, with zero condition failures.

This run exercises credential status for the first time. Until now the tested configuration produced no status list at all: default PID generation was gated on `w.BaseURL != ""`, and the wrapper starts the wallet with only `--port`, so the credentials carried no `status` claim and the suite skipped `FetchStatusListToken` and everything after it. Once the gate became `StatusListURL() != ""` (which falls back to the always-derived issuer URL), those conditions started running and surfaced two defects that had never been exercised:

- the status list token carried the self-signed trust anchor inside its `x5c` chain, which HAIP 6.1 rejects ("Trust anchor certificate must not be included in x5c chain"). 14 modules
- the token offered no key-resolution route the Final (non-HAIP) plans accept: that branch verifies with a `jwk` embedded in the header or with `server_jwks`, and `server_jwks` is unreachable in these plans. 17 modules

Both are fixed. The token now strips the trust anchor from `x5c` and additionally embeds the signing key as a `jwk` header, derived from the signing key so it cannot disagree with the `x5c` leaf. `x5c` remains the anchored route that HAIP validates. `jwk` is the convenience route, permitted because Token Status List §5.1 requires only `typ` and `jwk` is a registered JOSE header (RFC 7515 §4.1.3).

## Run of 2026-08-05

Re-run for the 1.19.2 release against the same suite baseline, after the browser hardening and the authorization code flow changes: **106 modules PASSED, 38 negative modules REVIEW, 0 FAILED**, 13,951 condition successes with 0 failures and 0 warnings across all 12 plans. Same totals as 2026-08-04, so neither the stricter `redirect_uri` scheme check nor the reworked authorization code flow moved conformance. The suite drives the authorization endpoint through redirects, so it never takes the interactive-login branch the demo issuer uses.

## Run of 2026-08-07

Re-run for the 1.19.19 release against the same suite baseline, after the conformance work of 1.19.18 and 1.19.19: **114 modules PASSED, 38 negative modules REVIEW, 2 SKIPPED, 0 FAILED**, 15,228 condition successes with 0 failures and 0 warnings across 14 plans.

The matrix is 14 plans rather than 12: the pre-authorized code flow is now covered for both credential formats (plans 7 and 8).

The 2 `SKIPPED` modules are `credential-issuance-notification` in the `vci_credential_issuance_mode=deferred` variant of the two VCI HAIP plans. The suite exits non-zero on an unexpected skip even with no failures, so a run reporting these ends with status 1.

These figures cover the 5 mdoc `batch-credential-issuance` modules as `PASSED`. They are `SKIPPED` under the single-proof rule the key attestation appendices carry (see below), which puts the current expectation at 109 `PASSED` and 7 `SKIPPED`, pending a re-run.

## Run of 2026-08-08

Full matrix for the 1.19.22 release, suite pinned to `release-v5.2.1` to match the running server: **110 modules PASSED, 38 negative modules REVIEW, 5 SKIPPED, 1 FAILED**, 15,404 condition successes across 14 plans, with no watchdog termination.

Runs need `EUDI_REMOTE_TIMEOUT` to complete. The suite shares this machine with the wallet and pauses under load, and at the wallet's 15 second default a request it would normally answer at once times out, which ends that module's exchange and cannot be resumed. The wrapper sets `120s`, and this run recorded 6 such pauses (visible as `[monitor] failed to monitor module`) and completed through all of them. Runs before that setting existed died partway with `context deadline exceeded`.

The 5 `SKIPPED` are the mdoc `batch-credential-issuance` modules, which is deliberate (see below).

The 1 `FAILED` is `oid4vci-1_0-wallet-test-credential-issuance-notification` on `VCIVerifyIssuerStateInAuthorizationRequest`, and it is an artifact of two modules overlapping rather than anything the wallet did. The module logs the check twice: the first authorization request carries the `issuer_state` of the offer under test and passes, and a second one 18 seconds later carries the `issuer_state` of a later offer, which the module is still comparing against the first. The wallet echoed the value each offer gave it, which is what OID4VCI 1.0 §5.1.3 asks of it. Expect this and the flake below to move between runs.

## Run of 2026-08-09

Full matrix on suite `release-v5.2.2`, the first run on that release: **111 modules PASSED, 44 negative modules REVIEW, 5 SKIPPED, 0 FAILED**, 16,305 condition successes across 14 plans and 160 modules, with no watchdog termination through 11 suite pauses.

The matrix is 160 modules rather than 154 because `oid4vp-1final-wallet-negative-test-invalid-client-id-prefix` is back in 6 VP plans (REVIEW in all): release-v5.2.2 fixed the module (upstream `4f790f161`, placeholder established before WAITING). It stays out of the DC API plans only, per its own `@VariantNotApplicableWhen`: an unsigned DC API request carries no `client_id` to corrupt (OID4VP 1.0 Appendix A.2).

Release-v5.2.2 also reworked `alternate-happy-flow` to plant a decoy origin in an unsigned DC API request's `expected_origins` and check the wallet ignores it. That exposed a defect in this harness, not the wallet: the monitor built the `Origin` header of its stand-in browser POST from the request content, so it impersonated the decoy and the wallet honoured its caller. The monitor now derives the origin from the submit URL, where the suite actually serves the page, which is what a real browser does.

The 1 condition failure sits in a module that still finished `PASSED`: a suite pause made the monitor retry an offer submission, the wallet ran the flow twice, and `ValidateAuthorizationCode` compared the code of one flow against the other. The same retry artifact family as the 2026-08-08 `issuer_state` failure. Release-v5.2.2 retired the `RequestUriFetchedMoreThanOnce` symptom of this family upstream (`a05a0e298`: multi-fetch no longer fails a wallet), so the note below is historical.

### Flaky module to expect

`RequestUriFetchedMoreThanOnce` can fail spuriously. `submit_wallet_request` retries a submission up to five times after a transient HTTP 502, and each submission makes the wallet fetch the `request_uri` once, so a retry produces a second fetch that the suite flags. It appeared once in an earlier run of this same code on a loaded machine and did not reproduce on a quiet one. Re-run before treating it as a defect.

## New release-v5.2.1 Coverage

Release-v5.2.1 added two wallet test modules. Both are implemented by the wallet and pass:

- `oid4vci-1_0-wallet-test-batch-credential-issuance`: the emulated issuer advertises `batch_credential_issuance` with `batch_size: 10` and returns the issued credentials in reverse proof order. The wallet requests the advertised batch (one proof per copy, capped at its own ceiling of 8) with distinct, freshly generated keys and identifies the holder-key-bound credential from the credential itself (`cnf.jwk` for SD-JWT, MSO `deviceKey` for mdoc). It passes in the SD-JWT plans.

  The 5 mdoc variants are `SKIPPED`. Those plans request `eu.europa.ec.eudi.pid.mdoc.1.jwt.keyattest`, a configuration requiring key attestations, and there the wallet sends a single proof, which the module skips as "batch behavior cannot be evaluated". Appendix F.1 and F.3 both put the batch count on the attestation rather than the proofs, so where an attestation is required the request holds one proof and the issuer issues for each key in `attested_keys`. The suite's credential builder counts `proof_jwts` for the `jwt` proof type and reads `attested_keys` only for the `attestation` proof type, so this module expects a shape an issuer applying those appendices answers `invalid_proof` to.
- `oid4vp-1final-wallet-ignores-unusable-encryption-key`: the verifier's `client_metadata.jwks` advertises two unusable keys (a post-quantum-shaped `kty: AKP` key and a made-up `kty`) alongside the usable key. The wallet ignores keys it cannot use per RFC 7517 §5 and encrypts to the usable key. Passes in all encrypted response mode variants (plans 2, 4, 9, 10, 11, 12).

Release-v5.2.1 also enforces RFC 8414 §3.1 on the wallet's OAuth authorization server metadata request: the wallet now strips the issuer's terminating `/` before inserting `/.well-known/oauth-authorization-server`, while continuing to preserve the Credential Issuer Identifier path verbatim for `/.well-known/openid-credential-issuer` per OID4VCI 1.0 §12.2.2.

## Result Classification

- `PASSED` is green.
- `REVIEW` is pass-equivalent for this local harness when the runner summary shows `FINISHED`, `REVIEW`, and `0 FAILURE`. These modules are negative tests where the wallet rejects the request and the harness uploads the required screenshot placeholder.
- `INTERRUPTED` is not pass-equivalent. The current selected matrix has no `INTERRUPTED` modules.

## Matrix

Condition counts are from the 2026-08-09 run on suite release-v5.2.2. The screenshots are the plan-detail pages of the 2026-07-30 12-plan run, so they are linked against the plan they depict rather than the row number, and the two pre-authorized code plans have none.

| # | Plan | Variant | Current result | Screenshot |
|---|---|---|---|---|
| 1 | VP Final | SD-JWT, `direct_post`, signed `x509_hash` | 507 success / 0 failure. `REVIEW` negative modules are pass-equivalent. | [PNG](./conformance-results/2026-07-30/plan-01-vp-final-sdjwt-direct-post.png) |
| 2 | VP Final | SD-JWT, `direct_post.jwt`, signed `x509_hash` | 711 success / 0 failure. Includes `ignores-unusable-encryption-key`. | [PNG](./conformance-results/2026-07-30/plan-02-vp-final-sdjwt-direct-post-jwt.png) |
| 3 | VP Final | SD-JWT, `direct_post`, unsigned `redirect_uri` | 507 success / 0 failure. `response-uri-not-client-id` finishes as pass-equivalent `REVIEW`. | [PNG](./conformance-results/2026-07-30/plan-03-vp-final-sdjwt-unsigned-direct-post.png) |
| 4 | VP Final | mDoc, `direct_post.jwt`, signed `x509_hash` | 592 success / 0 failure. Includes `ignores-unusable-encryption-key`. | [PNG](./conformance-results/2026-07-30/plan-04-vp-final-mdoc-direct-post-jwt.png) |
| 5 | VCI Final | SD-JWT | 1021 success / 0 failure. Includes batch credential issuance. | [PNG](./conformance-results/2026-07-30/plan-05-vci-final-sdjwt.png) |
| 6 | VCI Final | mDoc | 1055 success / 0 failure. Batch credential issuance is `SKIPPED` here, see below. | [PNG](./conformance-results/2026-07-30/plan-06-vci-final-mdoc.png) |
| 7 | VCI Final | SD-JWT, pre-authorized code | 665 success / 0 failure. | (added after the screenshot run) |
| 8 | VCI Final | mDoc, pre-authorized code | 671 success / 0 failure. Batch credential issuance is `SKIPPED` here, see below. | (added after the screenshot run) |
| 9 | VP HAIP | SD-JWT, `direct_post.jwt` | 751 success / 0 failure. Includes `ignores-unusable-encryption-key`. | [PNG](./conformance-results/2026-07-30/plan-07-vp-haip-sdjwt-direct-post-jwt.png) |
| 10 | VP HAIP | mDoc, `direct_post.jwt` | 625 success / 0 failure. Includes `ignores-unusable-encryption-key`. | [PNG](./conformance-results/2026-07-30/plan-08-vp-haip-mdoc-direct-post-jwt.png) |
| 11 | VP HAIP | SD-JWT, `dc_api.jwt` | 579 success / 0 failure. Includes `ignores-unusable-encryption-key`. | [PNG](./conformance-results/2026-07-30/plan-09-vp-haip-sdjwt-dc-api-jwt.png) |
| 12 | VP HAIP | mDoc, `dc_api.jwt` | 399 success / 0 failure. Includes `ignores-unusable-encryption-key`. | [PNG](./conformance-results/2026-07-30/plan-10-vp-haip-mdoc-dc-api-jwt.png) |
| 13 | VCI HAIP | SD-JWT | 3978 success / 0 failure. Batch issuance passes in immediate, deferred, and encrypted variants. | [PNG](./conformance-results/2026-07-30/plan-11-vci-haip-sdjwt.png) |
| 14 | VCI HAIP | mDoc | 4244 success / 1 failure. Batch issuance is `SKIPPED` in all three variants, see below. The 1 failure is the retried-submission artifact described above. The module finished `PASSED`. | [PNG](./conformance-results/2026-07-30/plan-12-vci-haip-mdoc.png) |

## Passing VCI Coverage

- VCI Final SD-JWT and mDoc issuer-initiated authorization-code flows pass. The SD-JWT plan includes the batch credential issuance module (the mdoc batch modules are the deliberate skips described above).
- VCI Final SD-JWT and mDoc pre-authorized code flows pass, including the notification endpoint and, for SD-JWT, batch issuance.
- VCI HAIP SD-JWT and mDoc pass for plain immediate issuance, deferred issuance, encrypted credential request variants, FAPI happy-path modules, and FAPI negative authorization-response modules, plus batch issuance for SD-JWT.
- Strict mode rejects issuer mismatch in authorization server metadata, invalid authorization-response `iss`, removed authorization-response `iss`, invalid `state`, and missing `state`.

## Debug Mode Reference Run

The documented matrix above runs the wallet in `strict` mode. A full reference run with `OIDF_WALLET_MODE=debug` (2026-07-31, same suite baseline, run directory `/tmp/oidf-wallet-conformance-local-debug`) shows exactly which coverage depends on strict-mode enforcement:

- 38 negative modules fail in debug mode because the wallet logs the violation and continues instead of rejecting:
  - every VP plan: `invalid-request-object-signature` (signed variants), `missing-nonce`, `unknown-transaction-data-type`, plus `redirect-uri-with-direct-post` (redirect variants) and `response-uri-not-client-id` (plan 3)
  - both VCI HAIP plans: FAPI `discovery-issuer-mismatch`, `invalid-authorization-response-iss`, `remove-authorization-response-iss`, and `missing-state`
- Everything else still passes: all positive modules, both VCI Final plans in full, and the negative checks that are not mode-gated (`mismatched-client-id`, `wrong-expected-origins`, FAPI `invalid-state`).

Debug mode is for troubleshooting verifier and issuer integrations. Only strict-mode runs count as conformance results.

## VP Module Selection

The current wrapper passes explicit module lists for VP plans instead of relying on release-v5.2.1 `VariantNotApplicable` filtering. This keeps the local result pages focused on executable coverage for each generated variant.

Known release-v5.2.1 suite-side exclusions:

- `invalid-client-id-prefix` runs everywhere except the DC API plans, whose unsigned requests carry no `client_id` to corrupt (the module's own `@VariantNotApplicableWhen`). It was excluded entirely on release-v5.2.1, whose `performRedirect()` ordering bug killed the module before the wallet was invoked, and release-v5.2.2 fixed that (`4f790f161`).
- VP Final `direct_post` omits `alternate-happy-flow` because that module unconditionally replaces encrypted-response setup that is absent for plain `direct_post` (unchanged from release-v5.1.44).
- VP Final x509 variants omit `response-uri-not-client-id`. The suite marks that module not applicable for `x509_hash`, and the applicable `redirect_uri` variant passes as `REVIEW`.
- VP Final non-multisigned variants omit `multisigned-one-invalid-signature`.
- VP unencrypted variants (`direct_post`, `dc_api`) omit `ignores-unusable-encryption-key` per the module's `@VariantNotApplicable`. The unencrypted modes never advertise an encryption key.

Current `no-claims-in-dcql-query` status:

- VP Final SD-JWT `no-claims-in-dcql-query` passes for plans 1, 2, and 3.
- VP Final mDoc `no-claims-in-dcql-query` passes for plan 4.
- VP HAIP SD-JWT `no-claims-in-dcql-query` passes for plans 9 and 11.
- VP HAIP mDoc `no-claims-in-dcql-query` passes for plans 10 and 12.

## Visual Evidence

These screenshots are the local OIDF `plan-detail.html` pages from the current documented runs. They preserve the suite's green, review, and not-run status boxes.

<details>
<summary>Plan 1: VP Final SD-JWT direct_post</summary>

![Plan 1 VP Final SD-JWT direct_post](./conformance-results/2026-07-30/plan-01-vp-final-sdjwt-direct-post.png)

</details>

<details>
<summary>Plan 2: VP Final SD-JWT direct_post.jwt</summary>

![Plan 2 VP Final SD-JWT direct_post.jwt](./conformance-results/2026-07-30/plan-02-vp-final-sdjwt-direct-post-jwt.png)

</details>

<details>
<summary>Plan 3: VP Final SD-JWT unsigned direct_post</summary>

![Plan 3 VP Final SD-JWT unsigned direct_post](./conformance-results/2026-07-30/plan-03-vp-final-sdjwt-unsigned-direct-post.png)

</details>

<details>
<summary>Plan 4: VP Final mDoc direct_post.jwt</summary>

![Plan 4 VP Final mDoc direct_post.jwt](./conformance-results/2026-07-30/plan-04-vp-final-mdoc-direct-post-jwt.png)

</details>

<details>
<summary>Plan 5: VCI Final SD-JWT</summary>

![Plan 5 VCI Final SD-JWT](./conformance-results/2026-07-30/plan-05-vci-final-sdjwt.png)

</details>

<details>
<summary>Plan 6: VCI Final mDoc</summary>

![Plan 6 VCI Final mDoc](./conformance-results/2026-07-30/plan-06-vci-final-mdoc.png)

</details>

<details>
<summary>Plan 7: VP HAIP SD-JWT direct_post.jwt</summary>

![Plan 7 VP HAIP SD-JWT direct_post.jwt](./conformance-results/2026-07-30/plan-07-vp-haip-sdjwt-direct-post-jwt.png)

</details>

<details>
<summary>Plan 8: VP HAIP mDoc direct_post.jwt</summary>

![Plan 8 VP HAIP mDoc direct_post.jwt](./conformance-results/2026-07-30/plan-08-vp-haip-mdoc-direct-post-jwt.png)

</details>

<details>
<summary>Plan 9: VP HAIP SD-JWT dc_api.jwt</summary>

![Plan 9 VP HAIP SD-JWT dc_api.jwt](./conformance-results/2026-07-30/plan-09-vp-haip-sdjwt-dc-api-jwt.png)

</details>

<details>
<summary>Plan 10: VP HAIP mDoc dc_api.jwt</summary>

![Plan 10 VP HAIP mDoc dc_api.jwt](./conformance-results/2026-07-30/plan-10-vp-haip-mdoc-dc-api-jwt.png)

</details>

<details>
<summary>Plan 11: VCI HAIP SD-JWT</summary>

![Plan 11 VCI HAIP SD-JWT](./conformance-results/2026-07-30/plan-11-vci-haip-sdjwt.png)

</details>

<details>
<summary>Plan 12: VCI HAIP mDoc</summary>

![Plan 12 VCI HAIP mDoc](./conformance-results/2026-07-30/plan-12-vci-haip-mdoc.png)

</details>

## Result Inspection

Use this query to summarize important runner lines from a run:

```bash
rg -n \
  "Results for \\[[0-9]+\\]|Overall totals|\\*\\* SOME TEST|\\*\\* Exiting|INTERRUPTED|result .*FAILED|result .*REVIEW|no-claims-in-dcql-query|batch-credential-issuance|ignores-unusable-encryption-key" \
  "$OIDF_RUN_DIR/runner.log"
```

Use the printed `plan-detail.html?plan=...` URLs from `runner.log` to inspect module details in the local suite UI.

## Update Rules

When the wallet or suite baseline changes:

- rerun the full matrix unless the change is clearly limited to a documented targeted rerun
- preserve all previously passing conformance coverage
- update the baseline tag, suite revision, run directory, runner log, and exported artifact location
- update the matrix, suite-side exclusions, and screenshots in this file
- keep suite-side exclusions visible until the upstream suite behavior changes
