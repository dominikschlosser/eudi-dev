# Current OIDF Wallet Conformance Results

These are the current local wallet conformance results for `eudi-dev`. Use [Running OIDF Wallet Conformance](./conformance-run.md) to reproduce or update them.

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
