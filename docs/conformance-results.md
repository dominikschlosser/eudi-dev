# Current OIDF Wallet Conformance Results

These are the current documented local wallet conformance results for `oid4vc-dev`. Use [Running OIDF Wallet Conformance](./conformance-run.md) to reproduce or update them.

## Baseline

- date: 2026-06-05
- wallet mode: strict
- suite server: local `https://localhost:8443/`
- suite baseline: `release-v5.1.44`, version `5.1.44`, revision `f326f6a`
- full run directory: `/tmp/oidf-wallet-conformance-final`
- full runner log: `/tmp/oidf-wallet-conformance-final/runner.log`
- targeted rerun directory: `/tmp/oidf-wallet-conformance-rerun-failed`
- targeted rerun log: `/tmp/oidf-wallet-conformance-rerun-failed/runner.log`

Full matrix command:

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.1.44 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-final \
  scripts/oidf-wallet-conformance.sh
```

Targeted rerun command used for the current VP failure classification:

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.1.44 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-rerun-failed \
  scripts/oidf-wallet-conformance.sh --rerun \
  '1:2,1:6,1:7,1:9,2:6,2:7,2:9,3:2,3:6,3:8,4:7,4:9,7:6,9:5,9:7,9:13,9:23,9:28,10:7,10:28'
```

The commands exit `1` because VP plans still contain unexpected suite interruptions. VCI wallet coverage is green.

## Matrix

| # | Plan | Variant | Current result |
|---|---|---|---|
| 1 | VP Final | SD-JWT, `direct_post`, signed `x509_hash` | `no-claims-in-dcql-query` passes; 3 suite interruptions remain |
| 2 | VP Final | SD-JWT, `direct_post.jwt`, signed `x509_hash` | `no-claims-in-dcql-query` passes; 2 suite interruptions remain |
| 3 | VP Final | SD-JWT, `direct_post`, unsigned `redirect_uri` | `no-claims-in-dcql-query` passes; 2 suite interruptions remain |
| 4 | VP Final | mDoc, `direct_post.jwt`, signed `x509_hash` | `no-claims-in-dcql-query` passes; 2 suite interruptions remain |
| 5 | VCI Final | SD-JWT | 775 success / 0 failure |
| 6 | VCI Final | mDoc | 803 success / 0 failure |
| 7 | VP HAIP | SD-JWT, `direct_post.jwt` | `no-claims-in-dcql-query` passes; 0 rerun failures |
| 8 | VP HAIP | mDoc, `direct_post.jwt` | full run passed; 0 failure |
| 9 | VP HAIP | SD-JWT, `dc_api.jwt` | `no-claims-in-dcql-query` passes; 2 invalid-client-prefix modules still interrupt |
| 10 | VP HAIP | mDoc, `dc_api.jwt` | 2 invalid-client-prefix modules still interrupt |
| 11 | VCI HAIP | SD-JWT | 3181 success / 0 failure |
| 12 | VCI HAIP | mDoc | 3262 success / 0 failure |

## Passing VCI Coverage

Current VCI pass coverage:

- VCI Final SD-JWT and mDoc issuer-initiated authorization-code flows pass.
- VCI HAIP SD-JWT and mDoc pass for plain immediate issuance, deferred issuance, encrypted credential request variants, FAPI happy-path modules, and FAPI negative authorization-response modules.
- Strict mode rejects issuer mismatch in authorization server metadata, invalid authorization-response `iss`, removed authorization-response `iss`, invalid `state`, and missing `state`.

## Current VP Gaps

Remaining failures are VP-only:

- Some VP Final variants still interrupt in the suite:
  - `oid4vp-1final-wallet-alternate-happy-flow` for plain `direct_post`
  - `oid4vp-1final-wallet-negative-test-response-uri-not-client-id` for selected signed `x509_hash` variants
  - `oid4vp-1final-wallet-multisigned-one-invalid-signature` in non-multisigned plan variants
- HAIP Browser API `dc_api.jwt` still has `invalid-client-id-prefix` failures for selected variants.

Current `no-claims-in-dcql-query` status:

- VP Final SD-JWT `no-claims-in-dcql-query` passes for plans 1, 2, and 3.
- VP HAIP SD-JWT `no-claims-in-dcql-query` passes for plans 7 and 9.
- VP Final and HAIP mDoc `no-claims-in-dcql-query` passes.

## Result Inspection

Use this query to summarize important runner lines from a run:

```bash
rg -n \
  "Results for \\[[0-9]+\\]|Overall totals|\\*\\* SOME TEST|\\*\\* Exiting|no-claims-in-dcql-query|invalid-client-id-prefix" \
  "$OIDF_RUN_DIR/runner.log"
```

Use the printed `plan-detail.html?plan=...` URLs from `runner.log` to inspect module details in the local suite UI.

## Update Rules

When the wallet or suite baseline changes:

- rerun the full matrix unless the change is clearly limited to a documented targeted rerun
- preserve all previously passing conformance coverage
- update the baseline tag, suite revision, run directories, and runner logs
- update the matrix and current gaps in this file
- keep known failures visible until the wallet harness gains the missing functionality or the upstream suite behavior changes
