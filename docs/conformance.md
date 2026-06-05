# OIDF Conformance

This repository can run the current OpenID Foundation wallet plans for OID4VP 1.0 Final, OID4VCI 1.0 Final, and the current HAIP wallet variants against the local wallet implementation.

The wrapper uses the current Final wallet plans plus the current HAIP wallet plans against a locally running OpenID Foundation conformance-suite server by default:

- `oid4vp-1final-wallet-test-plan`
- `oid4vci-1_0-wallet-test-plan`
- `oid4vp-1final-wallet-haip-test-plan`
- `oid4vci-1_0-wallet-haip-test-plan`

It does not use the older ID3 wallet plan, and it does not add suite-specific behavior to the wallet. The runner adapts the OIDF config to the wallet's normal keys, CA, credentials, and HTTPS issuer metadata.

## What the wrapper does

[`scripts/oidf-wallet-conformance.sh`](/Users/dominik/projects/oid4vc-dev/scripts/oidf-wallet-conformance.sh):

- defaults to `CONFORMANCE_MODE=local`
- targets `https://localhost:8443/` and `https://localhost:8444/` for the local suite and mTLS endpoints
- downloads the latest upstream conformance-suite release tarball from GitLab, unless `OIDF_SUITE_DIR` or `OIDF_SUITE_URL` is set
- checks the local suite `/api/server` tag when available and fails early if the running server does not match the runner/templates release
- creates a Python virtualenv for the official runner
- starts `oid4vc-dev wallet serve` in strict mode with default PID credentials
- configures the wallet's normal OID4VCI authorization-code client settings
- runs the official `run-test-plan.py` against the local conformance-suite server
- forwards `--rerun` to the official runner for targeted plan/module reruns

[`scripts/oidf_wallet_conformance.py`](/Users/dominik/projects/oid4vc-dev/scripts/oidf_wallet_conformance.py):

- verifies the extracted suite contains the current Final wallet plans and templates
- reads the wallet's holder binding key from `/api/credentials`
- reads the wallet's issuer signing JWK from `/.well-known/jwt-vc-issuer`
- uses the shared wallet CA as the attestation and trust anchor PEM
- generates per-scenario OIDF config files from the upstream templates
- keeps the VCI suite alias aligned with the configured `redirect_uri` / helper-page paths
- disables the suite's VCI browser helper page and drives the same offer URL directly through the wallet API
- drives Browser API `dc_api` / `dc_api.jwt` presentation requests through the wallet's `/api/dc-api` endpoint
- enables HAIP enforcement only for HAIP VP modules, while keeping the Final VP modules in strict non-HAIP mode
- monitors waiting modules and automatically:
  - submits presentation requests to `/api/presentations`
  - executes Browser API presentation requests from `browser.browserApiRequests`
  - submits credential offers to `/api/offers`
  - follows returned verifier `redirect_uri` values
  - uploads placeholder screenshots for negative-review modules
- prints the created local `plan-detail.html?plan=...` URLs

## Default Matrix

The default run covers the current Final and HAIP scenarios tracked by this wallet harness:

- VP Final: SD-JWT `direct_post`, signed `request_uri`, `x509_hash`
- VP Final: SD-JWT `direct_post.jwt`, signed `request_uri`, `x509_hash`
- VP Final: SD-JWT `direct_post`, unsigned `request_uri`, `redirect_uri`
- VP Final: mDoc `direct_post.jwt`, signed `request_uri`, `x509_hash`
- VP HAIP: SD-JWT `direct_post.jwt`
- VP HAIP: mDoc `direct_post.jwt`
- VP HAIP: SD-JWT `dc_api.jwt` plan, covering both unsigned `web-origin` and signed `x509_san_dns` Browser API modules
- VP HAIP: mDoc `dc_api.jwt` plan, covering both unsigned `web-origin` and signed `x509_san_dns` Browser API modules
- VCI Final: SD-JWT authorization-code issuer-initiated flow with client attestation + DPoP
- VCI Final: mDoc authorization-code issuer-initiated flow with client attestation + DPoP
- VCI HAIP: SD-JWT plan, covering immediate plain, deferred plain, and immediate encrypted responses
- VCI HAIP: mDoc plan, covering immediate plain, deferred plain, and immediate encrypted responses

Those runs are fixed in the wrapper. There is no plan selector and no ID3 fallback.

## Prerequisites

Start a recent local OIDF conformance-suite checkout first. The expected baseline for this document is the latest release available when this workflow was updated, `release-v5.1.44` from 2026-06-04, or a newer release when intentionally updating the baseline.

```bash
cd ../conformance-suite
git fetch --tags
git checkout release-v5.1.44
mvn clean package
```

The wrapper defaults to plain `localhost` URLs. The upstream dev compose files currently advertise `localhost.emobix.co.uk`, so add a local compose override when running this wallet conformance flow:

```bash
cat >/tmp/conformance-suite-localhost.override.yml <<'YAML'
services:
  server:
    command: >
      java
      -Xdebug -Xrunjdwp:transport=dt_socket,address=*:9999,server=y,suspend=n
      -jar /server/fapi-test-suite.jar
      -Djdk.tls.maxHandshakeMessageSize=65536
      --fintechlabs.base_url=https://localhost:8443
      --fintechlabs.base_mtls_url=https://localhost:8444
      --fintechlabs.devmode=true
      --fintechlabs.startredir=true
YAML

docker compose \
  -f docker-compose-dev-mac.yml \
  -f /tmp/conformance-suite-localhost.override.yml \
  up --detach
```

The local suite must advertise the same host in generated authorization, callback, and helper URLs:

- `CONFORMANCE_SERVER=https://localhost:8443/`
- `CONFORMANCE_SERVER_LOCAL=https://localhost:8443/`
- `CONFORMANCE_SERVER_MTLS=https://localhost:8444/`

Check the running suite before starting the wallet run:

```bash
curl -k https://localhost:8443/api/server
```

For the June 5, 2026 baseline this returned:

```json
{"tag":"release-v5.1.44","version":"5.1.44","revision":"f326f6a"}
```

You also need:

- `python3`
- `curl`
- `go`
- a reachable local conformance-suite server

## Running it

```bash
scripts/oidf-wallet-conformance.sh
```

To keep the artifacts in a stable location:

```bash
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-local-strict \
  scripts/oidf-wallet-conformance.sh
```

To force the wrapper to use the same checkout as the running local server:

```bash
OIDF_SUITE_DIR=/Users/dominik/projects/conformance-suite \
OIDF_SUITE_TAG=release-v5.1.44 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-local-strict \
  scripts/oidf-wallet-conformance.sh
```

To rerun only specific failed plans or modules, pass the official runner selector through the wrapper:

```bash
OIDF_SUITE_DIR=/Users/dominik/projects/conformance-suite \
OIDF_SUITE_TAG=release-v5.1.44 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-rerun-failed \
  scripts/oidf-wallet-conformance.sh --rerun '1:6,2:6'
```

The selector syntax is the same as `run-test-plan.py`: `2` reruns plan 2, `2:6` reruns one module, and `1:6,2:6` reruns multiple modules. The harness still generates all configs so the official runner keeps the same plan numbering, but it filters execution to the requested plans/modules.

Useful environment overrides:

- `CONFORMANCE_MODE`: `local` by default; use `hosted` only when intentionally running against the OIDF hosted service
- `CONFORMANCE_SERVER`: local conformance-suite base URL; defaults to `https://localhost:8443/`
- `CONFORMANCE_SERVER_LOCAL`: local callback/helper base URL; defaults to `CONFORMANCE_SERVER`
- `CONFORMANCE_SERVER_MTLS`: local mTLS base URL; defaults to `https://localhost:8444/`
- `PORT`: wallet port; defaults to a free local port
- `OIDF_RUN_DIR`: keep all runner artifacts in a chosen directory instead of a temp dir
- `OIDF_SUITE_DIR`: use an existing conformance-suite checkout for runner/templates instead of downloading the latest release archive
- `OIDF_SUITE_TAG`: expected conformance-suite tag when `OIDF_SUITE_DIR` or `OIDF_SUITE_URL` is used
- `OIDF_WALLET_DIR`: reuse a specific wallet store
- `OIDF_WALLET_ISSUER_URL`: override the wallet HTTPS issuer URL if needed
- `OIDF_WALLET_CA_CERT`: override the shared wallet CA PEM path
- `OIDF_VCI_CLIENT_ID`: override the configured OID4VCI client ID
- `OIDF_VCI_REDIRECT_URI`: override the configured OID4VCI redirect URI
- `OIDF_VCI_ALIAS`: convenience alias used by the default `OIDF_VCI_REDIRECT_URI`
- `OIDF_SUITE_URL`: override the suite tarball URL; defaults to the latest upstream release archive
- `OIDF_MODULE_IDLE_TIMEOUT`: seconds without `run-test-plan.py` output before the wrapper terminates a stuck module; defaults to `180`, set `0` to disable

For the hosted OIDF service only:

- `CONFORMANCE_MODE=hosted`
- `OIDF_TOKEN` in `.env` or `CONFORMANCE_TOKEN` in the environment

The script prints the run directory and leaves behind:

- wallet log
- mirrored official runner log
- exported OIDF result archives
- generated OIDF config files

With the current `release-v5.1.44` baseline, the command exits nonzero because VP plans still contain unexpected failures. VCI Final and HAIP VCI plans pass in strict mode.

## Hosted OIDF Results

Hosted mode creates private plans on the OIDF service. It does not:

- delete plans
- publish plans
- create certification packages

If you do not see hosted-mode runs on the public OIDF pages, that is expected. Use the printed `plan-detail.html?plan=...` URLs, and make sure you are signed into the same OIDF account that owns the bearer token.

## Current Local Results

Latest checked run:

- date: 2026-06-05
- wallet mode: strict
- suite server: local `https://localhost:8443/`
- suite baseline: `release-v5.1.44`, version `5.1.44`, revision `f326f6a`
- full run directory: `/tmp/oidf-wallet-conformance-final`
- full runner log: `/tmp/oidf-wallet-conformance-final/runner.log`
- targeted rerun directory: `/tmp/oidf-wallet-conformance-rerun-failed`
- targeted rerun log: `/tmp/oidf-wallet-conformance-rerun-failed/runner.log`

Full run command:

```bash
OIDF_SUITE_DIR=/Users/dominik/projects/conformance-suite \
OIDF_SUITE_TAG=release-v5.1.44 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-final \
  scripts/oidf-wallet-conformance.sh
```

Targeted rerun command after fixing SD-JWT zero-disclosure serialization:

```bash
OIDF_SUITE_DIR=/Users/dominik/projects/conformance-suite \
OIDF_SUITE_TAG=release-v5.1.44 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-rerun-failed \
  scripts/oidf-wallet-conformance.sh --rerun \
  '1:2,1:6,1:7,1:9,2:6,2:7,2:9,3:2,3:6,3:8,4:7,4:9,7:6,9:5,9:7,9:13,9:23,9:28,10:7,10:28'
```

The commands exit `1` because VP plans still contain unexpected suite interruptions. VCI wallet coverage is green, including Final VCI, HAIP VCI, encrypted credential request variants, and embedded FAPI 2 authorization-response negative tests. The targeted rerun confirms the wallet-side SD-JWT no-claims failures are fixed.

| # | Plan | Variant | Result |
|---|---|---|---|
| 1 | VP Final | SD-JWT, `direct_post`, signed `x509_hash` | no-claims now passes; 3 suite interruptions remain |
| 2 | VP Final | SD-JWT, `direct_post.jwt`, signed `x509_hash` | no-claims now passes; 2 suite interruptions remain |
| 3 | VP Final | SD-JWT, `direct_post`, unsigned `redirect_uri` | no-claims now passes; 2 suite interruptions remain |
| 4 | VP Final | mDoc, `direct_post.jwt`, signed `x509_hash` | no-claims passes; 2 suite interruptions remain |
| 5 | VCI Final | SD-JWT | 775 success / 0 failure |
| 6 | VCI Final | mDoc | 803 success / 0 failure |
| 7 | VP HAIP | SD-JWT, `direct_post.jwt` | no-claims now passes; 0 rerun failures |
| 8 | VP HAIP | mDoc, `direct_post.jwt` | full run passed; 0 failure |
| 9 | VP HAIP | SD-JWT, `dc_api.jwt` | no-claims now passes; 2 invalid-client-prefix modules still interrupt |
| 10 | VP HAIP | mDoc, `dc_api.jwt` | 2 invalid-client-prefix modules still interrupt |
| 11 | VCI HAIP | SD-JWT | 3181 success / 0 failure |
| 12 | VCI HAIP | mDoc | 3262 success / 0 failure |

Current VCI pass coverage:

- VCI Final SD-JWT and mDoc issuer-initiated authorization-code flows pass.
- VCI HAIP SD-JWT and mDoc pass for plain immediate issuance, deferred issuance, encrypted credential request variants, FAPI happy-path modules, and FAPI negative authorization-response modules.
- Strict mode rejects issuer mismatch in authorization server metadata, invalid authorization-response `iss`, removed authorization-response `iss`, invalid `state`, and missing `state`.

Targeted rerun fixes confirmed:

- VP Final SD-JWT `no-claims-in-dcql-query` now passes for plans 1, 2, and 3.
- VP HAIP SD-JWT `no-claims-in-dcql-query` now passes for plans 7 and 9.
- VP Final and HAIP mDoc `no-claims-in-dcql-query` already passed.

Remaining failures are VP-only:

- Some VP Final variants still interrupt in the suite:
  - `oid4vp-1final-wallet-alternate-happy-flow` for plain `direct_post`
  - `oid4vp-1final-wallet-negative-test-response-uri-not-client-id` for selected signed `x509_hash` variants
  - `oid4vp-1final-wallet-multisigned-one-invalid-signature` in non-multisigned plan variants
- HAIP Browser API `dc_api.jwt` still has `invalid-client-id-prefix` failures for selected variants.

Use this log query to summarize the important lines from a run:

```bash
rg -n \
  "Results for \\[[0-9]+\\]|Overall totals|\\*\\* SOME TEST|\\*\\* Exiting|no-claims-in-dcql-query|invalid-client-id-prefix" \
  "$OIDF_RUN_DIR/runner.log"
```

The practical next functionality work is:

- adjust Browser API negative error handling for HAIP `invalid-client-id-prefix` so the suite receives the expected failure result instead of an interrupted module
- investigate remaining VP Final suite interruptions and either fix wallet routing/validation or report the suite variant applicability issue upstream

## Design Rule

There is no conformance-only wallet mode in this flow.

The wallet uses:

- its normal holder key for DPoP and proof binding
- its normal issuer signing key and certificate chain for client attestation and key attestation
- its normal shared wallet CA as the trust anchor

That keeps the conformance run aligned with real wallet behavior instead of carrying suite-only signing paths.

## Known Gaps

The current known gaps are listed in [Current Local Results](#current-local-results). Keep those failures visible in runs until the wallet harness gains the missing functionality or the upstream suite behavior changes. Do not silently skip them in the wrapper.

## References

- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [OIDF Conformance Service](https://www.certification.openid.net/)
