# Running OIDF Wallet Conformance

Use this runbook to execute the current OIDF Final and HAIP wallet plans against the local `oid4vc-dev` testing wallet. The current status and result matrix live in [Current conformance results](./conformance-results.md).

## Prerequisites

You need:

- `go`
- `python3`
- `curl`
- Docker
- Maven
- a local OpenID Foundation conformance-suite checkout

The current documented suite baseline is `release-v5.2.1`, released on 2026-07-20. Use a newer release only when intentionally updating the conformance baseline and [results](./conformance-results.md).

## Start the Local Suite

Build the suite from the baseline checkout:

```bash
cd ../conformance-suite
git fetch --tags
git checkout release-v5.2.1
mvn clean package
```

The `oid4vc-dev` wrapper defaults to plain `localhost` URLs. The upstream dev compose files advertise `localhost.emobix.co.uk`, so add this local override for wallet conformance runs:

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

The suite must advertise the same host in generated authorization, callback, and helper URLs:

- `CONFORMANCE_SERVER=https://localhost:8443/`
- `CONFORMANCE_SERVER_LOCAL=https://localhost:8443/`
- `CONFORMANCE_SERVER_MTLS=https://localhost:8444/`

Check the running suite before starting the wallet run:

```bash
curl -k https://localhost:8443/api/server
```

For the current baseline, the server returns:

```json
{"tag":"release-v5.2.1","version":"5.2.1","revision":"932b46f"}
```

## Run the Wallet Matrix

From this repository:

```bash
scripts/oidf-wallet-conformance.sh
```

To keep artifacts in a stable location:

```bash
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-local-strict \
  scripts/oidf-wallet-conformance.sh
```

To force the wrapper to use the same checkout as the running local server:

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.2.1 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-local-strict \
  scripts/oidf-wallet-conformance.sh
```

At the current baseline the full matrix passes and the command exits zero. If a run reports failures, compare against the matrix and documented suite-side exclusions in [Current conformance results](./conformance-results.md) before treating the wallet as regressed.

## Rerun Selected Plans or Modules

Pass the official `run-test-plan.py` selector through the wrapper:

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.2.1 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-rerun \
  scripts/oidf-wallet-conformance.sh --rerun '1:6,2:6'
```

The selector syntax is the official runner syntax:

- `2` reruns plan 2
- `2:6` reruns one module
- `1:6,2:6` reruns multiple modules

The harness still generates all configs so the official runner keeps the same plan numbering, then filters execution to the requested plans or modules.

## Result Artifacts

The wrapper prints the run directory and leaves these artifacts:

- `wallet.log`: wallet process log
- `runner.log`: mirrored official runner output
- `results/`: exported OIDF result archives
- `results/*-config.json`: generated OIDF config files

The Python runner also prints local `plan-detail.html?plan=...` URLs for inspecting the created plans in the suite UI.

Use this query to summarize important runner lines:

```bash
rg -n \
  "Results for \\[[0-9]+\\]|Overall totals|\\*\\* SOME TEST|\\*\\* Exiting|no-claims-in-dcql-query|invalid-client-id-prefix" \
  "$OIDF_RUN_DIR/runner.log"
```

When updating [Current conformance results](./conformance-results.md), include the suite tag, suite revision, wallet mode, run directory, runner log path, result matrix, and any targeted rerun evidence used to refine a failure.

## Environment Overrides

- `CONFORMANCE_MODE`: `local` by default; use `hosted` only when intentionally running against the OIDF hosted service
- `CONFORMANCE_SERVER`: local conformance-suite base URL; defaults to `https://localhost:8443/`
- `CONFORMANCE_SERVER_LOCAL`: local callback/helper base URL; defaults to `CONFORMANCE_SERVER`
- `CONFORMANCE_SERVER_MTLS`: local mTLS base URL; defaults to `https://localhost:8444/`
- `OIDF_WALLET_MODE`: wallet validation mode for the run, `strict` (default) or `debug`; debug mode fails the negative modules listed in [Current conformance results](./conformance-results.md)
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

## Hosted Mode

Hosted mode creates private plans on the OIDF service. It does not delete plans, publish plans, or create certification packages.

Use hosted mode only when that is the intended target:

```bash
CONFORMANCE_MODE=hosted \
CONFORMANCE_TOKEN="$OIDF_TOKEN" \
  scripts/oidf-wallet-conformance.sh
```

If hosted-mode runs do not appear on the public OIDF pages, that is expected. Use the printed `plan-detail.html?plan=...` URLs, and make sure you are signed into the same OIDF account that owns the bearer token.
