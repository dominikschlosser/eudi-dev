# Running OIDF Wallet Conformance

This runbook runs the current OIDF Final and HAIP wallet plans against the local `eudi-dev` testing wallet. Status and result matrix: [Current conformance results](./conformance-results.md).

## Prerequisites

You need:

- `go`
- `python3`
- `curl`
- Docker
- Maven
- a local OpenID Foundation conformance-suite checkout

The documented suite baseline is `release-v5.2.2`. Use a newer release only when intentionally updating the baseline and [results](./conformance-results.md).

## Start the Local Suite

Build the suite from the baseline checkout:

```bash
cd ../conformance-suite
git fetch --tags
git checkout release-v5.2.2
mvn clean package
```

Run the suite server **on the host**, not inside a container. The wallet advertises its status list at `https://localhost:<port+1>` and the suite fetches that URL itself. Inside a container, `localhost` is the container. Every module that checks credential status then fails with `Connect to https://localhost:<port> failed: Connection refused`. The `-nodocker` compose file keeps mongo and nginx in Docker and expects the server on the host, so `localhost` resolves to the machine the wallet runs on.

The `eudi-dev` wrapper defaults to plain `localhost` URLs. The server must advertise the same host, not the upstream default of `localhost.emobix.co.uk`:

```bash
cd ../conformance-suite
docker compose -f docker-compose-dev-mac-nodocker.yml up --detach

java -jar target/fapi-test-suite.jar \
  --fintechlabs.devmode=true \
  --fintechlabs.startredir=true \
  --fintechlabs.base_url=https://localhost:8443 \
  --fintechlabs.base_mtls_url=https://localhost:8444 \
  --spring.mongodb.uri=mongodb://127.0.0.1:27017/test_suite
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
{"tag":"release-v5.2.2","version":"5.2.2","revision":"321bc5b"}
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
OIDF_SUITE_TAG=release-v5.2.2 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-local-strict \
  scripts/oidf-wallet-conformance.sh
```

At the current baseline the full matrix passes and the command exits zero. If a run reports failures, first compare against the matrix and suite-side exclusions in [Current conformance results](./conformance-results.md) before treating the wallet as regressed.

## Rerun Selected Plans or Modules

Pass the official `run-test-plan.py` selector through the wrapper:

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.2.2 \
OIDF_RUN_DIR=/tmp/oidf-wallet-conformance-rerun \
  scripts/oidf-wallet-conformance.sh --rerun '1:6,2:6'
```

The selector syntax is the official runner syntax:

- `2` reruns plan 2
- `2:6` reruns one module
- `1:6,2:6` reruns multiple modules

The harness still generates all configs, so plan numbering stays the same. It then runs only the requested plans or modules.

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

- `CONFORMANCE_MODE`: `local` by default. Use `hosted` only when intentionally running against the OIDF hosted service
- `CONFORMANCE_SERVER`: local conformance-suite base URL. Defaults to `https://localhost:8443/`
- `CONFORMANCE_SERVER_LOCAL`: local callback/helper base URL. Defaults to `CONFORMANCE_SERVER`
- `CONFORMANCE_SERVER_MTLS`: local mTLS base URL. Defaults to `https://localhost:8444/`
- `OIDF_WALLET_MODE`: wallet validation mode for the run, `strict` (default) or `debug`. Debug mode fails the negative modules listed in [Current conformance results](./conformance-results.md)
- `PORT`: wallet port. Defaults to a free local port
- `OIDF_RUN_DIR`: keep all runner artifacts in a chosen directory instead of a temp dir
- `OIDF_SUITE_DIR`: use an existing conformance-suite checkout for runner/templates instead of downloading the latest release archive
- `OIDF_SUITE_TAG`: expected conformance-suite tag when `OIDF_SUITE_DIR` or `OIDF_SUITE_URL` is used
- `OIDF_WALLET_DIR`: reuse a specific wallet store
- `OIDF_WALLET_ISSUER_URL`: override the wallet HTTPS issuer URL if needed
- `OIDF_WALLET_CA_CERT`: override the shared wallet CA PEM path
- `OIDF_VCI_CLIENT_ID`: override the configured OID4VCI client ID
- `OIDF_VCI_REDIRECT_URI`: override the configured OID4VCI redirect URI
- `OIDF_VCI_ALIAS`: convenience alias used by the default `OIDF_VCI_REDIRECT_URI`
- `OIDF_SUITE_URL`: override the suite tarball URL. Defaults to the latest upstream release archive
- `OIDF_MODULE_IDLE_TIMEOUT`: seconds without `run-test-plan.py` output before the wrapper terminates a stuck module. Defaults to `180`, set `0` to disable
- `EUDI_REMOTE_TIMEOUT`: how long the wallet waits for a counterparty, as a Go duration (`45s`, `2m`). The wrapper sets `120s` because the suite shares the machine with the wallet and can take tens of seconds to answer under load. The wallet's own default is `15s`, kept short for interactive use. An unparseable value is ignored and the default applies
- `OIDF_KEEP_SUITE_DB`: set to `1` to keep the local suite database after a run. Otherwise the wrapper drops it, because a database carrying days of runs makes the server pause long enough to stall a run

## Hosted Mode

Hosted mode creates private plans on the OIDF service. It does not delete plans, publish plans, or create certification packages.

Use hosted mode only when that is the intended target:

```bash
CONFORMANCE_MODE=hosted \
CONFORMANCE_TOKEN="$OIDF_TOKEN" \
  scripts/oidf-wallet-conformance.sh
```

Hosted-mode runs do not appear on the public OIDF pages. That is expected. Use the printed `plan-detail.html?plan=...` URLs while signed into the OIDF account that owns the bearer token.
