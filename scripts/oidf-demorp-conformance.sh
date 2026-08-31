#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  . "$ROOT_DIR/.env"
  set +a
fi

. "$ROOT_DIR/scripts/oidf-conformance-lib.sh"

PORT=${PORT:-$(pick_port_pair)}
RUN_DIR=${OIDF_RUN_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/oidf-demorp-conformance.XXXXXX")}
WALLET_DIR=${OIDF_WALLET_DIR:-"$RUN_DIR/wallet"}
WALLET_URL=${OIDF_WALLET_URL:-"http://127.0.0.1:${PORT}"}
# The demo issuer and verifier live on the wallet's https base URL: the suite
# requires https for the verifier's request_uri and response_uri, and the HAIP
# issuer metadata checks require an https credential issuer. --serve-tls has
# the wallet bind this origin itself with its own certificate.
DEMO_BASE_URL=${OIDF_DEMO_BASE_URL:-"https://localhost:$((PORT + 1))"}
WALLET_CA_CERT=${OIDF_WALLET_CA_CERT:-"$RUN_DIR/wallet-ca-cert.pem"}
CONFORMANCE_MODE=${CONFORMANCE_MODE:-local}

case "$CONFORMANCE_MODE" in
  local)
    CONFORMANCE_SERVER=${CONFORMANCE_SERVER:-https://localhost:8443/}
    CONFORMANCE_SERVER_LOCAL=${CONFORMANCE_SERVER_LOCAL:-https://localhost:8443/}
    CONFORMANCE_SERVER_MTLS=${CONFORMANCE_SERVER_MTLS:-https://localhost:8444/}
    CONFORMANCE_DEV_MODE=${CONFORMANCE_DEV_MODE:-1}
    DISABLE_SSL_VERIFY=${DISABLE_SSL_VERIFY:-1}
    ;;
  hosted)
    CONFORMANCE_SERVER=${CONFORMANCE_SERVER:-https://demo.certification.openid.net/}
    CONFORMANCE_SERVER_LOCAL=${CONFORMANCE_SERVER_LOCAL:-$CONFORMANCE_SERVER}
    CONFORMANCE_SERVER_MTLS=${CONFORMANCE_SERVER_MTLS:-$CONFORMANCE_SERVER}
    if [ -z "${CONFORMANCE_TOKEN:-}" ]; then
      CONFORMANCE_TOKEN=${OIDF_TOKEN:-}
    fi
    if [ -z "${CONFORMANCE_TOKEN:-}" ]; then
      echo "error: set OIDF_TOKEN in .env or export CONFORMANCE_TOKEN for CONFORMANCE_MODE=hosted" >&2
      exit 1
    fi
    ;;
  *)
    echo "error: CONFORMANCE_MODE must be local or hosted, got: $CONFORMANCE_MODE" >&2
    exit 1
    ;;
esac

export CONFORMANCE_SERVER CONFORMANCE_SERVER_LOCAL CONFORMANCE_SERVER_MTLS
if [ -n "${CONFORMANCE_TOKEN:-}" ]; then
  export CONFORMANCE_TOKEN
fi

VENV_DIR="$RUN_DIR/venv"
RESULTS_DIR="$RUN_DIR/results"
RUNNER_LOG="$RUN_DIR/runner.log"
WALLET_LOG="$RUN_DIR/wallet.log"

mkdir -p "$RESULTS_DIR" "$WALLET_DIR"
build_local_oid4vc_dev
fetch_suite_source

if [ "$CONFORMANCE_MODE" = "local" ]; then
  check_local_conformance_server
  export CONFORMANCE_DEV_MODE DISABLE_SSL_VERIFY
fi

# The suite signs the credentials it presents to the demo verifier with its
# own CAs: the vp-signing CA from certs-keys for SD-JWT VCs, and a built-in
# mdoc IACA root for mdocs. The demo verifier is given both as extra trust
# anchors. The IACA root is published at /mdoc-iaca-root.pem, with the source
# constant as the fallback for a server build where that endpoint errors.
SUITE_VP_SIGNING_CA="$RUN_DIR/suite-vp-signing-ca.pem"
SUITE_MDOC_IACA_ROOT="$RUN_DIR/suite-mdoc-iaca-root.pem"
cp "$SUITE_DIR/scripts/certs-keys/vp-signing-ca.crt" "$SUITE_VP_SIGNING_CA"
if ! curl -kfsS "${CONFORMANCE_SERVER%/}/mdoc-iaca-root.pem" -o "$SUITE_MDOC_IACA_ROOT" 2>/dev/null \
  || ! grep -q "BEGIN CERTIFICATE" "$SUITE_MDOC_IACA_ROOT"; then
  python3 - "$SUITE_DIR/src/main/kotlin/net/openid/conformance/util/TestKeysAndCerts.kt" "$SUITE_MDOC_IACA_ROOT" <<'PY'
import re
import sys

source = open(sys.argv[1]).read()
match = re.search(
    r"IACA_ROOT_CERT_PEM[^\"]*\"\"\"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
    source,
    re.DOTALL,
)
if not match:
    raise SystemExit("could not extract IACA_ROOT_CERT_PEM from the suite source")
open(sys.argv[2], "w").write(match.group(1) + "\n")
PY
  echo "Extracted the suite's mdoc IACA root from its source (the /mdoc-iaca-root.pem endpoint was unavailable)"
fi

cleanup() {
  if [ -n "${WALLET_PID:-}" ] && kill -0 "$WALLET_PID" 2>/dev/null; then
    kill "$WALLET_PID" 2>/dev/null || true
    wait "$WALLET_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "Using run directory: $RUN_DIR"

echo "Installing runner dependencies..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet -r "$SUITE_DIR/scripts/requirements.txt"

echo "Starting wallet with the demo issuer and verifier on $DEMO_BASE_URL"
(
  cd "$ROOT_DIR"
  exec "$LOCAL_OID4VC_DEV" wallet serve \
    --wallet-dir "$WALLET_DIR" \
    --port "$PORT" \
    --base-url "$DEMO_BASE_URL" \
    --serve-tls \
    --demo-verifier-trust-anchor "$SUITE_VP_SIGNING_CA" \
    --demo-verifier-trust-anchor "$SUITE_MDOC_IACA_ROOT"
) >"$WALLET_LOG" 2>&1 &
WALLET_PID=$!

attempt=0
until curl -fsS "$WALLET_URL/api/credentials" >/dev/null 2>&1 \
  && curl -kfsS "$DEMO_BASE_URL/.well-known/openid-credential-issuer/issuer" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if ! kill -0 "$WALLET_PID" 2>/dev/null; then
    echo "error: wallet exited before becoming ready" >&2
    cat "$WALLET_LOG" >&2
    exit 1
  fi
  if [ "$attempt" -ge 60 ]; then
    echo "error: wallet did not become ready" >&2
    exit 1
  fi
  sleep 1
done

echo "Running OIDF issuer + verifier plans against $CONFORMANCE_SERVER ($CONFORMANCE_MODE mode)"
RUN_STATUS=0
"$VENV_DIR/bin/python" "$ROOT_DIR/scripts/oidf_demorp_conformance.py" \
  --suite-dir "$SUITE_DIR" \
  --wallet-url "$WALLET_URL" \
  --demo-base-url "$DEMO_BASE_URL" \
  --wallet-ca-cert "$WALLET_CA_CERT" \
  --results-dir "$RESULTS_DIR" \
  --runner-log "$RUNNER_LOG" \
  "$@" || RUN_STATUS=$?

# Runs after a failed run too: a run that was killed leaves the most behind.
wipe_local_suite_database

echo "Wallet log:   $WALLET_LOG"
echo "Runner log:   $RUNNER_LOG"
echo "Results dir:  $RESULTS_DIR"

exit $RUN_STATUS
