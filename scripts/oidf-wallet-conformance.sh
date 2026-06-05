#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  . "$ROOT_DIR/.env"
  set +a
fi

build_local_oid4vc_dev() {
  if ! command -v go >/dev/null 2>&1; then
    echo "error: Go is required to build the checked-out oid4vc-dev binary" >&2
    exit 1
  fi

  LOCAL_OID4VC_DEV="$RUN_DIR/oid4vc-dev"
  echo "Building oid4vc-dev from the current checkout..."
  (
    cd "$ROOT_DIR"
    go build -o "$LOCAL_OID4VC_DEV" .
  )
}

pick_port_pair() {
  python3 - <<'PY'
import socket

def port_free(port: int) -> bool:
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True

for _ in range(128):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    if port < 1024 or port >= 65534:
        continue
    if port_free(port) and port_free(port + 1):
        print(port)
        raise SystemExit(0)

raise SystemExit("failed to find a free local port pair")
PY
}

latest_suite_release() {
  python3 - <<'PY'
import json
import urllib.request

url = "https://gitlab.com/api/v4/projects/openid%2Fconformance-suite/releases/permalink/latest"
with urllib.request.urlopen(url, timeout=20) as resp:
    release = json.loads(resp.read().decode("utf-8"))
tag = release.get("tag_name")
if not tag:
    raise SystemExit("latest OIDF conformance-suite release did not expose a tag_name")
for source in release.get("assets", {}).get("sources", []):
    if source.get("format") == "tar.gz" and source.get("url"):
        print(tag, source["url"])
        raise SystemExit(0)
raise SystemExit("latest OIDF conformance-suite release did not expose a tar.gz source archive")
PY
}

fetch_suite_source() {
  if [ -n "${OIDF_SUITE_DIR:-}" ]; then
    SUITE_DIR=$OIDF_SUITE_DIR
    SUITE_TAG=${OIDF_SUITE_TAG:-$(git -C "$SUITE_DIR" describe --tags --always 2>/dev/null || printf unknown)}
    if [ ! -f "$SUITE_DIR/scripts/run-test-plan.py" ]; then
      echo "error: OIDF_SUITE_DIR does not look like a conformance-suite checkout: $SUITE_DIR" >&2
      exit 1
    fi
    echo "Using OIDF conformance-suite source: $SUITE_DIR ($SUITE_TAG)"
    return
  fi

  SUITE_DIR="$RUN_DIR/conformance-suite"
  if [ -n "${OIDF_SUITE_URL:-}" ]; then
    SUITE_URL=$OIDF_SUITE_URL
    SUITE_TAG=${OIDF_SUITE_TAG:-unknown}
  else
    set -- $(latest_suite_release)
    SUITE_TAG=$1
    SUITE_URL=$2
  fi
  mkdir -p "$SUITE_DIR"
  echo "Fetching latest official OIDF conformance-suite source..."
  echo "Suite archive: $SUITE_URL ($SUITE_TAG)"
  curl -fsSL "$SUITE_URL" | tar -xz --strip-components=1 -C "$SUITE_DIR"
}

check_local_conformance_server() {
  server_info=$(curl -kfsS "${CONFORMANCE_SERVER%/}/api/server" 2>/dev/null || true)
  if [ -z "$server_info" ]; then
    if curl -kfsS "${CONFORMANCE_SERVER%/}/api/runner/available" >/dev/null 2>&1; then
      return
    fi
  else
    server_tag=$(printf '%s' "$server_info" | python3 -c 'import json,sys; print((json.load(sys.stdin).get("tag") or "unknown"))')
    echo "Local OIDF conformance-suite server: $server_tag"
    if [ -n "${SUITE_TAG:-}" ] && [ "$SUITE_TAG" != "unknown" ] && [ "$server_tag" != "$SUITE_TAG" ]; then
      cat >&2 <<EOF
error: local OIDF conformance-suite server is $server_tag but runner/templates are $SUITE_TAG

Update and restart the local suite, or set OIDF_SUITE_DIR/OIDF_SUITE_TAG to match the running server.
EOF
      exit 1
    fi
    return
  fi
  cat >&2 <<EOF
error: local OIDF conformance-suite is not reachable at ${CONFORMANCE_SERVER%/}

Start the latest local suite first, for example:
  cd ../conformance-suite
  git fetch --tags
  git checkout release-v5.1.44
  mvn clean package
  docker compose -f docker-compose-dev-mac.yml up --detach

Override CONFORMANCE_SERVER, CONFORMANCE_SERVER_LOCAL, and CONFORMANCE_SERVER_MTLS if your local suite uses different URLs.
EOF
  exit 1
}

PORT=${PORT:-$(pick_port_pair)}
RUN_DIR=${OIDF_RUN_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/oidf-wallet-conformance.XXXXXX")}
WALLET_DIR=${OIDF_WALLET_DIR:-"$RUN_DIR/wallet"}
WALLET_URL=${OIDF_WALLET_URL:-"http://127.0.0.1:${PORT}"}
WALLET_ISSUER_URL=${OIDF_WALLET_ISSUER_URL:-"https://localhost:$((PORT + 1))"}
WALLET_CA_CERT=${OIDF_WALLET_CA_CERT:-"$RUN_DIR/wallet-ca-cert.pem"}
CONFORMANCE_MODE=${CONFORMANCE_MODE:-local}
OIDF_VCI_CLIENT_ID=${OIDF_VCI_CLIENT_ID:-52480754053}
OIDF_VCI_ALIAS=${OIDF_VCI_ALIAS:-"oid4vc-dev-vci-${PORT}"}

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

OIDF_VCI_REDIRECT_URI=${OIDF_VCI_REDIRECT_URI:-"${CONFORMANCE_SERVER_LOCAL%/}/test/a/${OIDF_VCI_ALIAS}/callback"}

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

echo "Starting wallet on $WALLET_URL"
(
  cd "$ROOT_DIR"
  exec "$LOCAL_OID4VC_DEV" wallet serve \
    --mode strict \
    --auto-accept \
    --pid \
    --preferred-format dc+sd-jwt \
    --wallet-dir "$WALLET_DIR" \
    --port "$PORT" \
    --vci-client-id "$OIDF_VCI_CLIENT_ID" \
    --vci-redirect-uri "$OIDF_VCI_REDIRECT_URI"
) >"$WALLET_LOG" 2>&1 &
WALLET_PID=$!

attempt=0
until curl -fsS "$WALLET_URL/api/credentials" >/dev/null 2>&1; do
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

echo "Running OIDF Final + HAIP wallet plans against $CONFORMANCE_SERVER ($CONFORMANCE_MODE mode)"
"$VENV_DIR/bin/python" "$ROOT_DIR/scripts/oidf_wallet_conformance.py" \
  --suite-dir "$SUITE_DIR" \
  --wallet-url "$WALLET_URL" \
  --wallet-issuer-url "$WALLET_ISSUER_URL" \
  --wallet-ca-cert "$WALLET_CA_CERT" \
  --vci-client-id "$OIDF_VCI_CLIENT_ID" \
  --vci-redirect-uri "$OIDF_VCI_REDIRECT_URI" \
  --results-dir "$RESULTS_DIR" \
  --runner-log "$RUNNER_LOG" \
  "$@"

echo "Wallet log:   $WALLET_LOG"
echo "Runner log:   $RUNNER_LOG"
echo "Results dir:  $RESULTS_DIR"
