#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/examples/lib/public-ngrok.sh"
example_load_env_files "${REPO_ROOT}/.env" "${SCRIPT_DIR}/.env"
APP_PID=""
PROXY_PID=""
WALLET_PID=""
compose_args=(-f docker-compose.yml)
transport="http"
trust_mode="trustlist"
cleanup_enabled="false"
public_mode="false"
local_wallet_mode="false"
wallet_port="${OID4VC_WALLET_PORT:-8087}"
keycloak_ngrok_domain="${KEYCLOAK_NGROK_DOMAIN:-${NGROK_DOMAIN:-}}"
public_proxy_port="${PUBLIC_PROXY_PORT:-18090}"
ngrok_override=""

ensure_oid4vc_dev() {
  if command -v oid4vc-dev >/dev/null 2>&1; then
    return 0
  fi
  if ! command -v go >/dev/null 2>&1; then
    echo "Missing required command: go" >&2
    exit 1
  fi

  local gobin
  gobin="$(go env GOBIN)"
  if [[ -z "${gobin}" ]]; then
    gobin="$(go env GOPATH)/bin"
  fi
  mkdir -p "${gobin}"

  echo "oid4vc-dev not found. Installing latest with Go..."
  GOBIN="${gobin}" go install github.com/dominikschlosser/oid4vc-dev@latest
  export PATH="${gobin}:${PATH}"
}

usage() {
  cat <<'EOF'
Usage: ./start.sh [--http|--https] [--setup-only|--smoke] [--public|--local-wallet] [--wallet-port <port>] [--keycloak-domain <name>]

  default      Same as --http: start Keycloak on http://localhost:8080, bootstrap the realm, and start the demo app
  --http       Use http://localhost:8080 and a custom trust list for verifier trust
  --https      Use https://localhost:8443 and issuer metadata for verifier trust
  --smoke      Run the full headless smoke flow after setup
  --setup-only Download/build dependencies, start Keycloak, and bootstrap the realm only
  --public     Sandbox mode: publish both Keycloak and the demo app through one ngrok HTTPS hostname
  --local-wallet  Start an oid4vc-dev PID wallet locally and configure Keycloak for it
  --wallet-port  oid4vc-dev wallet port in --local-wallet mode (default: 8087)
  --keycloak-domain  Fixed ngrok hostname (otherwise detect from sandbox cert SAN when available)
EOF
}

cleanup() {
  if [[ -n "${APP_PID}" ]]; then
    kill "${APP_PID}" >/dev/null 2>&1 || true
    wait "${APP_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${PROXY_PID}" ]]; then
    kill "${PROXY_PID}" >/dev/null 2>&1 || true
    wait "${PROXY_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${WALLET_PID}" ]]; then
    kill "${WALLET_PID}" >/dev/null 2>&1 || true
    wait "${WALLET_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "${cleanup_enabled}" == "true" ]]; then
    docker compose "${compose_args[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "${ngrok_override}" ]]; then
    rm -f "${ngrok_override}" >/dev/null 2>&1 || true
  fi
  example_stop_ngrok
}

wait_for_app() {
  local app_base_url="http://${APP_HOST:-127.0.0.1}:${APP_PORT:-8090}"
  local health_url="${app_base_url}/healthz"
  for _ in $(seq 1 60); do
    if curl -fsS "${health_url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Demo app did not become ready at ${health_url}" >&2
  exit 1
}

wait_for_proxy() {
  local proxy_url="http://127.0.0.1:${public_proxy_port}/"
  local status=""

  for _ in $(seq 1 40); do
    if [[ -n "${PROXY_PID}" ]] && ! kill -0 "${PROXY_PID}" 2>/dev/null; then
      echo "Public reverse proxy exited before becoming ready." >&2
      exit 1
    fi
    status="$(curl -s -o /dev/null -w '%{http_code}' "${proxy_url}" || true)"
    if [[ "${status}" =~ ^(200|302|400|401|403|404|502)$ ]]; then
      return 0
    fi
    sleep 0.25
  done

  echo "Public reverse proxy did not become ready at ${proxy_url}" >&2
  exit 1
}

require_sandbox_file() {
  local label="$1"
  local path="$2"

  if [[ -z "${path}" || ! -f "${path}" ]]; then
    echo "${label} file not found: ${path:-<unset>}" >&2
    echo "Set SANDBOX_DIR, EXAMPLES_SANDBOX_PEM / EXAMPLES_SANDBOX_VERIFIER_INFO, or the OID4VP_SANDBOX_* path variables." >&2
    exit 1
  fi
}

start_local_wallet() {
  if [[ "${local_wallet_mode}" != "true" ]]; then
    return 0
  fi

  echo "Starting oid4vc-dev wallet on port ${wallet_port}..."
  oid4vc-dev wallet serve --pid --docker --port "${wallet_port}" --base-url "" --register &
  WALLET_PID=$!
  trap cleanup EXIT INT TERM
  sleep 1
  if ! kill -0 "${WALLET_PID}" 2>/dev/null; then
    echo "oid4vc-dev wallet exited before startup completed." >&2
    wait "${WALLET_PID}" 2>/dev/null || true
    exit 1
  fi
  echo "Wallet UI: http://localhost:${wallet_port}/"
}

mode="app"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup-only) mode="setup-only" ;;
    --smoke) mode="smoke" ;;
    --public) public_mode="true" ;;
    --local-wallet) local_wallet_mode="true" ;;
    --wallet-port)
      wallet_port="$2"
      shift
      ;;
    --keycloak-domain)
      keycloak_ngrok_domain="$2"
      shift
      ;;
    --domain)
      keycloak_ngrok_domain="$2"
      shift
      ;;
    --http)
      transport="http"
      trust_mode="trustlist"
      ;;
    --https)
      transport="https"
      trust_mode="metadata"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [[ "${public_mode}" == "true" && "${local_wallet_mode}" == "true" ]]; then
  echo "--public and --local-wallet are mutually exclusive." >&2
  exit 1
fi

cd "${SCRIPT_DIR}"

ensure_oid4vc_dev
./scripts/download-extension.sh
./scripts/build-link-provider.sh

if [[ "${public_mode}" == "true" ]]; then
  public_proxy_port="$(example_resolve_free_port "${public_proxy_port}" "public proxy")"
  export OID4VP_PUBLIC_WALLET="true"
  export OID4VP_SANDBOX_PEM_PATH="${OID4VP_SANDBOX_PEM_PATH:-$(example_find_sandbox_pem "${REPO_ROOT}" "${SCRIPT_DIR}" || true)}"
  export OID4VP_SANDBOX_VERIFIER_INFO_PATH="${OID4VP_SANDBOX_VERIFIER_INFO_PATH:-$(example_find_sandbox_verifier_info "${REPO_ROOT}" "${SCRIPT_DIR}" || true)}"
  require_sandbox_file "Sandbox PEM" "${OID4VP_SANDBOX_PEM_PATH}"
  require_sandbox_file "Sandbox verifier info" "${OID4VP_SANDBOX_VERIFIER_INFO_PATH}"
  if [[ -z "${keycloak_ngrok_domain}" ]]; then
    keycloak_ngrok_domain="$(example_env_keycloak_ngrok_domain || true)"
  fi
  detected_domain="$(example_default_ngrok_domain "${REPO_ROOT}" "${SCRIPT_DIR}" "" || true)"
  if [[ -n "${detected_domain}" ]] && [[ "${detected_domain}" != "${keycloak_ngrok_domain}" ]]; then
    echo "Using ngrok hostname from sandbox certificate SAN: ${detected_domain}"
    keycloak_ngrok_domain="${detected_domain}"
  fi
  (
    cd "${REPO_ROOT}"
    exec go run ./examples/lib/single-host-proxy \
      --listen "127.0.0.1:${public_proxy_port}" \
      --app "http://127.0.0.1:8090" \
      --keycloak "http://127.0.0.1:8080"
  ) &
  PROXY_PID=$!
  wait_for_proxy
  public_base_url="$(example_start_ngrok_tunnel "keycloak-issuer-verifier-app-public" "${public_proxy_port}" "${keycloak_ngrok_domain}")"
  export KEYCLOAK_BASE_URL="${public_base_url}"
  export APP_BASE_URL="${public_base_url}"
  export APP_REDIRECT_URI="${public_base_url%/}/callback"
  export OID4VP_TRUST_LIST_URL="${public_base_url%/}/keycloak-trustlist.jwt"
  export ALLOWED_ISSUER="${public_base_url%/}/realms/${KEYCLOAK_REALM:-wallet-app-demo}"
  unset KEYCLOAK_CA_CERT
  compose_args=(-f docker-compose.yml)
  ngrok_override="${SCRIPT_DIR}/docker-compose.ngrok.override.yml"
  example_write_keycloak_public_override "${ngrok_override}" "${KEYCLOAK_BASE_URL}"
  compose_args+=(-f "${ngrok_override}")
  echo "Public URL: ${public_base_url}"
else
  export OID4VP_PUBLIC_WALLET="false"
  if [[ "${local_wallet_mode}" == "true" ]]; then
    export OID4VP_TRUST_LIST_URL="${OID4VP_TRUST_LIST_URL:-http://host.docker.internal:${wallet_port}/api/trustlists/pid}"
    export WALLET_UI_URL="http://localhost:${wallet_port}/"
  fi
  case "${transport}" in
    http)
      export KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
      compose_args=(-f docker-compose.yml)
      ;;
    https)
      export KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-https://localhost:8443}"
      export KEYCLOAK_CA_CERT="${KEYCLOAK_CA_CERT:-${SCRIPT_DIR}/keycloak-ca-cert.pem}"
      ./scripts/generate-keycloak-cert.sh
      compose_args=(-f docker-compose.yml -f docker-compose.https.yml)
      ;;
  esac
fi

export OID4VP_TRUST_MODE="${OID4VP_TRUST_MODE:-${trust_mode}}"
export KEYCLOAK_TRUST_LIST_PATH="${KEYCLOAK_TRUST_LIST_PATH:-${SCRIPT_DIR}/keycloak-trustlist.jwt}"

start_local_wallet
docker compose "${compose_args[@]}" up -d --force-recreate
./scripts/bootstrap.sh

if [[ "${mode}" != "smoke" && "${local_wallet_mode}" != "true" ]]; then
  oid4vc-dev wallet register
fi

case "${mode}" in
  app)
    cleanup_enabled="true"
    trap cleanup EXIT INT TERM
    ./scripts/start-app.sh &
    APP_PID=$!
    wait "${APP_PID}"
    ;;
  smoke)
    cleanup_enabled="true"
    trap cleanup EXIT
    oid4vc-dev wallet remove --all >/dev/null
    ./scripts/start-app.sh &
    APP_PID=$!
    wait_for_app
    ./scripts/smoke.py
    ;;
  setup-only)
    echo
    echo "Combined example is ready."
    ;;
esac
