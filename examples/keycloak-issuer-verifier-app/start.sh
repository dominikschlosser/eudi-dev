#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/examples/lib/public-ngrok.sh"
example_load_env_files "${REPO_ROOT}/.env" "${SCRIPT_DIR}/.env"
APP_PID=""
DEBUG_PROXY_PID=""
ROUTE_PROXY_PID=""
WALLET_PID=""
compose_args=(-f docker-compose.yml)
transport="http"
trust_mode="metadata"
cleanup_enabled="false"
ngrok_mode="${OID4VP_NGROK:-auto}"
wallet_port="${OID4VC_WALLET_PORT:-8087}"
keycloak_ngrok_domain="${KEYCLOAK_NGROK_DOMAIN:-${NGROK_DOMAIN:-}}"
public_proxy_port="${PUBLIC_PROXY_PORT:-9090}"
route_proxy_port="${ROUTE_PROXY_PORT:-18090}"
dashboard_port="${OID4VC_PROXY_DASHBOARD_PORT:-9091}"
ngrok_override=""
sandbox_pem_path=""
sandbox_verifier_info_path=""
sandbox_material_available="false"
public_base_url=""

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
Usage: ./start.sh [--http|--https] [--setup-only|--smoke] [--ngrok|--no-ngrok] [--wallet-port <port>] [--keycloak-domain <name>]

  default      Start Keycloak, the demo app, the local wallet, oid4vc-dev proxy, and the route proxy. Use ngrok automatically when sandbox verifier files are available.
  --http       Use local Keycloak on http://localhost:8080 when ngrok is disabled
  --https      Use local Keycloak on https://localhost:8443 when ngrok is disabled
  --smoke      Run the full headless smoke flow after setup
  --setup-only Download/build dependencies, start Keycloak, and bootstrap the realm only
  --ngrok      Publish Keycloak and the demo app through one ngrok HTTPS hostname
  --no-ngrok   Keep Keycloak and the demo app local
  --wallet-port  oid4vc-dev wallet port (default: 8087)
  --keycloak-domain  Fixed ngrok hostname (otherwise detect from sandbox cert SAN when available)
EOF
}

cleanup() {
  if [[ -n "${APP_PID}" ]]; then
    kill "${APP_PID}" >/dev/null 2>&1 || true
    wait "${APP_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${DEBUG_PROXY_PID}" ]]; then
    kill "${DEBUG_PROXY_PID}" >/dev/null 2>&1 || true
    wait "${DEBUG_PROXY_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${ROUTE_PROXY_PID}" ]]; then
    kill "${ROUTE_PROXY_PID}" >/dev/null 2>&1 || true
    wait "${ROUTE_PROXY_PID}" >/dev/null 2>&1 || true
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
  local proxy_url="$1"
  local label="${2:-proxy}"
  local status=""

  for _ in $(seq 1 40); do
    if [[ -n "${ROUTE_PROXY_PID}" ]] && ! kill -0 "${ROUTE_PROXY_PID}" 2>/dev/null; then
      echo "Single-host route proxy exited before becoming ready." >&2
      exit 1
    fi
    if [[ -n "${DEBUG_PROXY_PID}" ]] && ! kill -0 "${DEBUG_PROXY_PID}" 2>/dev/null; then
      echo "oid4vc-dev proxy exited before becoming ready." >&2
      exit 1
    fi
    status="$(curl -s -o /dev/null -w '%{http_code}' "${proxy_url}" || true)"
    if [[ "${status}" =~ ^(200|302|400|401|403|404|502)$ ]]; then
      return 0
    fi
    sleep 0.25
  done

  echo "${label} did not become ready at ${proxy_url}" >&2
  exit 1
}

wait_for_public_app() {
  local health_url="${public_base_url%/}/healthz"
  local status=""

  for _ in $(seq 1 80); do
    status="$(curl -s -o /dev/null -w '%{http_code}' "${health_url}" || true)"
    if [[ "${status}" == "200" ]]; then
      return 0
    fi
    sleep 0.5
  done

  echo "Public app did not become ready at ${health_url}" >&2
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

find_worktree_sandbox_file() {
  local filename="$1"
  local worktree_path
  local candidate

  while IFS= read -r worktree_path; do
    candidate="${worktree_path%/}/sandbox/${filename}"
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done < <(git -C "${REPO_ROOT}" worktree list --porcelain 2>/dev/null | sed -n 's/^worktree //p')

  return 1
}

resolve_sandbox_material() {
  sandbox_pem_path="${OID4VP_SANDBOX_PEM_PATH:-$(example_find_sandbox_pem "${REPO_ROOT}" "${SCRIPT_DIR}" || true)}"
  sandbox_verifier_info_path="${OID4VP_SANDBOX_VERIFIER_INFO_PATH:-$(example_find_sandbox_verifier_info "${REPO_ROOT}" "${SCRIPT_DIR}" || true)}"
  if [[ -z "${sandbox_pem_path}" ]]; then
    sandbox_pem_path="$(find_worktree_sandbox_file "sandbox-ngrok-combined.pem" || true)"
  fi
  if [[ -z "${sandbox_verifier_info_path}" ]]; then
    sandbox_verifier_info_path="$(find_worktree_sandbox_file "sandbox-verifier-info.json" || true)"
  fi

  if [[ -n "${sandbox_pem_path}" && -f "${sandbox_pem_path}" && -n "${sandbox_verifier_info_path}" && -f "${sandbox_verifier_info_path}" ]]; then
    sandbox_material_available="true"
  else
    sandbox_material_available="false"
  fi
}

resolve_ngrok_mode() {
  case "${ngrok_mode}" in
    auto)
      if [[ "${sandbox_material_available}" == "true" ]]; then
        ngrok_mode="true"
      else
        ngrok_mode="false"
      fi
      ;;
    true|false)
      ;;
    *)
      echo "Invalid OID4VP_NGROK value: ${ngrok_mode}. Use auto, true, or false." >&2
      exit 1
      ;;
  esac

  if [[ "${ngrok_mode}" == "true" ]]; then
    require_sandbox_file "Sandbox PEM" "${sandbox_pem_path}"
    require_sandbox_file "Sandbox verifier info" "${sandbox_verifier_info_path}"
  fi
  echo "ngrok mode: ${ngrok_mode} (sandbox verifier files: ${sandbox_material_available})"
  if [[ "${sandbox_material_available}" == "true" ]]; then
    echo "Sandbox PEM: ${sandbox_pem_path}"
    echo "Sandbox verifier info: ${sandbox_verifier_info_path}"
  fi
}

start_public_proxy() {
  public_proxy_port="$(example_resolve_free_port "${public_proxy_port}" "public proxy")"
  if [[ "${route_proxy_port}" == "${public_proxy_port}" ]]; then
    route_proxy_port="$((route_proxy_port + 1))"
  fi
  route_proxy_port="$(example_resolve_free_port "${route_proxy_port}" "single-host route proxy")"
  while [[ "${route_proxy_port}" == "${public_proxy_port}" ]]; do
    route_proxy_port="$(example_resolve_free_port "$((route_proxy_port + 1))" "single-host route proxy")"
  done
  if [[ "${dashboard_port}" == "${public_proxy_port}" || "${dashboard_port}" == "${route_proxy_port}" ]]; then
    dashboard_port="$((dashboard_port + 1))"
  fi
  dashboard_port="$(example_resolve_free_port "${dashboard_port}" "proxy dashboard")"
  while [[ "${dashboard_port}" == "${public_proxy_port}" || "${dashboard_port}" == "${route_proxy_port}" ]]; do
    dashboard_port="$(example_resolve_free_port "$((dashboard_port + 1))" "proxy dashboard")"
  done
  (
    cd "${REPO_ROOT}"
    exec go run ./examples/lib/single-host-proxy \
      --listen "127.0.0.1:${route_proxy_port}" \
      --app "http://127.0.0.1:8090" \
      --keycloak "http://127.0.0.1:8080"
  ) &
  ROUTE_PROXY_PID=$!
  trap cleanup EXIT INT TERM
  wait_for_proxy "http://127.0.0.1:${route_proxy_port}/" "single-host route proxy"
  (
    exec oid4vc-dev proxy \
      --target "http://127.0.0.1:${route_proxy_port}" \
      --port "${public_proxy_port}" \
      --dashboard "${dashboard_port}"
  ) &
  DEBUG_PROXY_PID=$!
  wait_for_proxy "http://127.0.0.1:${public_proxy_port}/" "oid4vc-dev proxy"
  echo "Single-host route proxy: http://127.0.0.1:${route_proxy_port}/"
  echo "oid4vc-dev proxy: http://127.0.0.1:${public_proxy_port}/"
  echo "oid4vc-dev proxy dashboard: http://127.0.0.1:${dashboard_port}/"
}

start_local_wallet() {
  wallet_port="$(resolve_wallet_port_pair "${wallet_port}")"
  export OID4VC_WALLET_PORT="${wallet_port}"
  export WALLET_UI_URL="http://localhost:${wallet_port}/"
  echo "Starting oid4vc-dev wallet on port ${wallet_port}..."
  oid4vc-dev wallet serve --docker --port "${wallet_port}" --base-url "" --register &
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

resolve_wallet_port_pair() {
  local preferred_port="$1"
  local candidate

  for candidate in $(seq "${preferred_port}" $((preferred_port + 100))); do
    if wallet_port_pair_available "${candidate}"; then
      if [[ "${candidate}" != "${preferred_port}" ]]; then
        echo "wallet port ${preferred_port}/${preferred_port}+1 is not fully available; using ${candidate}/$((candidate + 1)) instead." >&2
      fi
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  echo "Could not find free adjacent wallet HTTP/HTTPS ports near ${preferred_port}." >&2
  exit 1
}

wallet_port_pair_available() {
  local candidate="$1"
  local https_port="$((candidate + 1))"
  local reserved_port
  local reserved_ports=(
    "${APP_PORT:-8090}"
    "8080"
    "8443"
    "${public_proxy_port}"
    "${route_proxy_port}"
    "${dashboard_port}"
  )

  for reserved_port in "${reserved_ports[@]}"; do
    if [[ "${candidate}" == "${reserved_port}" || "${https_port}" == "${reserved_port}" ]]; then
      return 1
    fi
  done

  ! example_port_is_listening "${candidate}" && ! example_port_is_listening "${https_port}"
}

mode="app"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup-only) mode="setup-only" ;;
    --smoke) mode="smoke" ;;
    --ngrok) ngrok_mode="true" ;;
    --no-ngrok) ngrok_mode="false" ;;
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
      ;;
    --https)
      transport="https"
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

cd "${SCRIPT_DIR}"

ensure_oid4vc_dev
./scripts/download-extension.sh
./scripts/build-link-provider.sh

resolve_sandbox_material
resolve_ngrok_mode
start_public_proxy

export WALLET_UI_URL="http://localhost:${wallet_port}/"
if [[ "${sandbox_material_available}" == "true" ]]; then
  export OID4VP_SANDBOX_PEM_PATH="${sandbox_pem_path}"
  export OID4VP_SANDBOX_VERIFIER_INFO_PATH="${sandbox_verifier_info_path}"
fi

if [[ "${ngrok_mode}" == "true" ]]; then
  trust_mode="trustlist"
  export OID4VP_PUBLIC_WALLET="true"
  if [[ -z "${keycloak_ngrok_domain}" ]]; then
    keycloak_ngrok_domain="$(example_env_keycloak_ngrok_domain || true)"
  fi
  detected_domain="$(example_detect_ngrok_domain_from_pem "${sandbox_pem_path}" || true)"
  if [[ -n "${detected_domain}" ]] && [[ "${detected_domain}" != "${keycloak_ngrok_domain}" ]]; then
    echo "Using ngrok hostname from sandbox certificate SAN: ${detected_domain}"
    keycloak_ngrok_domain="${detected_domain}"
  fi
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

export OID4VP_TRUST_MODE="${trust_mode}"
export KEYCLOAK_TRUST_LIST_PATH="${KEYCLOAK_TRUST_LIST_PATH:-${SCRIPT_DIR}/keycloak-trustlist.jwt}"

start_local_wallet
docker compose "${compose_args[@]}" up -d --force-recreate
./scripts/bootstrap.sh

case "${mode}" in
  app)
    cleanup_enabled="true"
    trap cleanup EXIT INT TERM
    ./scripts/start-app.sh &
    APP_PID=$!
    wait_for_app
    if [[ "${ngrok_mode}" == "true" ]]; then
      wait_for_public_app
    fi
    echo
    if [[ "${ngrok_mode}" == "true" ]]; then
      echo "Open demo app: ${public_base_url}"
    else
      echo "Open demo app: ${APP_BASE_URL:-http://127.0.0.1:8090}"
    fi
    wait "${APP_PID}"
    ;;
  smoke)
    cleanup_enabled="true"
    trap cleanup EXIT
    oid4vc-dev wallet remove --all >/dev/null
    ./scripts/start-app.sh &
    APP_PID=$!
    wait_for_app
    if [[ "${ngrok_mode}" == "true" ]]; then
      wait_for_public_app
    fi
    ./scripts/smoke.py
    ;;
  setup-only)
    echo
    echo "Combined example is ready."
    ;;
esac
