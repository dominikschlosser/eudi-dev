#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

SETUP_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --setup-only) SETUP_ONLY=true ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Usage: $0 [--setup-only]" >&2
      exit 1
      ;;
  esac
done

# The compose file publishes KEYCLOAK_PORT, WALLET_PORT and APP_PORT with
# listen port == published port (see docker-compose.yml). The defaults live in
# the 9xxx range so they don't collide with a locally running oid4vc-dev
# wallet (8085) or Keycloak (8080); if one is taken anyway, pick the next free
# port instead of failing in `docker compose up`. Explicit overrides are
# validated but respected, and a port held by this project's own keycloak
# container counts as free so re-running the script reuses the binding.

port_listening() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

port_is_ours() {
  local mapping
  mapping="$(docker compose port keycloak "$1" 2>/dev/null || true)"
  [[ -n "${mapping}" && "${mapping}" != *:0 ]]
}

CLAIMED_PORTS=" "
port_free() {
  [[ "${CLAIMED_PORTS}" != *" $1 "* ]] || return 1
  ! port_listening "$1" || port_is_ours "$1"
}

resolve_port() { # resolve_port VAR DEFAULT [SPAN]
  local var="$1" def="$2" span="${3:-1}" port offset all_free
  if [[ -n "${!var:-}" ]]; then
    port="${!var}"
    for ((offset = 0; offset < span; offset++)); do
      if ! port_free "$((port + offset))"; then
        echo "${var}=${port} is set, but port $((port + offset)) is already in use." >&2
        exit 1
      fi
    done
  else
    port="${def}"
    while :; do
      all_free=true
      for ((offset = 0; offset < span; offset++)); do
        port_free "$((port + offset))" || { all_free=false; break; }
      done
      [[ "${all_free}" == "true" ]] && break
      port=$((port + 1))
    done
    if [[ "${port}" -ne "${def}" ]]; then
      echo "Port ${def} is already in use — using ${port} for ${var} instead."
    fi
  fi
  for ((offset = 0; offset < span; offset++)); do
    CLAIMED_PORTS+="$((port + offset)) "
  done
  printf -v "${var}" '%s' "${port}"
  export "${var}"
}

resolve_port KEYCLOAK_PORT 9080
# The wallet also serves HTTPS on WALLET_PORT+1 inside the shared network
# namespace (status-list endpoint), so it needs two consecutive ports.
resolve_port WALLET_PORT 9085 2
resolve_port APP_PORT 9090

# Wallet web-URL support in walletScheme is not released yet (> 0.6.4), so the
# extension jar is built from a local checkout of keycloak-extension-oid4vp.
# Once released, scripts/download-extension.sh takes over as the fallback.
EXTENSION_REPO="${KEYCLOAK_OID4VP_REPO:-${SCRIPT_DIR}/../../../keycloak-extension-oid4vp}"
if [[ ! -f providers/keycloak-extension-oid4vp.jar ]]; then
  if [[ -d "${EXTENSION_REPO}" ]] && command -v mvn >/dev/null 2>&1; then
    echo "Building keycloak-extension-oid4vp snapshot from ${EXTENSION_REPO}..."
    (cd "${EXTENSION_REPO}" && mvn -q -pl core -am package -DskipTests)
    cp "${EXTENSION_REPO}/core/target/keycloak-extension-oid4vp.jar" providers/
  elif ! ./scripts/download-extension.sh; then
    echo >&2
    echo "No local keycloak-extension-oid4vp checkout found and the download failed." >&2
    echo "Set KEYCLOAK_OID4VP_REPO to a checkout with wallet web-URL support (> 0.6.4)," >&2
    echo "or build the jar there (mvn -pl core -am package -DskipTests) and copy" >&2
    echo "core/target/keycloak-extension-oid4vp.jar into providers/." >&2
    exit 1
  fi
fi

echo "Exporting the wallet CA certificate for Keycloak's truststore..."
docker compose build wallet-init
current_ca="$(docker compose run --rm -T wallet-init wallet ca-cert)"
compose_up_flags=""
if [[ ! -f wallet-ca-cert.pem ]] || [[ "$(cat wallet-ca-cert.pem)" != "${current_ca}" ]]; then
  # The CA changes when the wallet volume is recreated; Keycloak only reads
  # the truststore at startup, so recreate the containers in that case.
  printf '%s\n' "${current_ca}" > wallet-ca-cert.pem
  compose_up_flags="--force-recreate"
fi

echo "Starting Keycloak, the wallet, and the demo UI..."
docker compose up -d --build ${compose_up_flags} keycloak wallet app

echo "Waiting for the services to become ready..."
docker compose run --rm --entrypoint sh demo /scripts/wait-ready.sh

echo "Configuring the verifier's wallet links (walletScheme, trustListUrl)..."
docker compose run --rm demo configure-wallet-links.py

if [[ "${SETUP_ONLY}" == "true" ]]; then
  echo
  echo "Setup complete. Run the demos with:"
  echo "  docker compose run --rm demo demo-issuance.py"
  echo "  docker compose run --rm demo demo-verification.py"
  exit 0
fi

echo
echo "=== Issuance via wallet URL ==="
docker compose run --rm demo demo-issuance.py

echo
echo "=== Verification via wallet URL ==="
docker compose run --rm demo demo-verification.py

echo
echo "Demo UI: http://localhost:${APP_PORT:-9090}"
