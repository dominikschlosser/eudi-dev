#!/usr/bin/env bash
set -euo pipefail

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SCENARIO_DIR}/../.." && pwd)"

need go
export APP_HOST="${APP_HOST:-127.0.0.1}"
export APP_PORT="${APP_PORT:-8090}"
export APP_BASE_URL="${APP_BASE_URL:-http://127.0.0.1:${APP_PORT}}"
export KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
export KEYCLOAK_REALM="${KEYCLOAK_REALM:-wallet-app-demo}"
export APP_CLIENT_ID="${APP_CLIENT_ID:-wallet-app}"
export APP_REDIRECT_URI="${APP_REDIRECT_URI:-${APP_BASE_URL%/}/callback}"

cd "${REPO_ROOT}"
exec go run ./examples/keycloak-issuer-verifier-app/app
