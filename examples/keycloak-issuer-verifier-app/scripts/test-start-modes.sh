#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
START_SH="${SCENARIO_DIR}/start.sh"
BOOTSTRAP_SH="${SCRIPT_DIR}/bootstrap.sh"

assert_contains() {
  local file="$1"
  local expected="$2"

  if ! grep -Fq -- "$expected" "$file"; then
    echo "Expected ${file#${SCENARIO_DIR}/} to contain:" >&2
    echo "  ${expected}" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local unexpected="$2"

  if grep -Fq -- "$unexpected" "$file"; then
    echo "Expected ${file#${SCENARIO_DIR}/} not to contain:" >&2
    echo "  ${unexpected}" >&2
    exit 1
  fi
}

assert_contains "$START_SH" "--ngrok"
assert_contains "$START_SH" "--no-ngrok"
assert_contains "$START_SH" 'ngrok_mode="${OID4VP_NGROK:-auto}"'
assert_contains "$START_SH" "--ngrok) ngrok_mode=\"true\" ;;"
assert_contains "$START_SH" "--no-ngrok) ngrok_mode=\"false\" ;;"
assert_not_contains "$START_SH" "public_mode="
assert_not_contains "$START_SH" "local_wallet_mode="
assert_not_contains "$START_SH" "--public)"
assert_not_contains "$START_SH" "--local-wallet)"
assert_contains "$START_SH" "--wallet-port"
assert_contains "$START_SH" "eudi wallet serve --docker --port"
assert_not_contains "$START_SH" "eudi wallet serve --pid"
assert_not_contains "$START_SH" "/api/trustlists/pid"
assert_contains "$START_SH" "WALLET_UI_URL=\"http://localhost:\${wallet_port}/\""
assert_contains "$START_SH" "resolve_wallet_port_pair"
assert_contains "$START_SH" "wallet_port_pair_available"
assert_contains "$START_SH" "candidate + 1"
assert_contains "$START_SH" '${APP_PORT:-8090}'
assert_contains "$START_SH" "start_public_proxy"
assert_contains "$START_SH" "start_local_wallet"
assert_contains "$START_SH" "start_keycloak_logs"
assert_contains "$START_SH" 'docker compose "${compose_args[@]}" logs -f --tail=80 keycloak'
assert_contains "$START_SH" 'docker compose "${compose_args[@]}" down -v --remove-orphans'
assert_contains "$START_SH" "eudi proxy"
assert_contains "$START_SH" "--target \"http://127.0.0.1:\${route_proxy_port}\""
assert_contains "$START_SH" 'ngrok_override="$(mktemp -t keycloak-issuer-verifier-app-ngrok.XXXXXX.yml)"'
assert_contains "$START_SH" "example_detect_ngrok_domain_from_pem \"\${sandbox_pem_path}\""
assert_contains "$START_SH" "wait_for_public_app"
assert_contains "$START_SH" "auto)"
assert_contains "$START_SH" "sandbox_material_available"
assert_contains "$START_SH" "find_worktree_sandbox_file"
assert_contains "$START_SH" "git -C \"\${REPO_ROOT}\" worktree list --porcelain"
assert_contains "$START_SH" "sandbox-ngrok-combined.pem"
assert_contains "$START_SH" "sandbox-verifier-info.json"
assert_contains "$START_SH" 'trust_mode="metadata"'
assert_contains "$START_SH" 'trust_mode="trustlist"'
assert_contains "$START_SH" 'export OID4VP_TRUST_LIST_URL="${public_base_url%/}/keycloak-trustlist.jwt"'
assert_contains "$START_SH" 'export OID4VP_TRUST_MODE="${trust_mode}"'

assert_contains "$BOOTSTRAP_SH" ".config.enforceHaip = \"true\""
assert_contains "$BOOTSTRAP_SH" 'OID4VP_TRUST_MODE="${OID4VP_TRUST_MODE:-metadata}"'
assert_contains "$BOOTSTRAP_SH" ".config.walletScheme = \"haip-vp://\""
assert_contains "$BOOTSTRAP_SH" ".config.responseMode = \"direct_post.jwt\""
assert_contains "$BOOTSTRAP_SH" ".config.clientIdScheme = \"x509_hash\""
assert_contains "$BOOTSTRAP_SH" "require_file \"\${sandbox_pem_path}\""
assert_contains "$BOOTSTRAP_SH" ".config.x509CertificatePem = \$sandbox_pem"
assert_contains "$BOOTSTRAP_SH" "normalize_credential_scope \"\${OID4VCI_CREDENTIAL_SCOPE}\""
assert_contains "$BOOTSTRAP_SH" '.attributes |= del(."vc.credential_identifier")'

echo "start mode contract checks passed"
