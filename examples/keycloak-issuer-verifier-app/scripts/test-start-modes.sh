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
assert_contains "$START_SH" "oid4vc-dev wallet serve --docker --port"
assert_not_contains "$START_SH" "oid4vc-dev wallet serve --pid"
assert_not_contains "$START_SH" "/api/trustlists/pid"
assert_contains "$START_SH" "WALLET_UI_URL=\"http://localhost:\${wallet_port}/\""
assert_contains "$START_SH" "start_public_proxy"
assert_contains "$START_SH" "start_local_wallet"
assert_contains "$START_SH" "auto)"
assert_contains "$START_SH" "sandbox_material_available"
assert_contains "$START_SH" "find_worktree_sandbox_file"
assert_contains "$START_SH" "git -C \"\${REPO_ROOT}\" worktree list --porcelain"
assert_contains "$START_SH" "sandbox-ngrok-combined.pem"
assert_contains "$START_SH" "sandbox-verifier-info.json"
assert_contains "$START_SH" 'trust_mode="metadata"'
assert_contains "$START_SH" 'trust_mode="trustlist"'
assert_contains "$START_SH" 'export OID4VP_TRUST_LIST_URL="${public_base_url%/}/keycloak-trustlist.jwt"'
assert_contains "$START_SH" 'export OID4VP_TRUST_MODE="${OID4VP_TRUST_MODE:-${trust_mode}}"'

assert_contains "$BOOTSTRAP_SH" ".config.enforceHaip = (if \$public_wallet_flag == \"true\" then \"true\" else \"false\" end)"
assert_contains "$BOOTSTRAP_SH" 'OID4VP_TRUST_MODE="${OID4VP_TRUST_MODE:-metadata}"'
assert_contains "$BOOTSTRAP_SH" ".config.responseMode = (if \$public_wallet_flag == \"true\" then \"direct_post.jwt\" else \"direct_post\" end)"
assert_contains "$BOOTSTRAP_SH" ".config.clientIdScheme = (if \$public_wallet_flag == \"true\" then \"x509_hash\" else \"plain\" end)"
assert_contains "$BOOTSTRAP_SH" ".config |= del(.x509CertificatePem, .verifierInfo)"

echo "start mode contract checks passed"
