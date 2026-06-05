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

assert_contains "$START_SH" "--local-wallet"
assert_contains "$START_SH" "--wallet-port"
assert_contains "$START_SH" "oid4vc-dev wallet serve --pid --docker --port"
assert_contains "$START_SH" "http://host.docker.internal:\${wallet_port}/api/trustlists/pid"
assert_contains "$START_SH" "WALLET_UI_URL=\"http://localhost:\${wallet_port}/\""

assert_contains "$BOOTSTRAP_SH" ".config.enforceHaip = (if \$public_wallet_flag == \"true\" then \"true\" else \"false\" end)"
assert_contains "$BOOTSTRAP_SH" ".config.responseMode = (if \$public_wallet_flag == \"true\" then \"direct_post.jwt\" else \"direct_post\" end)"
assert_contains "$BOOTSTRAP_SH" ".config.clientIdScheme = (if \$public_wallet_flag == \"true\" then \"x509_hash\" else \"plain\" end)"
assert_contains "$BOOTSTRAP_SH" ".config |= del(.x509CertificatePem, .verifierInfo)"

echo "start mode contract checks passed"
