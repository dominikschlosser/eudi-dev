#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
require_oid4vc_dev() {
  if command -v oid4vc-dev >/dev/null 2>&1; then
    return 0
  fi
  echo "oid4vc-dev not found in PATH. Install it first or run ./start.sh." >&2
  exit 1
}

require_oid4vc_dev
OFFER_URI="$("${SCRIPT_DIR}/create-offer.sh")"

echo "Redeeming offer:"
echo "  ${OFFER_URI}"

eudi wallet accept "${OFFER_URI}"

echo
echo "Stored credentials:"
eudi wallet list
