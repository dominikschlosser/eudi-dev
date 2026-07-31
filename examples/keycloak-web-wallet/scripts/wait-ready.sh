#!/bin/sh
# Waits until Keycloak has imported both realms and the wallet is serving.
# Runs inside the compose network (see start.sh).
set -eu

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:9080}"
WALLET_BASE_URL="${WALLET_BASE_URL:-http://localhost:9085}"

wait_for() {
  url="$1"
  name="$2"
  i=0
  while ! curl -fs -o /dev/null "$url" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
      echo "Timed out waiting for $name at $url" >&2
      exit 1
    fi
    sleep 2
  done
  echo "$name is ready."
}

wait_for "$KEYCLOAK_BASE_URL/realms/oid4vc-demo/.well-known/openid-credential-issuer" "Keycloak issuer realm"
wait_for "$KEYCLOAK_BASE_URL/realms/wallet-demo/.well-known/openid-configuration" "Keycloak verifier realm"
wait_for "$WALLET_BASE_URL/api/credentials" "Wallet"
