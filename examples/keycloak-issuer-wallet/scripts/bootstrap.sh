#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-oid4vc-demo}"
OID4VCI_CLIENT_ID="${OID4VCI_CLIENT_ID:-oid4vc-demo-client}"
OID4VCI_CREDENTIAL_SCOPE="${OID4VCI_CREDENTIAL_SCOPE:-membership-credential}"
OID4VCI_USER="${OID4VCI_USER:-alice}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need curl
need jq

wait_for_endpoint() {
  local url="$1"
  for _ in $(seq 1 60); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "Keycloak did not become ready at ${url}" >&2
  exit 1
}

issuer_metadata_url="${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/.well-known/openid-credential-issuer"

echo "Waiting for Keycloak realm import at ${issuer_metadata_url}..."
wait_for_endpoint "${issuer_metadata_url}"

jq -er '.credential_issuer' < <(curl -fsS "${issuer_metadata_url}") >/dev/null

# Keycloak 26.7 issues an offer only for a credential the user actually holds
# (OID4VCUtil.hasVerifiableCredential checks a stored user record), so the user
# is assigned the credential here. Earlier versions did not need this. The
# assignment is an admin operation, and the master realm refuses admin auth over
# plain HTTP, so it runs through kcadm inside the container over the loopback.
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
KEYCLOAK_SERVICE="${KEYCLOAK_SERVICE:-keycloak}"
kcadm() { docker compose exec -T "${KEYCLOAK_SERVICE}" /opt/keycloak/bin/kcadm.sh "$@"; }

kcadm config credentials --server http://localhost:8080 \
  --realm master --user "${KEYCLOAK_ADMIN}" --password "${KEYCLOAK_ADMIN_PASSWORD}" >/dev/null

user_id="$(kcadm get users -r "${KEYCLOAK_REALM}" -q "username=${OID4VCI_USER}" -q exact=true \
  --fields id --format csv --noquotes | tr -d '\r')"

# A conflict means the user already holds it, which the re-runnable setup allows.
if ! kcadm create "users/${user_id}/vc/credentials" -r "${KEYCLOAK_REALM}" \
    -b "{\"credentialScopeName\":\"${OID4VCI_CREDENTIAL_SCOPE}\"}" >/dev/null 2>&1; then
  if ! kcadm get "users/${user_id}/vc/credentials" -r "${KEYCLOAK_REALM}" 2>/dev/null \
      | grep -q "${OID4VCI_CREDENTIAL_SCOPE}"; then
    echo "Failed to assign ${OID4VCI_CREDENTIAL_SCOPE} to ${OID4VCI_USER}" >&2
    exit 1
  fi
fi

echo
echo "Issuer metadata:"
echo "  ${issuer_metadata_url}"
echo
echo "Offer endpoint:"
echo "  ${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/oid4vc/create-credential-offer"
echo
echo "Ready:"
echo "  realm=${KEYCLOAK_REALM}"
echo "  user=${OID4VCI_USER}"
echo "  client=${OID4VCI_CLIENT_ID}"
echo "  credential_configuration_id=${OID4VCI_CREDENTIAL_SCOPE}"
