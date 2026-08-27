#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-oid4vc-demo}"
OID4VCI_CLIENT_ID="${OID4VCI_CLIENT_ID:-oid4vc-demo-client}"
OID4VCI_CREDENTIAL_SCOPE="${OID4VCI_CREDENTIAL_SCOPE:-membership-credential}"
OID4VCI_USER="${OID4VCI_USER:-alice}"
OID4VCI_USER_PASSWORD="${OID4VCI_USER_PASSWORD:-alice}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need curl
need jq

curl_common() {
  if [[ "${KEYCLOAK_BASE_URL}" == https://* ]] && [[ -n "${KEYCLOAK_CA_CERT:-}" ]] && [[ -f "${KEYCLOAK_CA_CERT}" ]]; then
    curl --cacert "${KEYCLOAK_CA_CERT}" "$@"
  else
    curl "$@"
  fi
}

USER_TOKEN="$(
  curl_common -fsS \
    -X POST "${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${OID4VCI_CLIENT_ID}" \
    -d "username=${OID4VCI_USER}" \
    -d "password=${OID4VCI_USER_PASSWORD}" \
    -d "scope=openid ${OID4VCI_CREDENTIAL_SCOPE}" \
    | jq -er '.access_token'
)"

OFFER_JSON="$(
  curl_common -fsS \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/oid4vc/create-credential-offer?credential_configuration_id=${OID4VCI_CREDENTIAL_SCOPE}&pre_authorized=true&type=uri"
)"

ISSUER="$(printf '%s' "$OFFER_JSON" | jq -er '.issuer')"
NONCE="$(printf '%s' "$OFFER_JSON" | jq -er '.nonce')"
PUBLIC_ISSUER="$(
  jq -rn \
    --arg issuer "${ISSUER}" \
    --arg base "${KEYCLOAK_BASE_URL%/}" \
    '$issuer | sub("^[A-Za-z][A-Za-z0-9+.-]*://[^/]+"; $base)'
)"
RAW_OFFER_URI="${PUBLIC_ISSUER%/}/${NONCE#/}"
INLINE_OFFER_JSON="$(
  curl_common -fsS "${RAW_OFFER_URI}" \
    | jq -c --arg base "${KEYCLOAK_BASE_URL%/}" '
        .credential_issuer |= sub("^[A-Za-z][A-Za-z0-9+.-]*://[^/]+"; $base)
      '
)"
ENCODED_OFFER_JSON="$(jq -rn --arg offer "$INLINE_OFFER_JSON" '$offer|@uri')"

printf 'openid-credential-offer://?credential_offer=%s\n' "$ENCODED_OFFER_JSON"
