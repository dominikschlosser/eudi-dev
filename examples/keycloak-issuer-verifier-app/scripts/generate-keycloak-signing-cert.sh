#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KEY_PATH="${KEYCLOAK_SIGNING_KEY_PATH:-${SCENARIO_DIR}/keycloak-signing-key.pem}"
CERT_PATH="${KEYCLOAK_SIGNING_CERT_PATH:-${SCENARIO_DIR}/keycloak-signing-cert.pem}"
CA_KEY_PATH="${KEYCLOAK_SIGNING_CA_KEY_PATH:-${SCENARIO_DIR}/keycloak-signing-ca-key.pem}"
CA_CERT_PATH="${KEYCLOAK_SIGNING_CA_CERT_PATH:-${SCENARIO_DIR}/keycloak-signing-ca-cert.pem}"
SUBJECT="${KEYCLOAK_SIGNING_CERT_SUBJECT:-/CN=wallet-app-demo}"
CA_SUBJECT="${KEYCLOAK_SIGNING_CA_SUBJECT:-/CN=wallet-app-demo Issuer CA}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need openssl

if [[ -f "${KEY_PATH}" && -f "${CERT_PATH}" ]]; then
  echo "Using existing Keycloak signing key material:"
  echo "  ${KEY_PATH}"
  echo "  ${CERT_PATH}"
  exit 0
fi

mkdir -p "$(dirname "${KEY_PATH}")"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# A CA-issued leaf, because Keycloak refuses to issue an SD-JWT credential
# signed with a self-signed certificate. The realm signing key is the leaf; the
# credential references it by key id and the keycloak-realm-issuer trust
# provider verifies it against the realm's own published keys.
openssl req -x509 -newkey rsa:2048 -keyout "${CA_KEY_PATH}" -out "${CA_CERT_PATH}" \
  -sha256 -days 3650 -nodes -subj "${CA_SUBJECT}" >/dev/null 2>&1

openssl req -newkey rsa:2048 -keyout "${KEY_PATH}" -out "${work}/leaf.csr" \
  -sha256 -nodes -subj "${SUBJECT}" >/dev/null 2>&1

openssl x509 -req -in "${work}/leaf.csr" \
  -CA "${CA_CERT_PATH}" -CAkey "${CA_KEY_PATH}" -CAcreateserial \
  -sha256 -days 3650 -out "${CERT_PATH}" >/dev/null 2>&1

echo "Generated persistent CA-issued Keycloak signing key material:"
echo "  ${KEY_PATH}"
echo "  ${CERT_PATH}"
echo "  ${CA_CERT_PATH}"
