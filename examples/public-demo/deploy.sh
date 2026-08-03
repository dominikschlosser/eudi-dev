#!/usr/bin/env bash
# Deploy and operate a public demo host (see docs/public-demo.md).
#
# The target is configured, never hardcoded: set DEMO_HOST to an ssh
# destination (a ~/.ssh/config alias, user@host, or just a host). Values can
# live in a local deploy.env next to this script, which is gitignored:
#
#   DEMO_HOST=root@demo.example
#   DEMO_DIR=/opt/eudi-demo          # optional, this is the default
#   DEMO_URL=https://demo.example    # optional, enables the post-deploy check
#
# Usage: ./deploy.sh <command>
#   setup     install Docker, copy the stack, start it (first deployment)
#   push      copy Caddyfile, compose file and imprint, then apply them
#   update    pull the latest image and restart (no file changes)
#   status    container status and the version the site reports
#   logs      follow the wallet log
#   verify    check that the deployed endpoints respond
#   stats     print a usage summary from the access log
#   stats-password  generate credentials for the /stats report
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# shellcheck disable=SC1091
[[ -f deploy.env ]] && source deploy.env

DEMO_DIR="${DEMO_DIR:-/opt/eudi-demo}"
COMMAND="${1:-}"

die() { echo "error: $*" >&2; exit 1; }

require_host() {
  [[ -n "${DEMO_HOST:-}" ]] || die "DEMO_HOST is not set. Export it or create deploy.env (see the header of this script)."
}

# Run a command on the demo host inside the stack directory.
remote() {
  ssh "${DEMO_HOST}" "cd ${DEMO_DIR} && $*"
}

compose() {
  remote "docker compose $*"
}

copy_stack() {
  echo "Copying the stack to ${DEMO_HOST}:${DEMO_DIR}..."
  ssh "${DEMO_HOST}" "mkdir -p ${DEMO_DIR}"
  scp -q Caddyfile docker-compose.yml "${DEMO_HOST}:${DEMO_DIR}/"
  # The imprint carries the operator's real address, so it is never taken from
  # the repository (which only holds a placeholder). Keep yours in
  # imprint.local.html (gitignored); without it the host's copy is left alone.
  if [[ -f imprint.local.html ]]; then
    scp -q imprint.local.html "${DEMO_HOST}:${DEMO_DIR}/imprint.html"
  else
    echo "  no imprint.local.html, keeping the imprint already on the host"
  fi
  # Basic auth credentials for the /stats report live in stats.env, next to
  # the compose file, and never in the repository.
  [[ -f stats.env ]] && scp -q stats.env "${DEMO_HOST}:${DEMO_DIR}/stats.env"
}

deployed_version() {
  [[ -n "${DEMO_URL:-}" ]] || return 0
  curl -fsS --max-time 15 "${DEMO_URL%/}/api/version" 2>/dev/null |
    sed -n 's/.*"version":"\([^"]*\)".*/\1/p'
}

case "${COMMAND}" in
  setup)
    require_host
    echo "Installing Docker (skipped when already present)..."
    ssh "${DEMO_HOST}" "command -v docker >/dev/null || curl -fsSL https://get.docker.com | sh"
    copy_stack
    # The image runs as uid 1000, but Docker creates a named volume owned by
    # root, which makes the wallet crash-loop on a fresh host.
    echo "Preparing the wallet data volume..."
    remote "docker volume create eudi-demo_wallet-data >/dev/null && docker run --rm -v eudi-demo_wallet-data:/d alpine chown 1000:1000 /d >/dev/null"
    compose "up -d"
    echo
    echo "Deployed. Point your domain's A and AAAA records at this host if you have not yet:"
    ssh "${DEMO_HOST}" "hostname -I 2>/dev/null || true"
    ;;
  push)
    require_host
    copy_stack
    compose "up -d"
    ;;
  update)
    require_host
    compose "pull -q wallet" >/dev/null
    compose "up -d --quiet-pull" >/dev/null
    sleep 3
    compose "ps --format '{{.Name}} {{.Status}}'"
    version="$(deployed_version)"
    [[ -n "${version}" ]] && echo "Version now live: ${version}"
    ;;
  status)
    require_host
    compose "ps --format '{{.Name}} {{.Status}}'"
    version="$(deployed_version)"
    [[ -n "${version}" ]] && echo "Version reported by ${DEMO_URL}: ${version}"
    ;;
  logs)
    require_host
    compose "logs -f --tail 100 wallet"
    ;;
  stats)
    require_host
    # Let goaccess produce the summary: the log stores epoch timestamps, so
    # picking days apart with grep here would not work. Its CSV output uses
    # CRLF, hence the tr.
    summary="$(mktemp)"
    remote "docker compose exec -T stats sh -c 'goaccess /var/log/caddy/access.log --log-format=CADDY --ignore-crawlers -o /tmp/summary.csv >/dev/null 2>&1; cat /tmp/summary.csv'" |
      tr -d '\r' > "${summary}"
    sed -n 's/^"[0-9]*",,"general",,,,,,,,"\([^"]*\)","\([^"]*\)"$/\2 \1/p' "${summary}" |
      grep -E 'requests|visitors|log_size' |
      while read -r name value; do printf '%-18s %s\n' "${name}" "${value}"; done
    echo
    echo "Top requests (bots excluded):"
    sed -n 's/^"[0-9]*",,"requests","\([0-9]*\)".*,"\([^"]*\)"$/\1 \2/p' "${summary}" |
      head -12 | while read -r hits path; do printf '  %6s  %s\n' "${hits}" "${path}"; done
    rm -f "${summary}"
    [[ -n "${DEMO_URL:-}" ]] && echo && echo "Full report: ${DEMO_URL%/}/stats/"
    ;;
  stats-password)
    read -r -p "Username for /stats [admin]: " user
    user="${user:-admin}"
    read -r -s -p "Password: " password
    echo
    hash="$(docker run --rm caddy:2 caddy hash-password --plaintext "${password}")"
    # Compose interpolates env_file values, so a bcrypt hash's "$" has to be
    # written as "$$" to survive into the container.
    escaped="${hash//\$/\$\$}"
    printf 'STATS_USER=%s\nSTATS_PASSWORD_HASH=%s\n' "${user}" "${escaped}" > stats.env
    echo "Wrote stats.env (gitignored). Apply it with: ./deploy.sh push"
    ;;
  verify)
    [[ -n "${DEMO_URL:-}" ]] || die "DEMO_URL is not set, nothing to verify."
    base="${DEMO_URL%/}"
    failed=0
    for path in / /decoder/ /issuer/ /verifier/ /imprint /favicon.svg /logo.svg /api/trustlist; do
      code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "${base}${path}" || echo 000)"
      printf '%-16s %s\n' "${path}" "${code}"
      [[ "${code}" == "200" ]] || failed=1
    done
    [[ "${failed}" -eq 0 ]] || die "some endpoints did not return 200"
    echo "All endpoints healthy."
    ;;
  *)
    # Print the header comment block as usage.
    awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "${BASH_SOURCE[0]}"
    exit 1
    ;;
esac
