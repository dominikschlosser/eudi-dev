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
#   rollback [version]  put the previous release back (or a named one, e.g.
#             v1.19.16). Without an argument it uses the release that was live
#             before the last push or update
#   status    container status and the version the site reports
#   logs      follow the wallet log
#   verify    check that the deployed endpoints respond
#   stats     print a usage summary from the access log (pages and API calls)
#   stats-reset     discard the access log and rebuild the report from zero
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
  scp -q Caddyfile Dockerfile docker-compose.yml "${DEMO_HOST}:${DEMO_DIR}/"
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

# The release the site reports is the same string the image is tagged with
# (the release workflow tags the image with the git tag), so what is live can
# be recorded and put back without a lookup.
record_running_version() {
  local version
  version="$(deployed_version)"
  [[ -n "${version}" ]] || return 0
  remote "printf '%s\n' '${version}' > .last-version"
}

previous_version() {
  remote "cat .last-version 2>/dev/null" || true
}

# WALLET_TAG lives in the host's .env, which is where compose reads variables
# for interpolation. Other variables in that file are left alone.
set_wallet_tag() {
  local tag="$1"
  if [[ -z "${tag}" ]]; then
    remote "touch .env && sed -i.bak '/^WALLET_TAG=/d' .env && rm -f .env.bak"
  else
    remote "touch .env && sed -i.bak '/^WALLET_TAG=/d' .env && rm -f .env.bak && printf 'WALLET_TAG=%s\n' '${tag}' >> .env"
  fi
}

apply_stack() {
  compose "pull -q wallet" >/dev/null
  # --build keeps the Caddy image in step with the Dockerfile (the rate
  # limiting plugin is compiled into it). Layer caching makes it a no-op when
  # nothing changed.
  compose "up -d --build --quiet-pull" >/dev/null
  sleep 3
  compose "ps --format '{{.Name}} {{.Status}}'"
  local version
  version="$(deployed_version)"
  if [[ -n "${version}" ]]; then
    echo "Version now live: ${version}"
  fi
  # An explicit success: without DEMO_URL there is no version to report, and
  # the caller must not read that as a failed deployment.
  return 0
}

# The pin currently in effect on the host, empty when the newest release runs.
current_wallet_tag() {
  remote "sed -n 's/^WALLET_TAG=//p' .env 2>/dev/null" || true
}

# The pin only does something if the compose file on the host reads
# WALLET_TAG. A host deployed before rollback existed still has one with a
# fixed tag, where writing the pin changes nothing and the demo quietly stays
# where it is. Only the image line differs, so the file can be brought up to
# date without touching how the wallet is run.
ensure_pinnable_compose() {
  if remote "grep -q WALLET_TAG docker-compose.yml 2>/dev/null"; then
    return 0
  fi
  echo "  the compose file on the host cannot pin a release, copying the current one..."
  scp -q docker-compose.yml "${DEMO_HOST}:${DEMO_DIR}/"
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
    compose "up -d --build"
    echo
    echo "Deployed. Point your domain's A and AAAA records at this host if you have not yet:"
    ssh "${DEMO_HOST}" "hostname -I 2>/dev/null || true"
    ;;
  push)
    require_host
    record_running_version
    copy_stack
    # Pull first: the compose file can use flags a released image does not
    # know yet (a wall-clock --demo-reset once crash-looped the wallet this
    # way), and recreating containers against a stale image is the one way
    # push can take the demo down.
    apply_stack
    ;;
  update)
    require_host
    record_running_version
    # An update after a rollback has to leave the pin behind, or it would keep
    # serving the release that was rolled back to.
    set_wallet_tag ""
    apply_stack
    ;;

  rollback)
    require_host
    target="${2:-}"
    if [[ -z "${target}" ]]; then
      target="$(previous_version)"
      [[ -n "${target}" ]] || die "no recorded previous version. Pass one: ./deploy.sh rollback v1.19.16"
    fi
    current="$(deployed_version)"
    if [[ -n "${current}" && "${target}" == "${current}" ]]; then
      die "${target} is already live, nothing to roll back to."
    fi
    echo "Rolling back${current:+ from ${current}} to ${target}..."
    record_running_version
    ensure_pinnable_compose
    previous_tag="$(current_wallet_tag)"
    set_wallet_tag "${target}"
    # Pulling after the pin is set is what tests the release being asked for.
    # A tag that was never published (an aborted release, a typo) must leave
    # the running demo alone rather than take it down.
    if ! compose "pull -q wallet" >/dev/null 2>&1; then
      set_wallet_tag "${previous_tag}"
      die "ghcr.io/dominikschlosser/eudi-dev:${target} could not be pulled, so nothing was changed. Check that the release exists."
    fi
    apply_stack
    live="$(deployed_version)"
    if [[ -n "${live}" && "${live}" != "${target}" ]]; then
      die "asked for ${target} but ${live} is live. Check that the tag names a published release (the image is ghcr.io/dominikschlosser/eudi-dev:${target}), then ./deploy.sh logs."
    fi
    echo "Rolled back to ${target}. ./deploy.sh update returns to the newest release."
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
    # Pages only. The API paths are listed separately below, because they
    # outnumber page requests and would bury them.
    echo "Top pages (bots excluded, API calls omitted):"
    sed -n 's/^"[0-9]*",,"requests","\([0-9]*\)".*,"\([^"]*\)"$/\1 \2/p' "${summary}" |
      grep -v '/api/' |
      head -10 | while read -r hits path; do printf '  %6s  %s\n' "${hits}" "${path}"; done

    # The API is where the demo is actually used: every credential issued,
    # presented, imported or deleted goes through it, whether it came from the
    # UI, from an external wallet, or from someone's test suite.
    api="$(sed -n 's/^"[0-9]*",,"requests","\([0-9]*\)".*,"\([^"]*\)"$/\1 \2/p' "${summary}" | grep '/api/' || true)"
    if [[ -n "${api}" ]]; then
      echo
      echo "Top API calls (bots excluded):"
      echo "${api}" | head -10 | while read -r hits path; do printf '  %6s  %s\n' "${hits}" "${path}"; done
      # Reads are mostly the UI polling itself. What is left is what somebody
      # did, which is the number worth reading.
      writes="$(echo "${api}" | grep -E '^[0-9]+ +(POST|PUT|PATCH|DELETE)\b' || true)"
      if [[ -n "${writes}" ]]; then
        echo
        echo "API calls that changed something:"
        echo "${writes}" | head -10 | while read -r hits path; do printf '  %6s  %s\n' "${hits}" "${path}"; done
      fi
    fi
    rm -f "${summary}"
    [[ -n "${DEMO_URL:-}" ]] && echo && echo "Full report: ${DEMO_URL%/}/stats/"
    ;;
  stats-reset)
    require_host
    read -r -p "Discard the access log and every past statistic? [y/N] " confirm
    [[ "${confirm}" =~ ^[yY]$ ]] || die "aborted"
    # Truncate in place and drop the rolled files, then restart Caddy so its
    # log writer starts over from a known size.
    remote "docker compose exec -T caddy sh -c 'rm -f /var/log/caddy/access-*.log*; : > /var/log/caddy/access.log'"
    compose "restart caddy" >/dev/null
    if [[ -n "${DEMO_URL:-}" ]]; then
      # One request so the log is not empty, otherwise the report generator
      # skips its run and /stats keeps showing the old numbers.
      curl -fsS -o /dev/null --max-time 15 --retry 5 --retry-delay 2 --retry-connrefused "${DEMO_URL%/}/api/version" || true
    fi
    remote "docker compose exec -T stats sh -c 'goaccess /var/log/caddy/access.log --log-format=CADDY --ignore-crawlers --anonymize-ip --html-report-title=\"Demo usage\" -o /srv/stats/report.html'" >/dev/null 2>&1 || true
    echo "Access log cleared, report rebuilt."
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
