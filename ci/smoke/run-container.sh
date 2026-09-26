#!/usr/bin/env bash
# ci/smoke/run-container.sh - PLAN 18.2 smoke test for the container image,
# using docker/docker-compose.yml (db + cp-api + appliance).
#
#   ci/smoke/run-container.sh
#
# 1. Ensures the dev CA exists (ci/build.sh --dev) so the daemon image can be
#    built with an embedded root and cp-api uses the same CA.
# 2. Starts db + cp-api, waits for the admin API.
# 3. Creates an appliance row, writes the code into docker/.env, starts the
#    appliance service (-e APPLIANCE_CODE).
# 4. Waits for status=enrolled + heartbeat (+ engine health unless
#    SMOKE_SKIP_ENGINE=1), then queues set_interval and stop_all and waits
#    for the acks.
#
# The appliance service carries mem_limit 8g (docker-compose.yml): the Docker
# host needs at least that much free memory for the engine checks to pass.
#
# Environment (see also ci/smoke/lib.sh):
#   CP_ADMIN_TOKEN     defaults to dev-admin-token (matches docker/.env.example)
#   CP_ENROLL_PORT     host port of the enroll listener (8443), used by the
#                      appliance container (APPLIANCE_CP_URL)
#   CP_MTLS_PORT       host port of the mTLS listener (9443), which also
#                      serves the /admin API used here
#   SMOKE_KEEP=1       leave the stack running afterwards
#   SMOKE_NO_BUILD=1   do not (re)build images
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export CP_ADMIN_TOKEN="${CP_ADMIN_TOKEN:-dev-admin-token}"
export CP_ADMIN_URL="${CP_ADMIN_URL:-https://127.0.0.1:${CP_MTLS_PORT:-9443}}"
# shellcheck source=ci/smoke/lib.sh
source "$HERE/lib.sh"

smoke_require_tools docker curl jq
docker compose version >/dev/null 2>&1 || smoke_die "docker compose v2 is required"

COMPOSE=(docker compose -f "$ROOT/docker/docker-compose.yml")
ENV_FILE="$ROOT/docker/.env"

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "----- cp-api logs -----" >&2
    "${COMPOSE[@]}" logs --no-color --tail=100 cp-api >&2 || true
    echo "----- appliance logs -----" >&2
    "${COMPOSE[@]}" logs --no-color --tail=100 appliance >&2 || true
  fi
  if [[ "${SMOKE_KEEP:-0}" == "1" ]]; then
    smoke_log "stack left running (SMOKE_KEEP=1)"
  else
    smoke_log "tearing down the stack"
    "${COMPOSE[@]}" --profile appliance down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  exit $rc
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Dev CA + embedded root
# ---------------------------------------------------------------------------
if [[ ! -s "$ROOT/dev/pki/root.pem" || ! -s "$ROOT/daemon/internal/pki/roots.pem" ]]; then
  smoke_log "preparing development CA"
  smoke_require_tools go
  (cd "$ROOT" && ci/build.sh --dev --arch "$(go env GOARCH)" --skip-cp >/dev/null)
fi

# docker/.env: start from the example, keep the token consistent.
if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ROOT/docker/.env.example" "$ENV_FILE"
fi
set_env() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i.bak "s|^${key}=.*|${key}=${val}|" "$ENV_FILE" && rm -f "${ENV_FILE}.bak"
  else
    printf '%s=%s\n' "$key" "$val" >>"$ENV_FILE"
  fi
}
set_env CP_ADMIN_TOKEN "$CP_ADMIN_TOKEN"
set_env CP_ENROLL_PORT "${CP_ENROLL_PORT:-8443}"
set_env CP_MTLS_PORT "${CP_MTLS_PORT:-9443}"
set_env APPLIANCE_CODE ""

# ---------------------------------------------------------------------------
# 2. Control plane
# ---------------------------------------------------------------------------
build_flag=(--build)
[[ "${SMOKE_NO_BUILD:-0}" == "1" ]] && build_flag=()
smoke_log "starting db + cp-api"
"${COMPOSE[@]}" up -d ${build_flag[@]+"${build_flag[@]}"} db cp-api
cp_wait_ready 120

# ---------------------------------------------------------------------------
# 3. Appliance
# ---------------------------------------------------------------------------
read -r APPLIANCE_ID CODE < <(cp_create_appliance)
smoke_log "created appliance $APPLIANCE_ID"
set_env APPLIANCE_CODE "$CODE"

smoke_log "starting the appliance container"
"${COMPOSE[@]}" up -d ${build_flag[@]+"${build_flag[@]}"} appliance

# ---------------------------------------------------------------------------
# 4. Enrollment, heartbeat, directives
# ---------------------------------------------------------------------------
cp_wait_enrolled "$APPLIANCE_ID" "$SMOKE_TIMEOUT"
cp_directive_roundtrip "$APPLIANCE_ID"

# The container path has no console; the TTY test lives in run-qemu.sh.
smoke_log "PASS: container appliance $APPLIANCE_ID enrolled and directives acked"
