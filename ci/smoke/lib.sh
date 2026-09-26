#!/usr/bin/env bash
# ci/smoke/lib.sh - helpers shared by run-qemu.sh and run-container.sh.
# Source it; do not execute. Needs bash >= 4 (mapfile), curl and jq.
#
# Environment:
#   CP_ADMIN_URL     base URL of the cp-api /admin API (default https://127.0.0.1:9443).
#                    The admin API is served on the mTLS listener (:9443) with
#                    a bearer token; no client certificate is needed. The
#                    enroll listener (:8443) is what the appliance talks to
#                    (CP_URL_FOR_GUEST / APPLIANCE_CP_URL), not this.
#   CP_ADMIN_TOKEN   bearer token (required)
#   CP_CA_FILE       PEM to verify the control plane's TLS cert; defaults to
#                    dev/pki/root.pem when present. SMOKE_INSECURE=1 disables
#                    verification (dev only).
#   SMOKE_VENDOR / SMOKE_SITE / SMOKE_CIDRS   appliance row metadata
#   SMOKE_TIMEOUT    seconds to wait for enrollment + first heartbeat (180)
#   SMOKE_ACK_TIMEOUT seconds to wait for directive acks (150)
#   SMOKE_ENGINE_TIMEOUT seconds to wait for engine.ospd_up and
#                    engine.vt_cache_loaded in the heartbeat (300)
#   SMOKE_SKIP_ENGINE=1  do not require the engine checks (image built
#                    without a feed, or engine not yet wired)

CP_ADMIN_URL="${CP_ADMIN_URL:-https://127.0.0.1:9443}"
SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-180}"
SMOKE_ACK_TIMEOUT="${SMOKE_ACK_TIMEOUT:-150}"
SMOKE_ENGINE_TIMEOUT="${SMOKE_ENGINE_TIMEOUT:-300}"
SMOKE_VENDOR="${SMOKE_VENDOR:-smoke-vendor}"
SMOKE_SITE="${SMOKE_SITE:-smoke-site}"
SMOKE_CIDRS="${SMOKE_CIDRS:-10.0.0.0/8}"

smoke_log() { printf '[smoke] %s\n' "$*"; }
smoke_die() { printf '[smoke] FAIL: %s\n' "$*" >&2; exit 1; }

smoke_require_tools() {
  local t
  for t in "$@"; do
    command -v "$t" >/dev/null || smoke_die "missing tool: $t"
  done
}

smoke_repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

smoke_curl_args() {
  # Prints the curl TLS/auth arguments, one per line.
  [[ -n "${CP_ADMIN_TOKEN:-}" ]] || smoke_die "CP_ADMIN_TOKEN is not set"
  printf '%s\n' -sS --max-time 15 -H "Authorization: Bearer ${CP_ADMIN_TOKEN}" -H "Content-Type: application/json"
  local ca="${CP_CA_FILE:-}"
  if [[ -z "$ca" && -s "$(smoke_repo_root)/dev/pki/root.pem" ]]; then
    ca="$(smoke_repo_root)/dev/pki/root.pem"
  fi
  if [[ "${SMOKE_INSECURE:-0}" == "1" ]]; then
    printf '%s\n' -k
  elif [[ -n "$ca" ]]; then
    printf '%s\n' --cacert "$ca"
  fi
}

# cp_api <METHOD> <path> [json body]  -> body on stdout; non-2xx fails.
cp_api() {
  local method="$1" path="$2" body="${3:-}"
  local -a args
  mapfile -t args < <(smoke_curl_args)
  local out code
  if [[ -n "$body" ]]; then
    out="$(curl "${args[@]}" -X "$method" --data "$body" -w '\n%{http_code}' "${CP_ADMIN_URL}${path}")" || return 1
  else
    out="$(curl "${args[@]}" -X "$method" -w '\n%{http_code}' "${CP_ADMIN_URL}${path}")" || return 1
  fi
  code="${out##*$'\n'}"
  out="${out%$'\n'*}"
  if [[ "$code" != 2* ]]; then
    printf '%s\n' "$out" >&2
    return 1
  fi
  printf '%s' "$out"
}

# cp_wait_ready [timeout]: wait until the admin API answers at all.
cp_wait_ready() {
  local timeout="${1:-90}" deadline=$((SECONDS + ${1:-90}))
  local -a args
  mapfile -t args < <(smoke_curl_args)
  smoke_log "waiting up to ${timeout}s for ${CP_ADMIN_URL}"
  while (( SECONDS < deadline )); do
    local code
    code="$(curl "${args[@]}" -o /dev/null -w '%{http_code}' "${CP_ADMIN_URL}/admin/appliances/probe" 2>/dev/null || true)"
    case "$code" in
      2*|400|401|403|404|405) return 0 ;;
    esac
    sleep 2
  done
  smoke_die "control plane at ${CP_ADMIN_URL} did not become ready"
}

# cp_create_appliance -> "<appliance_id> <code>"
cp_create_appliance() {
  local cidrs body resp
  cidrs="$(printf '%s' "$SMOKE_CIDRS" | jq -R 'split(",") | map(select(length > 0))')"
  body="$(jq -cn --arg v "$SMOKE_VENDOR" --arg s "$SMOKE_SITE" --argjson c "$cidrs" '{vendor: $v, site: $s, allowed_cidrs: $c}')"
  resp="$(cp_api POST /admin/appliances "$body")" || smoke_die "POST /admin/appliances failed"
  local id code
  id="$(jq -er '.appliance_id' <<<"$resp")" || smoke_die "no appliance_id in: $resp"
  code="$(jq -er '.code' <<<"$resp")" || smoke_die "no code in: $resp"
  printf '%s %s\n' "$id" "$code"
}

# cp_wait_enrolled <appliance_id> [timeout]
cp_wait_enrolled() {
  local id="$1" timeout="${2:-$SMOKE_TIMEOUT}"
  local deadline=$((SECONDS + timeout)) resp status hb last=""
  smoke_log "waiting up to ${timeout}s for $id to enroll and heartbeat"
  while (( SECONDS < deadline )); do
    if resp="$(cp_api GET "/admin/appliances/${id}" 2>/dev/null)"; then
      status="$(jq -r '.status // empty' <<<"$resp")"
      hb="$(jq -r '.last_heartbeat_at // empty' <<<"$resp")"
      if [[ "$status $hb" != "$last" ]]; then
        smoke_log "  status=${status:-?} last_heartbeat_at=${hb:-none}"
        last="$status $hb"
      fi
      if [[ "$status" == "enrolled" && -n "$hb" && "$hb" != "null" ]]; then
        smoke_log "enrolled with heartbeat after $((SECONDS - deadline + timeout))s"
        cp_wait_engine "$id"
        return 0
      fi
    fi
    sleep 5
  done
  smoke_die "appliance $id did not reach status=enrolled with a heartbeat within ${timeout}s"
}

# cp_wait_engine <appliance_id> [timeout]: after enrollment, require the
# heartbeat's engine health (PLAN 20, Phase 1 definition of done):
#   last_heartbeat.engine = {ospd_up, vt_cache_loaded, vt_count, openvas_version}
# Both flags must be true unless SMOKE_SKIP_ENGINE=1. The first heartbeats
# can precede ospd finishing its VT cache check, so this polls.
cp_wait_engine() {
  local id="$1" timeout="${2:-$SMOKE_ENGINE_TIMEOUT}"
  if [[ "${SMOKE_SKIP_ENGINE:-0}" == "1" ]]; then
    smoke_log "SMOKE_SKIP_ENGINE=1: not checking engine health"
    return 0
  fi
  local deadline=$((SECONDS + timeout)) resp engine last=""
  smoke_log "waiting up to ${timeout}s for engine.ospd_up and engine.vt_cache_loaded"
  while (( SECONDS < deadline )); do
    if resp="$(cp_api GET "/admin/appliances/${id}" 2>/dev/null)"; then
      engine="$(jq -c '.last_heartbeat.engine // empty' <<<"$resp")"
      if [[ "$engine" != "$last" ]]; then
        smoke_log "  engine=${engine:-absent}"
        last="$engine"
      fi
      if [[ -n "$engine" ]] && jq -e '.ospd_up == true and .vt_cache_loaded == true' <<<"$engine" >/dev/null; then
        smoke_log "engine ready: $(jq -r '"openvas \(.openvas_version // "?"), \(.vt_count // 0) VTs"' <<<"$engine")"
        return 0
      fi
    fi
    sleep 5
  done
  smoke_die "engine not healthy within ${timeout}s (last engine=${last:-absent}); set SMOKE_SKIP_ENGINE=1 for images built without a feed"
}

# cp_queue_directive <appliance_id> <type> <payload-json> -> directive id
cp_queue_directive() {
  local id="$1" type="$2" payload="${3:?payload json required}"
  local body resp did
  body="$(jq -cn --arg t "$type" --argjson p "$payload" '{type: $t, payload: $p}')"
  resp="$(cp_api POST "/admin/appliances/${id}/directives" "$body")" || smoke_die "queueing $type failed"
  did="$(jq -er '.id' <<<"$resp")" || smoke_die "no directive id in: $resp"
  smoke_log "queued $type as $did"
  printf '%s\n' "$did"
}

# cp_wait_acked <appliance_id> <timeout> <directive_id>...
cp_wait_acked() {
  local id="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout)) resp pending
  while (( SECONDS < deadline )); do
    if resp="$(cp_api GET "/admin/appliances/${id}/directives" 2>/dev/null)"; then
      pending=""
      local d acked
      for d in "$@"; do
        acked="$(jq -r --arg d "$d" '
          (if type == "array" then . else (.directives // .items // []) end)
          | map(select(.id == $d)) | .[0].acked_at // empty' <<<"$resp")"
        [[ -n "$acked" && "$acked" != "null" ]] || pending="$pending $d"
      done
      if [[ -z "$pending" ]]; then
        smoke_log "all directives acked"
        return 0
      fi
    fi
    sleep 5
  done
  smoke_die "directives not acked within ${timeout}s:${pending:-}"
}

# cp_directive_roundtrip <appliance_id>: set_interval + stop_all, wait for acks.
cp_directive_roundtrip() {
  local id="$1" d1 d2
  d1="$(cp_queue_directive "$id" set_interval '{"s":30}')"
  d2="$(cp_queue_directive "$id" stop_all '{}')"
  cp_wait_acked "$id" "$SMOKE_ACK_TIMEOUT" "$d1" "$d2"
}
