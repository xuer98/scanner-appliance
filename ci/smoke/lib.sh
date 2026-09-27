#!/usr/bin/env bash
# ci/smoke/lib.sh - helpers shared by run-qemu.sh and run-container.sh.
# Source it; do not execute. Needs bash >= 3.2 (macOS's works), curl and jq.
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
#   SMOKE_JOB_TARGETS  targets for the smoke scan job (default 127.0.0.1/32:
#                    the appliance scans itself, which needs no lab network)
#   SMOKE_JOB_TIMEOUT  seconds to wait for the smoke job to finish (300)
#   SMOKE_SKIP_JOBS=1  do not run the job round-trip (image without naabu)

CP_ADMIN_URL="${CP_ADMIN_URL:-https://127.0.0.1:9443}"
SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-180}"
SMOKE_ACK_TIMEOUT="${SMOKE_ACK_TIMEOUT:-150}"
SMOKE_ENGINE_TIMEOUT="${SMOKE_ENGINE_TIMEOUT:-300}"
SMOKE_VENDOR="${SMOKE_VENDOR:-smoke-vendor}"
SMOKE_SITE="${SMOKE_SITE:-smoke-site}"
# Loopback is included so the default smoke job (scan yourself) is in scope.
SMOKE_CIDRS="${SMOKE_CIDRS:-10.0.0.0/8,172.16.0.0/12,127.0.0.0/8}"
SMOKE_JOB_TARGETS="${SMOKE_JOB_TARGETS:-127.0.0.1/32}"
SMOKE_JOB_TIMEOUT="${SMOKE_JOB_TIMEOUT:-300}"

# Progress goes to stderr so helpers whose result is captured with $(...)
# (cp_create_appliance, cp_queue_directive, cp_create_job) return only the value.
smoke_log() { printf '[smoke] %s\n' "$*" >&2; }
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
  local -a args=()
  local a
  while IFS= read -r a; do args+=("$a"); done < <(smoke_curl_args)
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
  local -a args=()
  local a
  while IFS= read -r a; do args+=("$a"); done < <(smoke_curl_args)
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

# cp_directive_roundtrip <appliance_id>: set_interval + stop_all, wait for
# acks, then clear stop_all again so the appliance is not left halted.
cp_directive_roundtrip() {
  local id="$1" d1 d2 d3
  d1="$(cp_queue_directive "$id" set_interval '{"s":30}')"
  d2="$(cp_queue_directive "$id" stop_all '{}')"
  cp_wait_acked "$id" "$SMOKE_ACK_TIMEOUT" "$d1" "$d2"
  d3="$(cp_queue_directive "$id" stop_all '{"clear":true}')"
  cp_wait_acked "$id" "$SMOKE_ACK_TIMEOUT" "$d3"
}

# cp_create_job <appliance_id> <mode> <targets-csv> -> job id (run-now)
cp_create_job() {
  local id="$1" mode="$2" targets="$3" body resp jid
  body="$(jq -cn --arg a "$id" --arg m "$mode" --arg t "$targets" \
    '{appliance_id: $a, mode: $m, targets: ($t | split(",") | map(select(length > 0)))}')"
  resp="$(cp_api POST /admin/jobs "$body")" || smoke_die "POST /admin/jobs ($mode) failed"
  jid="$(jq -er '.id' <<<"$resp")" || smoke_die "no job id in: $resp"
  cp_api POST "/admin/jobs/${jid}/run-now" >/dev/null || smoke_die "run-now failed for $jid"
  smoke_log "created $mode job $jid (targets $targets)"
  printf '%s\n' "$jid"
}

# cp_wait_job <job_id> [timeout]: wait for a terminal status; done passes.
cp_wait_job() {
  local jid="$1" timeout="${2:-$SMOKE_JOB_TIMEOUT}"
  local deadline=$((SECONDS + timeout)) resp status last="" reason
  while (( SECONDS < deadline )); do
    if resp="$(cp_api GET "/admin/jobs/${jid}" 2>/dev/null)"; then
      status="$(jq -r '"\(.status) \(.phase // "") \(.progress_pct // 0)%"' <<<"$resp")"
      if [[ "$status" != "$last" ]]; then
        smoke_log "  job $jid: $status"
        last="$status"
      fi
      case "$(jq -r '.status' <<<"$resp")" in
        done)
          smoke_log "job $jid done: $(jq -c '.stats // {}' <<<"$resp")"
          return 0 ;;
        failed|rejected|cancelled)
          reason="$(jq -r '.reject_reason // ""' <<<"$resp")"
          smoke_die "job $jid ended $(jq -r '.status' <<<"$resp"): $reason" ;;
      esac
    fi
    sleep 5
  done
  smoke_die "job $jid not finished within ${timeout}s (last: ${last:-unknown})"
}

# cp_job_roundtrip <appliance_id>: PLAN §18.2 - a discovery job, then an
# inventory job when the engine is healthy. Results must land on the
# control plane (hosts for the job).
cp_job_roundtrip() {
  local id="$1" jid hosts
  if [[ "${SMOKE_SKIP_JOBS:-0}" == "1" ]]; then
    smoke_log "SMOKE_SKIP_JOBS=1: not running scan jobs"
    return 0
  fi
  jid="$(cp_create_job "$id" discovery "$SMOKE_JOB_TARGETS")"
  cp_wait_job "$jid"
  hosts="$(cp_api GET "/admin/jobs/${jid}/hosts" | jq 'length')"
  smoke_log "discovery job reported $hosts host(s)"
  if [[ "${SMOKE_SKIP_ENGINE:-0}" == "1" ]]; then
    smoke_log "SMOKE_SKIP_ENGINE=1: skipping the inventory job"
    return 0
  fi
  jid="$(cp_create_job "$id" inventory "$SMOKE_JOB_TARGETS")"
  cp_wait_job "$jid"
  hosts="$(cp_api GET "/admin/jobs/${jid}/hosts" | jq 'length')"
  smoke_log "inventory job reported $hosts host(s)"
}

# ---------------------------------------------------------------------------
# Phase 3: signature bundle delta (PLAN §13, §18.2 "apply a synthetic feed
# delta bundle") and the canary rollout (PLAN §14).
#
# Builds a small bundle on the host with `cp-api bundle build` (shipped scan
# configs + fragile ports; SMOKE_BUNDLE_FEED=1 adds a two-VT synthetic feed
# so a real engine reloads it), publishes it, makes the appliance a canary
# and waits until its heartbeat reports the bundle version. A second bundle
# with a changed config file exercises the delta path.
#
#   SMOKE_BUNDLE_TIMEOUT  seconds to wait for bundle_version (300)
#   SMOKE_SKIP_BUNDLE=1   skip
#   SMOKE_RELEASE_KEY     release signing key (dev/pki/release-key.pem)
# ---------------------------------------------------------------------------
SMOKE_BUNDLE_TIMEOUT="${SMOKE_BUNDLE_TIMEOUT:-300}"

# cp_build_bundle <out-dir> <version> <feed-version|""> -> stdout: version
cp_build_bundle() {
  local out="$1" version="$2" feedver="$3" root cfg feed
  smoke_require_tools go
  root="$(smoke_repo_root)"
  rm -rf "$out"; mkdir -p "$out"
  cfg="$out/configs"; mkdir -p "$cfg"
  # A config override that still passes policy (safe families only).
  cat >"$cfg/inventory.json" <<EOF
{"name":"inventory","families":["Web Servers","SSL and TLS"],"udp_ports":[161],"params":{"optimize_test":"1","smoke_version":"${version}"}}
EOF
  local args=(bundle build --out "$out/bundle" --configs "$cfg" --version "$version" --key "${SMOKE_RELEASE_KEY:-$root/dev/pki/release-key.pem}")
  if [[ -n "$feedver" ]]; then
    feed="$out/feed"; mkdir -p "$feed"
    printf 'PLUGIN_SET = "%s";\nPLUGIN_FEED = "Smoke Feed";\nFEED_VENDOR = "TPRM";\nFEED_HOME = "https://example.invalid";\nFEED_NAME = "SMOKE";\n' "$feedver" >"$feed/plugin_feed_info.inc"
    for n in 1 2; do
      cat >"$feed/smoke_${n}.nasl" <<EOF
if(description){
  script_oid("1.3.6.1.4.1.25623.1.0.99999${n}");
  script_version("2026-09-26T00:00:00+0000");
  script_name("Smoke test VT ${n}");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_tag(name:"summary", value:"smoke");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}
exit(0);
EOF
    done
    args+=(--feed "$feed")
  fi
  (cd "$root" && go run ./controlplane/cmd/cp-api "${args[@]}" >"$out/summary.json") || smoke_die "bundle build failed"
  smoke_log "built bundle $version ($(jq -r '.files' "$out/summary.json") files)"
  printf '%s\n' "$version"
}

# cp_publish_bundle <out-dir> [canary-hours]
cp_publish_bundle() {
  local out="$1" hours="${2:-48}" root
  root="$(smoke_repo_root)"
  local args=(admin publish-bundle --dir "$out/bundle" --canary-hours "$hours" --url "$CP_ADMIN_URL" --token "$CP_ADMIN_TOKEN")
  if [[ -n "${CP_CA_FILE:-}" ]]; then args+=(--ca "$CP_CA_FILE"); else args+=(--insecure); fi
  (cd "$root" && go run ./controlplane/cmd/cp-api "${args[@]}" >"$out/publish.json") || { cat "$out/publish.json" >&2; smoke_die "publish-bundle failed"; }
  smoke_log "published bundle $(jq -r '.version + " status=" + .status' "$out/publish.json")"
}

# cp_wait_bundle <appliance_id> <version> [timeout]
cp_wait_bundle() {
  local id="$1" want="$2" timeout="${3:-$SMOKE_BUNDLE_TIMEOUT}" deadline resp got err last=""
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if resp="$(cp_api GET "/admin/appliances/${id}" 2>/dev/null)"; then
      got="$(jq -r '.bundle_version // ""' <<<"$resp")"
      err="$(jq -r '.update_error // ""' <<<"$resp")"
      if [[ "$got $err" != "$last" ]]; then
        smoke_log "  bundle_version=${got:-<none>} update_error=${err:-<none>}"
        last="$got $err"
      fi
      [[ "$got" == "$want" ]] && return 0
      [[ -n "$err" && "$err" == bundle\ "$want":* ]] && smoke_die "appliance failed to apply bundle $want: $err"
    fi
    sleep 5
  done
  smoke_die "appliance did not report bundle $want within ${timeout}s"
}

# cp_bundle_roundtrip <appliance_id>: publish v1 to the canary, then a delta.
cp_bundle_roundtrip() {
  local id="$1" work v1 v2 feed1="" feed2=""
  if [[ "${SMOKE_SKIP_BUNDLE:-0}" == "1" ]]; then
    smoke_log "SMOKE_SKIP_BUNDLE=1: not testing bundles"
    return 0
  fi
  work="$(mktemp -d "${TMPDIR:-/tmp}/smoke-bundle.XXXXXX")"
  if [[ "${SMOKE_BUNDLE_FEED:-0}" == "1" ]]; then
    feed1="$(date -u +%Y%m%d%H%M)"; feed2="$((feed1 + 1))"
  fi
  cp_api PATCH "/admin/appliances/${id}" '{"canary":true}' >/dev/null || smoke_die "set canary failed"
  v1="$(cp_build_bundle "$work/v1" "smoke-$(date -u +%Y%m%dT%H%M%SZ)-1" "$feed1")"
  cp_publish_bundle "$work/v1"
  cp_wait_bundle "$id" "$v1"
  smoke_log "canary applied bundle $v1"
  v2="$(cp_build_bundle "$work/v2" "smoke-$(date -u +%Y%m%dT%H%M%SZ)-2" "$feed2")"
  cp_publish_bundle "$work/v2"
  cp_wait_bundle "$id" "$v2"
  smoke_log "delta bundle $v2 applied"
  cp_api GET /admin/bundles | jq -c '.[] | {version, status, installed, fleet}' | while read -r line; do smoke_log "  $line"; done
  rm -rf "$work"
}

# cp_lan_roundtrip <appliance_id>: split-network DoD (PLAN §20 Phase 3) - a
# discovery job against the no-egress LAN segment must find something.
#   SMOKE_LAN_TARGETS  the lan0 segment (run-qemu: 10.0.3.0/24)
#   SMOKE_SKIP_LAN=1   skip
cp_lan_roundtrip() {
  local id="$1" jid hosts
  if [[ "${SMOKE_SKIP_LAN:-0}" == "1" || -z "${SMOKE_LAN_TARGETS:-}" ]]; then
    smoke_log "no SMOKE_LAN_TARGETS: not testing the split-network segment"
    return 0
  fi
  jid="$(cp_create_job "$id" discovery "$SMOKE_LAN_TARGETS")"
  cp_wait_job "$jid"
  hosts="$(cp_api GET "/admin/jobs/${jid}/hosts" | jq 'length')"
  smoke_log "split-network discovery of $SMOKE_LAN_TARGETS reported $hosts host(s)"
  (( hosts >= 1 )) || smoke_die "no hosts found on the no-egress segment $SMOKE_LAN_TARGETS"
}
