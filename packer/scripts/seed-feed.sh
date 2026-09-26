#!/usr/bin/env bash
# seed-feed.sh - ships a VT feed snapshot in the image (PLAN 4.3) and
# pre-warms the redis VT cache so the first boot does not spend 10+ minutes
# loading ~100k NASL scripts.
#
# Runs as root after install-openvas.sh (Packer VM: sudo -E; Dockerfile feed
# stage: IN_CONTAINER=1). Offline by design: nothing is fetched from the
# Greenbone network during an image build.
#
# Environment:
#   FEED_TARBALL      Path (or http(s) URL) of a tarball containing the VT feed
#                     tree, i.e. the directory that holds plugin_feed_info.inc
#                     and the *.nasl/*.inc files at any depth. CI fetches this
#                     from the control-plane feed mirror (FEED_TARBALL_URL
#                     secret) and Packer uploads it to /tmp/feed.tar. For a
#                     dev build, point it at a `greenbone-feed-sync`-produced
#                     tree or at a snapshot taken from the community rsync:
#                       rsync -ltvrP rsync://feed.community.greenbone.net/community/vulnerability-feed/22.04/vt-data/nasl/ ./nasl/
#                       tar -C . -czf vt-feed.tar.gz nasl
#                     Empty (or an empty file): skipped with a loud warning;
#                     the plugins dir stays empty and the heartbeat reports
#                     engine.vt_cache_loaded=false.
#   FEED_SHA256       optional sha256 of the tarball.
#   FEED_SKIP_PREWARM=1  copy the feed but do not build the redis cache.
#   IN_CONTAINER=1    no systemd: redis is started directly for the pre-warm.
set -euo pipefail

log() { printf '[seed-feed] %s\n' "$*"; }
warn() { printf '[seed-feed] WARNING: %s\n' "$*" >&2; }
die() { printf '[seed-feed] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"

FEED_TARBALL="${FEED_TARBALL:-}"
FEED_SHA256="${FEED_SHA256:-}"
FEED_SKIP_PREWARM="${FEED_SKIP_PREWARM:-0}"
IN_CONTAINER="${IN_CONTAINER:-0}"

PLUGINS_DIR=/var/lib/openvas/plugins
FEED_INFO=/var/lib/openvas/feed-info
REDIS_CONF=/etc/redis/redis-openvas.conf
REDIS_SOCK=/run/redis-openvas/redis.sock
OPENVAS=/usr/local/sbin/openvas
# How long the VT load may take (4 vCPU: typically 5-12 minutes).
PREWARM_TIMEOUT="${PREWARM_TIMEOUT:-3600}"

id openvas >/dev/null 2>&1 || die "openvas user missing; run install-openvas.sh first"
install -d -o openvas -g openvas -m 0755 /var/lib/openvas "$PLUGINS_DIR"

write_info() {
  # write_info <feed-version> <vt-count> <prewarmed yes|no>
  cat >"$FEED_INFO" <<EOF
feed_version=$1
vt_count=$2
vt_cache_prewarmed=$3
seeded_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
  chown openvas:openvas "$FEED_INFO"
  chmod 0644 "$FEED_INFO"
  if [[ -d /etc/appliance ]]; then
    printf '%s\n' "$1" >/etc/appliance/feed-version
    chmod 0644 /etc/appliance/feed-version
  fi
}

# ---------------------------------------------------------------------------
# 0. No feed: warn loudly, leave the directory empty.
# ---------------------------------------------------------------------------
if [[ -z "$FEED_TARBALL" || ( "$FEED_TARBALL" != http* && ! -s "$FEED_TARBALL" ) ]]; then
  cat >&2 <<'EOF'
[seed-feed] ==================================================================
[seed-feed] WARNING: no VT feed tarball supplied (FEED_TARBALL is empty or an
[seed-feed] empty file). The image ships WITHOUT vulnerability tests:
[seed-feed]   - /var/lib/openvas/plugins stays empty
[seed-feed]   - the redis VT cache is not pre-warmed
[seed-feed]   - heartbeats will report engine.vt_cache_loaded=false
[seed-feed] This is fine for a dev build; a release build must pass the feed.
[seed-feed] ==================================================================
EOF
  write_info none 0 no
  exit 0
fi

WORK="$(mktemp -d /var/tmp/seed-feed.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# 1. Obtain and verify the tarball
# ---------------------------------------------------------------------------
tarball="$FEED_TARBALL"
if [[ "$FEED_TARBALL" == http* ]]; then
  log "downloading feed tarball"
  tarball="$WORK/feed.tar"
  curl -fsSL --retry 3 --retry-delay 5 -o "$tarball" "$FEED_TARBALL" || die "download failed: $FEED_TARBALL"
fi
if [[ -n "$FEED_SHA256" ]]; then
  got="$(sha256sum "$tarball" | awk '{print $1}')"
  [[ "$got" == "$FEED_SHA256" ]] || die "feed tarball sha256 mismatch: got $got, want $FEED_SHA256"
  log "feed tarball sha256 verified"
fi

# ---------------------------------------------------------------------------
# 2. Extract and locate the feed root (the dir with plugin_feed_info.inc)
# ---------------------------------------------------------------------------
log "extracting $(du -h "$tarball" | cut -f1) tarball"
mkdir -p "$WORK/x"
tar -C "$WORK/x" -xf "$tarball" || die "tar extraction failed"
info="$(find "$WORK/x" -type f -name plugin_feed_info.inc -print -quit)"
[[ -n "$info" ]] || die "plugin_feed_info.inc not found anywhere in the tarball; is this a VT feed tree?"
src="$(dirname "$info")"
feed_version="$(sed -n 's/^PLUGIN_SET *= *"\([0-9]*\)".*/\1/p' "$info" | head -n1)"
[[ -n "$feed_version" ]] || feed_version="unknown"
vt_count="$(find "$src" -type f -name '*.nasl' | wc -l | tr -d ' ')"
log "feed version ${feed_version}, ${vt_count} NASL scripts at ${src#"$WORK/x"}"
(( vt_count > 1000 )) || die "only ${vt_count} .nasl files found; refusing to seed a truncated feed"

# ---------------------------------------------------------------------------
# 3. Install into /var/lib/openvas/plugins
# ---------------------------------------------------------------------------
log "installing feed into $PLUGINS_DIR"
find "$PLUGINS_DIR" -mindepth 1 -delete
cp -a "$src"/. "$PLUGINS_DIR"/
# Normalise ownership/permissions: openvas (Phase 3 user) owns the tree,
# everything else may read it.
chown -R openvas:openvas "$PLUGINS_DIR"
find "$PLUGINS_DIR" -type d -exec chmod 0755 {} +
find "$PLUGINS_DIR" -type f -exec chmod 0644 {} +
rm -rf "$WORK/x"

if [[ "$FEED_SKIP_PREWARM" == "1" ]]; then
  warn "FEED_SKIP_PREWARM=1: redis VT cache not built; first boot will load VTs"
  write_info "$feed_version" "$vt_count" no
  exit 0
fi

# ---------------------------------------------------------------------------
# 4. Pre-warm the redis VT cache and persist it as dump.rdb
# ---------------------------------------------------------------------------
[[ -x "$OPENVAS" ]] || die "$OPENVAS missing; run install-openvas.sh first"
[[ -f "$REDIS_CONF" ]] || die "$REDIS_CONF missing; run install-openvas.sh first"
redis_dir="$(awk '$1=="dir"{print $2}' "$REDIS_CONF")"
[[ -n "$redis_dir" ]] || die "no 'dir' in $REDIS_CONF"
install -d -o redis -g redis -m 0750 "$redis_dir"
rm -f "$redis_dir/dump.rdb"

redis_cli() { redis-cli -s "$REDIS_SOCK" "$@"; }

start_redis() {
  if [[ "$IN_CONTAINER" == "1" ]]; then
    install -d -o redis -g redis -m 0750 /run/redis-openvas
    runuser -u redis -- redis-server "$REDIS_CONF" --daemonize yes --supervised no \
      --logfile /var/tmp/seed-feed-redis.log
  else
    systemctl start redis-openvas.service
  fi
  local _i
  for _i in $(seq 1 60); do
    [[ "$(redis_cli ping 2>/dev/null || true)" == "PONG" ]] && return 0
    sleep 1
  done
  [[ -f /var/tmp/seed-feed-redis.log ]] && cat /var/tmp/seed-feed-redis.log >&2
  die "redis did not come up on $REDIS_SOCK"
}

stop_redis() {
  if [[ "$IN_CONTAINER" == "1" ]]; then
    # SHUTDOWN performs a final save when save points are configured.
    redis_cli shutdown >/dev/null 2>&1 || true
    local _i
    for _i in $(seq 1 60); do
      [[ -S "$REDIS_SOCK" ]] || return 0
      sleep 1
    done
    warn "redis still running after shutdown request"
  else
    systemctl stop redis-openvas.service
  fi
}

log "starting redis for the VT cache pre-warm"
start_redis
redis_cli flushall >/dev/null

log "loading VTs into redis (openvas --update-vt-info); this takes several minutes"
start_ts=$SECONDS
if ! timeout "$PREWARM_TIMEOUT" "$OPENVAS" --update-vt-info >"$WORK/update-vt-info.log" 2>&1; then
  tail -n 60 "$WORK/update-vt-info.log" >&2
  tail -n 60 /var/log/gvm/openvas.log 2>/dev/null >&2 || true
  stop_redis
  die "openvas --update-vt-info failed"
fi
log "VT load finished in $((SECONDS - start_ts))s"

# The nvticache lives in the first KB database (index 1); the 'nvticache' key
# carries the feed version openvas loaded. Informational only.
cached_version="$(redis_cli -n 1 get nvticache 2>/dev/null | tr -d '"' || true)"
cached_keys="$(redis_cli -n 1 dbsize 2>/dev/null | tr -dc '0-9' || true)"
log "redis db1: nvticache=${cached_version:-?} keys=${cached_keys:-?}"
if [[ -n "$cached_version" && "$feed_version" != "unknown" && "$cached_version" != "$feed_version" ]]; then
  warn "cached feed version ${cached_version} != plugin_feed_info ${feed_version}"
fi

log "saving the RDB snapshot"
save_out="$(redis_cli save 2>&1 || true)"
[[ "$save_out" == "OK" ]] || { stop_redis; die "redis SAVE failed: $save_out"; }
stop_redis
rm -f /var/tmp/seed-feed-redis.log

[[ -s "$redis_dir/dump.rdb" ]] || die "$redis_dir/dump.rdb missing or empty after save"
chown redis:redis "$redis_dir/dump.rdb"
chmod 0640 "$redis_dir/dump.rdb"
# openvas creates the feed lock as root; hand it to the openvas user.
[[ -e /var/lib/openvas/feed-update.lock ]] && chown openvas:openvas /var/lib/openvas/feed-update.lock
log "dump.rdb: $(du -h "$redis_dir/dump.rdb" | cut -f1); plugins: $(du -sh "$PLUGINS_DIR" | cut -f1)"

write_info "$feed_version" "$vt_count" yes
log "done"
