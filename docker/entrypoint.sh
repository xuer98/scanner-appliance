#!/usr/bin/env bash
# docker/entrypoint.sh - container entrypoint (PLAN 4.7).
#
# Phase 1 stop-gap: starts the redis instance and ospd-openvas in the
# background (when they are in the image) and then execs `applianced run`.
# In Phase 2 applianced supervises redis -> ospd-openvas -> job loop itself and
# this script collapses to the exec line. Because applianced becomes PID 1 the
# helpers are killed with the container; the pre-warmed VT cache is on disk in
# the /var/lib/openvas volume (redis dump.rdb), so nothing is lost on stop.
set -euo pipefail

log() { printf '[entrypoint] %s\n' "$*" >&2; }

REDIS_CONF=/etc/redis/redis-openvas.conf
REDIS_SOCK=/run/redis-openvas/redis.sock
OSPD=/opt/ospd/bin/ospd-openvas
OSPD_SOCK=/run/ospd/ospd.sock

if [[ -x /usr/bin/redis-server && -f "$REDIS_CONF" ]] && id redis >/dev/null 2>&1; then
  redis_dir="$(awk '$1=="dir"{print $2}' "$REDIS_CONF")"
  install -d -o redis -g redis -m 0750 /run/redis-openvas "${redis_dir:-/var/lib/openvas/redis}"
  # A bind-mounted or freshly created volume may not carry the image's
  # ownership; fix the small bits (the plugin tree is left alone).
  [[ -d /var/lib/openvas ]] && chown openvas:openvas /var/lib/openvas 2>/dev/null || true
  log "starting redis-openvas"
  runuser -u redis -- redis-server "$REDIS_CONF" --daemonize no --supervised no &
  for _ in $(seq 1 30); do
    [[ "$(redis-cli -s "$REDIS_SOCK" ping 2>/dev/null || true)" == "PONG" ]] && break
    sleep 1
  done
fi

if [[ -x "$OSPD" ]]; then
  install -d -m 0755 /run/ospd /var/log/gvm
  log "starting ospd-openvas"
  "$OSPD" --foreground --unix-socket "$OSPD_SOCK" --socket-mode 0o660 \
    --log-file /var/log/gvm/ospd-openvas.log --lock-file-dir /run/ospd \
    --pid-file /run/ospd/ospd-openvas.pid &
fi

exec /usr/local/bin/applianced run "$@"
