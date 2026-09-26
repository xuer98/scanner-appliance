#!/usr/bin/env bash
# docker/entrypoint.sh - container entrypoint (PLAN 4.7).
#
# applianced supervises redis-openvas and ospd-openvas itself when
# APPLIANCE_SUPERVISE_ENGINE=1 (there is no systemd in the container), so
# this script only prepares the runtime directories a fresh or bind-mounted
# volume may lack and then execs the daemon as PID 1.
set -euo pipefail

REDIS_CONF=/etc/redis/redis-openvas.conf

if id redis >/dev/null 2>&1 && [[ -f "$REDIS_CONF" ]]; then
  redis_dir="$(awk '$1=="dir"{print $2}' "$REDIS_CONF")"
  install -d -o redis -g redis -m 0750 /run/redis-openvas "${redis_dir:-/var/lib/openvas/redis}"
fi
install -d -m 0755 /run/ospd /var/log/gvm /run/appliance
install -d -m 0700 /var/lib/appliance
# A bind-mounted volume may not carry the image's ownership; fix the small
# bits (the plugin tree is left alone).
[[ -d /var/lib/openvas ]] && chown openvas:openvas /var/lib/openvas 2>/dev/null || true

export APPLIANCE_SUPERVISE_ENGINE="${APPLIANCE_SUPERVISE_ENGINE:-1}"
exec /usr/local/bin/applianced run "$@"
