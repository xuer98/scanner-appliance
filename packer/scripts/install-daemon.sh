#!/usr/bin/env bash
# install-daemon.sh - installs applianced and the scan-engine binaries that the
# Packer file provisioners uploaded to /tmp, creates the appliance directories
# and enables the service. Runs as root inside the Packer VM.
set -euo pipefail

log() { printf '[install-daemon] %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
  echo "install-daemon.sh must run as root" >&2
  exit 1
fi

DAEMON_SRC="${DAEMON_SRC:-/tmp/applianced}"
ENGINE_SRC="${ENGINE_SRC:-/tmp/engine}"

# ---------------------------------------------------------------------------
# applianced
# ---------------------------------------------------------------------------
if [[ ! -s "$DAEMON_SRC" ]]; then
  echo "daemon binary not found at $DAEMON_SRC" >&2
  exit 1
fi
log "installing /usr/local/bin/applianced"
install -o root -g root -m 0755 "$DAEMON_SRC" /usr/local/bin/applianced
rm -f "$DAEMON_SRC"

if ! /usr/local/bin/applianced version >/dev/null 2>&1; then
  echo "applianced version failed; wrong architecture or broken binary?" >&2
  exit 1
fi
log "installed $(/usr/local/bin/applianced version 2>/dev/null | head -n1)"

# ---------------------------------------------------------------------------
# Scan engine binaries (optional in Phase 1)
# ---------------------------------------------------------------------------
install -d -o root -g root -m 0755 /opt/engine
if [[ -d "$ENGINE_SRC" ]]; then
  count=0
  # The file provisioner may upload either the directory itself or its
  # contents depending on the trailing slash; handle both layouts.
  while IFS= read -r -d '' f; do
    install -o root -g root -m 0755 "$f" "/opt/engine/$(basename "$f")"
    count=$((count + 1))
  done < <(find "$ENGINE_SRC" -maxdepth 2 -type f -print0)
  log "installed $count engine binaries to /opt/engine"
  rm -rf "$ENGINE_SRC"
else
  log "no engine directory at $ENGINE_SRC; /opt/engine left empty"
fi

# ---------------------------------------------------------------------------
# Directories and static files
# ---------------------------------------------------------------------------
log "creating state and config directories"
install -d -o root -g root -m 0700 /var/lib/appliance
install -d -o root -g root -m 0755 /etc/appliance
install -d -o root -g root -m 0755 /run/appliance

if [[ ! -s /etc/appliance/oss-notices.txt ]]; then
  cat >/etc/appliance/oss-notices.txt <<'EOF'
Open source notices - Scanner Appliance
=======================================

This appliance is built on Debian GNU/Linux 12 (https://www.debian.org) and
ships the following third-party components. Full licence texts are
available at the URLs below and on the transparency page in the portal.

Detection engine (Greenbone Community Edition)
  openvas-scanner  GPL-2.0-or-later  https://github.com/greenbone/openvas-scanner
  gvm-libs         GPL-2.0-or-later  https://github.com/greenbone/gvm-libs
  ospd-openvas     AGPL-3.0-or-later https://github.com/greenbone/ospd-openvas
  Greenbone Community Feed (vulnerability tests in /var/lib/openvas/plugins)
                   ODbL 1.0          https://www.greenbone.net/en/community-feed/
                   Copyright Greenbone AG. Redistributed with attribution; any
                   database derived from it is shared under the same terms.
  redis            BSD-3-Clause      https://github.com/redis/redis
                   (Debian 12 ships redis 7.0, the last BSD-licensed line;
                   redis 7.4+ moved to RSALv2/SSPL and is not used)

Written offer for source code: the exact source archives (pinned release tags
listed in /etc/appliance/openvas-build-info.txt) and our build scripts are
available from the transparency page or on request from the programme owner
for three years from distribution of this image (GPL-2.0 section 3 / AGPL-3.0
section 6).

Discovery and port scanning
  naabu            MIT               https://github.com/projectdiscovery/naabu

Web add-on (Phase 3; not present in this image unless enabled)
  httpx            MIT               https://github.com/projectdiscovery/httpx
  nuclei           MIT               https://github.com/projectdiscovery/nuclei
  nuclei-templates MIT               https://github.com/projectdiscovery/nuclei-templates
  fingerprintx     Apache-2.0        https://github.com/praetorian-inc/fingerprintx
  zgrab2           Apache-2.0        https://github.com/zmap/zgrab2

Platform
  open-vm-tools    GPL-2.0/LGPL      https://github.com/vmware/open-vm-tools
  htpdate          GPL-2.0           https://github.com/twekkel/htpdate

Debian package licences: /usr/share/doc/<package>/copyright.
The complete SBOM for this image is published alongside the release.
EOF
fi
chmod 0644 /etc/appliance/oss-notices.txt

if [[ -n "${APPLIANCE_VERSION:-}" ]]; then
  echo "$APPLIANCE_VERSION" >/etc/appliance/image-version
  chmod 0644 /etc/appliance/image-version
fi

# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------
if [[ ! -f /etc/systemd/system/applianced.service ]]; then
  echo "/etc/systemd/system/applianced.service missing; run harden.sh first" >&2
  exit 1
fi
systemctl daemon-reload
systemctl enable applianced.service
log "done"
