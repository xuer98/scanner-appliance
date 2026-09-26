#!/usr/bin/env bash
# cleanup.sh - PLAN 4.4 plus removal of every build-time access path.
#
# Runs last, as root, over the Packer SSH session. At the end the "packer" user
# is gone, openssh-server is purged, root is locked and the machine powers off
# on its own (transient systemd timer) because nothing that needs sudo can run
# once the invoking user has been deleted.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
log() { printf '[cleanup] %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
  echo "cleanup.sh must run as root" >&2
  exit 1
fi
cd /

# ---------------------------------------------------------------------------
# Packages: drop build-only tooling and installer leftovers.
# ---------------------------------------------------------------------------
log "purging openssh-server and build-time packages"
apt-get purge -y -q openssh-server openssh-sftp-server 2>/dev/null || true
rm -rf /etc/ssh/ssh_host_* /etc/ssh/sshd_config.d /run/sshd

# openvas build toolchain: install-openvas.sh recorded every build-only
# package in this marker; the runtime libraries it needs are apt-marked
# manual so autoremove keeps them. The redis dump with the pre-warmed VT
# cache (/var/lib/redis-openvas/dump.rdb) and /var/lib/openvas are kept.
BUILD_DEPS_MARKER=/etc/appliance/openvas-build-deps.list
if [[ -s "$BUILD_DEPS_MARKER" ]]; then
  log "purging openvas build dependencies"
  mapfile -t build_deps < <(grep -v '^#' "$BUILD_DEPS_MARKER" | sed '/^[[:space:]]*$/d')
  if ! apt-get purge -y -q "${build_deps[@]}" >/dev/null 2>&1; then
    for p in "${build_deps[@]}"; do
      dpkg -s "$p" >/dev/null 2>&1 && apt-get purge -y -q "$p" >/dev/null 2>&1 || true
    done
  fi
  rm -f "$BUILD_DEPS_MARKER"
  # Headers, pkg-config files and static archives are useless without a
  # compiler; the shared libraries in /usr/local/lib stay.
  rm -rf /usr/local/include/gvm /usr/local/include/openvas /usr/local/lib/pkgconfig \
    /usr/local/lib/cmake /usr/local/src/openvas-build 2>/dev/null || true
  find /usr/local/lib -maxdepth 1 -name '*.a' -delete 2>/dev/null || true
  ldconfig
fi
# pip leftovers inside and outside the ospd venv.
rm -rf /root/.cache/pip /opt/ospd/share/python-wheels 2>/dev/null || true
find /opt/ospd -type d -name '.cache' -prune -exec rm -rf {} + 2>/dev/null || true

apt-get autoremove -y -q --purge
apt-get clean
for svc in redis-openvas.service ospd-openvas.service; do
  systemctl is-enabled "$svc" >/dev/null 2>&1 || log "NOTE: $svc is not enabled"
done

# ---------------------------------------------------------------------------
# Accounts: no interactive users, root locked.
# ---------------------------------------------------------------------------
log "removing the packer build user"
rm -f /etc/sudoers.d/90-packer
if id packer >/dev/null 2>&1; then
  # -f: the user still owns this SSH session; that is fine, the session
  # survives and the processes keep running as uid 1000.
  userdel -f -r packer 2>/dev/null || userdel -f packer
fi
rm -rf /home/packer

log "locking root"
passwd -l root >/dev/null
usermod -s /usr/sbin/nologin root 2>/dev/null || true
# Belt and braces: no password hash for anyone.
awk -F: '$2 != "*" && $2 != "!" && $2 != "!*" {print $1}' /etc/shadow | while read -r u; do
  usermod -p '!' "$u"
done

# ---------------------------------------------------------------------------
# Identity: every deployed appliance must get its own machine-id, DHCP
# client ID, and journal.
# ---------------------------------------------------------------------------
log "clearing machine identity"
truncate -s0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id
rm -rf /var/lib/systemd/network/* /var/lib/dhcp/* 2>/dev/null || true
rm -f /var/lib/systemd/random-seed
rm -rf /var/lib/systemd/timers/* 2>/dev/null || true
rm -f /etc/hostname
echo "appliance" >/etc/hostname

# ---------------------------------------------------------------------------
# Logs, caches, history, temp files.
# ---------------------------------------------------------------------------
log "clearing logs and caches"
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
rm -rf /var/log/journal/* /run/log/journal/* 2>/dev/null || true
find /var/log -type f -name '*.gz' -delete
find /var/log -type f -name '*.[0-9]' -delete
find /var/log -type f -exec truncate -s0 {} +
rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /var/cache/apt/archives/*.deb
rm -rf /var/cache/debconf/*-old /var/lib/dpkg/*-old
rm -rf /tmp/* /var/tmp/* 2>/dev/null || true
rm -f /root/.bash_history /root/.lesshst /root/.viminfo /root/.wget-hsts
rm -rf /root/.cache /root/.local /root/.ssh
unset HISTFILE
# Installer state and the preseed answers (they contain the build password).
rm -rf /var/log/installer /var/lib/preseed 2>/dev/null || true
find / -xdev \( -name 'preseed.cfg' -o -name '.bash_history' \) -type f -delete 2>/dev/null || true

# cloud-init is not installed, but make sure nothing else re-seeds ssh.
rm -rf /var/lib/cloud 2>/dev/null || true

# ---------------------------------------------------------------------------
# Free space: discard so the qcow2 (and the OVA) stay small.
# ---------------------------------------------------------------------------
log "trimming free space"
sync
if fstrim -av >/dev/null 2>&1; then
  log "fstrim done"
else
  log "fstrim unsupported; zero-filling free space instead"
  for mp in / /boot /var; do
    dd if=/dev/zero of="${mp%/}/zero.fill" bs=1M status=none 2>/dev/null || true
    rm -f "${mp%/}/zero.fill"
  done
  # Swap: recreate it zeroed so it carries no build-time data.
  if swap_dev="$(awk '$2=="swap"{print $1}' /etc/fstab | head -n1)" && [[ -n "$swap_dev" ]]; then
    swap_path="$swap_dev"
    case "$swap_dev" in
      UUID=*) swap_path="/dev/disk/by-uuid/${swap_dev#UUID=}" ;;
    esac
    if [[ -b "$swap_path" ]]; then
      uuid="$(blkid -s UUID -o value "$swap_path" || true)"
      swapoff "$swap_path" 2>/dev/null || true
      dd if=/dev/zero of="$swap_path" bs=1M status=none 2>/dev/null || true
      if [[ -n "$uuid" ]]; then mkswap -U "$uuid" "$swap_path" >/dev/null; else mkswap "$swap_path" >/dev/null; fi
    fi
  fi
fi
sync

# ---------------------------------------------------------------------------
# Power off. The SSH session's user no longer exists, so Packer cannot run a
# privileged shutdown_command; schedule the power-off from here instead. The
# timer is a system unit and is unaffected by the SSH session going away.
# ---------------------------------------------------------------------------
log "scheduling power-off"
systemd-run --quiet --on-active=15 --timer-property=AccuracySec=1s \
  --unit=appliance-build-poweroff /bin/systemctl poweroff
log "done; powering off in 15 s"
