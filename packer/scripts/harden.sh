#!/usr/bin/env bash
# harden.sh - PLAN 4.3. Runs as root inside the Packer VM (Debian 12).
#
# Firewall, console lock-down, GRUB password, sysctl, systemd-networkd with
# deterministic NIC names (wan0/lan0), htpdate, unattended-upgrades (security
# pocket via the control-plane apt mirror), the self-update guard and the
# applianced.service unit. Idempotent: safe to re-run.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

log() { printf '[harden] %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
  echo "harden.sh must run as root" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------
log "installing packages"
apt-get update -q
apt-get install -y -q --no-install-recommends \
  nftables systemd-resolved htpdate util-linux ca-certificates open-vm-tools \
  unattended-upgrades

# ifupdown / NetworkManager / chrony: not wanted; networkd + htpdate instead.
for pkg in ifupdown network-manager chrony isc-dhcp-client; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    log "purging $pkg"
    apt-get purge -y -q "$pkg"
  fi
done
rm -f /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null || true
systemctl disable --now systemd-timesyncd.service 2>/dev/null || true
systemctl mask systemd-timesyncd.service 2>/dev/null || true

# ---------------------------------------------------------------------------
# Firewall (nftables)
# ---------------------------------------------------------------------------
log "writing /etc/nftables.conf"
cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
# Scanner appliance firewall (PLAN 4.3).
# input: default drop. Raw-socket scanners (naabu SYN mode) capture replies at
# the device layer before netfilter, so dropping here does not break scanning;
# it also stops the kernel answering probe replies with RSTs.
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    iif "lo" accept
    ct state established,related accept
    ct state invalid drop

    # ICMP echo replies to our own probes; IPv6 neighbour discovery so the
    # link stays usable.
    ip protocol icmp icmp type echo-reply accept
    ip6 nexthdr icmpv6 icmpv6 type { echo-reply, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }

  chain output {
    type filter hook output priority filter; policy accept;
  }
}
EOF
chmod 0644 /etc/nftables.conf
nft -c -f /etc/nftables.conf
systemctl enable nftables.service

# ---------------------------------------------------------------------------
# Console: only tty1 (and the serial console) exist, and they run the daemon's
# menu instead of a login prompt.
# ---------------------------------------------------------------------------
log "locking down consoles"
install -d -m 0755 /etc/systemd/logind.conf.d
cat >/etc/systemd/logind.conf.d/10-appliance.conf <<'EOF'
[Login]
NAutoVTs=0
ReserveVT=0
EOF

for n in 2 3 4 5 6; do
  systemctl mask "getty@tty${n}.service" "autovt@tty${n}.service" 2>/dev/null || true
done

install -d -m 0755 /etc/systemd/system/getty@tty1.service.d
cat >/etc/systemd/system/getty@tty1.service.d/10-appliance.conf <<'EOF'
[Service]
# The console menu is part of applianced; no login(1) on tty1.
ExecStart=
ExecStart=-/usr/local/bin/applianced tty
Type=idle
StandardInput=tty
StandardOutput=tty
StandardError=journal
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes
Restart=always
RestartSec=1
EOF
systemctl enable getty@tty1.service

# systemd-getty-generator instantiates serial-getty@ttyS0 for the
# "console=ttyS0" kernel argument (used by the CI smoke test and available to
# vendors on KVM). Serve the same menu there rather than a login prompt.
install -d -m 0755 /etc/systemd/system/serial-getty@.service.d
cat >/etc/systemd/system/serial-getty@.service.d/10-appliance.conf <<'EOF'
[Service]
ExecStart=
ExecStart=-/usr/local/bin/applianced tty
Type=idle
StandardInput=tty
StandardOutput=tty
StandardError=journal
TTYPath=/dev/%I
Restart=always
RestartSec=1
EOF

# ---------------------------------------------------------------------------
# Boot: GRUB superuser password (locks the editor and the command line;
# normal boot entries stay unrestricted), no recovery/rescue paths.
# ---------------------------------------------------------------------------
log "configuring GRUB"
GRUB_PASSWORD="${GRUB_PASSWORD:-}"
if [[ -z "$GRUB_PASSWORD" ]]; then
  # Random and discarded: nobody, including us, can edit boot entries on
  # shipped images. Pass GRUB_PASSWORD at build time for a known value.
  GRUB_PASSWORD="$(head -c 48 /dev/urandom | base64 | tr -d '\n=/+')"
fi
GRUB_HASH="$(printf '%s\n%s\n' "$GRUB_PASSWORD" "$GRUB_PASSWORD" \
  | grub-mkpasswd-pbkdf2 | awk '/PBKDF2 hash of your password is/ {print $NF}')"
if [[ "$GRUB_HASH" != grub.pbkdf2.sha512.* ]]; then
  echo "grub-mkpasswd-pbkdf2 did not produce a hash" >&2
  exit 1
fi
unset GRUB_PASSWORD

cat >/etc/grub.d/09_appliance <<EOF
#!/bin/sh
# Installed by packer/scripts/harden.sh. Sets a GRUB superuser so the menu
# editor ("e") and the command line ("c") require a password. Menu entries
# generated by 10_linux carry --unrestricted (see the sed below) so the
# appliance still boots without interaction.
exec tail -n +7 "\$0"
set superusers="appliance"
password_pbkdf2 appliance ${GRUB_HASH}
export superusers
EOF
chmod 0755 /etc/grub.d/09_appliance

# Make the generated Linux entries bootable without the password. Debian's
# 10_linux builds every menuentry line from ${CLASS}; appending --unrestricted
# there is the documented way to do this (the "Advanced options" submenu and
# its recovery entries stay password-protected).
if ! grep -q -- '--unrestricted' /etc/grub.d/10_linux; then
  sed -i 's/^CLASS="--class gnu-linux --class gnu --class os"$/CLASS="--class gnu-linux --class gnu --class os --unrestricted"/' /etc/grub.d/10_linux
fi
grep -q -- '--unrestricted' /etc/grub.d/10_linux || {
  echo "failed to mark GRUB entries --unrestricted" >&2
  exit 1
}

# No recovery entries, short timeout, keep the serial console set by preseed.
sed -i 's/^#\?GRUB_DISABLE_RECOVERY=.*/GRUB_DISABLE_RECOVERY="true"/' /etc/default/grub
grep -q '^GRUB_DISABLE_RECOVERY=' /etc/default/grub || echo 'GRUB_DISABLE_RECOVERY="true"' >>/etc/default/grub
sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=1/' /etc/default/grub
grep -q '^GRUB_TIMEOUT_STYLE=' /etc/default/grub || echo 'GRUB_TIMEOUT_STYLE=hidden' >>/etc/default/grub
update-grub

# ---------------------------------------------------------------------------
# Hybrid boot (Phase 5, PLAN 4.1 Hyper-V/KVM variants). The installer ran in
# BIOS mode and put grub-pc into the bios_grub partition; add the UEFI
# loader so the same disk boots on Hyper-V Generation 2 (UEFI, Secure Boot
# with the "Microsoft UEFI Certificate Authority" template), KVM with OVMF
# and VMware EFI firmware:
#   EFI/debian/ - shim (Microsoft-signed) + Debian-signed GRUB + the stub
#                 grub.cfg the signed image looks for at that fixed path
#   EFI/BOOT/   - the removable-media fallback every firmware tries first,
#                 because no NVRAM boot entry survives an image copy
# --no-nvram keeps this build VM's firmware variables untouched. The
# preseed created the ESP as a plain FAT32 partition (partman-efi is not
# available to a BIOS-mode installer); the ESP flag is set here.
# ---------------------------------------------------------------------------
log "installing the UEFI boot loader (hybrid BIOS + UEFI)"
apt-get install -y -q --no-install-recommends grub-efi-amd64-bin grub-efi-amd64-signed shim-signed parted
esp_dev="$(findmnt -no SOURCE /boot/efi 2>/dev/null || true)"
if [[ -z "$esp_dev" ]]; then
  echo "/boot/efi is not mounted: the preseed must create the EFI system partition" >&2
  exit 1
fi
esp_disk="/dev/$(lsblk -no PKNAME "$esp_dev")"
esp_part="$(cat "/sys/class/block/$(basename "$esp_dev")/partition")"
parted -s "$esp_disk" set "$esp_part" esp on
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --uefi-secure-boot --no-nvram
grub-install --target=x86_64-efi --efi-directory=/boot/efi --uefi-secure-boot --no-nvram --removable
grub-install --target=i386-pc "$esp_disk"
update-grub
for f in /boot/efi/EFI/BOOT/BOOTX64.EFI /boot/efi/EFI/debian/grubx64.efi /boot/efi/EFI/debian/shimx64.efi /boot/efi/EFI/debian/grub.cfg; do
  [[ -s "$f" ]] || { echo "UEFI loader incomplete: $f missing" >&2; exit 1; }
done
log "UEFI loader installed on $esp_dev (ESP flag set on $esp_disk partition $esp_part)"

systemctl mask rescue.target emergency.target rescue.service emergency.service
# Also block the debug shell and the sysrq keys.
systemctl mask debug-shell.service 2>/dev/null || true

# ---------------------------------------------------------------------------
# Kernel
# ---------------------------------------------------------------------------
log "writing sysctl"
cat >/etc/sysctl.d/90-appliance.conf <<'EOF'
# Scanner appliance (PLAN 4.3)
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
EOF
sysctl -q -p /etc/sysctl.d/90-appliance.conf || true

# ---------------------------------------------------------------------------
# Networking: systemd-networkd + resolved, NICs named wan0 / lan0.
#
# NIC naming approach
# -------------------
# The daemon and the vendor docs talk about "wan0" (egress) and "lan0" (the
# scanned segment). The rule is: the NIC with the lowest PCI address is wan0,
# the next one is lan0. Two mechanisms implement it:
#
#  1. systemd .link files (10-wan0.link, 20-lan0.link) match the udev ID_PATH
#     of the NIC. They list the PCI paths that VMware (first two adapters,
#     pci-0000:03:00.0 / pci-0000:0b:00.0) and QEMU/KVM with the default "pc"
#     machine (pci-0000:00:03.0 / pci-0000:00:04.0) use. When the path matches,
#     the name is assigned by systemd-udevd's net_setup_link builtin.
#
#  2. A fallback udev rule (81-appliance-nic.rules) runs after the .link files
#     for any physical NIC that did not end up as wan0/lan0 (unknown PCI slots,
#     Hyper-V vmbus devices which have no PCI path). It calls
#     /usr/local/sbin/appliance-nicname which sorts all physical NICs by their
#     sysfs device path (== PCI enumeration order) and hands out wan0 to the
#     first and lan0 to the second, skipping a name that is already taken.
#     Hyper-V vmbus adapters carry random instance GUIDs, so they are sorted
#     by MAC address instead: Hyper-V hands out dynamic MACs in the order the
#     adapters were added, and packer/hyperv/New-ApplianceVM.ps1 assigns
#     static ones in WAN, LAN order.
#
# Hot-plugged or additional NICs keep their kernel/predictable name and are
# ignored by the daemon. The daemon's netcfg module may later rewrite the
# .network files (ReadWritePaths includes /etc/systemd/network).
# ---------------------------------------------------------------------------
log "configuring systemd-networkd"
install -d -m 0755 /etc/systemd/network

cat >/etc/systemd/network/10-wan0.link <<'EOF'
# wan0: first NIC (lowest PCI address). See harden.sh for the naming approach.
[Match]
Type=ether
Path=pci-0000:03:00.0 pci-0000:00:03.0

[Link]
NamePolicy=
Name=wan0
EOF

cat >/etc/systemd/network/20-lan0.link <<'EOF'
# lan0: second NIC. See harden.sh for the naming approach.
[Match]
Type=ether
Path=pci-0000:0b:00.0 pci-0000:00:04.0

[Link]
NamePolicy=
Name=lan0
EOF

cat >/etc/systemd/network/10-wan0.network <<'EOF'
# wan0: management / egress leg. Default route lives here.
[Match]
Name=wan0

[Network]
DHCP=yes
IPv6AcceptRA=yes
LLMNR=no
MulticastDNS=no

[DHCPv4]
UseHostname=no
SendHostname=no
RouteMetric=100

[DHCPv6]
UseHostname=no
EOF

cat >/etc/systemd/network/20-lan0.network <<'EOF'
# lan0: scanning leg. Never receives a default route (PLAN 15): only the
# subnet route from the lease. Additional LAN routes are pushed by the
# control plane and written by the daemon.
[Match]
Name=lan0

[Network]
DHCP=ipv4
IPv6AcceptRA=yes
LLMNR=no
MulticastDNS=no

[DHCPv4]
UseRoutes=no
UseGateway=no
UseDNS=no
UseNTP=no
UseHostname=no
SendHostname=no
RouteMetric=1000

[IPv6AcceptRA]
UseGateway=no
UseDNS=no
EOF
chmod 0644 /etc/systemd/network/*

install -d -m 0755 /usr/local/sbin
cat >/usr/local/sbin/appliance-nicname <<'EOF'
#!/bin/sh
# Fallback NIC namer for the scanner appliance (see harden.sh).
# Usage: appliance-nicname <kernel ifname>   -> prints wan0, lan0 or nothing.
# Sorts every physical NIC by its sysfs device path and maps index 0 -> wan0,
# 1 -> lan0. A name that already exists on another interface is skipped.
set -eu
me="${1:?ifname}"
[ -e "/sys/class/net/$me/device" ] || exit 0

list=""
for d in /sys/class/net/*; do
  n="${d##*/}"
  [ -e "$d/device" ] || continue                 # skip virtual devices
  [ "$(cat "$d/type" 2>/dev/null)" = "1" ] || continue  # ethernet only
  key="$(readlink -f "$d/device")"
  case "$key" in
    *VMBUS*|*vmbus*) key="vmbus-$(cat "$d/address" 2>/dev/null)" ;;  # Hyper-V: order by MAC, not by random GUID
  esac
  list="${list}${key} ${n}
"
done

idx=0
for n in $(printf '%s' "$list" | sort | awk '{print $2}'); do
  if [ "$n" = "$me" ]; then break; fi
  idx=$((idx + 1))
done

taken() { [ -e "/sys/class/net/$1" ] && [ "$1" != "$me" ]; }

case "$idx" in
  0) want=wan0; alt=lan0 ;;
  1) want=lan0; alt=wan0 ;;
  *) exit 0 ;;
esac
if ! taken "$want"; then
  printf '%s\n' "$want"
elif ! taken "$alt"; then
  printf '%s\n' "$alt"
fi
exit 0
EOF
chmod 0755 /usr/local/sbin/appliance-nicname

cat >/etc/udev/rules.d/81-appliance-nic.rules <<'EOF'
# Fallback naming for NICs the .link files in /etc/systemd/network did not
# match (unknown PCI slot, Hyper-V vmbus). Runs after 80-net-setup-link.rules.
SUBSYSTEM=="net", ACTION=="add", ATTR{type}=="1", DEVPATH!="*/virtual/*", NAME!="wan0", NAME!="lan0", PROGRAM="/usr/local/sbin/appliance-nicname $env{INTERFACE}", RESULT!="", NAME="%c"
EOF

# resolved: stub listener for local lookups; DNS comes from wan0's lease or the
# static config written by the daemon.
install -d -m 0755 /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/10-appliance.conf <<'EOF'
[Resolve]
LLMNR=no
MulticastDNS=no
DNSStubListener=yes
EOF
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

systemctl enable systemd-networkd.service systemd-networkd-wait-online.service systemd-resolved.service
# Wait for wan0 only: lan0 may sit on a segment without DHCP.
install -d -m 0755 /etc/systemd/system/systemd-networkd-wait-online.service.d
cat >/etc/systemd/system/systemd-networkd-wait-online.service.d/10-appliance.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --interface=wan0 --timeout=60
EOF

# ---------------------------------------------------------------------------
# Time: htpdate over HTTPS against the control-plane FQDN (NTP does not cross
# the vendor proxy). The FQDN is read from /etc/appliance/cp-fqdn, which the
# daemon rewrites after enrollment; proxy settings come from /etc/htpdate.conf.
# ---------------------------------------------------------------------------
log "configuring htpdate"
install -d -m 0755 /etc/appliance
[[ -s /etc/appliance/cp-fqdn ]] || echo "appliance.tprm.example.com" >/etc/appliance/cp-fqdn
chmod 0644 /etc/appliance/cp-fqdn

cat >/etc/htpdate.conf <<'EOF'
# Scanner appliance htpdate settings, sourced by /usr/local/sbin/appliance-htpdate.
# The time source host is /etc/appliance/cp-fqdn (rewritten by applianced).
# HTP_PROXY: host:port of an HTTP proxy, empty for direct.
HTP_PROXY=""
# Extra htpdate flags (see htpdate(8)).
HTP_OPTIONS="-s -l"
EOF
chmod 0644 /etc/htpdate.conf

cat >/usr/local/sbin/appliance-htpdate <<'EOF'
#!/bin/sh
# Wrapper that runs htpdate in the foreground against the control-plane FQDN.
set -eu
fqdn="$(head -n1 /etc/appliance/cp-fqdn 2>/dev/null | tr -d '[:space:]')"
[ -n "$fqdn" ] || fqdn="appliance.tprm.example.com"
HTP_PROXY=""
HTP_OPTIONS="-s -l"
# shellcheck disable=SC1091
[ -r /etc/htpdate.conf ] && . /etc/htpdate.conf
# shellcheck disable=SC2086  # HTP_OPTIONS is a flag list, splitting is intended
set -- -F $HTP_OPTIONS
[ -n "$HTP_PROXY" ] && set -- "$@" -P "$HTP_PROXY"
exec /usr/sbin/htpdate "$@" "https://${fqdn}"
EOF
chmod 0755 /usr/local/sbin/appliance-htpdate

install -d -m 0755 /etc/systemd/system/htpdate.service.d
cat >/etc/systemd/system/htpdate.service.d/10-appliance.conf <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=
ExecStart=
ExecStart=/usr/local/sbin/appliance-htpdate
Restart=always
RestartSec=30
EOF

# Restart htpdate whenever the daemon rewrites the FQDN.
cat >/etc/systemd/system/appliance-htpdate-reload.path <<'EOF'
[Unit]
Description=Restart htpdate when the control-plane FQDN changes

[Path]
PathChanged=/etc/appliance/cp-fqdn
PathChanged=/etc/htpdate.conf

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/appliance-htpdate-reload.service <<'EOF'
[Unit]
Description=Restart htpdate after a configuration change

[Service]
Type=oneshot
ExecStart=/bin/systemctl try-restart htpdate.service
EOF
systemctl enable htpdate.service appliance-htpdate-reload.path

# ---------------------------------------------------------------------------
# Updates (PLAN 4.4, 14): unattended-upgrades from the security pocket only,
# fetched from the apt mirror behind the control-plane FQDN over mTLS. The
# daemon writes the sources entry and the client-certificate settings at
# enrollment (/etc/apt/sources.list.d/appliance-security.sources,
# /etc/apt/apt.conf.d/50appliance); until then apt has nothing to fetch.
# Reboots are not automatic: applianced reboots an idle appliance in the
# maintenance slot when /var/run/reboot-required appears.
# ---------------------------------------------------------------------------
log "configuring unattended-upgrades (security pocket via the control-plane mirror)"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat >/etc/apt/apt.conf.d/52unattended-upgrades-appliance <<'EOF'
// Scanner appliance: security updates only, no automatic reboot (applianced
// handles the reboot in the site's maintenance slot).
Unattended-Upgrade::Origins-Pattern {
  "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::MinimalSteps "true";
EOF
systemctl enable unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

# ---------------------------------------------------------------------------
# Self-update guard (PLAN 14): applianced swaps its own binary on
# update_daemon and keeps the previous one as applianced.prev with a
# pending record. If the new binary cannot even start, this ExecStartPre
# puts the previous binary back after three failed starts; the daemon then
# reports the rollback in its heartbeat.
# ---------------------------------------------------------------------------
log "installing appliance-update-guard"
cat >/usr/local/sbin/appliance-update-guard <<'EOF'
#!/bin/sh
# Crash-loop protection for applianced self-updates. Sources the pending
# record written by the daemon (KEY='value' lines) and restores the
# previous binary after three unconfirmed starts.
set -eu
P=/var/lib/appliance/update/pending.env
[ -f "$P" ] || exit 0
VERSION=''; PREV_VERSION=''; PREV=''; EXE=''; STARTED='0'; STARTS='0'; ROLLED_BACK='0'; REASON=''
# shellcheck disable=SC1090
. "$P"
STARTS=$((STARTS + 1))
if [ "$ROLLED_BACK" = "0" ] && [ "$STARTS" -ge 3 ] && [ -n "$PREV" ] && [ -f "$PREV" ] && [ -n "$EXE" ]; then
  mv -f "$PREV" "$EXE"
  chmod 0755 "$EXE"
  ROLLED_BACK=1
  REASON="rolled back after $STARTS failed starts"
fi
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\''/g")"; }
{
  printf 'VERSION=%s\n' "$(q "$VERSION")"
  printf 'PREV_VERSION=%s\n' "$(q "$PREV_VERSION")"
  printf 'PREV=%s\n' "$(q "$PREV")"
  printf 'EXE=%s\n' "$(q "$EXE")"
  printf 'STARTED=%s\n' "$STARTED"
  printf 'STARTS=%s\n' "$STARTS"
  printf 'ROLLED_BACK=%s\n' "$ROLLED_BACK"
  printf 'REASON=%s\n' "$(q "$REASON")"
} >"$P.tmp" && mv -f "$P.tmp" "$P"
exit 0
EOF
chmod 0755 /usr/local/sbin/appliance-update-guard

# ---------------------------------------------------------------------------
# open-vm-tools: needed to read the OVF environment on VMware. Harmless
# elsewhere (the unit has ConditionVirtualization=vmware).
# ---------------------------------------------------------------------------
systemctl enable open-vm-tools.service 2>/dev/null || true

# ---------------------------------------------------------------------------
# applianced.service
# ---------------------------------------------------------------------------
log "installing applianced.service"
cat >/etc/systemd/system/applianced.service <<'EOF'
[Unit]
Description=Scanner appliance daemon
Documentation=https://github.com/tprm/scanner-appliance
After=network-online.target systemd-resolved.service nftables.service
# Engine health in the heartbeat probes /run/ospd/ospd.sock; start after ospd
# but do not require it (the daemon reports ospd_up=false instead of failing).
After=ospd-openvas.service
Wants=network-online.target
# Log spool lives on /var; make sure it is mounted.
RequiresMountsFor=/var/lib/appliance

[Service]
Type=simple
ExecStartPre=/usr/local/sbin/appliance-update-guard
ExecStart=/usr/local/bin/applianced run
# Restart=always also covers the clean exit the daemon uses to hand over
# to a freshly installed binary (update_daemon).
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=30

StateDirectory=appliance
StateDirectoryMode=0700
RuntimeDirectory=appliance
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
WorkingDirectory=/var/lib/appliance

# Raw sockets for scanning, NET_ADMIN for policy routing, SYS_ADMIN to mount
# the APPLIANCE seed volume at /run/appliance/seed.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_BIND_SERVICE CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_KILL CAP_SETUID CAP_SETGID CAP_SYS_CHROOT CAP_SYS_RESOURCE
NoNewPrivileges=no
ProtectSystem=strict
# connect(2) on a Unix socket needs write access to its path: /run/ospd for
# ospd-openvas ("-": tolerate it not existing yet). Phase 3 adds the VT feed
# (bundle deltas), openvas.conf (source_iface in split mode), the daemon's
# own binary (self-update) and apt's config (mirror credentials).
ReadWritePaths=/var/lib/appliance /run/appliance /etc/systemd/network /etc/appliance /etc/htpdate.conf -/run/ospd
ReadWritePaths=-/var/lib/openvas -/etc/openvas /usr/local/bin -/etc/apt/apt.conf.d -/etc/apt/sources.list.d
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=no
ProtectControlGroups=no
RestrictSUIDSGID=yes
LockPersonality=yes

Environment=PATH=/opt/engine:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/applianced.service

systemctl daemon-reload
log "done"
