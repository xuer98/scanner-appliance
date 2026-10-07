#!/usr/bin/env bash
# install-openvas.sh - builds and installs the v1 detection engine (PLAN 4.3):
# gvm-libs + openvas-scanner from pinned Greenbone release tags, ospd-openvas
# in a Python venv at /opt/ospd, and a dedicated redis instance on a Unix
# socket. No notus-scanner and no MQTT broker (unauthenticated scanning only).
#
# Runs as root. Two callers:
#   Packer VM  : sudo -E bash install-openvas.sh   (after harden.sh and
#                install-daemon.sh, before seed-feed.sh and cleanup.sh)
#   Dockerfile : IN_CONTAINER=1 bash install-openvas.sh  (build stage), then
#                IN_CONTAINER=1 OPENVAS_SKIP_BUILD=1 bash install-openvas.sh
#                in the final stage to recreate users, directories and config
#                around the COPY --from'ed binaries.
#
# Environment (all optional):
#   GVM_LIBS_TAG / OPENVAS_SCANNER_TAG / OSPD_OPENVAS_TAG / OPENVAS_SMB_TAG
#       Greenbone release tags. openvas-smb is only needed for authenticated
#       SMB checks and is off (empty) by default.
#   GVM_LIBS_SHA256 / OPENVAS_SCANNER_SHA256 / OSPD_OPENVAS_SHA256 / OPENVAS_SMB_SHA256
#       sha256 of the GitHub source tarballs. Empty = not checked (a warning
#       is printed and the observed hash recorded in /etc/appliance/
#       openvas-build-info.txt so it can be pinned afterwards).
#   OPENVAS_REQUIRE_CHECKSUMS=1   fail instead of warning when a sha256 is empty.
#   OPENVAS_WITH_MQTT=1           install mosquitto bound to 127.0.0.1 and point
#                                 openvas at it. Only needed if the pinned
#                                 openvas-scanner refuses to run without a
#                                 broker; the tags below do not.
#   IN_CONTAINER=1                no systemd units, no sysctl, no service
#                                 enablement; redis data dir defaults to
#                                 /var/lib/openvas/redis (inside the volume).
#   OPENVAS_SKIP_BUILD=1          configure only (users, dirs, config files,
#                                 settings dump); binaries must already exist.
#   REDIS_OPENVAS_DIR             redis working dir (dump.rdb lives here).
#
# Phase 1 privilege model: ospd-openvas (and therefore the openvas processes it
# spawns) run as root with CAP_NET_RAW/CAP_NET_ADMIN granted explicitly, and
# applianced (also root in Phase 1) talks to /run/ospd/ospd.sock, which is
# root:root 0660. The Phase 3 goal per PLAN 4.4 is to run ospd-openvas as the
# `openvas` system user created here with AmbientCapabilities only, with the
# socket group-owned by the applianced service group. The user, the `redis`
# group membership and the directory ownership below are already laid out for
# that switch; only the User= lines in the units and the socket group change.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
log() { printf '[install-openvas] %s\n' "$*"; }
warn() { printf '[install-openvas] WARNING: %s\n' "$*" >&2; }
die() { printf '[install-openvas] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"

# ---------------------------------------------------------------------------
# Pinned releases (latest as of 2026-09-26; tags and tarballs confirmed to
# exist, dependency lists taken from their CMakeLists/pyproject, but the
# combination has NOT yet been built end to end from this script):
#   https://github.com/greenbone/gvm-libs/releases        (23.x = current stable)
#   https://github.com/greenbone/openvas-scanner/releases (needs libgvm >= 22.4;
#                                    Greenbone CI builds it against gvm-libs:stable)
#   https://github.com/greenbone/ospd-openvas/releases    (bundles ospd)
#   https://github.com/greenbone/openvas-smb/releases
# Greenbone publishes no source assets, only <name>.tar.gz.asc signatures of
# the GitHub-generated tag tarballs (archive/refs/tags/<tag>.tar.gz), so those
# are what is downloaded and what the sha256 pins below refer to. If GitHub
# ever regenerates an archive the pin fails loudly; re-verify with the .asc
# and update the hash.
# ---------------------------------------------------------------------------
DEFAULT_GVM_LIBS_TAG=v23.11.0
DEFAULT_GVM_LIBS_SHA256=73ad593be2203566eba24bd5c050bf864461356bd2ba51e545bf450a18c171a4
DEFAULT_OPENVAS_SCANNER_TAG=v23.50.24
DEFAULT_OPENVAS_SCANNER_SHA256=af8b1e0175dfc57f38bdecc08607dbac294459e684e2f3e7d69c85101fa13517
DEFAULT_OSPD_OPENVAS_TAG=v22.10.5
DEFAULT_OSPD_OPENVAS_SHA256=2d4a61cbd440005596ab2a36d941812045c5692534b9842f9c977dbe04204826

GVM_LIBS_TAG="${GVM_LIBS_TAG:-$DEFAULT_GVM_LIBS_TAG}"
OPENVAS_SCANNER_TAG="${OPENVAS_SCANNER_TAG:-$DEFAULT_OPENVAS_SCANNER_TAG}"
OSPD_OPENVAS_TAG="${OSPD_OPENVAS_TAG:-$DEFAULT_OSPD_OPENVAS_TAG}"
OPENVAS_SMB_TAG="${OPENVAS_SMB_TAG:-}"
# The pinned hash only applies to the pinned tag; a bumped tag needs its own
# hash (or OPENVAS_REQUIRE_CHECKSUMS=0 to build with a warning).
GVM_LIBS_SHA256="${GVM_LIBS_SHA256:-}"
OPENVAS_SCANNER_SHA256="${OPENVAS_SCANNER_SHA256:-}"
OSPD_OPENVAS_SHA256="${OSPD_OPENVAS_SHA256:-}"
[[ -n "$GVM_LIBS_SHA256" || "$GVM_LIBS_TAG" != "$DEFAULT_GVM_LIBS_TAG" ]] || GVM_LIBS_SHA256="$DEFAULT_GVM_LIBS_SHA256"
[[ -n "$OPENVAS_SCANNER_SHA256" || "$OPENVAS_SCANNER_TAG" != "$DEFAULT_OPENVAS_SCANNER_TAG" ]] || OPENVAS_SCANNER_SHA256="$DEFAULT_OPENVAS_SCANNER_SHA256"
[[ -n "$OSPD_OPENVAS_SHA256" || "$OSPD_OPENVAS_TAG" != "$DEFAULT_OSPD_OPENVAS_TAG" ]] || OSPD_OPENVAS_SHA256="$DEFAULT_OSPD_OPENVAS_SHA256"
OPENVAS_SMB_SHA256="${OPENVAS_SMB_SHA256:-}"
OPENVAS_REQUIRE_CHECKSUMS="${OPENVAS_REQUIRE_CHECKSUMS:-0}"
OPENVAS_WITH_MQTT="${OPENVAS_WITH_MQTT:-0}"
IN_CONTAINER="${IN_CONTAINER:-0}"
OPENVAS_SKIP_BUILD="${OPENVAS_SKIP_BUILD:-0}"

if [[ "$IN_CONTAINER" == "1" ]]; then
  REDIS_OPENVAS_DIR="${REDIS_OPENVAS_DIR:-/var/lib/openvas/redis}"
else
  REDIS_OPENVAS_DIR="${REDIS_OPENVAS_DIR:-/var/lib/redis-openvas}"
fi

PREFIX=/usr/local
OSPD_VENV=/opt/ospd
SRC_DIR=/usr/local/src/openvas-build
REDIS_SOCK=/run/redis-openvas/redis.sock
REDIS_CONF=/etc/redis/redis-openvas.conf
OSPD_SOCK=/run/ospd/ospd.sock
PLUGINS_DIR=/var/lib/openvas/plugins
BUILD_DEPS_MARKER=/etc/appliance/openvas-build-deps.list
BUILD_INFO=/etc/appliance/openvas-build-info.txt
JOBS="$(nproc 2>/dev/null || echo 2)"

# Shared libraries and tools the engine needs at runtime. Kept (apt-mark
# manual) when cleanup.sh purges the build dependencies.
RUNTIME_DEPS=(
  libglib2.0-0 libgpgme11 libgnutls30 libssh-gcrypt-4 libksba8 libpcap0.8
  libjson-glib-1.0-0 libcurl3-gnutls libhiredis0.14 libbsd0 libnet1
  libpaho-mqtt1.3 libgcrypt20 libcjson1 libsnmp40 libxml2 libuuid1 zlib1g
  libkrb5-3 libgssapi-krb5-2 libmagic1
  redis-server redis-tools python3 ca-certificates
)
# Build-only packages: recorded in $BUILD_DEPS_MARKER and purged by cleanup.sh.
# Beyond PLAN's list, the pinned releases require (from their CMakeLists):
# gvm-libs 23: zlib, libcjson, libgcrypt, paho-mqtt3c (hard SEND_ERROR),
# libnet, libcurl; openvas-scanner 23.50: mit-krb5 + gssapi (REQUIRED),
# net-snmp (BUILD_WITH_NETSNMP default on), libmagic (optional, wanted).
BUILD_DEPS=(
  cmake pkg-config gcc make
  libglib2.0-dev libgpgme-dev libgnutls28-dev libssh-gcrypt-dev libksba-dev
  libpcap-dev libjson-glib-dev libcurl4-gnutls-dev libhiredis-dev libbsd-dev
  libnet1-dev libpaho-mqtt-dev uuid-dev libxml2-dev libgcrypt20-dev
  libcjson-dev libsnmp-dev zlib1g-dev libkrb5-dev libmagic-dev bison flex
  python3-venv python3-pip
)

tag_to_version() { printf '%s' "${1#v}"; }

# fetch <name> <repo> <tag> <expected-sha256> -> path of the tarball on stdout
fetch() {
  local name="$1" repo="$2" tag="$3" want="$4"
  local url="https://github.com/greenbone/${repo}/archive/refs/tags/${tag}.tar.gz"
  local out
  out="${SRC_DIR}/${name}-$(tag_to_version "$tag").tar.gz"
  log "downloading ${repo} ${tag}" >&2
  curl -fsSL --retry 3 --retry-delay 5 -o "$out" "$url" || die "download failed: $url"
  local got
  got="$(sha256sum "$out" | awk '{print $1}')"
  if [[ -n "$want" ]]; then
    [[ "$got" == "$want" ]] || die "sha256 mismatch for ${name} ${tag}: got ${got}, want ${want}"
    log "verified ${name} ${tag} sha256=${got}" >&2
  elif [[ "$OPENVAS_REQUIRE_CHECKSUMS" == "1" ]]; then
    die "no sha256 pinned for ${name} ${tag} (OPENVAS_REQUIRE_CHECKSUMS=1); observed ${got}"
  else
    warn "no sha256 pinned for ${name} ${tag}; observed ${got} (pin it via ${name^^}_SHA256)"
  fi
  printf '%s %s %s %s\n' "$name" "$tag" "$got" "$url" >>"${SRC_DIR}/build-info.txt"
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 1. Packages
# ---------------------------------------------------------------------------
install -d -m 0755 /etc/appliance
if [[ "$OPENVAS_SKIP_BUILD" != "1" ]]; then
  log "installing runtime and build dependencies"
  apt-get update -q
  apt-get install -y -q --no-install-recommends curl "${RUNTIME_DEPS[@]}" "${BUILD_DEPS[@]}"
  apt-mark manual "${RUNTIME_DEPS[@]}" >/dev/null
  printf '%s\n' "${BUILD_DEPS[@]}" >"$BUILD_DEPS_MARKER"
  chmod 0644 "$BUILD_DEPS_MARKER"
else
  log "configure-only mode (OPENVAS_SKIP_BUILD=1)"
  for b in "$PREFIX/sbin/openvas" "$OSPD_VENV/bin/ospd-openvas" /usr/bin/redis-server; do
    [[ -x "$b" ]] || die "$b missing; configure-only mode needs the built engine in place"
  done
fi

# The Debian redis-server package enables a TCP instance on 6379; the
# appliance uses its own socket-only instance instead.
if [[ "$IN_CONTAINER" != "1" ]]; then
  systemctl disable --now redis-server.service 2>/dev/null || true
  systemctl mask redis-server.service 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 2. Build gvm-libs, openvas-scanner (and optionally openvas-smb)
# ---------------------------------------------------------------------------
if [[ "$OPENVAS_SKIP_BUILD" != "1" ]]; then
  rm -rf "$SRC_DIR"
  install -d -m 0755 "$SRC_DIR"
  : >"${SRC_DIR}/build-info.txt"
  multiarch="$(gcc -print-multiarch 2>/dev/null || echo x86_64-linux-gnu)"
  export PKG_CONFIG_PATH="${PREFIX}/lib/pkgconfig:${PREFIX}/lib/${multiarch}/pkgconfig:${PKG_CONFIG_PATH:-}"

  # -- gvm-libs -------------------------------------------------------------
  tarball="$(fetch gvm-libs gvm-libs "$GVM_LIBS_TAG" "$GVM_LIBS_SHA256")"
  tar -C "$SRC_DIR" -xzf "$tarball"
  srcdir="${SRC_DIR}/gvm-libs-$(tag_to_version "$GVM_LIBS_TAG")"
  [[ -d "$srcdir" ]] || die "unexpected gvm-libs tarball layout (no $srcdir)"
  log "building gvm-libs $GVM_LIBS_TAG"
  # openvas-scanner links libgvm_base/util/boreas only. The gvmd-side
  # libraries gvm-libs 23 builds by default (openvasd/http, agent controller,
  # credential stores, security intelligence, web app scanner, AD/LDAP) are
  # switched off: fewer dependencies (no libldap), smaller image. Unknown
  # -D options (older tags) only produce a cmake warning.
  cmake -S "$srcdir" -B "${srcdir}/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DSYSCONFDIR=/etc \
    -DLOCALSTATEDIR=/var \
    -DBUILD_WITH_LDAP=OFF \
    -DBUILD_WITH_RADIUS=OFF \
    -DBUILD_TESTS=OFF \
    -DENABLE_OPENVASD=OFF \
    -DENABLE_AGENTS=OFF \
    -DENABLE_CREDENTIAL_STORES=OFF \
    -DENABLE_SECURITY_INTELLIGENCE=OFF \
    -DENABLE_WEB_APPLICATION_SCANNER=OFF \
    -DENABLE_ACTIVE_DIRECTORY_INTEGRATION=OFF \
    >"${SRC_DIR}/gvm-libs.cmake.log" 2>&1 || { cat "${SRC_DIR}/gvm-libs.cmake.log" >&2; die "gvm-libs cmake failed"; }
  make -C "${srcdir}/build" -j"$JOBS" >"${SRC_DIR}/gvm-libs.make.log" 2>&1 || { tail -n 80 "${SRC_DIR}/gvm-libs.make.log" >&2; die "gvm-libs build failed"; }
  make -C "${srcdir}/build" install >/dev/null
  ldconfig

  # -- openvas-smb (optional) -----------------------------------------------
  if [[ -n "$OPENVAS_SMB_TAG" ]]; then
    apt-get install -y -q --no-install-recommends gcc-mingw-w64 heimdal-dev libpopt-dev libglib2.0-dev libgnutls28-dev perl-base
    printf '%s\n' gcc-mingw-w64 heimdal-dev libpopt-dev >>"$BUILD_DEPS_MARKER"
    tarball="$(fetch openvas-smb openvas-smb "$OPENVAS_SMB_TAG" "$OPENVAS_SMB_SHA256")"
    tar -C "$SRC_DIR" -xzf "$tarball"
    srcdir="${SRC_DIR}/openvas-smb-$(tag_to_version "$OPENVAS_SMB_TAG")"
    log "building openvas-smb $OPENVAS_SMB_TAG"
    cmake -S "$srcdir" -B "${srcdir}/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
      >"${SRC_DIR}/openvas-smb.cmake.log" 2>&1 || { cat "${SRC_DIR}/openvas-smb.cmake.log" >&2; die "openvas-smb cmake failed"; }
    make -C "${srcdir}/build" -j"$JOBS" >"${SRC_DIR}/openvas-smb.make.log" 2>&1 || { tail -n 80 "${SRC_DIR}/openvas-smb.make.log" >&2; die "openvas-smb build failed"; }
    make -C "${srcdir}/build" install >/dev/null
    ldconfig
  fi

  # -- openvas-scanner ------------------------------------------------------
  tarball="$(fetch openvas-scanner openvas-scanner "$OPENVAS_SCANNER_TAG" "$OPENVAS_SCANNER_SHA256")"
  tar -C "$SRC_DIR" -xzf "$tarball"
  srcdir="${SRC_DIR}/openvas-scanner-$(tag_to_version "$OPENVAS_SCANNER_TAG")"
  [[ -d "$srcdir" ]] || die "unexpected openvas-scanner tarball layout (no $srcdir)"
  log "building openvas-scanner $OPENVAS_SCANNER_TAG"
  # Note: the INSTALL_OLD_SYNC_SCRIPT / BUILD_WITH_NASL_LINT switches named in
  # PLAN do not exist in the 23.x CMake files (greenbone-nvt-sync is gone and
  # openvas-nasl-lint is always built), so they are not passed. The feed
  # comes from our bundle; nothing in the image syncs from Greenbone.
  cmake -S "$srcdir" -B "${srcdir}/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DSYSCONFDIR=/etc \
    -DLOCALSTATEDIR=/var \
    -DOPENVAS_RUN_DIR=/run/ospd \
    -DOPENVAS_FEED_LOCK_PATH=/var/lib/openvas/feed-update.lock \
    -DOPENVAS_GPG_BASE_DIR=/var/lib/openvas/gnupg \
    -DBUILD_WITH_NETSNMP=TRUE \
    >"${SRC_DIR}/openvas-scanner.cmake.log" 2>&1 || { cat "${SRC_DIR}/openvas-scanner.cmake.log" >&2; die "openvas-scanner cmake failed"; }
  make -C "${srcdir}/build" -j"$JOBS" >"${SRC_DIR}/openvas-scanner.make.log" 2>&1 || { tail -n 80 "${SRC_DIR}/openvas-scanner.make.log" >&2; die "openvas-scanner build failed"; }
  make -C "${srcdir}/build" install >/dev/null
  ldconfig
  [[ -x "$PREFIX/sbin/openvas" ]] || die "$PREFIX/sbin/openvas not installed"
  # Remove the man/doc tree and the always-built nasl lint helper's docs; the
  # binaries stay (openvas-nasl is handy for support).
  rm -rf "$PREFIX/share/doc/openvas-scanner" "$PREFIX/share/man" 2>/dev/null || true

  # -- ospd-openvas in a venv -----------------------------------------------
  # Plain (non system-site-packages) venv: pip resolves ospd-openvas's
  # dependencies from PyPI at build time so the Debian python3-* versions do
  # not have to satisfy the release's constraints. Nothing is fetched at
  # runtime; the venv is self-contained.
  tarball="$(fetch ospd-openvas ospd-openvas "$OSPD_OPENVAS_TAG" "$OSPD_OPENVAS_SHA256")"
  log "installing ospd-openvas $OSPD_OPENVAS_TAG into $OSPD_VENV"
  rm -rf "$OSPD_VENV"
  python3 -m venv "$OSPD_VENV"
  "$OSPD_VENV/bin/pip" install --no-cache-dir --disable-pip-version-check "$tarball" \
    >"${SRC_DIR}/ospd-openvas.pip.log" 2>&1 || { tail -n 80 "${SRC_DIR}/ospd-openvas.pip.log" >&2; die "pip install ospd-openvas failed"; }
  [[ -x "$OSPD_VENV/bin/ospd-openvas" ]] || die "$OSPD_VENV/bin/ospd-openvas missing after install"
  rm -rf /root/.cache/pip "$OSPD_VENV/share/python-wheels" 2>/dev/null || true
  find "$OSPD_VENV" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true

  # Record what was built, then drop the sources (the toolchain itself is
  # purged by cleanup.sh via $BUILD_DEPS_MARKER).
  {
    echo "# component tag sha256 url"
    cat "${SRC_DIR}/build-info.txt"
    echo "# built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -m)"
  } >"$BUILD_INFO"
  chmod 0644 "$BUILD_INFO"
  rm -rf "$SRC_DIR"
fi

# ---------------------------------------------------------------------------
# 3. Users and directories
# ---------------------------------------------------------------------------
if ! getent group openvas >/dev/null; then
  groupadd --system openvas
fi
if ! id openvas >/dev/null 2>&1; then
  useradd --system --gid openvas --no-create-home --home-dir /var/lib/openvas \
    --shell /usr/sbin/nologin --comment "OpenVAS scanner" openvas
fi
getent group redis >/dev/null || die "redis group missing (redis-server not installed?)"
# Phase 3: openvas will talk to redis as itself; give it the socket group now.
usermod -a -G redis openvas

install -d -o openvas -g openvas -m 0755 /var/lib/openvas
install -d -o openvas -g openvas -m 0755 "$PLUGINS_DIR"
install -d -o openvas -g openvas -m 0700 /var/lib/openvas/gnupg
install -d -o openvas -g openvas -m 0775 /var/log/gvm
install -d -o redis -g redis -m 0750 "$REDIS_OPENVAS_DIR"
install -d -m 0755 /etc/openvas /etc/redis
if [[ "$IN_CONTAINER" == "1" ]]; then
  # No RuntimeDirectory= in a container; entrypoint.sh recreates these on
  # start, but have them in the image as well.
  install -d -o redis -g redis -m 0750 /run/redis-openvas
  install -d -m 0755 /run/ospd
fi

# ---------------------------------------------------------------------------
# 4. redis (socket only, no TCP)
# ---------------------------------------------------------------------------
log "writing $REDIS_CONF (dir=$REDIS_OPENVAS_DIR)"
cat >"$REDIS_CONF" <<EOF
# redis instance for openvas - written by install-openvas.sh.
# Unix socket only (PLAN 4.3): no TCP listener at all.
port 0
unixsocket ${REDIS_SOCK}
unixsocketperm 770
protected-mode yes
timeout 0
tcp-keepalive 300
# openvas addresses the VT cache and one KB per scanned host by DB index.
databases 1025
daemonize no
supervised auto
pidfile /run/redis-openvas/redis-server.pid
loglevel notice
# Empty logfile = stdout (the journal under systemd, docker logs in a container).
logfile ""
# RDB snapshots stay enabled on purpose: seed-feed.sh saves the pre-warmed VT
# cache here so the image ships with dump.rdb and first boot does not spend
# minutes loading VTs. Do not set 'save ""'.
dir ${REDIS_OPENVAS_DIR}
dbfilename dump.rdb
save 3600 1 300 100 60 10000
rdbcompression yes
rdbchecksum yes
stop-writes-on-bgsave-error no
appendonly no
maxclients 4096
EOF
chown root:redis "$REDIS_CONF"
chmod 0640 "$REDIS_CONF"

# ---------------------------------------------------------------------------
# 5. openvas configuration
# ---------------------------------------------------------------------------
log "writing /etc/openvas/openvas.conf"
mqtt_line="# mqtt_server_uri: unset - no broker, no notus (unauthenticated scanning only)"
if [[ "$OPENVAS_WITH_MQTT" == "1" ]]; then
  mqtt_line="mqtt_server_uri = localhost:1883"
fi
cat >/etc/openvas/openvas.conf <<EOF
# openvas.conf - written by install-openvas.sh. Support-bundle copy of the
# effective settings: /etc/appliance/openvas-settings.txt.
db_address = ${REDIS_SOCK}
plugins_folder = ${PLUGINS_DIR}
# The feed ships inside a signed, content-addressed bundle from the control
# plane, and the daemon checks every file against the bundle's manifest. The
# engine's own check is off. It would need Greenbone's key in
# /var/lib/openvas/gnupg and Greenbone's sha256sums list in the plugins
# directory, and bundles leave that list out: it names every script, so it
# changes with each feed release and was 10.6 MB of every daily update.
nasl_no_signature_check = yes
# Notus (table-driven local security checks) is not installed.
table_driven_lsc = no
${mqtt_line}
# Scan intensity limits are set per job by ospd (PLAN guardrails, Phase 2).
max_hosts = 20
max_checks = 4
EOF
chmod 0644 /etc/openvas/openvas.conf

if [[ ! -f /etc/openvas/openvas_log.conf ]]; then
  cat >/etc/openvas/openvas_log.conf <<'EOF'
[sd   main]
prepend=%t %p
prepend_time_format=%Y-%m-%d %Hh%M.%S %Z
file=/var/log/gvm/openvas.log
level=127
EOF
  chmod 0644 /etc/openvas/openvas_log.conf
fi

# Optional MQTT broker: only if the pinned openvas refuses to run without one.
if [[ "$OPENVAS_WITH_MQTT" == "1" ]]; then
  log "OPENVAS_WITH_MQTT=1: installing mosquitto bound to 127.0.0.1"
  apt-get install -y -q --no-install-recommends mosquitto
  install -d -m 0755 /etc/mosquitto/conf.d
  cat >/etc/mosquitto/conf.d/appliance.conf <<'EOF'
# Loopback only; openvas is the sole client. Written by install-openvas.sh.
listener 1883 127.0.0.1
allow_anonymous true
EOF
  if [[ "$IN_CONTAINER" != "1" ]]; then
    systemctl enable mosquitto.service
  fi
fi

# ---------------------------------------------------------------------------
# 6. systemd units (VM only)
# ---------------------------------------------------------------------------
if [[ "$IN_CONTAINER" != "1" ]]; then
  log "installing redis-openvas.service and ospd-openvas.service"
  cat >/etc/systemd/system/redis-openvas.service <<EOF
[Unit]
Description=Redis instance for openvas (Unix socket only)
Documentation=https://redis.io/docs/
After=network.target
RequiresMountsFor=${REDIS_OPENVAS_DIR}

[Service]
Type=notify
User=redis
Group=redis
ExecStart=/usr/bin/redis-server ${REDIS_CONF} --supervised systemd --daemonize no
# SIGTERM makes redis write a final RDB snapshot before exiting.
KillSignal=SIGTERM
TimeoutStopSec=90
Restart=always
RestartSec=5
RuntimeDirectory=redis-openvas
RuntimeDirectoryMode=0750
UMask=007
LimitNOFILE=65536
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=${REDIS_OPENVAS_DIR}
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 /etc/systemd/system/redis-openvas.service

  # Phase 1: User=root (openvas needs raw sockets and ospd execs it directly).
  # Phase 3 (PLAN 4.4): User=openvas Group=openvas with the AmbientCapabilities
  # below and the socket group set to the applianced service group.
  cat >/etc/systemd/system/ospd-openvas.service <<EOF
[Unit]
Description=OSPD wrapper for the openvas scanner
Documentation=https://github.com/greenbone/ospd-openvas
After=network.target redis-openvas.service
Requires=redis-openvas.service
RequiresMountsFor=/var/lib/openvas

[Service]
Type=simple
User=root
Group=root
ExecStart=${OSPD_VENV}/bin/ospd-openvas --foreground --unix-socket ${OSPD_SOCK} --socket-mode 0o660 --log-file /var/log/gvm/ospd-openvas.log --lock-file-dir /run/ospd --pid-file /run/ospd/ospd-openvas.pid
Restart=on-failure
RestartSec=10
TimeoutStopSec=60
KillMode=mixed
RuntimeDirectory=ospd
RuntimeDirectoryMode=0755
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
Environment=PATH=${PREFIX}/sbin:${PREFIX}/bin:/usr/sbin:/usr/bin:/sbin:/bin
PrivateTmp=yes
ProtectHome=yes
ProtectControlGroups=yes
# openvas itself is memory hungry on large scans; redis is capped separately.
OOMScoreAdjust=200

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 /etc/systemd/system/ospd-openvas.service

  cat >/etc/sysctl.d/60-redis-openvas.conf <<'EOF'
# redis (openvas VT cache / KB): avoid fork() failures on RDB save and
# listen-backlog warnings. Written by install-openvas.sh.
vm.overcommit_memory = 1
net.core.somaxconn = 1024
EOF
  sysctl -q -p /etc/sysctl.d/60-redis-openvas.conf 2>/dev/null || true

  systemctl daemon-reload
  systemctl enable redis-openvas.service ospd-openvas.service
fi

# ---------------------------------------------------------------------------
# 7. Version and settings dump for the support bundle
# ---------------------------------------------------------------------------
log "recording engine versions"
{
  "$PREFIX/sbin/openvas" --version 2>/dev/null | head -n 2 || echo "openvas: version unavailable"
  "$OSPD_VENV/bin/ospd-openvas" --version 2>/dev/null || echo "ospd-openvas: version unavailable"
  /usr/bin/redis-server --version 2>/dev/null || echo "redis: version unavailable"
} >/etc/appliance/openvas-version
chmod 0644 /etc/appliance/openvas-version
# `openvas -s` prints the effective settings without touching redis.
if ! timeout 30 "$PREFIX/sbin/openvas" -s >/etc/appliance/openvas-settings.txt 2>&1; then
  warn "openvas -s failed; see /etc/appliance/openvas-settings.txt"
fi
chmod 0644 /etc/appliance/openvas-settings.txt
log "done: $(head -n 1 /etc/appliance/openvas-version)"
