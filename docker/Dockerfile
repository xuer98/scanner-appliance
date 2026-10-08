# syntax=docker/dockerfile:1.7
# Scanner appliance container (PLAN 4.7). Build from the repo root:
#
#   docker buildx build -f docker/Dockerfile --build-arg VERSION=1.2.3 \
#       --platform linux/amd64,linux/arm64 -t ghcr.io/tprm/scanner-appliance:1.2.3 .
#
# daemon/internal/pki/roots.pem (the pinned root CA) must exist in the build
# context; ci/build.sh puts it there (--dev generates a development CA).
#
# The detection engine (gvm-libs + openvas-scanner + ospd-openvas + redis) is
# built by the same packer/scripts/install-openvas.sh the VM image uses, with
# IN_CONTAINER=1 (no systemd). The VT feed is shipped when a tarball is placed
# in docker/feed/ before the build (see docker/feed/README and
# packer/scripts/seed-feed.sh); without it the image has no VTs and heartbeats
# report engine.vt_cache_loaded=false.
#
# Run requirements (docs/DEPLOY.md): --cap-add NET_RAW --cap-add NET_ADMIN,
# --network host, 8 GB memory limit, volumes for /var/lib/appliance (identity)
# and /var/lib/openvas (feed + redis dump).

# Both carry their tag here. hadolint cannot see through a build argument and
# reports every FROM that uses one as untagged (DL3006), hence the ignore
# lines below.
ARG GO_IMAGE=golang:1.26
ARG BASE_IMAGE=debian:12-slim

# Pinned scan-engine versions; bump here.
ARG NAABU_VERSION=v2.3.6
# Phase 3 web add-on (httpx + nuclei; templates arrive in the signed
# bundle) is on by default. The Phase 5 fingerprint pass needs nmap, which
# is NPSL-licensed (PLAN 21): WITH_NMAP=1 installs Debian's nmap package and
# is only used for builds made after the legal sign-off is recorded on the
# control plane (cp-api admin signoff nmap); the default image ships without
# it and the daemon skips the pass with a warning.
ARG WITH_WEB_ADDON=1
ARG WITH_NMAP=0
ARG HTTPX_VERSION=v1.7.1
ARG NUCLEI_VERSION=v3.4.10
# nuclei's sonic dependency (via gin) uses runtime internals that changed in
# Go 1.26; the web tools are built with this pinned toolchain (downloaded by
# the go command) until nuclei ships a compatible sonic. Keep in sync with
# ci/build-engine.sh.
ARG ENGINE_GOTOOLCHAIN=go1.25.14

# Greenbone release tags and tarball hashes: empty = the pins inside
# packer/scripts/install-openvas.sh (the single source of truth); set to bump.
ARG GVM_LIBS_TAG=
ARG OPENVAS_SCANNER_TAG=
ARG OSPD_OPENVAS_TAG=
ARG OPENVAS_SMB_TAG=
ARG GVM_LIBS_SHA256=
ARG OPENVAS_SCANNER_SHA256=
ARG OSPD_OPENVAS_SHA256=
ARG OPENVAS_REQUIRE_CHECKSUMS=0
ARG OPENVAS_WITH_MQTT=0
# Optional sha256 of the feed tarball in docker/feed/.
ARG FEED_SHA256=

# ---------------------------------------------------------------------------
# build: static applianced, cross-compiled on the build platform.
# ---------------------------------------------------------------------------
# hadolint ignore=DL3006
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG VERSION=dev
ARG TARGETARCH
WORKDIR /src

COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN test -s daemon/internal/pki/roots.pem \
    || { echo "daemon/internal/pki/roots.pem missing: run ci/build.sh (or --dev) first" >&2; exit 1; }

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p bin && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o bin/applianced-linux-${TARGETARCH} ./daemon/cmd/applianced

# ---------------------------------------------------------------------------
# engine: third-party scanners. Built natively on the target platform because
# naabu links libpcap (CGO). Slow under emulation for arm64 but simple.
# naabu plus httpx/nuclei (WITH_WEB_ADDON=1, the default since Phase 3).
# ---------------------------------------------------------------------------
# hadolint ignore=DL3006
FROM ${GO_IMAGE} AS engine
ARG NAABU_VERSION
ARG WITH_WEB_ADDON
ARG HTTPX_VERSION
ARG NUCLEI_VERSION
ARG ENGINE_GOTOOLCHAIN
ENV GOBIN=/out GOFLAGS=-trimpath
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev build-essential \
    && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /out \
    && CGO_ENABLED=1 go install -ldflags="-s -w" github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} \
    && if [ "${WITH_WEB_ADDON}" = "1" ]; then \
         GOTOOLCHAIN=${ENGINE_GOTOOLCHAIN} CGO_ENABLED=0 go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
      && GOTOOLCHAIN=${ENGINE_GOTOOLCHAIN} CGO_ENABLED=0 go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}; \
       fi

# ---------------------------------------------------------------------------
# openvas: gvm-libs + openvas-scanner + ospd-openvas venv, built natively on
# the target platform by the shared install script (IN_CONTAINER=1 skips
# systemd units and sysctl). Produces /usr/local (openvas, libgvm_*) and
# /opt/ospd; the final stage copies those and re-runs the script in
# configure-only mode for users, directories and config files.
# ---------------------------------------------------------------------------
# hadolint ignore=DL3006
FROM ${BASE_IMAGE} AS openvas
ARG GVM_LIBS_TAG
ARG OPENVAS_SCANNER_TAG
ARG OSPD_OPENVAS_TAG
ARG OPENVAS_SMB_TAG
ARG GVM_LIBS_SHA256
ARG OPENVAS_SCANNER_SHA256
ARG OSPD_OPENVAS_SHA256
ARG OPENVAS_REQUIRE_CHECKSUMS
ARG OPENVAS_WITH_MQTT
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY packer/scripts/install-openvas.sh /usr/local/sbin/install-openvas.sh
RUN IN_CONTAINER=1 \
    GVM_LIBS_TAG=${GVM_LIBS_TAG} OPENVAS_SCANNER_TAG=${OPENVAS_SCANNER_TAG} \
    OSPD_OPENVAS_TAG=${OSPD_OPENVAS_TAG} OPENVAS_SMB_TAG=${OPENVAS_SMB_TAG} \
    GVM_LIBS_SHA256=${GVM_LIBS_SHA256} OPENVAS_SCANNER_SHA256=${OPENVAS_SCANNER_SHA256} \
    OSPD_OPENVAS_SHA256=${OSPD_OPENVAS_SHA256} \
    OPENVAS_REQUIRE_CHECKSUMS=${OPENVAS_REQUIRE_CHECKSUMS} OPENVAS_WITH_MQTT=${OPENVAS_WITH_MQTT} \
    bash /usr/local/sbin/install-openvas.sh \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# feed: VT feed snapshot + pre-warmed redis cache. Uses the openvas stage so
# `openvas --update-vt-info` and redis are available. docker/feed/ holds the
# tarball (or only the README, in which case the stage yields an empty
# plugins dir and seed-feed.sh warns loudly).
# ---------------------------------------------------------------------------
FROM openvas AS feed
ARG FEED_SHA256
COPY docker/feed/ /feed-src/
COPY packer/scripts/seed-feed.sh /usr/local/sbin/seed-feed.sh
RUN FEED_TARBALL="$(find /feed-src -maxdepth 1 -type f \( -name '*.tar' -o -name '*.tar.*' -o -name '*.tgz' \) -print -quit)" \
    FEED_SHA256=${FEED_SHA256} IN_CONTAINER=1 \
    bash /usr/local/sbin/seed-feed.sh \
    && rm -rf /feed-src /var/log/gvm/*

# ---------------------------------------------------------------------------
# final
# ---------------------------------------------------------------------------
# hadolint ignore=DL3006
FROM ${BASE_IMAGE}
ARG VERSION=dev
ARG TARGETARCH
ARG WITH_NMAP
LABEL org.opencontainers.image.title="scanner-appliance" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/tprm/scanner-appliance" \
      org.opencontainers.image.description="TPRM scanner appliance daemon and scan engine"

ENV DEBIAN_FRONTEND=noninteractive
# Runtime libraries for openvas/gvm-libs (keep in sync with RUNTIME_DEPS in
# packer/scripts/install-openvas.sh), redis for the VT cache, python3 for the
# ospd venv, util-linux for runuser.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates util-linux iproute2 \
        libglib2.0-0 libgpgme11 libgnutls30 libssh-gcrypt-4 libksba8 libpcap0.8 \
        libjson-glib-1.0-0 libcurl3-gnutls libhiredis0.14 libbsd0 libnet1 \
        libpaho-mqtt1.3 libgcrypt20 libcjson1 libsnmp40 libxml2 libuuid1 zlib1g \
        libkrb5-3 libgssapi-krb5-2 libmagic1 \
        redis-server redis-tools python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/appliance /run/appliance /etc/appliance /opt/engine \
    && chmod 0700 /var/lib/appliance

# Engine binaries and libraries (install-openvas.sh copied itself to
# /usr/local/sbin in that stage, so it comes along for the configure step).
COPY --from=openvas /usr/local/ /usr/local/
COPY --from=openvas /opt/ospd/ /opt/ospd/
RUN IN_CONTAINER=1 OPENVAS_SKIP_BUILD=1 bash /usr/local/sbin/install-openvas.sh \
    && ldconfig

# VT feed + redis dump. --chown resolves the names against this stage's
# /etc/passwd (uids may differ between stages); the redis subtree is copied
# again with its own owner.
COPY --from=feed --chown=openvas:openvas /var/lib/openvas/ /var/lib/openvas/
COPY --from=feed --chown=redis:redis /var/lib/openvas/redis/ /var/lib/openvas/redis/

# Phase 5 fingerprint pass: Debian's nmap (NPSL) only when asked for; the
# daemon finds it on $PATH (/usr/bin/nmap) and reports it in engine.tools.
RUN if [ "${WITH_NMAP}" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/* \
      && nmap --version > /tmp/nmap-version \
      && sed -n 1p /tmp/nmap-version > /etc/appliance/nmap-version && rm -f /tmp/nmap-version; \
    fi

COPY --from=build /src/bin/applianced-linux-${TARGETARCH} /usr/local/bin/applianced
COPY --from=engine /out/ /opt/engine/
COPY docker/oss-notices.txt /etc/appliance/oss-notices.txt
COPY docker/entrypoint.sh /usr/local/sbin/appliance-entrypoint.sh
RUN chmod 0755 /usr/local/sbin/appliance-entrypoint.sh \
    && printf '%s\n' "${VERSION}" > /etc/appliance/image-version

ENV PATH=/opt/engine:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Certificate + state MUST persist across restarts (PLAN 4.7).
VOLUME /var/lib/appliance
# Feed + redis dump; avoids re-seeding on restart.
VOLUME /var/lib/openvas
# applianced (PID 1) supervises redis-openvas and ospd-openvas itself
# (APPLIANCE_SUPERVISE_ENGINE=1, set by the entrypoint) and runs the job
# loop; the entrypoint only prepares runtime directories on the volumes.
ENV APPLIANCE_SUPERVISE_ENGINE=1
ENTRYPOINT ["/usr/local/sbin/appliance-entrypoint.sh"]
CMD []
