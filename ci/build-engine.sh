#!/usr/bin/env bash
# ci/build-engine.sh - build the scan-engine helper binaries that ship in
# /opt/engine of the VM image (the container builds its own in the
# Dockerfile's `engine` stage from the same pins).
#
#   ci/build-engine.sh [--arch amd64] [--out bin/engine]
#
# Phase 2 ships naabu (discovery + port scan, PLAN §10.2). naabu links
# libpcap through cgo, so this builds natively on a Linux host with
# libpcap-dev installed (ubuntu: apt-get install -y libpcap-dev). The
# result also lands in dist/engine/<name>-linux-<arch> for the release job.
#
# Versions are pinned here and in docker/Dockerfile (NAABU_VERSION); bump
# both together.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NAABU_VERSION="${NAABU_VERSION:-v2.3.6}"
ARCH="${ARCH:-$(go env GOARCH)}"
OUT="bin/engine"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) ARCH="${2:?--arch needs a value}"; shift 2 ;;
    --arch=*) ARCH="${1#*=}"; shift ;;
    --out) OUT="${2:?--out needs a value}"; shift 2 ;;
    --out=*) OUT="${1#*=}"; shift ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

log() { printf '[build-engine] %s\n' "$*"; }

if [[ "$(go env GOOS)" != "linux" ]]; then
  echo "naabu needs a native Linux build (cgo + libpcap); run this on Linux or use the container image" >&2
  exit 1
fi
if ! printf '#include <pcap.h>\n' | gcc -E - >/dev/null 2>&1; then
  echo "libpcap headers missing: apt-get install -y libpcap-dev" >&2
  exit 1
fi

mkdir -p "$OUT" dist/engine
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

log "building naabu ${NAABU_VERSION} for linux/${ARCH}"
GOBIN="$tmp" GOFLAGS=-trimpath CGO_ENABLED=1 GOOS=linux GOARCH="$ARCH" \
  go install -ldflags="-s -w" "github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}"
bin="$tmp/naabu"
[[ -x "$bin" ]] || bin="$(find "$tmp" -type f -name naabu -perm -u+x | head -n1)"
[[ -n "$bin" && -x "$bin" ]] || { echo "naabu binary not produced" >&2; exit 1; }
install -m 0755 "$bin" "$OUT/naabu"
cp "$OUT/naabu" "dist/engine/naabu-linux-${ARCH}"
printf 'naabu %s\n' "$NAABU_VERSION" >"$OUT/VERSIONS"
log "done: $(wc -c <"$OUT/naabu" | tr -d ' ') bytes -> $OUT/naabu, dist/engine/naabu-linux-${ARCH}"
