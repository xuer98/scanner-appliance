#!/usr/bin/env bash
# ci/build.sh - build applianced and cp-api for linux/amd64 + linux/arm64.
#
#   ci/build.sh [--version X] [--dev] [--arch "amd64 arm64"] [--skip-cp]
#
# The daemon embeds the pinned root CA from daemon/internal/pki/roots.pem.
# That file is copied from $APPLIANCE_ROOT_CA (path to a PEM) before building;
# with --dev a development CA is generated instead:
#   go run ./controlplane/cmd/cp-api ca init --dir dev/pki
# which creates dev/pki/{root.pem,intermediate.pem,intermediate-key.pem}.
#
# Outputs:
#   bin/applianced-linux-<arch>   (what packer/base.pkr.hcl uploads)
#   dist/applianced-linux-<arch>, dist/cp-api-linux-<arch>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION=""
DEV=0
ARCHES="amd64 arm64"
BUILD_CP=1

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --dev) DEV=1; shift ;;
    --arch) ARCHES="${2:?--arch needs a value}"; shift 2 ;;
    --arch=*) ARCHES="${1#*=}"; shift ;;
    --skip-cp) BUILD_CP=0; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

log() { printf '[build] %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Version: explicit flag, else git tag (v1.2.3 -> 1.2.3), else "dev".
# ---------------------------------------------------------------------------
if [[ -z "$VERSION" ]]; then
  if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"
    VERSION="${VERSION#v}"
  else
    VERSION="dev"
  fi
fi
log "version $VERSION"

# ---------------------------------------------------------------------------
# Root CA to embed.
# ---------------------------------------------------------------------------
ROOTS_DEST="daemon/internal/pki/roots.pem"
if [[ $DEV -eq 1 ]]; then
  if [[ ! -s dev/pki/root.pem ]]; then
    log "generating development CA in dev/pki"
    mkdir -p dev/pki
    go run ./controlplane/cmd/cp-api ca init --dir dev/pki
  fi
  for f in root.pem intermediate.pem intermediate-key.pem; do
    [[ -s "dev/pki/$f" ]] || { echo "dev/pki/$f missing after ca init" >&2; exit 1; }
  done
  APPLIANCE_ROOT_CA="dev/pki/root.pem"
  log "using development root CA dev/pki/root.pem (NOT for release builds)"
fi

if [[ -z "${APPLIANCE_ROOT_CA:-}" ]]; then
  cat >&2 <<'EOF'
APPLIANCE_ROOT_CA is not set. Point it at the PEM of the root CA the daemon
must pin, or pass --dev to generate a throw-away development CA.
EOF
  exit 1
fi
[[ -s "$APPLIANCE_ROOT_CA" ]] || { echo "APPLIANCE_ROOT_CA=$APPLIANCE_ROOT_CA is not a readable file" >&2; exit 1; }
grep -q 'BEGIN CERTIFICATE' "$APPLIANCE_ROOT_CA" || { echo "$APPLIANCE_ROOT_CA does not look like a PEM certificate" >&2; exit 1; }
mkdir -p "$(dirname "$ROOTS_DEST")"
cp "$APPLIANCE_ROOT_CA" "$ROOTS_DEST"
log "embedded root CA from $APPLIANCE_ROOT_CA"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
mkdir -p bin dist
export CGO_ENABLED=0 GOOS=linux GOFLAGS="${GOFLAGS:-}"

build_one() {
  local pkg="$1" name="$2" arch="$3"
  local out="bin/${name}-linux-${arch}"
  log "building $out"
  GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "$out" "$pkg"
  cp "$out" "dist/${name}-linux-${arch}"
}

for arch in $ARCHES; do
  build_one ./daemon/cmd/applianced applianced "$arch"
  if [[ $BUILD_CP -eq 1 ]]; then
    build_one ./controlplane/cmd/cp-api cp-api "$arch"
  fi
done

echo "$VERSION" >dist/VERSION
log "done:"
ls -l dist/
