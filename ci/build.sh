#!/usr/bin/env bash
# ci/build.sh - build applianced and cp-api for every release target.
#
#   ci/build.sh [--version X] [--dev] [--targets "linux/amd64 linux/arm64 windows/amd64"] [--skip-cp]
#   ci/build.sh --arch "amd64 arm64"      # Linux only (older spelling)
#
# Targets are GOOS/GOARCH pairs; the default is the release set. Linux is the
# appliance (image + container); Windows is the daemon-only host build
# (README "Running the daemon on Windows").
#
# The daemon embeds the pinned root CA from daemon/internal/pki/roots.pem and
# the release signing public key from daemon/internal/pki/release-pub.pem
# (bundles and self-updates, PLAN §13/§14). They are copied from
# $APPLIANCE_ROOT_CA and $APPLIANCE_RELEASE_PUB (PEM paths) before building;
# with --dev a development CA and release key are generated instead:
#   go run ./controlplane/cmd/cp-api ca init --dir dev/pki
# which creates dev/pki/{root.pem,intermediate.pem,intermediate-key.pem,
# release-key.pem,release-pub.pem}. An unset APPLIANCE_RELEASE_PUB leaves the
# embedded key empty (updates refused) with a warning.
#
# Outputs:
#   bin/applianced-linux-<arch>           (what packer/base.pkr.hcl uploads)
#   bin/applianced-windows-<arch>.exe
#   dist/applianced-<os>-<arch>[.exe], dist/cp-api-<os>-<arch>[.exe]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION=""
DEV=0
TARGETS="linux/amd64 linux/arm64 windows/amd64"
BUILD_CP=1

usage() {
  sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
}

linux_targets() {
  local out="" a
  for a in $1; do out="$out linux/$a"; done
  printf '%s' "${out# }"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --dev) DEV=1; shift ;;
    --targets) TARGETS="${2:?--targets needs a value}"; shift 2 ;;
    --targets=*) TARGETS="${1#*=}"; shift ;;
    --arch) TARGETS="$(linux_targets "${2:?--arch needs a value}")"; shift 2 ;;
    --arch=*) TARGETS="$(linux_targets "${1#*=}")"; shift ;;
    --skip-cp) BUILD_CP=0; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

log() { printf '[build] %s\n' "$*"; }

for t in $TARGETS; do
  case "$t" in
    */*) ;;
    *) echo "bad target '$t': want GOOS/GOARCH, e.g. linux/amd64" >&2; exit 2 ;;
  esac
done

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
  # Older dev/pki directories predate the release key.
  [[ -s dev/pki/release-pub.pem ]] || go run ./controlplane/cmd/cp-api ca release-key --dir dev/pki
  APPLIANCE_ROOT_CA="dev/pki/root.pem"
  APPLIANCE_RELEASE_PUB="dev/pki/release-pub.pem"
  log "using development root CA and release key from dev/pki (NOT for release builds)"
fi

if [[ -z "${APPLIANCE_ROOT_CA:-}" ]]; then
  cat >&2 <<'EOM'
APPLIANCE_ROOT_CA is not set. Point it at the PEM of the root CA the daemon
must pin, or pass --dev to generate a throw-away development CA.
EOM
  exit 1
fi
[[ -s "$APPLIANCE_ROOT_CA" ]] || { echo "APPLIANCE_ROOT_CA=$APPLIANCE_ROOT_CA is not a readable file" >&2; exit 1; }
grep -q 'BEGIN CERTIFICATE' "$APPLIANCE_ROOT_CA" || { echo "$APPLIANCE_ROOT_CA does not look like a PEM certificate" >&2; exit 1; }
mkdir -p "$(dirname "$ROOTS_DEST")"
cp "$APPLIANCE_ROOT_CA" "$ROOTS_DEST"
log "embedded root CA from $APPLIANCE_ROOT_CA"

RELEASE_DEST="daemon/internal/pki/release-pub.pem"
if [[ -n "${APPLIANCE_RELEASE_PUB:-}" ]]; then
  [[ -s "$APPLIANCE_RELEASE_PUB" ]] || { echo "APPLIANCE_RELEASE_PUB=$APPLIANCE_RELEASE_PUB is not a readable file" >&2; exit 1; }
  grep -q 'BEGIN PUBLIC KEY' "$APPLIANCE_RELEASE_PUB" || { echo "$APPLIANCE_RELEASE_PUB does not look like a PEM public key" >&2; exit 1; }
  cp "$APPLIANCE_RELEASE_PUB" "$RELEASE_DEST"
  log "embedded release signing key from $APPLIANCE_RELEASE_PUB"
else
  : >"$RELEASE_DEST"
  log "WARNING: APPLIANCE_RELEASE_PUB not set; the daemon will refuse bundles and self-updates"
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
mkdir -p bin dist
export CGO_ENABLED=0 GOFLAGS="${GOFLAGS:-}"

build_one() {
  local pkg="$1" name="$2" goos="$3" goarch="$4"
  local suffix=""
  [[ "$goos" == "windows" ]] && suffix=".exe"
  local out="bin/${name}-${goos}-${goarch}${suffix}"
  log "building $out"
  GOOS="$goos" GOARCH="$goarch" go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "$out" "$pkg"
  cp "$out" "dist/$(basename "$out")"
}

for t in $TARGETS; do
  goos="${t%%/*}"
  goarch="${t#*/}"
  build_one ./daemon/cmd/applianced applianced "$goos" "$goarch"
  if [[ $BUILD_CP -eq 1 ]]; then
    build_one ./controlplane/cmd/cp-api cp-api "$goos" "$goarch"
  fi
done

echo "$VERSION" >dist/VERSION
log "done:"
ls -l dist/
