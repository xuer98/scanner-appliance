#!/usr/bin/env bash
# build-vhdx.sh - convert the Packer qcow2 into a dynamic VHDX for Hyper-V
# (PLAN 4.1). No OVF properties on Hyper-V: seed via a volume labelled
# APPLIANCE or the console.
#
#   packer/build-vhdx.sh <image.qcow2> <version> [output-dir]
#
# Writes appliance-<version>.vhdx and appliance-<version>.vhdx.zip, each with
# a .sha256. The release carries the zip: ext4 scatters its metadata across
# the whole 60 GB disk, so even a dynamic VHDX with 1 MB blocks is over 3 GB
# while the data in it is under 1 GB, and GitHub rejects release assets above
# 2 GiB. The zip is about a quarter of that and Windows opens it natively.
set -euo pipefail

usage() {
  echo "usage: $0 <image.qcow2> <version> [output-dir]" >&2
  exit 2
}

[[ $# -ge 2 && $# -le 3 ]] || usage
QCOW2="$1"
VERSION="$2"
OUT_DIR="${3:-$(dirname "$QCOW2")}"

[[ -s "$QCOW2" ]] || { echo "qcow2 not found: $QCOW2" >&2; exit 1; }
for tool in qemu-img zip; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

sha256_of() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

mkdir -p "$OUT_DIR"
VHDX="${OUT_DIR}/appliance-${VERSION}.vhdx"

echo "[build-vhdx] converting $QCOW2 -> $VHDX (dynamic, 1 MB blocks)"
rm -f "$VHDX" "${VHDX}.zip"
# 1 MB blocks: Microsoft's recommendation for Linux guests on dynamic VHDX,
# and the file stays close to the size of the data in it (32 MB blocks, the
# Hyper-V default, made this image five times larger).
qemu-img convert -p -f qcow2 -O vhdx -o subformat=dynamic,block_state_zero=on,block_size=1M "$QCOW2" "$VHDX"
qemu-img check -f vhdx "$VHDX" >/dev/null 2>&1 || true
sha256_of "$VHDX" >"${VHDX}.sha256"
echo "[build-vhdx] wrote $VHDX"

echo "[build-vhdx] compressing $VHDX -> ${VHDX}.zip"
zip -q -j "${VHDX}.zip" "$VHDX"
sha256_of "${VHDX}.zip" >"${VHDX}.zip.sha256"
echo "[build-vhdx] wrote ${VHDX}.zip"
