#!/usr/bin/env bash
# build-vhdx.sh - convert the Packer qcow2 into a dynamic VHDX for Hyper-V
# (PLAN 4.1). No OVF properties on Hyper-V: seed via a volume labelled
# APPLIANCE or the console.
#
#   packer/build-vhdx.sh <image.qcow2> <version> [output-dir]
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
command -v qemu-img >/dev/null || { echo "missing tool: qemu-img" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

mkdir -p "$OUT_DIR"
VHDX="${OUT_DIR}/appliance-${VERSION}.vhdx"

echo "[build-vhdx] converting $QCOW2 -> $VHDX (dynamic)"
rm -f "$VHDX"
qemu-img convert -p -f qcow2 -O vhdx -o subformat=dynamic,block_state_zero=on "$QCOW2" "$VHDX"
qemu-img check -f vhdx "$VHDX" >/dev/null 2>&1 || true
sha256_of "$VHDX" >"${VHDX}.sha256"
echo "[build-vhdx] wrote $VHDX"
