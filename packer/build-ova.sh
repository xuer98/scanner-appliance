#!/usr/bin/env bash
# build-ova.sh - convert the Packer qcow2 into a VMware OVA (PLAN 4.1).
#
#   packer/build-ova.sh <image.qcow2> <version> [output-dir]
#
# Steps: qcow2 -> streamOptimized vmdk, fill packer/ovf/descriptor.ovf.tmpl,
# write the .mf SHA256 manifest, tar (OVF first, then vmdk, then mf), and
# validate with ovftool when it is installed.
set -euo pipefail

usage() {
  echo "usage: $0 <image.qcow2> <version> [output-dir]" >&2
  exit 2
}

[[ $# -ge 2 && $# -le 3 ]] || usage
QCOW2="$1"
VERSION="$2"
OUT_DIR="${3:-$(dirname "$QCOW2")}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${OVF_TEMPLATE:-$HERE/ovf/descriptor.ovf.tmpl}"

[[ -s "$QCOW2" ]] || { echo "qcow2 not found: $QCOW2" >&2; exit 1; }
[[ -s "$TEMPLATE" ]] || { echo "template not found: $TEMPLATE" >&2; exit 1; }
for tool in qemu-img tar; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

sha256_of() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

size_of() {
  if stat -c %s "$1" >/dev/null 2>&1; then
    stat -c %s "$1"
  else
    stat -f %z "$1"
  fi
}

NAME="appliance-${VERSION}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/build-ova.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT_DIR"

OVF="${NAME}.ovf"
VMDK="${NAME}-disk1.vmdk"
MF="${NAME}.mf"
OVA="${OUT_DIR}/${NAME}.ova"

echo "[build-ova] converting $QCOW2 -> $VMDK (streamOptimized)"
qemu-img convert -p -f qcow2 -O vmdk -o subformat=streamOptimized "$QCOW2" "$WORK/$VMDK"

capacity="$(qemu-img info --output=json "$QCOW2" | sed -n 's/.*"virtual-size": *\([0-9]*\).*/\1/p' | head -n1)"
[[ -n "$capacity" ]] || { echo "could not read virtual size of $QCOW2" >&2; exit 1; }
vmdk_size="$(size_of "$WORK/$VMDK")"

echo "[build-ova] writing $OVF"
sed \
  -e "s|{{VERSION}}|${VERSION}|g" \
  -e "s|{{DISK_FILE}}|${VMDK}|g" \
  -e "s|{{DISK_SIZE}}|${vmdk_size}|g" \
  -e "s|{{DISK_CAPACITY}}|${capacity}|g" \
  -e "s|{{DISK_POPULATED}}|${vmdk_size}|g" \
  "$TEMPLATE" >"$WORK/$OVF"

if grep -q '{{[A-Z_]*}}' "$WORK/$OVF"; then
  echo "unfilled placeholders remain in $OVF:" >&2
  grep -o '{{[A-Z_]*}}' "$WORK/$OVF" | sort -u >&2
  exit 1
fi
if command -v xmllint >/dev/null; then
  xmllint --noout "$WORK/$OVF"
fi

echo "[build-ova] writing $MF"
{
  printf 'SHA256(%s)= %s\n' "$OVF" "$(sha256_of "$WORK/$OVF")"
  printf 'SHA256(%s)= %s\n' "$VMDK" "$(sha256_of "$WORK/$VMDK")"
} >"$WORK/$MF"

echo "[build-ova] packing $OVA"
rm -f "$OVA"
# OVA = plain ustar with the descriptor as the first member.
tar --format=ustar -cf "$OVA" -C "$WORK" "$OVF" "$VMDK" "$MF"

if command -v ovftool >/dev/null; then
  echo "[build-ova] validating with ovftool"
  ovftool --schemaValidate "$OVA"
else
  echo "[build-ova] ovftool not installed; skipping schema validation" >&2
fi

sha256_of "$OVA" >"${OVA}.sha256"
echo "[build-ova] wrote $OVA ($(size_of "$OVA") bytes)"
