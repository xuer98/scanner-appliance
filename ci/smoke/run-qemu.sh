#!/usr/bin/env bash
# ci/smoke/run-qemu.sh - PLAN 18.2 smoke test for the qcow2 image.
#
#   ci/smoke/run-qemu.sh <appliance.qcow2>
#
# 1. Creates an appliance row on the control plane (admin API) and gets a code.
# 2. Builds a seed ISO (volume label APPLIANCE, seed.yaml with code + cp url).
# 3. Boots the image headless in qemu-system-x86_64 with the serial console on
#    a local TCP port (equivalent of -nographic, but scriptable) and both NICs
#    on user-mode networking.
# 4. Waits until the appliance is "enrolled" with a heartbeat (180 s default).
# 5. Drives the console menu over serial with tty.expect.
# 6. Queues set_interval and stop_all and waits for the acks.
#
# Environment (see also ci/smoke/lib.sh):
#   CP_ADMIN_URL, CP_ADMIN_TOKEN   /admin API (from this host; the mTLS
#                                  listener, :9443 by default)
#   CP_URL_FOR_GUEST               enrollment URL as seen from inside the VM
#                                  (default https://10.0.2.2:8443 = the host
#                                  through QEMU user networking)
#   SMOKE_QEMU_MEM / SMOKE_QEMU_CPUS  guest size (8192 MB / 4, the appliance
#                                  minimum; redis holds the VT cache)
#   QEMU_ACCEL                     kvm|tcg (auto: kvm when /dev/kvm is usable)
#   SMOKE_SERIAL_PORT              TCP port for the serial console (auto)
#   SMOKE_KEEP=1                   keep the work directory and serial log
#   SMOKE_SKIP_TTY=1               skip the expect-driven console test
#   SMOKE_UEFI=1                   boot through OVMF instead of SeaBIOS (the
#                                  hybrid image's UEFI loader, Phase 5; needs
#                                  the ovmf package). Secure Boot itself needs
#                                  a secboot firmware with enrolled keys and
#                                  is exercised on Hyper-V, not here.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/smoke/lib.sh
source "$HERE/lib.sh"

[[ $# -eq 1 ]] || { echo "usage: $0 <appliance.qcow2>" >&2; exit 2; }
QCOW2="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
[[ -s "$QCOW2" ]] || smoke_die "image not found: $QCOW2"

smoke_require_tools qemu-system-x86_64 qemu-img curl jq
if [[ "${SMOKE_SKIP_TTY:-0}" != "1" ]]; then
  smoke_require_tools expect
fi

CP_URL_FOR_GUEST="${CP_URL_FOR_GUEST:-https://10.0.2.2:8443}"
ACCEL="${QEMU_ACCEL:-}"
if [[ -z "$ACCEL" ]]; then
  if [[ -w /dev/kvm ]]; then ACCEL=kvm; else ACCEL=tcg; fi
fi
SERIAL_PORT="${SMOKE_SERIAL_PORT:-$((20000 + RANDOM % 20000))}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/smoke-qemu.XXXXXX")"
QEMU_PID=""
cleanup() {
  local rc=$?
  if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    smoke_log "stopping qemu (pid $QEMU_PID)"
    kill "$QEMU_PID" 2>/dev/null || true
    sleep 2
    kill -9 "$QEMU_PID" 2>/dev/null || true
  fi
  if [[ $rc -ne 0 && -s "$WORK/serial.log" ]]; then
    echo "----- last 80 lines of serial console -----" >&2
    tail -n 80 "$WORK/serial.log" >&2
  fi
  if [[ "${SMOKE_KEEP:-0}" == "1" ]]; then
    smoke_log "work directory kept: $WORK"
  else
    rm -rf "$WORK"
  fi
  exit $rc
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Appliance row + code
# ---------------------------------------------------------------------------
cp_wait_ready 60
read -r APPLIANCE_ID CODE < <(cp_create_appliance)
smoke_log "created appliance $APPLIANCE_ID"

# ---------------------------------------------------------------------------
# 2. Seed ISO
# ---------------------------------------------------------------------------
mkdir -p "$WORK/seed"
cat >"$WORK/seed/seed.yaml" <<EOF
code: "${CODE}"
cp_url: "${CP_URL_FOR_GUEST}"
network:
  wan0: { mode: dhcp }
  lan0: { mode: dhcp }
split: ${SMOKE_SPLIT:-true}
EOF

if command -v genisoimage >/dev/null; then
  genisoimage -quiet -o "$WORK/seed.iso" -V APPLIANCE -r -J "$WORK/seed"
elif command -v mkisofs >/dev/null; then
  mkisofs -quiet -o "$WORK/seed.iso" -V APPLIANCE -r -J "$WORK/seed"
elif command -v xorrisofs >/dev/null; then
  xorrisofs -quiet -o "$WORK/seed.iso" -V APPLIANCE -r -J "$WORK/seed"
elif command -v hdiutil >/dev/null; then
  hdiutil makehybrid -quiet -iso -joliet -default-volume-name APPLIANCE -o "$WORK/seed.iso" "$WORK/seed"
else
  smoke_die "need genisoimage, mkisofs, xorrisofs or hdiutil to build the seed ISO"
fi
smoke_log "seed ISO built"

# ---------------------------------------------------------------------------
# 3. Boot (copy-on-write overlay keeps the release artifact pristine)
# ---------------------------------------------------------------------------
qemu-img create -q -f qcow2 -b "$QCOW2" -F qcow2 "$WORK/overlay.qcow2"

qemu_args=(
  -name appliance-smoke
  -machine "type=pc,accel=${ACCEL}"
  -m "${SMOKE_QEMU_MEM:-8192}" -smp "${SMOKE_QEMU_CPUS:-4}"
  -drive "file=${WORK}/overlay.qcow2,if=virtio,format=qcow2,discard=unmap"
  -drive "file=${WORK}/seed.iso,media=cdrom,readonly=on"
  # wan0: user-mode net, host reachable as 10.0.2.2
  -netdev "user,id=wan,net=10.0.2.0/24"
  -device "virtio-net-pci,netdev=wan,addr=0x3"
  # lan0: a second, different user-mode subnet with no route out
  -netdev "user,id=lan,net=10.0.3.0/24,restrict=on"
  -device "virtio-net-pci,netdev=lan,addr=0x4"
  -display none -monitor none
  -chardev "socket,id=ser0,host=127.0.0.1,port=${SERIAL_PORT},server=on,wait=off,logfile=${WORK}/serial.log"
  -serial chardev:ser0
  -boot c
  -rtc base=utc
)
if [[ "$ACCEL" == "kvm" ]]; then
  qemu_args+=(-cpu host)
fi
if [[ "${SMOKE_UEFI:-0}" == "1" ]]; then
  ovmf_code=""
  for c in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/edk2/x64/OVMF_CODE.4m.fd /usr/share/qemu/edk2-x86_64-code.fd; do
    [[ -s "$c" ]] && { ovmf_code="$c"; break; }
  done
  [[ -n "$ovmf_code" ]] || smoke_die "SMOKE_UEFI=1 but no OVMF firmware found (apt-get install ovmf)"
  ovmf_vars="${ovmf_code/CODE/VARS}"
  ovmf_vars="${ovmf_vars/code/vars}"
  if [[ -s "$ovmf_vars" ]]; then
    cp "$ovmf_vars" "$WORK/ovmf-vars.fd"
  else
    truncate -s "$(stat -c %s "$ovmf_code" 2>/dev/null || stat -f %z "$ovmf_code")" "$WORK/ovmf-vars.fd"
  fi
  qemu_args+=(-drive "if=pflash,format=raw,readonly=on,file=${ovmf_code}" -drive "if=pflash,format=raw,file=${WORK}/ovmf-vars.fd")
  smoke_log "UEFI boot through $ovmf_code"
fi

smoke_log "booting $QCOW2 (accel=$ACCEL, serial on 127.0.0.1:$SERIAL_PORT)"
qemu-system-x86_64 "${qemu_args[@]}" >"$WORK/qemu.out" 2>&1 &
QEMU_PID=$!
sleep 3
kill -0 "$QEMU_PID" 2>/dev/null || { cat "$WORK/qemu.out" >&2; smoke_die "qemu exited early"; }

# ---------------------------------------------------------------------------
# 4. Enrollment + first heartbeat
# ---------------------------------------------------------------------------
cp_wait_enrolled "$APPLIANCE_ID" "$SMOKE_TIMEOUT"

# ---------------------------------------------------------------------------
# 5. Console menu over serial
# ---------------------------------------------------------------------------
if [[ "${SMOKE_SKIP_TTY:-0}" != "1" ]]; then
  smoke_log "driving the console menu over serial"
  expect -f "$HERE/tty.expect" 127.0.0.1 "$SERIAL_PORT"
else
  smoke_log "SMOKE_SKIP_TTY=1: skipping console test"
fi

# ---------------------------------------------------------------------------
# 6. Scan jobs (PLAN §18.2), then directives
# ---------------------------------------------------------------------------
cp_job_roundtrip "$APPLIANCE_ID"
# Split-network mode (PLAN §15): lan0 sits on the restricted 10.0.3.0/24
# user-mode network (no route out); QEMU's virtual gateway answers there.
SMOKE_LAN_TARGETS="${SMOKE_LAN_TARGETS:-10.0.3.0/24}" cp_lan_roundtrip "$APPLIANCE_ID"
cp_directive_roundtrip "$APPLIANCE_ID"
cp_bundle_roundtrip "$APPLIANCE_ID"
cp_pilot_roundtrip "$APPLIANCE_ID"
cp_depth_roundtrip "$APPLIANCE_ID"
cp_replace_roundtrip "$APPLIANCE_ID"

smoke_log "PASS: appliance $APPLIANCE_ID enrolled, console OK, scan jobs done (incl. the no-egress segment), directives acked, bundles applied, pilot, depth and replacement operations OK"
