#!/usr/bin/env bash
# create-vm.sh - define and start a libvirt/KVM VM for the scanner appliance
# from the qcow2 (PLAN 4.1 KVM variant, Phase 5).
#
#   packer/kvm/create-vm.sh --name appliance-reno --image /var/lib/libvirt/images/appliance-1.2.3.qcow2 \
#       --wan-bridge br-mgmt [--lan-bridge br-floor] [--seed seed.yaml | --seed-iso seed.iso] \
#       [--uefi] [--memory 8192] [--cpus 4] [--no-start]
#
# The first network becomes wan0, the second lan0 (virtio NICs on the "pc"
# machine type land on the PCI paths the image's .link files know; any other
# layout falls back to enumeration order). --uefi boots through OVMF (the
# image carries both a BIOS and a UEFI loader). --seed builds the APPLIANCE
# ISO from a seed.yaml (docs/DEPLOY.md, Option B) with genisoimage, mkisofs
# or xorrisofs. The serial console is reachable with `virsh console <name>`.
set -euo pipefail

NAME=""
IMAGE=""
WAN=""
LAN=""
SEED=""
SEED_ISO=""
UEFI=0
MEMORY=8192
CPUS=4
START=1
OSINFO="${OSINFO:-debian12}"

usage() { sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) NAME="${2:?}"; shift 2 ;;
    --image) IMAGE="${2:?}"; shift 2 ;;
    --wan-bridge) WAN="${2:?}"; shift 2 ;;
    --lan-bridge) LAN="${2:?}"; shift 2 ;;
    --seed) SEED="${2:?}"; shift 2 ;;
    --seed-iso) SEED_ISO="${2:?}"; shift 2 ;;
    --uefi) UEFI=1; shift ;;
    --memory) MEMORY="${2:?}"; shift 2 ;;
    --cpus) CPUS="${2:?}"; shift 2 ;;
    --no-start) START=0; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[[ -n "$NAME" && -n "$IMAGE" && -n "$WAN" ]] || usage
[[ -s "$IMAGE" ]] || { echo "image not found: $IMAGE" >&2; exit 1; }
command -v virt-install >/dev/null || { echo "virt-install missing (apt-get install virtinst)" >&2; exit 1; }
if (( MEMORY < 8192 )); then
  echo "WARNING: the appliance minimum is 8 GB; the engine keeps its VT cache in memory" >&2
fi

log() { printf '[create-vm] %s\n' "$*"; }

# Seed ISO from seed.yaml (volume label APPLIANCE is what the daemon looks for).
if [[ -n "$SEED" ]]; then
  [[ -s "$SEED" ]] || { echo "seed file not found: $SEED" >&2; exit 1; }
  work="$(mktemp -d "${TMPDIR:-/tmp}/appliance-seed.XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  mkdir -p "$work/seed"
  cp "$SEED" "$work/seed/seed.yaml"
  SEED_ISO="$(dirname "$IMAGE")/${NAME}-seed.iso"
  if command -v genisoimage >/dev/null; then
    genisoimage -quiet -o "$SEED_ISO" -V APPLIANCE -r -J "$work/seed"
  elif command -v mkisofs >/dev/null; then
    mkisofs -quiet -o "$SEED_ISO" -V APPLIANCE -r -J "$work/seed"
  elif command -v xorrisofs >/dev/null; then
    xorrisofs -quiet -o "$SEED_ISO" -V APPLIANCE -r -J "$work/seed"
  else
    echo "need genisoimage, mkisofs or xorrisofs to build the seed ISO (or pass --seed-iso)" >&2
    exit 1
  fi
  log "seed ISO written to $SEED_ISO"
fi

args=(
  --name "$NAME" --memory "$MEMORY" --vcpus "$CPUS" --cpu host-passthrough
  --osinfo "$OSINFO" --import
  --disk "path=$IMAGE,format=qcow2,bus=virtio,discard=unmap"
  --network "bridge=$WAN,model=virtio"
  --graphics none --console "pty,target_type=serial" --noautoconsole
  --rng /dev/urandom
  --memballoon none
)
if [[ -n "$LAN" ]]; then
  args+=(--network "bridge=$LAN,model=virtio")
fi
if [[ -n "$SEED_ISO" ]]; then
  [[ -s "$SEED_ISO" ]] || { echo "seed ISO not found: $SEED_ISO" >&2; exit 1; }
  args+=(--disk "path=$SEED_ISO,device=cdrom,readonly=on")
fi
if [[ "$UEFI" == "1" ]]; then
  # OVMF; Secure Boot is enforced only with a secboot firmware and enrolled
  # keys (loader_secure=yes), which the Debian shim in the image supports.
  args+=(--boot uefi)
fi
if [[ "$START" != "1" ]]; then
  args+=(--noreboot)
fi

log "defining $NAME (wan0=$WAN${LAN:+ lan0=$LAN}${UEFI:+ uefi})"
virt-install "${args[@]}"
if [[ "$START" == "1" ]]; then
  log "started; console: virsh console $NAME (Ctrl-] to leave). Detach the seed ISO once the appliance is enrolled."
else
  log "defined; start with: virsh start $NAME"
fi
