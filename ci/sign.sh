#!/usr/bin/env bash
# ci/sign.sh - sign every release artifact in dist/ with cosign and produce a
# syft SBOM per artifact.
#
#   ci/sign.sh [dist-dir]
#
# Environment:
#   COSIGN_KEY        path or KMS URI of a signing key; unset => keyless (OIDC)
#   COSIGN_PASSWORD   passphrase for a file-based key (cosign reads it)
#   SIGN_SKIP_MISSING set to 0 to fail (instead of warn) when cosign/syft are absent
#
# Outputs next to each artifact: <name>.sig, <name>.pem (keyless certificate)
# and <name>.sbom.spdx.json. Signatures/SBOMs/manifest are never re-signed.
set -euo pipefail

DIST="${1:-dist}"
SKIP_MISSING="${SIGN_SKIP_MISSING:-1}"

log() { printf '[sign] %s\n' "$*"; }
warn() { printf '[sign] WARNING: %s\n' "$*" >&2; }

[[ -d "$DIST" ]] || { echo "dist directory not found: $DIST" >&2; exit 1; }

have_cosign=0
have_syft=0
command -v cosign >/dev/null && have_cosign=1
command -v syft >/dev/null && have_syft=1

if [[ $have_cosign -eq 0 ]]; then
  warn "cosign not installed; artifacts will NOT be signed"
  [[ "$SKIP_MISSING" == "1" ]] || exit 1
fi
if [[ $have_syft -eq 0 ]]; then
  warn "syft not installed; no SBOMs will be generated"
  [[ "$SKIP_MISSING" == "1" ]] || exit 1
fi

is_artifact() {
  case "$(basename "$1")" in
    *.sig|*.pem|*.sbom.spdx.json|*.sha256|manifest.json|VERSION|*.bundle) return 1 ;;
  esac
  [[ -f "$1" ]]
}

cosign_args=(--yes)
if [[ -n "${COSIGN_KEY:-}" ]]; then
  cosign_args+=(--key "$COSIGN_KEY")
  log "signing with key $COSIGN_KEY"
else
  log "signing keyless (Sigstore OIDC)"
fi

count=0
for f in "$DIST"/*; do
  is_artifact "$f" || continue
  name="$(basename "$f")"
  count=$((count + 1))

  if [[ $have_cosign -eq 1 ]]; then
    log "cosign sign-blob $name"
    sig_args=(--output-signature "${f}.sig")
    # The certificate only exists for keyless signing.
    [[ -n "${COSIGN_KEY:-}" ]] || sig_args+=(--output-certificate "${f}.pem")
    cosign sign-blob "${cosign_args[@]}" "${sig_args[@]}" "$f"
  fi

  if [[ $have_syft -eq 1 ]]; then
    log "syft $name"
    # Disk images (qcow2/ova/vhdx) are opaque to syft; the SBOM for the OS
    # inside them is produced from the container image, which shares the
    # daemon and engine binaries. Do not fail the release on them.
    if ! syft scan "file:${f}" -q -o "spdx-json=${f}.sbom.spdx.json"; then
      warn "syft failed on $name; writing no SBOM"
      rm -f "${f}.sbom.spdx.json"
    fi
  fi
done

if [[ $count -eq 0 ]]; then
  warn "no artifacts found in $DIST"
fi
log "processed $count artifact(s)"
