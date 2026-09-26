#!/usr/bin/env bash
# ci/manifest.sh - write dist/manifest.json describing every release artifact.
#
#   ci/manifest.sh [dist-dir] [version]
#
# {
#   "version": "1.2.3",
#   "built_at": "2026-09-26T12:00:00Z",
#   "artifacts": [
#     {"name": "...", "sha256": "...", "size": 123, "sig": "....sig"|null, "sbom": "....sbom.spdx.json"|null}
#   ]
# }
# The portal download page reads this file (PLAN 18.1).
set -euo pipefail

DIST="${1:-dist}"
VERSION="${2:-}"

[[ -d "$DIST" ]] || { echo "dist directory not found: $DIST" >&2; exit 1; }
if [[ -z "$VERSION" ]]; then
  if [[ -s "$DIST/VERSION" ]]; then
    VERSION="$(<"$DIST/VERSION")"
  elif git rev-parse --git-dir >/dev/null 2>&1; then
    VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
    VERSION="${VERSION#v}"
  else
    VERSION="dev"
  fi
fi

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

is_artifact() {
  case "$(basename "$1")" in
    *.sig|*.pem|*.sbom.spdx.json|*.sha256|manifest.json|VERSION|*.bundle) return 1 ;;
  esac
  [[ -f "$1" ]]
}

# Artifact names are produced by our own scripts (no quotes/backslashes), but
# escape anyway so the output is always valid JSON.
json_str() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '"%s"' "$s"
}

built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
out="$DIST/manifest.json"
tmp="$(mktemp "${TMPDIR:-/tmp}/manifest.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

{
  printf '{\n'
  printf '  "version": %s,\n' "$(json_str "$VERSION")"
  printf '  "built_at": %s,\n' "$(json_str "$built_at")"
  printf '  "artifacts": [\n'
  first=1
  for f in "$DIST"/*; do
    is_artifact "$f" || continue
    name="$(basename "$f")"
    sig="null"
    sbom="null"
    [[ -s "${f}.sig" ]] && sig="$(json_str "${name}.sig")"
    [[ -s "${f}.sbom.spdx.json" ]] && sbom="$(json_str "${name}.sbom.spdx.json")"
    [[ $first -eq 1 ]] || printf ',\n'
    first=0
    printf '    {"name": %s, "sha256": %s, "size": %s, "sig": %s, "sbom": %s}' \
      "$(json_str "$name")" "$(json_str "$(sha256_of "$f")")" "$(size_of "$f")" "$sig" "$sbom"
  done
  printf '\n  ]\n}\n'
} >"$tmp"

# Sanity-check the JSON when a parser is available.
if command -v jq >/dev/null; then
  jq -e . "$tmp" >/dev/null
elif command -v python3 >/dev/null; then
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$tmp"
fi

mv "$tmp" "$out"
trap - EXIT
echo "[manifest] wrote $out"
cat "$out"
