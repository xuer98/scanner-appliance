#!/usr/bin/env bash
# Entrypoint for the cp-api dev container: initialise the development CA on
# first start, then run `cp-api serve`.
#
# Environment:
#   CP_DB_URL        postgres URL; empty => --dev (in-memory)
#   CP_PKI_DIR       directory with root.pem, intermediate.pem, intermediate-key.pem (default /pki)
#   CP_ENROLL_ADDR   default :8443
#   CP_MTLS_ADDR     default :9443
#   CP_PUBLIC_URL    what appliances are told to use after enrollment (default https://cp-api:9443)
#   CP_SERVER_CERT / CP_SERVER_KEY  optional server TLS cert/key
#   CP_ADMIN_TOKEN   bearer token for /admin/* (read by cp-api itself)
#   CP_EXTRA_ARGS    extra flags appended verbatim
set -euo pipefail

PKI_DIR="${CP_PKI_DIR:-/pki}"

if [[ ! -s "$PKI_DIR/root.pem" ]]; then
  echo "[cp-api] no CA in $PKI_DIR; initialising a development CA"
  cp-api ca init --dir "$PKI_DIR"
fi

args=(serve --pki-dir "$PKI_DIR"
  --enroll-addr "${CP_ENROLL_ADDR:-:8443}"
  --mtls-addr "${CP_MTLS_ADDR:-:9443}"
  --public-url "${CP_PUBLIC_URL:-https://cp-api:9443}")

if [[ -n "${CP_DB_URL:-}" ]]; then
  args+=(--db "$CP_DB_URL")
else
  args+=(--dev)
fi
[[ -n "${CP_SERVER_CERT:-}" ]] && args+=(--server-cert "$CP_SERVER_CERT")
[[ -n "${CP_SERVER_KEY:-}" ]] && args+=(--server-key "$CP_SERVER_KEY")
[[ -n "${CP_ADMIN_TOKEN:-}" ]] && args+=(--admin-token "$CP_ADMIN_TOKEN")
if [[ -n "${CP_EXTRA_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  args+=(${CP_EXTRA_ARGS})
fi

echo "[cp-api] exec cp-api ${args[*]}"
exec cp-api "${args[@]}"
