# Scanner appliance

Vendor-run, outbound-only network scanner with its own control plane. See [PLAN.md](PLAN.md) for the design; this README covers what exists after **Phase 1** (foundation) and how to run it.

## What Phase 1 delivers

| Piece | Where | Status |
|-------|-------|--------|
| `applianced` daemon: seed resolution (OVF → volume → env → console), P-256 key + CSR, enrollment, mTLS heartbeat loop with jitter/backoff, directive dispatch + ack, clock-skew correction, cert renewal at ⅔ lifetime, wipe | `daemon/` | done, tested |
| TTY console (Status / Network / Proxy / Enroll / Support bundle / Wipe), fixed input grammar, 5-min idle return | `daemon/internal/tty` | done, tested |
| Engine health probe over OSP (`ospd_up`, `vt_cache_loaded`) reported in every heartbeat | `daemon/internal/osp` | done, tested against a fake ospd |
| `cp-api`: internal CA (root + issuing intermediate), single-use hashed enrollment codes, enroll listener (no client cert) + mTLS listener with per-request revocation check, heartbeat + directives, support-bundle upload, admin API + CLI, Postgres migrations, in-memory `--dev` mode | `controlplane/` | done, tested |
| Packer qemu build → qcow2 → OVA / VHDX, preseed, `harden.sh`, `install-openvas.sh`, `seed-feed.sh`, `cleanup.sh`, OVF with `ovf:transport=com.vmware.guestInfo` | `packer/` | written, validated with `packer validate`; not yet built (needs a KVM runner) |
| Container images (appliance, cp-api) + compose dev stack | `docker/` | written; not yet built here |
| CI: vet/test/build, shellcheck, packer validate; release: build → image → sign (cosign) + SBOM (syft) → manifest → smoke → publish | `ci/`, `.github/workflows` | written |
| Smoke tests: QEMU boot with seed ISO + expect-driven TTY; compose-based container run | `ci/smoke/` | written; need the image |

Not in Phase 1 (per PLAN §20): job polling, guardrails, scanning, results, bundle pipeline, self-update, apt mirror, split-network policy routing.

## Layout

```
api/v1/            wire types shared by daemon and control plane
daemon/            cmd/applianced, internal/{seed,state,enroll,heartbeat,tty,netcfg,cpclient,pki,osp,support,fingerprint}
controlplane/      cmd/cp-api, pkg/{ca,codes,store,server}, migrations → pkg/store/migrations
packer/            base.pkr.hcl, http/preseed.cfg, scripts/, ovf/, build-ova.sh, build-vhdx.sh
docker/            Dockerfile (appliance), Dockerfile.cp-api, docker-compose.yml
ci/                build.sh, sign.sh, manifest.sh, smoke/
docs/DEPLOY.md     vendor-facing deployment guide
```

One Go module. The daemon is `CGO_ENABLED=0` and depends only on `gopkg.in/yaml.v3`; the control plane adds `pgx`.

## Run it locally (no hypervisor, no Docker)

```sh
make dev-ca                      # dev/pki: root + intermediate (root-key.pem stays here only for dev)
make dev-cp                      # cp-api --dev: :8443 enroll, :9443 mTLS + /admin (token "dev"), in-memory store
```

In a second shell:

```sh
export CP_URL=https://localhost:9443 CP_ADMIN_TOKEN=dev CP_ROOT_CA=dev/pki/root.pem
go run ./controlplane/cmd/cp-api admin create-appliance --vendor "Acme 3PL" --site "Reno DC" --cidrs 10.30.0.0/16
# → {"appliance_id":"apl_…","code":"ABCD-EFGH-…", …}

make dev-appliance CODE=ABCD-EFGH-JKMN-PQRS-TVWX      # daemon enrolls with the code, then heartbeats
go run ./controlplane/cmd/cp-api admin get apl_…      # status enrolled, online true, last_heartbeat.engine…
go run ./controlplane/cmd/cp-api admin directive apl_… set_interval '{"s":30}'
go run ./controlplane/cmd/cp-api admin directive apl_… stop_all
go run ./controlplane/cmd/cp-api admin directives apl_…   # acked_at set after the next heartbeat
make dev-tty                                          # the console against the same state dir
```

`go test ./...` runs everything including `daemon/internal/e2e`, which drives the real daemon loop against the real server in-process: enroll → online → `set_interval` + `stop_all` acked → support bundle uploaded → wipe directive → control plane marks wiped and revokes the serial.

## Building the image and containers

```sh
export APPLIANCE_ROOT_CA=/path/to/root.pem      # or use --dev in ci/build.sh
./ci/build.sh --version 1.0.0                    # static applianced + cp-api, amd64 + arm64 → dist/
make ova VERSION=1.0.0                           # needs packer, qemu-system-x86_64, /dev/kvm, a VT feed tarball (see packer/scripts/seed-feed.sh)
make docker VERSION=1.0.0
./ci/sign.sh && ./ci/manifest.sh                 # cosign + syft, dist/manifest.json for the portal download page
```

The root CA is embedded at build time by copying it to `daemon/internal/pki/roots.pem`. In dev the daemon also accepts `APPLIANCE_ROOT_CA=<pem>` or `/etc/appliance/root-ca.pem`. The control-plane FQDN is baked in with `-X main.defaultCPURL=…` (`make CP_URL=…`).

## Contracts worth knowing

- **Enrollment code**: 20 chars, Crockford base32 (no I/L/O/U), 100 bits, shown as `XXXX-XXXX-XXXX-XXXX-XXXX`, 14-day TTL, single use, 3 failed checks lock it, SHA-256 at rest. Wrong guesses are rate-limited per source IP.
- **Identity**: the client certificate. CN = appliance id, URI SAN `urn:tprm:appliance:<vendor>:<site>:<id>`, 1 year. The mTLS listener verifies the chain to the intermediate, then on every request checks the serial against `revoked_serial` and that the path `{id}` matches the CN.
- **Directives** are a closed set (`api/v1`). `set_interval {s:10..3600}`, `stop_all` (`{clear:true}` clears it), `renew_cert`, `wipe {confirm_token:<appliance_id>}`, `noop`. `update_*` and `run_job_now` are accepted and acked but have no effect until Phase 2/3. Acks ride in the next heartbeat.
- **State on disk**: `/var/lib/appliance/{key.pem,cert.pem,state.json}`; live status for the console in `/run/appliance/status.json`. The console never gets a shell; it talks to the daemon only through these files.
- **Support bundle** never includes `key.pem` or the pending code; proxy credentials are redacted. It uploads over mTLS only.
- **Admin API** lives on the mTLS listener (`:9443`) behind a bearer token in this build; production fronts it with portal SSO.

## Secrets and runners the release workflow expects

`APPLIANCE_ROOT_CA_PEM`, `STAGING_CP_ADMIN_URL`, `STAGING_CP_ADMIN_TOKEN`, `STAGING_CP_URL_FOR_GUEST`, optional `STAGING_CP_CA_PEM`, `COSIGN_KEY`/`COSIGN_PASSWORD`, `FEED_TARBALL_URL`; a self-hosted runner labelled `kvm` with qemu, genisoimage, expect and jq.
