# Scanner appliance

Vendor-run, outbound-only network scanner with its own control plane. See [PLAN.md](PLAN.md) for the design; this README covers what exists after **Phase 2** (scan loop) and how to run it.

## What exists

| Piece | Where | Status |
|-------|-------|--------|
| `applianced` daemon: seed resolution (OVF → volume → env → console), P-256 key + CSR, enrollment, mTLS heartbeat loop with jitter/backoff, directive dispatch + ack, clock-skew correction, cert renewal at ⅔ lifetime, wipe | `daemon/` | Phase 1, tested |
| TTY console (Status / Network / Proxy / Enroll / Support bundle / Wipe), fixed input grammar, 5-min idle return; shows engine state, current job and spool backlog | `daemon/internal/tty` | Phase 1 + 2, tested |
| **Job loop**: poll `GET /v1/appliances/{id}/jobs` after every heartbeat, verify the job signature against the issuing CA chain and `issued_at` freshness, run the shared guardrails, report `running`/`rejected`/`failed`/`done`; `stop_all` cancels a running job (kills naabu, `stop_scan` over OSP); `run_job_now` forces an immediate poll | `daemon/internal/jobs` | Phase 2, tested |
| **Engine**: naabu discovery (`-sn`) and port scan, openvas over OSP with the port list pinned from naabu and `alive_test=consider alive`, `inventory` / `full` scan configs, fragile-device exclusion, `max_duration_s` deadline, per-phase progress, normalization into the PLAN §12.1 result model (service/product/CPE from detection VTs, OS guess from host details, findings with QoD) | `daemon/internal/engine` | Phase 2, tested against a scripted fake ospd and a fake naabu |
| **OSP client**: `get_version`, `get_vts` (count and per-OID metadata), `start_scan`, `get_scans` with `pop_results`, `stop_scan`, `delete_scan`; redis + ospd supervisor for the container | `daemon/internal/osp` | Phase 2, tested |
| **NVT metadata map**: OID → name, family, CVEs, CVSS (computed from the feed's v2/v3 vectors), QoD, solution; fetched lazily for OIDs that appear in results and cached per feed version | `daemon/internal/nvt` | Phase 2, tested |
| **Sealed spool**: every result chunk is encrypted to the control plane's spool public key before it touches disk (ECDH P-256 + HKDF + AES-GCM, stdlib only); chunked, resumable upload keyed on `(job, seq)`; terminal job status reported once the chunks are flushed | `daemon/internal/spool`, `internal/seal` | Phase 2, tested |
| `cp-api`: internal CA, enrollment codes, enroll + mTLS listeners, heartbeat + directives, support bundles, **job scheduling and dispatch with server-side guardrails and signing, results ingest with correlation against agent data, NVT mirror, admin API + CLI for jobs/sites/hosts/findings**, Postgres migrations, in-memory `--dev` mode | `controlplane/` | Phase 1 + 2, tested; the store conformance suite runs against both backends (Postgres 17 via `TEST_DATABASE_URL`) |
| Shared guardrails (scope, public ranges, window with skew tolerance, rate, concurrency, safe checks) and the cron window matcher, enforced by both sides from one implementation | `internal/guard`, `internal/cron` | Phase 2, tested |
| Packer qemu build → qcow2 → OVA / VHDX, preseed, `harden.sh`, `install-openvas.sh`, `seed-feed.sh`, `cleanup.sh`, OVF; naabu now built by `ci/build-engine.sh` and installed to `/opt/engine` | `packer/`, `ci/` | written, validated with `packer validate`; not yet built (needs a KVM runner) |
| Container images (appliance with naabu + openvas, cp-api) + compose dev stack; the daemon is PID 1 and supervises redis + ospd-openvas | `docker/` | built and smoke-tested locally on arm64 (without a VT feed, so the engine checks were skipped) |
| CI: vet/test (race), engine build, shellcheck, packer validate; release: build → image → sign + SBOM → manifest → smoke → publish | `.github/workflows` | written |
| Smoke tests: QEMU boot + expect-driven TTY, compose-based container run; both now dispatch a `discovery` job (and an `inventory` job when the engine is healthy) and require it to finish | `ci/smoke/` | container run passes locally (`SMOKE_SKIP_ENGINE=1`); QEMU run needs the KVM runner |

Not yet (PLAN §20 Phase 3+): feed mirror and delta bundles (scan configs ship in the daemon until then), daemon/openvas self-update, `reload_vts`, apt mirror, split-network policy routing, httpx + nuclei web add-on, portal views. Recurring schedules are one job per run today: the portal (Phase 4) creates the next occurrence.

## Layout

```
api/v1/            wire types shared by daemon and control plane (jobs, results, admin views)
internal/          cron (window matcher), guard (shared guardrails), seal (spool encryption)
daemon/            cmd/applianced, internal/{seed,state,enroll,heartbeat,jobs,engine,osp,nvt,spool,tty,netcfg,cpclient,pki,support,fingerprint}
controlplane/      cmd/cp-api, pkg/{ca,codes,store,server}, migrations → pkg/store/migrations
packer/            base.pkr.hcl, http/preseed.cfg, scripts/, ovf/, build-ova.sh, build-vhdx.sh
docker/            Dockerfile (appliance), Dockerfile.cp-api, docker-compose.yml
ci/                build.sh, build-engine.sh, sign.sh, manifest.sh, smoke/
docs/DEPLOY.md     vendor-facing deployment guide
```

One Go module. The daemon is `CGO_ENABLED=0` and depends only on `gopkg.in/yaml.v3`; the control plane adds `pgx`. naabu is a separate binary (cgo, libpcap) built by `ci/build-engine.sh` on Linux or by the Dockerfile.

## Run it locally (no hypervisor, no Docker)

```sh
make dev-ca                      # dev/pki: root + intermediate + spool key (root-key.pem stays here only for dev)
make dev-cp                      # cp-api --dev: :8443 enroll, :9443 mTLS + /admin (token "dev"), in-memory store
```

In a second shell:

```sh
export CP_URL=https://localhost:9443 CP_ADMIN_TOKEN=dev CP_ROOT_CA=dev/pki/root.pem
go run ./controlplane/cmd/cp-api admin create-appliance --vendor "Acme 3PL" --site "Reno DC" --cidrs 10.30.0.0/16,127.0.0.0/8
# → {"appliance_id":"apl_…","site_id":"site_…","code":"ABCD-EFGH-…", …}

make dev-appliance CODE=ABCD-EFGH-JKMN-PQRS-TVWX      # enrolls, heartbeats, polls for jobs
go run ./controlplane/cmd/cp-api admin get apl_…      # status enrolled, online true, last_heartbeat.engine…
```

Scan jobs (a discovery job only needs naabu on the appliance host: `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.6`, then `make dev-appliance … NAABU=$(go env GOPATH)/bin/naabu`; inventory/full jobs also need ospd-openvas on `APPLIANCE_OSPD_SOCKET`, which the images provide):

```sh
make dev-job APL=apl_… MODE=discovery TARGETS=127.0.0.1/32          # create + run-now
go run ./controlplane/cmd/cp-api admin jobs --appliance apl_…      # queued → dispatched → running → done
go run ./controlplane/cmd/cp-api admin job-hosts job_…             # hosts, ports, findings for that job
go run ./controlplane/cmd/cp-api admin create-job --appliance apl_… --mode inventory --targets 10.30.5.0/24 \
    --excludes 10.30.5.1 --cron "0 22 * * 6" --tz America/Los_Angeles --max-duration 21600   # queued for the next window
go run ./controlplane/cmd/cp-api admin directive apl_… stop_all      # halts a running scan (stop_scan over OSP, naabu killed)
go run ./controlplane/cmd/cp-api admin directive apl_… stop_all '{"clear":true}'
go run ./controlplane/cmd/cp-api admin hosts site_… ; … admin findings site_…
go run ./controlplane/cmd/cp-api admin agent-inventory site_… inventory.json   # feed agent-track data for correlation
go run ./controlplane/cmd/cp-api admin site-update site_… --cidrs 10.30.0.0/16 --fragile-ports 9100,515,631,161,502,44818
make dev-tty                                          # the console against the same state dir
```

`go test ./...` runs everything on the in-memory store; set `TEST_DATABASE_URL=postgres://cp:cp@127.0.0.1:5433/cp?sslmode=disable` (a throwaway database: the suite drops and recreates `public`) to run the store conformance suite against Postgres as well. The suite includes `daemon/internal/e2e`: Phase 1 (`TestPhase1`: enroll → online → directives → support bundle → wipe) and Phase 2 (`TestPhase2`: the real daemon loop, runner and engine against the real server with a fake naabu and a scripted fake ospd: a `discovery` job and an `inventory` job run against a lab subnet, the seeded CVE-2019-0708 is detected with QoD 97, the host is correlated with agent inventory into one `both` host with a `confirmed` finding, and `stop_all` halts an in-flight OSP scan and flushes partial results).

## Building the image and containers

```sh
export APPLIANCE_ROOT_CA=/path/to/root.pem      # or use --dev in ci/build.sh
./ci/build.sh --version 1.0.0                    # static applianced + cp-api, amd64 + arm64 → dist/
./ci/build-engine.sh --arch amd64                # naabu → bin/engine/naabu (Linux + libpcap-dev)
make ova VERSION=1.0.0                           # needs packer, qemu-system-x86_64, /dev/kvm, a VT feed tarball (see packer/scripts/seed-feed.sh)
make docker VERSION=1.0.0
./ci/sign.sh && ./ci/manifest.sh                 # cosign + syft, dist/manifest.json for the portal download page
SMOKE_SKIP_ENGINE=1 ci/smoke/run-container.sh    # compose stack: db + cp-api + appliance, enroll, discovery job, directives (needs 8 GB for Docker)
```

The appliance image builds gvm-libs, openvas-scanner and ospd-openvas from the pinned tags and naabu from source; without a feed tarball in `docker/feed/` the engine reports `vt_cache_loaded=false` and only discovery jobs run, which is what the local smoke exercises.

The root CA is embedded at build time by copying it to `daemon/internal/pki/roots.pem`. In dev the daemon also accepts `APPLIANCE_ROOT_CA=<pem>` or `/etc/appliance/root-ca.pem`. The control-plane FQDN is baked in with `-X main.defaultCPURL=…` (`make CP_URL=…`).

## Contracts worth knowing

- **Enrollment code**: 20 chars, Crockford base32 (no I/L/O/U), 100 bits, shown as `XXXX-XXXX-XXXX-XXXX-XXXX`, 14-day TTL, single use, 3 failed checks lock it, SHA-256 at rest. Wrong guesses are rate-limited per source IP.
- **Identity**: the client certificate. CN = appliance id, URI SAN `urn:tprm:appliance:<vendor>:<site>:<id>`, 1 year. The mTLS listener verifies the chain to the intermediate, then on every request checks the serial against `revoked_serial` and that the path `{id}` matches the CN.
- **Directives** are a closed set (`api/v1`). `set_interval {s:10..3600}`, `stop_all` (`{clear:true}` clears it; while active a running job is cancelled and no job is dispatched or accepted), `run_job_now {job_id}` (the server drops the job's window and the appliance polls at once), `renew_cert`, `wipe {confirm_token:<appliance_id>}`, `noop`. `update_*` are acked without effect until Phase 3. Acks ride in the next heartbeat.
- **Job spec** (PLAN §11): `mode` discovery | inventory | full, `targets`, `excludes`, `ports` (`standard` = naabu top-1000 + enterprise/OT extras, `full`, or an explicit list), `modules`, `openvas {config, max_hosts, max_checks, fragile_ports_exclude}`, `window {cron, tz, max_duration_s}`, `rate {pps, per_host_parallel}`, `safe_checks`, `allow_public`, `iface`, `issued_at`, `sig`. The control plane signs the canonical JSON (spec with `sig` empty) with the issuing intermediate key at dispatch; the appliance verifies against the chain it stored at enrollment and rejects anything older than an hour or addressed to another appliance.
- **Guardrails** run twice from `internal/guard`: targets ⊆ `allowed_cidrs`, no public ranges unless the job is `allow_public` **and** the site attests them, window open (±5 min skew tolerance), `rate.pps ≤ max_pps`, `max_hosts × max_checks ≤ max_concurrency` (default 16), `safe_checks` unless the site is `unsafe_ok` (never for Tier 1 vendors). The server additionally withholds jobs while the heartbeat reports `stop_all` or an engine that is not ready; the appliance additionally checks signature, freshness, appliance id, `stop_all`, engine health and the presence of a spool key. A rejected job reports the failing check verbatim and never partially runs. A missed window rolls to the next cron start.
- **Results**: `POST /v1/jobs/{job}/results` with `X-Result-Seq`, `X-Result-SHA256`, `X-Result-Final`; the body is a sealed envelope whose plaintext is a `ResultBatch` (hosts with ports, os_guess, findings; the final chunk carries `stats`). The server unseals with `spool-key.pem`, parses with a strict schema and size limits, stores the plaintext chunk in the object store (`results/<job>/<seq>.json`), dedupes on `(job, seq)` by content hash, and ingests. The final chunk marks the job `done`.
- **Correlation** (PLAN §12.3): host identity by MAC, then hostname (short name), then IP; `host.source` ∈ agent | appliance | both; agent inventory wins for packages and hostname, the appliance wins for ports; the same CVE from both sources becomes one finding with two evidence entries in state `confirmed`; openvas-only findings are `network_observed`, or `suspected` when QoD < 70 until a second scan or agent data confirms them. `POST /admin/sites/{id}/agent-inventory` is where the agent track hands over its data.
- **Scan configs**: `inventory` = detection families + Web Servers, Windows, Microsoft Bulletins, SSL/TLS, Databases, Default Accounts; `full` = every unauthenticated remote family. Denial of Service, Brute force attacks and all `* Local Security Checks` families are never selectable. Hosts with an open fragile-device port (site list, default 9100/515/631/161/502/44818) are kept out of openvas and tagged `fragile:<port>`; hosts with no open TCP port are skipped. The exact `inventory` family list is a Phase 4 tuning item (PLAN §23).
- **State on disk**: `/var/lib/appliance/{key.pem,cert.pem,state.json,spool/,nvt-cache/}`; live status for the console in `/run/appliance/status.json`. The spool holds only sealed chunks; the appliance cannot read them back. Wipe shreds all of it.
- **Support bundle** never includes `key.pem` or the pending code; proxy credentials are redacted. It uploads over mTLS only.
- **Admin API** lives on the mTLS listener (`:9443`) behind a bearer token in this build; production fronts it with portal SSO.

## Secrets and runners the release workflow expects

`APPLIANCE_ROOT_CA_PEM`, `STAGING_CP_ADMIN_URL`, `STAGING_CP_ADMIN_TOKEN`, `STAGING_CP_URL_FOR_GUEST`, optional `STAGING_CP_CA_PEM`, `COSIGN_KEY`/`COSIGN_PASSWORD`, `FEED_TARBALL_URL`; a self-hosted runner labelled `kvm` with qemu, genisoimage, expect and jq. The control plane's `pki-dir` must hold `spool-key.pem` (created by `cp-api ca init`; back it up with the intermediate key, results sealed to it are unreadable without it).

`cp-api serve` outside `--dev` needs `--server-cert/--server-key`, or `--self-issue` to mint the server certificate and the spool key from the pki dir on first start; the compose stack and the smoke tests use `--self-issue` (via `CP_SELF_ISSUE=1` / the container entrypoint). Production supplies a real certificate.
