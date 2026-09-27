# Scanner appliance

Vendor-run, outbound-only network scanner with its own control plane. See [PLAN.md](PLAN.md) for the design; this README covers what exists after **Phase 3** (operations: signed bundles, self-update with canary rollout, split-network scanning, the web add-on) and how to run it.

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
| **Signature bundles**: content-addressed manifest `{version, feed_version, files[{path, sha256, size}]}` signed with an ECDSA P-256 key in cosign's blob format; `cp-api feed sync` mirrors the Greenbone Community Feed, `cp-api bundle build` assembles feed + scan configs + filtered nuclei templates + fragile ports, `admin publish-bundle` uploads only the files the control plane lacks | `internal/bundle`, `internal/scanconfig`, `controlplane/cmd/cp-api` | Phase 3, tested |
| **Daemon updater**: `update_bundle` fetches the delta by sha256 into a local content-addressed store, links it into the openvas plugins directory, waits for ospd to load the new feed and rolls the directory back from the retained file set if it does not; `update_daemon` verifies sha256 + signature, sanity-runs the new binary, swaps it atomically, restarts and confirms with a heartbeat within 10 min or rolls back (plus an `ExecStartPre` guard for crash loops); `reload_vts` | `daemon/internal/update`, `daemon/internal/heartbeat` | Phase 3, tested (unit + e2e) |
| **Canary rollout**: bundles and releases go to the canary group first; after the canary period and one canary confirmation they are released to the fleet; a canary reporting `update_error` holds the rollout; releases are per platform (`applianced-<os>-<arch>`), containers are skipped (they update by image) | `controlplane/pkg/server/rollout.go` | Phase 3, tested |
| **Web add-on**: httpx fingerprints HTTP-looking open ports, nuclei runs the bundled HTTP templates with the job's severity floor, `dos`/`fuzz`/`intrusive` always excluded, no interactsh; findings carry the template id and correlate across scans | `daemon/internal/engine/web.go` | Phase 3, tested against scripted fakes |
| **Split-network**: naabu `-interface lan0` and `source_iface = lan0` in openvas.conf when the appliance is seeded with `split: true` (or the job names an interface); site `lan_routes` (`CIDR@gateway`) are written into lan0's networkd unit | `daemon/internal/engine`, `daemon/internal/netcfg` | Phase 3, tested; QEMU smoke scans the restricted 10.0.3.0/24 leg |
| **OS updates**: `unattended-upgrades` (security pocket only) from the apt mirror `cp-api` serves under `/apt/` over mTLS; the daemon writes the sources entry and client-certificate settings at enrollment and reboots an idle appliance in the site's 03:00 maintenance slot when the OS asks for it | `controlplane/pkg/server/bundles.go`, `daemon/internal/enroll/apt.go`, `packer/scripts/harden.sh` | Phase 3, written; mirror content is populated out of band |
| Packer qemu build → qcow2 → OVA / VHDX, preseed, `harden.sh`, `install-openvas.sh`, `seed-feed.sh`, `cleanup.sh`, OVF; naabu now built by `ci/build-engine.sh` and installed to `/opt/engine` | `packer/`, `ci/` | written, validated with `packer validate`; not yet built (needs a KVM runner) |
| Container images (appliance with naabu + openvas, cp-api) + compose dev stack; the daemon is PID 1 and supervises redis + ospd-openvas | `docker/` | built and smoke-tested locally on arm64 (without a VT feed, so the engine checks were skipped) |
| CI: vet/test (race), cross-compile check (windows/amd64, windows/arm64, darwin, freebsd), native Windows test job (advisory), engine build, shellcheck, packer validate; release: build (linux amd64 + arm64, windows amd64) → image → sign + SBOM → manifest → smoke → publish | `.github/workflows` | written |
| Smoke tests: QEMU boot + expect-driven TTY, compose-based container run; both dispatch a `discovery` job (and an `inventory` job when the engine is healthy), publish a synthetic bundle to the appliance as canary and then a delta (`SMOKE_BUNDLE_FEED=1` adds a two-VT feed for a real engine); the QEMU run boots split-network and scans the no-egress 10.0.3.0/24 leg | `ci/smoke/` | container run passes locally (`SMOKE_SKIP_ENGINE=1`); QEMU run needs the KVM runner |

Not yet (PLAN §20 Phase 4+): fragile-device policy tuning, coverage scoring, portal views and the transparency page, nmap fingerprinting, full-range ports, an S3 object store (the control plane ships a directory store meant for shared storage). Recurring schedules are one job per run today: the portal (Phase 4) creates the next occurrence. openvas/ospd binaries are still updated with the image, not with `update_daemon`.

## Layout

```
api/v1/            wire types shared by daemon and control plane (jobs, results, admin views)
internal/          cron (window matcher), guard (shared guardrails), seal (spool encryption), bundle (signed manifests), scanconfig (openvas configs)
daemon/            cmd/applianced, internal/{seed,state,enroll,heartbeat,jobs,engine,osp,nvt,spool,update,tty,netcfg,cpclient,pki,support,fingerprint,platform}
controlplane/      cmd/cp-api, pkg/{ca,codes,store,server}, migrations → pkg/store/migrations
packer/            base.pkr.hcl, http/preseed.cfg, scripts/, ovf/, build-ova.sh, build-vhdx.sh
docker/            Dockerfile (appliance), Dockerfile.cp-api, docker-compose.yml
ci/                build.sh, build-engine.sh, sign.sh, manifest.sh, smoke/
docs/DEPLOY.md     vendor-facing deployment guide
```

One Go module. The daemon is `CGO_ENABLED=0` and depends only on `gopkg.in/yaml.v3`; the control plane adds `pgx`. naabu is a separate binary (cgo, libpcap) built by `ci/build-engine.sh` on Linux or by the Dockerfile.

Linux is the product (VM image and container). The daemon also builds and runs on Windows ([below](#running-the-daemon-on-windows)) and on macOS/BSD for development; the Linux-only pieces (openvas/ospd supervision, systemd-networkd, htpdate, the tty1 console, OVF/volume seeds) report themselves unavailable there instead of failing the daemon (`daemon/internal/platform`).

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
./ci/build.sh --version 1.0.0                    # static applianced + cp-api: linux/amd64, linux/arm64, windows/amd64 (.exe) → dist/
./ci/build-engine.sh --arch amd64                # naabu + httpx + nuclei → bin/engine/ (Linux + libpcap-dev for naabu; httpx/nuclei use a pinned Go 1.25 toolchain, see ENGINE_GOTOOLCHAIN)
make ova VERSION=1.0.0                           # needs packer, qemu-system-x86_64, /dev/kvm, a VT feed tarball (see packer/scripts/seed-feed.sh)
make docker VERSION=1.0.0
./ci/sign.sh && ./ci/manifest.sh                 # cosign + syft, dist/manifest.json for the portal download page
SMOKE_SKIP_ENGINE=1 ci/smoke/run-container.sh    # compose stack: db + cp-api + appliance, enroll, discovery job, directives, bundle canary + delta (needs 8 GB for Docker)
```

The appliance image builds gvm-libs, openvas-scanner and ospd-openvas from the pinned tags and naabu from source; without a feed tarball in `docker/feed/` the engine reports `vt_cache_loaded=false` and only discovery jobs run, which is what the local smoke exercises.

The root CA is embedded at build time by copying it to `daemon/internal/pki/roots.pem`, and the release signing public key to `daemon/internal/pki/release-pub.pem` (`APPLIANCE_RELEASE_PUB`; `--dev` uses `dev/pki/release-pub.pem`). In dev the daemon also accepts `APPLIANCE_ROOT_CA=<pem>` / `APPLIANCE_RELEASE_KEY=<pem>` or `/etc/appliance/{root-ca,release-pub}.pem` (`%ProgramData%\TPRM Appliance\etc\` on Windows). The control-plane FQDN is baked in with `-X main.defaultCPURL=…` (`make CP_URL=…`).

## Bundles, updates and rollouts (Phase 3)

```sh
cp-api ca init --dir dev/pki                      # now also writes release-key.pem / release-pub.pem (cosign-compatible ECDSA P-256)
cp-api feed sync --dest feed-mirror               # rsync the Greenbone Community Feed, check sha256sums (+ .asc with --gpg-keyring)
cp-api bundle build --out bundle-out --feed feed-mirror --nuclei-templates nuclei-templates --key dev/pki/release-key.pem
cp-api admin publish-bundle --dir bundle-out      # asks which sha256s are missing, uploads only those, publishes the signed manifest
cp-api admin set-canary apl_… true                # the lab appliance
cp-api admin bundles                              # status canary → released after --canary-hours (48) once a canary confirmed it
cp-api admin rollout bundle 20260926T031700Z released --reason "lab verified"   # or held / retired
cp-api admin publish-release --file dist/applianced-linux-amd64 --component applianced-linux-amd64 --version 1.3.0 --key dev/pki/release-key.pem
cp-api admin releases | rollout release applianced-linux-amd64 1.3.0 held
```

- **Delivery** is by directive: `update_bundle {url, sha256, sig, version, feed_version}` and `update_daemon {url, sha256, sig, version}`, where `url` is always a control-plane path fetched over the appliance's mTLS session (`/v1/bundles/{v}/manifest`, `/v1/bundles/{v}/files/{sha256}`, `/v1/releases/{component}/{version}`). The rollout ticker (every minute, and right after a publish or state change) queues a directive per appliance that is not on the version, re-queuing at most hourly after an ack.
- **Apply**: the daemon adopts the image-seeded feed as its installed manifest on the first bundle so even that first delta can be rolled back; files live in `<state>/bundle/cas/<sha256>` and are hard-linked into `/var/lib/openvas/plugins` (feed) or `<state>/bundle/` (configs, templates, fragile ports). A changed feed makes the daemon wait for ospd to report the new `feed_version` with the VT cache loaded (30 min); on timeout the previous file set is restored and the heartbeat carries `update_error: "bundle <v>: …"`, which holds the rollout when the appliance is a canary. Updates never start while a job runs, and no job starts while an update runs (`state: updating`). No reboot is involved.
- **Self-update**: sha256 + signature are verified against the embedded release key, the new binary must answer `version` with the expected version, then it is swapped next to the running one (`applianced.prev` kept) with a pending record; the daemon exits 0 and systemd's `Restart=always` starts the new one, which must heartbeat within 10 minutes or it reinstates the previous binary. `packer/scripts/harden.sh` installs an `ExecStartPre` guard that does the same after three failed starts. Containers ignore `update_daemon` (pull a new image).
- **Daily pipeline**: `.github/workflows/bundle.yml` (cron) runs feed sync → bundle build → publish to the canary group; the release workflow publishes `applianced-linux-{amd64,arm64}` to the staging control plane. Secrets are listed in the workflow headers.
- **OS updates**: the image now enables `unattended-upgrades` for the security pocket only, sourced from `https://<fqdn>/apt/debian-security` over mTLS (`cp-api serve --apt-dir DIR` serves a `debmirror`/`apt-mirror` tree; `Acquire::https::<fqdn>::SslCert/SslKey` point at a `_apt`-readable copy under `/etc/appliance/apt/` that the daemon writes at enrollment and renewal). `Automatic-Reboot` is off: the daemon reboots an idle appliance during the site's 03:00 hour when `/var/run/reboot-required` appears and reports `reboot_required` in the heartbeat until then.
- **Split network**: seed `split: true` (OVF `appliance.split`, `APPLIANCE_SPLIT=1`) binds naabu (`-interface lan0`) and openvas (`source_iface = lan0`) to the scanning leg; `admin site-update SITE --lan-routes 10.31.0.0/16@10.30.5.1` pushes extra floor subnets into lan0's networkd unit. lan0 never receives a default route, so no policy-routing table is needed for egress to stay on wan0.
- **Web add-on**: `full` mode now includes the `web` module (`web: {min_severity: medium, exclude_tags: [dos, fuzz, intrusive]}`); httpx probes ports 80/443/8080/… and anything openvas called an HTTP service, nuclei runs the templates shipped in the bundle (`nuclei-templates/`, filtered to HTTP templates without excluded tags) without interactsh or template updates. Without httpx/nuclei/templates the phase is skipped and the job stats carry a warning.

## Running the daemon on Windows

`applianced-windows-amd64.exe` is a supported build of the daemon for a Windows host (a lab VM, a jump box, a site without a hypervisor slot). It is the daemon, not the appliance: it enrolls, heartbeats, acks directives, uploads support bundles and runs `discovery` / `portscan` jobs with naabu. There is no openvas on Windows, so `inventory` / `full` jobs are held by the control plane (*engine not ready*) and, if forced, rejected by the daemon with `engine`.

| | Linux appliance | Windows host |
|---|---|---|
| State | `/var/lib/appliance`, `/run/appliance`, `/etc/appliance` | `%ProgramData%\TPRM Appliance\{state,run,etc}` (`APPLIANCE_STATE_DIR` / `APPLIANCE_RUN_DIR` override) |
| Engine | `/opt/engine/naabu` + ospd-openvas | `engine\naabu.exe` beside the executable, or `APPLIANCE_NAABU`; no ospd |
| Seed | OVF → volume → env → console | env (`APPLIANCE_CODE`, `APPLIANCE_CP_URL`, `APPLIANCE_PROXY`) or `--seed-file` |
| Host metrics | `/proc` | kernel32 (uptime, free memory, free disk); no load average |
| Machine identity | `/etc/machine-id` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |
| Wipe | state deleted, `systemctl poweroff` | state deleted, `shutdown /s /t 0` |
| Network / time / console | systemd-networkd, htpdate, tty1 | not applicable: the Network screen reports unsupported; `applianced tty` is a plain stdin menu |

```powershell
# naabu: the Windows build from https://github.com/projectdiscovery/naabu/releases (v2.3.6). Host discovery and SYN
# scans use raw sockets, so install Npcap (https://npcap.com) and run from an elevated prompt; APPLIANCE_SCAN_TYPE=c
# switches the port scan to connect mode.
$env:APPLIANCE_CP_URL  = "https://appliance.tprm.example.com"     # only when it is not baked into the build
$env:APPLIANCE_CODE    = "ABCD-EFGH-JKMN-PQRS-TVWX"
$env:APPLIANCE_NAABU   = "C:\Program Files\TPRM Appliance\engine\naabu.exe"
$env:APPLIANCE_ROOT_CA = "C:\Program Files\TPRM Appliance\root.pem"    # dev/staging builds without an embedded root
.\applianced-windows-amd64.exe run
.\applianced-windows-amd64.exe status                                   # from another prompt
```

The daemon exits cleanly on Ctrl-C or a console close. It does not speak the Service Control Manager protocol yet, so to run it as a service wrap it with [WinSW](https://github.com/winsw/winsw) or NSSM, or register a scheduled task that runs at startup as SYSTEM. Build it with `make build-windows` (or `ci/build.sh --targets windows/amd64`). CI vets every push for windows/amd64 and windows/arm64 (the tests compile too) and runs the Go tests natively on a Windows runner; that job is advisory until it has been seen green there, since it has not been run on Windows hardware yet.

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

Phase 3 adds `APPLIANCE_RELEASE_PUB_PEM` (embedded into the daemon; without it appliances refuse bundles and self-updates), `RELEASE_KEY_PEM` (signs bundles and releases in `bundle.yml` and the release publication step), and for the bundle workflow `CP_ADMIN_URL`, `CP_ADMIN_TOKEN`, `CP_ROOT_CA_PEM`, optional `FEED_GPG_KEYRING_B64`, plus the variables `FEED_SOURCE` and `NUCLEI_TEMPLATES_REF`.

`APPLIANCE_ROOT_CA_PEM`, `STAGING_CP_ADMIN_URL`, `STAGING_CP_ADMIN_TOKEN`, `STAGING_CP_URL_FOR_GUEST`, optional `STAGING_CP_CA_PEM`, `COSIGN_KEY`/`COSIGN_PASSWORD`, `FEED_TARBALL_URL`; a self-hosted runner labelled `kvm` with qemu, genisoimage, expect and jq. The control plane's `pki-dir` must hold `spool-key.pem` (created by `cp-api ca init`; back it up with the intermediate key, results sealed to it are unreadable without it).

`cp-api serve` outside `--dev` needs `--server-cert/--server-key`, or `--self-issue` to mint the server certificate and the spool key from the pki dir on first start; the compose stack and the smoke tests use `--self-issue` (via `CP_SELF_ISSUE=1` / the container entrypoint). Production supplies a real certificate.
