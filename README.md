# Scanner appliance

A vendor-run, outbound-only network scanner with its own control plane. It is the network half of the in-house third-party risk platform: the Wazuh agent track covers the hosts a vendor will install software on, and the appliance covers what an agent cannot reach, such as handhelds, printers, network gear and unmanaged hosts at a 3PL site. It is built to take the place of a Qualys scanner appliance at those sites.

The vendor deploys an image, enters one enrollment code, and the appliance is online within minutes. It listens on nothing, needs one outbound FQDN on TCP 443, scans only inside the scope the vendor attested, and sends sealed results to the control plane, where they are correlated with agent inventory and with exports from other scanners.

[PLAN.md](PLAN.md) is the design specification. This README describes what is built, how to run it and how to operate it. Three guides go deeper:

| Guide                                              | Audience                                                                           |
| -------------------------------------------------- | ---------------------------------------------------------------------------------- |
| [docs/DEPLOY.md](docs/DEPLOY.md)                   | the vendor team hosting the appliance: VMware, Hyper-V, KVM, Docker, Windows host  |
| [docs/MIGRATION.md](docs/MIGRATION.md)             | the team replacing a Qualys scanner at a site: parallel run, parity report, switch |
| [docs/ENTERPRISE-FEED.md](docs/ENTERPRISE-FEED.md) | the Greenbone Enterprise Feed evaluation and how the coverage gap is measured      |

## Contents

- [How it works](#how-it-works)
- [Status](#status)
- [Repository layout](#repository-layout)
- [What is in the box](#what-is-in-the-box)
- [Quick start](#quick-start)
- [Operating it](#operating-it)
- [Building and releasing](#building-and-releasing)
- [Testing](#testing)
- [Running the daemon on Windows](#running-the-daemon-on-windows)
- [Contracts worth knowing](#contracts-worth-knowing)
- [Known gaps and next steps](#known-gaps-and-next-steps)

## How it works

```
  3PL site (vendor network)                          Control plane
+---------------------------------+               +------------------------------------+
| appliance (VM or container)     |   outbound    | cp-api                             |
|   applianced                    |   mTLS, 443   |   :8443 enroll                     |
|     naabu     discovery, ports  | ------------> |   :9443 mTLS API and /admin        |
|     openvas   detection (OSP)   |               |   CA, jobs, ingest, rollouts       |
|     nmap      fingerprint       | <------------ |   Postgres, object store           |
|     httpx, nuclei  web checks   |  signed jobs, +------------------------------------+
+---------------------------------+  directives,        ^                    ^
                                     bundles            |                    |
                                     (in responses)  portal, CLI,     agent inventory (Wazuh),
                                                     webhooks         Qualys exports
```

1. **Enroll.** The daemon resolves its seed (OVF properties, a seed volume, the environment or the console), generates a P-256 key and trades the one-time code for a client certificate. From then on the certificate is its identity.
2. **Heartbeat.** Every interval it reports health, engine state and update state over mTLS. The response carries directives from a closed set, and the acks ride in the next beat.
3. **Jobs.** The control plane checks each job against the site's guardrails and signs it at dispatch. The appliance verifies the signature and runs the same guardrails again before a single packet leaves.
4. **Scan.** Discovery, port scan, openvas detection on the ports naabu found, then the optional nmap fingerprint pass and web checks. Fragile devices stay out of detection.
5. **Results.** Each chunk is sealed to the control plane's key before it touches disk, so a lost appliance holds nothing readable.
6. **Evidence.** Ingest merges hosts by MAC, then hostname, then IP with agent inventory and imported scanner exports. Findings open, are fixed by a later scan of the same scope, and reopen if they return.
7. **Updates.** The daily feed bundle and daemon releases are signed, go to a canary group first, and roll back on the appliance if they fail.

## Status

All six phases are implemented. The Go code is covered by tests; the image build and the hypervisor variants are written and validated but have not run on real hosts. What remains is operational: building the image, and running it at real sites.

| Plan phase ([PLAN §20](PLAN.md#20-phasing)) | Scope                                                                                                       | State                                                          |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| 1 Foundation                                | image, console, enrollment, mTLS, heartbeat, directives                                                     | built and tested; the VM image build is pending a KVM runner   |
| 2 Scan loop                                 | jobs, guardrails, naabu, openvas over OSP, results ingest, correlation                                      | built and tested                                               |
| 3 Operations                                | feed bundles, daemon self-update, canary rollout, split network, web add-on, OS updates                     | built and tested                                               |
| 4 Pilot                                     | fragile-device policy, finding review, scope approval, schedules, coverage, transparency page               | built and tested; the live pilot is an operational step        |
| 5 Depth                                     | nmap fingerprint pass, full-range ports, Hyper-V and KVM variants, Enterprise Feed evaluation               | built and tested; needs the legal sign-off and hypervisor runs |
| 6 Qualys replacement (added after the plan) | Qualys imports, parity report, finding lifecycle, SLA, summaries, exports, webhooks, S3, retention, metrics | built and tested; the parallel run is an operational step      |

Verified by:

- `go test -race ./...`, including six end-to-end tests that run the real daemon loop against the real server with scripted scanner fakes.
- The store conformance suite on the in-memory store and on Postgres 17.
- The S3 object store against a fake in unit tests and against SeaweedFS with signature checks.
- Cross-compile vet for windows/amd64, windows/arm64, darwin and freebsd; shellcheck; `packer validate`.
- The container smoke test on arm64, without a VT feed.

Not verified in this repository:

- **The VM image.** It has not been built. The Packer build, the QEMU smoke test and the UEFI boot need a runner with KVM.
- **Hyper-V.** Generation 2 with Secure Boot has not been booted on a real host.
- **Windows.** The native Windows test job is advisory until it has been seen green on Windows hardware.
- **A real feed.** The local container smoke ran without a VT feed, so openvas detection is exercised only through the scripted fake ospd.
- **The apt mirror.** Its content is populated out of band.
- **Operational steps.** The nmap legal sign-off, the pilot at a 3PL site and the parallel run against Qualys.

What is not built, and what comes next, is in [Known gaps and next steps](#known-gaps-and-next-steps).

## Repository layout

```
api/v1/            wire types shared by daemon and control plane (jobs, results, heartbeat, admin views)
internal/          cron (window matcher), guard (shared guardrails), seal (spool encryption), bundle (signed manifests),
                   scanconfig (openvas configs), qualys (export parsers)
daemon/            cmd/applianced, internal/{seed,state,enroll,heartbeat,jobs,engine,osp,nvt,spool,update,tty,netcfg,
                   cpclient,pki,support,fingerprint,platform,e2e}
controlplane/      cmd/cp-api, pkg/{ca,codes,store,server}, migrations in pkg/store/migrations
packer/            base.pkr.hcl, http/preseed.cfg, scripts/, ovf/, build-ova.sh, build-vhdx.sh, hyperv/, kvm/
docker/            Dockerfile (appliance), Dockerfile.cp-api, docker-compose.yml
ci/                build.sh, build-engine.sh, sign.sh, manifest.sh, smoke/
docs/              DEPLOY.md, MIGRATION.md, ENTERPRISE-FEED.md
```

One Go module. The daemon is `CGO_ENABLED=0` and depends only on `gopkg.in/yaml.v3`; the control plane adds `pgx`. naabu is a separate binary (cgo, libpcap) built by `ci/build-engine.sh` on Linux or by the Dockerfile.

Linux is the product, as a VM image and as a container. The daemon also builds and runs on Windows ([below](#running-the-daemon-on-windows)) and on macOS and BSD for development. The Linux-only pieces (openvas and ospd supervision, systemd-networkd, htpdate, the tty1 console, OVF and volume seeds) report themselves unavailable there instead of failing the daemon.

## What is in the box

### The appliance (`daemon/`)

Paths are relative to `daemon/` unless they start with a slash.

| Area                     | What it does                                                                                                                                                                                                                                                                                                                                       | Where                                       |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| Enrollment and identity  | Seed resolution (OVF → volume → env → console), P-256 key and CSR, code exchange for a client certificate, renewal at two thirds of the certificate lifetime, wipe                                                                                                                                                                                 | `internal/{seed,enroll,pki,state}`          |
| Heartbeat and directives | mTLS loop with jitter and backoff, clock-skew correction, directive dispatch and ack. Every beat carries engine health, the tools the build carries, the running job and any update error                                                                                                                                                          | `internal/heartbeat`                        |
| Job loop                 | Polls `GET /v1/appliances/{id}/jobs` after every heartbeat, verifies the job signature and its freshness, runs the shared guardrails and reports `running` / `rejected` / `failed` / `done`. Honors `stop_all` and `run_job_now`                                                                                                                   | `internal/jobs`                             |
| Engine                   | naabu discovery (`-sn`) and port scan; openvas over OSP with the port list pinned from naabu and `alive_test=consider alive`; fragile-device exclusion; `max_duration_s` deadline; per-phase progress; normalization into the PLAN §12.1 result model (service, product and CPE from detection VTs, OS guess from host details, findings with QoD) | `internal/engine`                           |
| OSP client, NVT metadata | `get_version`, `get_vts`, `start_scan`, `get_scans` with `pop_results`, `stop_scan`, `delete_scan`; redis and ospd supervision in the container. VT metadata (name, family, CVEs, CVSS from the feed's vectors, QoD, solution) is fetched lazily and cached per feed version                                                                       | `internal/osp`, `internal/nvt`              |
| Fingerprint pass         | nmap service and OS detection on open ports, after the legal sign-off                                                                                                                                                                                                                                                                              | `internal/engine/nmap.go`                   |
| Web add-on               | httpx on HTTP-looking ports, nuclei with the bundled HTTP templates                                                                                                                                                                                                                                                                                | `internal/engine/web.go`                    |
| Sealed spool             | Every result chunk is encrypted to the control plane's spool public key before it touches disk (ECDH P-256, HKDF, AES-GCM, stdlib only). Upload is chunked and resumable, keyed on `(job, seq)`                                                                                                                                                    | `internal/spool`, `/internal/seal`          |
| Updater                  | Bundle deltas, daemon self-update and VT reload, each with rollback                                                                                                                                                                                                                                                                                | `internal/update`                           |
| Console                  | Status, Network, Proxy, Enroll, Support bundle, Wipe; fixed input grammar; 5-minute idle return. Shows engine state, the current job and the spool backlog, and lists a support bundle's contents before asking to upload                                                                                                                          | `internal/tty`, `internal/support`          |
| Network and OS           | Split-network scanning on `lan0`, site routes in lan0's networkd unit, security updates from the control plane's apt mirror                                                                                                                                                                                                                        | `internal/netcfg`, `internal/enroll/apt.go` |
| Platforms                | Linux is the product. On Windows, macOS and BSD the Linux-only pieces report themselves unavailable                                                                                                                                                                                                                                                | `internal/platform`                         |

### The control plane (`controlplane/`)

Paths are relative to `controlplane/` unless they start with a slash.

| Area                   | What it does                                                                                                                                                                                                                                                     | Where                                                       |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| CA and enrollment      | Internal CA, enrollment codes, the enroll listener and the mTLS listener, revocation by serial                                                                                                                                                                   | `pkg/ca`, `pkg/codes`, `pkg/server/server.go`               |
| Jobs                   | Server-side guardrails, signing at dispatch, scan windows. Recurring schedules materialize one job per occurrence ahead of time, roll forward after a run and cancel on disable. The calendar shows past jobs with rejection reasons and future occurrences      | `pkg/server/{jobs,admin_jobs,schedules}.go`                 |
| Ingest and correlation | Sealed chunks are opened, parsed with a strict schema and size limits, stored, deduplicated on `(job, seq)` and merged with agent inventory. VT metadata is mirrored                                                                                             | `pkg/server/results.go`, `pkg/store/correlate.go`           |
| Finding lifecycle      | `open` → `fixed` → reopened, decided by scan scope. Review as false positive or accepted, codified exclusions, SLA ageing by severity and vendor tier                                                                                                            | `pkg/store/correlate.go`, `pkg/server/{replace,pilot}.go`   |
| Site governance        | Scope requests only the vendor-owner token can approve, quarterly attestation, a versioned and audited fragile-device policy that travels with every job                                                                                                         | `pkg/server/pilot.go`                                       |
| Coverage and alerts    | Coverage score per site and vendor with reasons, appliance health, alerts, the onboarding checklist                                                                                                                                                              | `pkg/server/{coverage,depth}.go`                            |
| Other scanners         | Qualys scan-results CSV, host-list-detection XML and KnowledgeBase XML imported as a third evidence source correlated by CVE. The parity report scores the appliance against them                                                                                | `/internal/qualys`, `pkg/server/replace.go`                 |
| Reporting              | Site and vendor summaries, weekly trend, CSV exports, signed webhooks                                                                                                                                                                                            | `pkg/server/{replace,webhooks}.go`                          |
| Fleet updates          | Signed bundles and per-platform releases, canary rollout with a hold on failure, the apt mirror under `/apt/`                                                                                                                                                    | `pkg/server/{bundles,rollout}.go`, `/internal/bundle`       |
| Gates and evaluation   | The nmap legal sign-off, the full-range duration budget, the Enterprise Feed gap report                                                                                                                                                                          | `pkg/server/depth.go`, `/internal/guard`                    |
| Transparency page      | `GET /transparency` and `/transparency.json` on both listeners, no credentials: scan phases, tool versions and licenses, scan configs, never-selectable families, guardrails, data collected and never collected, updates, the closed directive set, OSS notices | `pkg/server/transparency.go`                                |
| Operations             | Postgres or in-memory store behind one interface, directory or S3 object store, retention, Prometheus metrics, advisory locks so several instances share one database                                                                                            | `pkg/store`, `pkg/server/{objects,s3,retention,metrics}.go` |

### Shared code

- **`api/v1`**: the wire types both sides compile against: job spec, result batch, heartbeat, directives, admin views.
- **`internal/guard`, `internal/cron`**: scope, public ranges, window with skew tolerance, rate, concurrency, safe checks and the duration budget, enforced by both sides from one implementation.
- **`internal/seal`**: spool encryption. **`internal/bundle`**: signed, content-addressed manifests. **`internal/scanconfig`**: the openvas scan configs. **`internal/qualys`**: the export parsers.

### Images, CI and smoke tests

| Piece                                                                                                                                                                                                                                                                                           | Where                                    | State                                                               |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------- |
| Packer qemu build → qcow2 → OVA and VHDX: preseed, `harden.sh`, `install-openvas.sh`, `seed-feed.sh`, `cleanup.sh`, OVF. The disk is GPT with a BIOS boot partition and an EFI system partition, with shim and signed GRUB next to the BIOS loader                                              | `packer/`                                | validated with `packer validate`; not built yet                     |
| Hypervisor helpers: `New-ApplianceVM.ps1` for Hyper-V Generation 2 and `create-vm.sh` for KVM, shipped as `*-hypervisor-helpers.zip`                                                                                                                                                            | `packer/hyperv`, `packer/kvm`            | written                                                             |
| Container images: the appliance (the daemon is PID 1 and supervises redis and ospd-openvas; naabu; optional web add-on and nmap) and cp-api, plus a compose dev stack                                                                                                                           | `docker/`                                | built and smoke-tested locally on arm64 without a VT feed           |
| CI: race tests, cross-compile vet, a native Windows test job (advisory), the engine build, shellcheck, `packer validate`, preseed hybrid-boot checks, a PowerShell parse of the Hyper-V helper, the container build with nmap, store conformance on Postgres and the S3 store against SeaweedFS | `.github/workflows/ci.yml`               | written                                                             |
| Release: build (linux amd64 and arm64, windows amd64) → image and helpers → sign and SBOM → manifest → smoke → publish. Daily bundle: feed sync → bundle build → publish to the canary group                                                                                                    | `.github/workflows/{release,bundle}.yml` | written                                                             |
| Smoke tests: a QEMU boot with an expect-driven console, and a compose-based container run                                                                                                                                                                                                       | `ci/smoke/`                              | the container run passes locally; the QEMU run needs the KVM runner |

## Quick start

No hypervisor and no Docker: the control plane runs in memory and the daemon runs as a local process.

```sh
make dev-ca                      # dev/pki: root, intermediate, spool key, release key (root-key.pem stays here only for dev)
make dev-cp                      # cp-api --dev: :8443 enroll, :9443 mTLS and /admin (token "dev"), in-memory store
```

In a second shell:

```sh
export CP_URL=https://localhost:9443 CP_ADMIN_TOKEN=dev CP_ROOT_CA=dev/pki/root.pem
go run ./controlplane/cmd/cp-api admin create-appliance --vendor "Acme 3PL" --site "Reno DC" --cidrs 10.30.0.0/16,127.0.0.0/8
# → {"appliance_id":"apl_…","site_id":"site_…","code":"ABCD-EFGH-…", …}

go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.6
make dev-appliance CODE=ABCD-EFGH-JKMN-PQRS-TVWX NAABU=$(go env GOPATH)/bin/naabu   # enrolls, heartbeats, polls for jobs
```

In a third shell:

```sh
go run ./controlplane/cmd/cp-api admin get apl_…                 # status enrolled, online true, last heartbeat, engine
make dev-job APL=apl_… MODE=discovery TARGETS=127.0.0.1/32       # create a job and run it now
go run ./controlplane/cmd/cp-api admin jobs --appliance apl_…    # queued → dispatched → running → done
go run ./controlplane/cmd/cp-api admin job-hosts job_…           # hosts, ports and findings for that job
make dev-tty                                                     # the console against the same state directory
```

A discovery job needs only naabu on the host. `inventory` and `full` jobs also need ospd-openvas on `APPLIANCE_OSPD_SOCKET`, which the images provide and a Mac or Windows host does not. For the whole stack with the real engine, use the compose stack: `SMOKE_KEEP=1 ci/smoke/run-container.sh` builds it, enrolls an appliance and leaves it running.

## Operating it

In the examples `cp-api` is the built binary, or `go run ./controlplane/cmd/cp-api`, with `CP_URL`, `CP_ADMIN_TOKEN` and `CP_ROOT_CA` exported. Running `cp-api` without arguments prints every command.

There are two admin roles. The operator token does everything except decide scope. The vendor-owner token (`--owner-token`, `CP_OWNER_TOKEN`) approves or rejects scope requests, attests the scope and edits `allowed_cidrs` directly (PLAN §16). `--actor` (`X-Actor`) names the human in the audit log.

### Jobs and schedules

```sh
cp-api admin create-job --appliance apl_… --mode discovery --targets 10.30.5.0/24 --now            # runs as soon as the appliance polls
cp-api admin create-job --appliance apl_… --mode inventory --targets 10.30.5.0/24 --excludes 10.30.5.1 \
    --cron "0 22 * * 6" --tz America/Los_Angeles --max-duration 21600                            # queued for the next window
cp-api admin jobs --appliance apl_… | job job_… | job-hosts job_… | run-now job_… | cancel-job job_…
cp-api admin create-schedule --appliance apl_… --mode inventory --targets 10.30.5.0/24 --cron "0 22 * * 6" \
    --tz America/Los_Angeles --name "weekly inventory"
cp-api admin schedules | schedule sch_… | schedule-update sch_… | delete-schedule sch_… | calendar site_… --days 30
cp-api admin directive apl_… stop_all                  # halts a running scan: stop_scan over OSP, naabu killed
cp-api admin directive apl_… stop_all '{"clear":true}'
cp-api admin hosts site_… | findings site_… | host host_… | finding fnd_…
cp-api admin agent-inventory site_… inventory.json     # hand over agent-track data for correlation
```

| Mode        | Modules by default                                                                                                 | Typical cadence                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------- |
| `discovery` | host discovery                                                                                                     | any time; the first contact with a site |
| `inventory` | discovery, port scan, openvas with the `inventory` config                                                          | weekly                                  |
| `full`      | discovery, port scan, openvas with the `full` config, the web add-on, and the fingerprint pass once it is approved | monthly                                 |

- **Scan windows.** A job waits for its window (`--cron`, `--tz`, `--max-duration`). A missed window rolls to the next cron start. `--now` and `run-now` drop the window.
- **Ports.** `standard` is naabu's top 1000 plus enterprise and OT extras. `full` is all 65535 TCP ports and is budgeted, see [Fingerprinting and full-range scans](#fingerprinting-and-full-range-scans). An explicit list also works.
- **Web add-on.** `full` jobs carry the `web` module (`web: {min_severity: medium, exclude_tags: [dos, fuzz, intrusive]}`). httpx probes ports 80, 443, 8080 and the like plus anything openvas called an HTTP service. nuclei runs the templates shipped in the bundle (`nuclei-templates/`, filtered to HTTP templates without excluded tags), with no interactsh and no template updates. Without httpx, nuclei or templates the phase is skipped and the job stats carry a warning.
- **Split network.** Seed `split: true` (OVF `appliance.split`, `APPLIANCE_SPLIT=1`) binds naabu (`-interface lan0`) and openvas (`source_iface = lan0`) to the scanning leg. `admin site-update SITE --lan-routes 10.31.0.0/16@10.30.5.1` pushes extra floor subnets (the site's `lan_routes`, as `CIDR@gateway`) into lan0's networkd unit. lan0 never receives a default route, so egress stays on wan0 without a policy-routing table.
- **Held jobs.** The server withholds jobs while the appliance reports `stop_all` or an engine that is not ready.

### Scope, fragile devices and finding review

```sh
cp-api admin scope-request site_… --cidrs 10.30.0.0/16,10.31.0.0/16 --reason "second floor"    # the operator asks
cp-api admin approve site_… scr_… --reason "attested on the onboarding call" --actor jane@acme  # the vendor owner decides (owner token)
cp-api admin attest site_… --actor jane@acme                                                   # quarterly re-attestation (PLAN §19.2)
cp-api admin site-update site_… --fragile-ports 9100,515,631,161,502,44818
cp-api admin fragile site_…                                                                    # hosts kept away from openvas, and why
cp-api admin fragile-set site_… --ip 10.30.5.21 --action clear --reason "printer survives probing"
cp-api admin review fnd_… --review false_positive --reason "banner only" --codify               # excludes the detector site-wide
cp-api admin tuning site_… | exclusions site_… | changes site_…                                # false-positive rate, exclusions, audit log
```

- **Scope.** A change to `allowed_cidrs` goes through a scope request that only the vendor owner can approve or reject. The owner attests the scope quarterly. Every scope or policy change is an audit entry and increments `site.version`, which travels to the appliance with each dispatched job.
- **Fragile devices.** The policy is per site, versioned and audited. A host with a fragile port open stays out of openvas until a human clears it, and a host can be marked fragile regardless of ports. The appliance enforces the version in force and notes `fragile:<port>`, `fragile:cleared:9100` or `fragile:policy` on the host.
- **Review.** A finding is reviewed as `false_positive` or `accepted` with a reason and an actor. `--codify` adds the detector (NVT OID or nuclei template) to the site's `vt_excludes`, reviews the existing findings from it and suppresses it on the appliance (`stats.suppressed`, nuclei `-exclude-id`). The tuning report gives the false-positive rate per detector.

### Coverage, health, alerts and onboarding

```sh
cp-api admin coverage site_… | vendor-coverage vnd_… | alerts
cp-api admin onboarding site_…                  # the PLAN §19.2 checklist with the next step
cp-api admin get apl_…                          # status, health, last heartbeat, engine, tools carried
curl -k https://localhost:8443/transparency     # what the appliance does, for the vendor (JSON: admin transparency)
```

- **Coverage score**, per site and per vendor: appliance health (40: online 40, degraded 25, stale 15, silent 0), inventory freshness (40: ≤ 8 days 40, ≤ 15 days 25, ≤ 31 days 10, discovery only 5), agent coverage of network-visible hosts (20 × fraction), minus 10 when the attestation is missing or older than 90 days. Findings from the appliance carry `network_reachable` and an `exposure_multiplier` of 1.5 for the vendor score (PLAN §12.3).
- **Health**: `online` (heartbeat within 3 intervals), `stale`, `silent` (24 h, alerted), `degraded` (engine not ready for 15 min), `never`.
- **Alerts** list silent, stale and degraded appliances, update errors, held rollouts, pending scope requests, stale attestations and failed scheduled scans.
- **Onboarding** tracks each site through scope attested, appliance enrolled and online, discovery done, fragile devices decided, weekly inventory and monthly full schedules, two cycles, attestation current.

### Fingerprinting and full-range scans

```sh
cp-api admin signoff nmap                                                               # the state; without a sign-off fingerprint jobs get 403 fingerprint_not_approved
cp-api admin signoff nmap --reference LEGAL-2026-014 --note "NPSL review" --actor jane   # record the legal review; full jobs now include the pass
cp-api admin create-job --appliance apl_… --mode inventory --targets 10.30.5.0/24 --fingerprint --now
cp-api admin create-schedule --appliance apl_… --mode inventory --targets 10.30.5.0/24 --cron "0 1 * * 2" --modules discovery,portscan,fingerprint
cp-api admin create-job --appliance apl_… --mode full --targets 10.30.5.0/24 --ports full --max-duration 43200   # all 65535 ports; refused with the estimate when it cannot fit
cp-api admin signoff nmap --revoke
make docker WITH_NMAP=1                                                                  # an image with nmap, only after the sign-off; packer: -var with_nmap=true
```

- **The sign-off.** nmap is licensed under the NPSL, so the control plane refuses the module until the legal review is recorded. The sign-off is a control-plane setting (`signoff:nmap`, with reference, actor and time) and shows on the transparency page either way. Revoking it stops new fingerprint jobs, and schedules that carry the module fail to materialize until it is recorded again.
- **The binary.** Only images built with `WITH_NMAP=1` or `with_nmap=true` contain nmap. The appliance reports the helpers it carries in `engine.tools` (`naabu`, `httpx`, `nuclei`, `nmap`). A fingerprint job on an appliance without nmap completes with the warning `fingerprint: nmap not installed`.
- **How nmap runs.** `-sV --version-intensity N -Pn -n --max-rate <pps> -p T:<open ports>`, plus `-sS -O --osscan-limit` when the daemon holds `CAP_NET_RAW` (the image's service unit and the container do) and `-sT` without OS detection otherwise. Excludes and the split-network interface are passed through. It never runs with `--script`. Port products from nmap only fill what naabu left empty, openvas detections keep precedence for the service label, and the OS guess with the higher confidence wins.
- **Full range.** `ports: full` is budgeted twice. At creation the `duration` guardrail estimates `hosts × ports × 1.1 / pps + 30 s` against `max_duration_s`, where `hosts` is the live hosts the inventory saw inside the targets in the last 45 days, or the address count when there are none; `expected_hosts` travels in the signed spec. On the appliance the same check runs after discovery with the real host count, before a single port probe leaves. Standard scans stay unbudgeted. A refusal names the fixes: raise `--pps` or `--max-duration`, narrow the targets, run discovery first, or use `standard`.

### Feed bundles, daemon releases and rollouts

```sh
cp-api ca init --dir dev/pki                      # also writes release-key.pem and release-pub.pem (cosign-compatible ECDSA P-256)
cp-api feed sync --dest feed-mirror               # rsync the Greenbone Community Feed, check sha256sums (and .asc with --gpg-keyring)
cp-api bundle build --out bundle-out --feed feed-mirror --nuclei-templates nuclei-templates --key dev/pki/release-key.pem
cp-api admin publish-bundle --dir bundle-out      # asks which sha256s are missing, uploads only those, publishes the signed manifest
cp-api admin set-canary apl_… true                # the lab appliance
cp-api admin bundles                              # canary → released after --canary-hours (48) once a canary confirmed it
cp-api admin rollout bundle 20260926T031700Z released --reason "lab verified"   # or held / retired
cp-api admin publish-release --file dist/applianced-linux-amd64 --component applianced-linux-amd64 --version 1.3.0 --key dev/pki/release-key.pem
cp-api admin releases | rollout release applianced-linux-amd64 1.3.0 held
```

- **Bundle.** A content-addressed manifest `{version, feed_version, files[{path, sha256, size}]}` signed with an ECDSA P-256 key in cosign's blob format. It carries the feed, the scan configs, the filtered nuclei templates and the fragile-port list.
- **Canary rollout.** Bundles and releases go to the canary group first. After the canary period and one canary confirmation they are released to the fleet. A canary that reports `update_error` holds the rollout. Releases are per platform (`applianced-<os>-<arch>`); containers are skipped because they update by image.
- **Delivery** is by directive: `update_bundle {url, sha256, sig, version, feed_version}` and `update_daemon {url, sha256, sig, version}`, where `url` is always a control-plane path fetched over the appliance's mTLS session (`/v1/bundles/{v}/manifest`, `/v1/bundles/{v}/files/{sha256}`, `/v1/releases/{component}/{version}`). The rollout ticker, every minute and right after a publish or state change, queues a directive per appliance that is not on the version, re-queuing at most hourly after an ack.
- **Applying a bundle.** The daemon adopts the image-seeded feed as its installed manifest on the first bundle, so even that first delta can be rolled back. Files live in `<state>/bundle/cas/<sha256>` and are hard-linked into `/var/lib/openvas/plugins` (feed) or `<state>/bundle/` (configs, templates, fragile ports). A changed feed makes the daemon wait up to 30 minutes for ospd to report the new `feed_version` with the VT cache loaded. On timeout the previous file set is restored and the heartbeat carries `update_error: "bundle <v>: …"`. Updates never start while a job runs, no job starts while an update runs (`state: updating`), and no reboot is involved.
- **Self-update.** The sha256 and signature are verified against the embedded release key, and the new binary must answer `version` with the expected version. It is then swapped next to the running one (`applianced.prev` is kept) with a pending record. The daemon exits 0, systemd's `Restart=always` starts the new one, and it must heartbeat within 10 minutes or it reinstates the previous binary. `packer/scripts/harden.sh` installs an `ExecStartPre` guard that does the same after three failed starts. Containers ignore `update_daemon`.
- **Daily pipeline.** `.github/workflows/bundle.yml` runs feed sync → bundle build → publish to the canary group on a cron. The release workflow publishes `applianced-linux-{amd64,arm64}` to the staging control plane.
- **OS updates.** The image enables `unattended-upgrades` for the security pocket only, sourced from `https://<fqdn>/apt/debian-security` over mTLS. `cp-api serve --apt-dir DIR` serves a `debmirror` or `apt-mirror` tree. `Acquire::https::<fqdn>::SslCert/SslKey` point at a `_apt`-readable copy of the client certificate under `/etc/appliance/apt/`, which the daemon writes at enrollment and renewal together with the sources entry. `Automatic-Reboot` is off: the daemon reboots an idle appliance during the site's 03:00 hour when `/var/run/reboot-required` appears, and reports `reboot_required` in the heartbeat until then.

### Replacing Qualys at a site

```sh
cp-api admin import-qualys site_… scan-results.csv                       # a Qualys export as external evidence (CSV, or XML with --kb kb.xml)
cp-api admin parity site_… --days-back 60 --min-severity medium          # the detection rate against Qualys and the gaps, with a verdict
cp-api admin summary site_… | vendor-summary vnd_… | trend site_… | sla   # open and overdue by severity, ageing, risk points, top findings
cp-api admin export site_… findings --status-filter open --out open.csv  # CSV for the portal and auditors; also hosts and vendor-export
cp-api admin feed-gaps --site-id site_…                                   # enterprise products by vendor, unidentified ports, hosts without findings, and a verdict
```

The principle is to run both scanners for two cycles, measure, then switch. The full runbook is [docs/MIGRATION.md](docs/MIGRATION.md); in short:

1. **Parallel run.** Keep the Qualys schedule. Create the appliance schedules for the same ranges, staggered a few hours later. After each Qualys scan, import its export.
2. **Read the parity report.** It compares host×CVE pairs: found by both, only by Qualys, only by the appliance. The detection rate is `both / (both + external_only)` and the verdict is parity at 90 % or more, gap at 70 % or more, and not ready below that. Work the Qualys-only list, which carries the QIDs, top down: scope or fragile exclusion, feed coverage, detection depth, or a Qualys false positive.
3. **Decide after cycle 2.** Switch when the verdict is parity on both cycles, or gap with every Qualys-only entry explained and accepted in writing, and the onboarding checklist is complete.
4. **Switch.** Disable the Qualys schedule, make the appliance the scanner of record, wire webhooks to ticketing, and keep the Qualys exports as the audit trail.

Imported findings appear with source `qualys` on the same hosts, matched by hostname and then IP. A CVE the appliance also found becomes one finding with two evidence entries in state `confirmed`. Informational rows are skipped.

| Status                           | Set when                                                                                                                                                                                                                                                                          |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `open`                           | first observed by any scanner                                                                                                                                                                                                                                                     |
| `fixed`                          | a later scan whose scope covers the finding observed the host without it: inventory findings by an inventory or full scan, full-only findings by a full scan, web findings by a job with the web module. Hosts the fragile policy kept away from detection never resolve findings |
| reopened (`open`, `reopens` + 1) | observed again after being fixed                                                                                                                                                                                                                                                  |

Agent-backed findings close through the agent track, and Qualys-only findings close through a `Fixed` row in a later import. Findings reviewed as false positives or accepted never count as overdue.

| Severity | SLA, Tier 1-2 | SLA, Tier 3-4 |
| -------- | ------------- | ------------- |
| critical | 15 days       | 30 days       |
| high     | 30 days       | 60 days       |
| medium   | 90 days       | 180 days      |
| low      | 180 days      | 360 days      |

Override the base values with `cp-api serve --sla critical=10,high=20`. Summaries give open and overdue counts by severity, what was new, fixed and reopened in 30 days, mean and oldest age, risk points, coverage, top findings and the last scans. The trend is weekly.

### Webhooks

```sh
cp-api admin webhook add --url-hook https://tickets.example/hook --secret S --events finding.new,findings.fixed,job.failed,alert.*
cp-api admin webhook list | test whk_… | deliveries whk_… | delete whk_…
```

- **Events**: `job.completed`, `job.failed`, `finding.new` (high and critical), `findings.fixed`, `alert.raised`, `alert.cleared`, `scope.requested`, `signoff.changed`, `rollout.held`, `import.completed`.
- **Body**: `{id, event, at, site_id, appliance_id, job_id, data}`.
- **Signature**: the `X-Webhook-Signature` header is `t=<unix>,sha256=<hmac(secret, "<unix>.<body>")>`. Receivers written in Go can verify it with `server.VerifyWebhookSignature`.
- **Delivery**: three attempts with backoff, a delivery log per webhook, and a test delivery.

### Running the control plane in production

```sh
cp-api serve --db postgres://… --pki-dir /etc/cp/pki --public-url https://cp.example.com:9443 \
    --server-cert server.pem --server-key server-key.pem --admin-token … --owner-token … \
    --s3-endpoint https://s3.us-east-1.amazonaws.com --s3-bucket cp --retention-days 90 --metrics-addr 127.0.0.1:9100
cp-api admin retention --dry-run | metrics
```

- **Certificates.** Outside `--dev`, `serve` needs `--server-cert` and `--server-key`, or `--self-issue` to mint the server certificate and the spool key from the pki directory on first start. The compose stack and the smoke tests use `--self-issue` (via `CP_SELF_ISSUE=1` and the container entrypoint); production supplies a real certificate.
- **The pki directory** must hold `spool-key.pem`, created by `cp-api ca init`. Back it up with the intermediate key: results sealed to it are unreadable without it.
- **Store.** `--db` points at Postgres, and pending migrations (embedded from `pkg/store/migrations`) are applied on start. `--dev` uses the in-memory store.
- **Object store.** A directory (`--object-dir`) or any S3-compatible service (`--s3-endpoint`, `--s3-bucket`, `--s3-region`, `--s3-prefix`, `--s3-path-style`, with `CP_S3_ACCESS_KEY` and `CP_S3_SECRET_KEY`), signed with SigV4 in the standard library.
- **Retention.** Raw result chunks are deleted after `--retention-days` (90) and support bundles after `--support-retention-days` (180). Findings, hosts and job history are kept.
- **Metrics.** Prometheus text at `GET /admin/metrics`, or on a plain listener for a private scrape network with `--metrics-addr`. Useful alerts: `cp_appliances{health="silent"}`, `cp_findings_overdue`, `cp_webhook_deliveries_total{result="failed"}`.
- **Several instances.** Two control-plane instances may run against one database. The rollout, scheduler, retention and alert-watch loops each take a Postgres advisory lock per tick (`store.TryLock`). The in-memory store keeps the locks local.
- **Admin API.** It lives on the mTLS listener (`:9443`) behind a bearer token in this build; production fronts it with portal SSO.

## Building and releasing

```sh
export APPLIANCE_ROOT_CA=/path/to/root.pem      # or use --dev in ci/build.sh
./ci/build.sh --version 1.0.0                    # static applianced and cp-api: linux/amd64, linux/arm64, windows/amd64 (.exe) → dist/
./ci/build-engine.sh --arch amd64                # naabu, httpx, nuclei → bin/engine/ (Linux with libpcap-dev for naabu; httpx and nuclei use a pinned Go 1.25 toolchain, see ENGINE_GOTOOLCHAIN)
make ova VERSION=1.0.0                           # qcow2 via Packer, then OVA and VHDX; needs packer, qemu-system-x86_64, /dev/kvm and a VT feed tarball (packer/scripts/seed-feed.sh)
make docker VERSION=1.0.0                        # container images; add WITH_NMAP=1 after the sign-off
./ci/sign.sh && ./ci/manifest.sh                 # cosign and syft; dist/manifest.json for the portal download page
```

- **Embedded trust.** The root CA is embedded at build time by copying it to `daemon/internal/pki/roots.pem`, and the release signing public key to `daemon/internal/pki/release-pub.pem` (`APPLIANCE_RELEASE_PUB`; `--dev` uses `dev/pki/release-pub.pem`). Both files are tracked empty. A dev build or a smoke run overwrites them, so restore them before committing: `git checkout daemon/internal/pki/roots.pem daemon/internal/pki/release-pub.pem`.
- **Development trust.** In dev the daemon also accepts `APPLIANCE_ROOT_CA=<pem>` and `APPLIANCE_RELEASE_KEY=<pem>`, or `/etc/appliance/{root-ca,release-pub}.pem` (`%ProgramData%\TPRM Appliance\etc\` on Windows).
- **Control-plane address.** The FQDN is baked in with `-X main.defaultCPURL=…` (`make CP_URL=…`).
- **The appliance image** builds gvm-libs, openvas-scanner and ospd-openvas from pinned tags and naabu from source. Without a feed tarball in `docker/feed/` the engine reports `vt_cache_loaded=false` and only discovery jobs run.
- **Boot.** The disk is GPT with a BIOS boot partition and an EFI system partition. `harden.sh` installs Debian's Microsoft-signed shim and signed GRUB (`EFI/BOOT/BOOTX64.EFI` as the removable-media fallback, and `EFI/debian/`) next to the BIOS loader. That gives Secure Boot on Hyper-V Generation 2 with the Microsoft UEFI CA template and on KVM with OVMF, while Generation 1 keeps working through the BIOS loader. Hyper-V adapters are named `wan0` and `lan0` by MAC order. The vendor steps are in [docs/DEPLOY.md](docs/DEPLOY.md), Option B.

The workflows expect these secrets and runners:

| Workflow                      | Needs                                                                                                                                                                                                                                                                                                                         |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| release                       | `APPLIANCE_ROOT_CA_PEM`, `APPLIANCE_RELEASE_PUB_PEM` (embedded into the daemon; without it appliances refuse bundles and self-updates), `RELEASE_KEY_PEM`, `COSIGN_KEY` and `COSIGN_PASSWORD`, `FEED_TARBALL_URL`, `STAGING_CP_ADMIN_URL`, `STAGING_CP_ADMIN_TOKEN`, `STAGING_CP_URL_FOR_GUEST`, optional `STAGING_CP_CA_PEM` |
| release, image and smoke jobs | a self-hosted runner labelled `kvm` with qemu, genisoimage, expect and jq                                                                                                                                                                                                                                                     |
| daily bundle                  | `CP_ADMIN_URL`, `CP_ADMIN_TOKEN`, `CP_ROOT_CA_PEM`, `RELEASE_KEY_PEM`, optional `FEED_GPG_KEYRING_B64`; variables `FEED_SOURCE` and `NUCLEI_TEMPLATES_REF`                                                                                                                                                                    |

## Testing

```sh
go test -race ./...                                            # everything, on the in-memory store
go test -count=1 -race -timeout 15m -v ./daemon/internal/e2e    # the six end-to-end tests, about a minute
make vet lint                                                  # go vet (native and windows/amd64), gofmt, shellcheck
SMOKE_SKIP_ENGINE=1 ci/smoke/run-container.sh                  # the compose stack end to end; Docker needs 8 GB
ci/smoke/run-qemu.sh packer/output-appliance/appliance-1.0.0.qcow2   # the built image, console included; needs KVM
```

The end-to-end tests run the real daemon loop, runner and engine against the real server in one process. The scanners are POSIX shell-script fakes, so these tests skip on Windows.

| Test         | Covers                                                                                                                                                                                                                                                                                                                      |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TestPhase1` | enroll → online → directives → support bundle → wipe                                                                                                                                                                                                                                                                        |
| `TestPhase2` | a `discovery` and an `inventory` job against a lab subnet with a fake naabu and a scripted fake ospd: the seeded CVE-2019-0708 is detected with QoD 97, the host is correlated with agent inventory into one `both` host with a `confirmed` finding, and `stop_all` halts an in-flight OSP scan and flushes partial results |
| `TestPhase3` | a feed delta applies without a reboot; the canary gets bundles and releases first; a failing bundle is rolled back on the appliance and held on the control plane; a daemon self-update is confirmed by the new version's heartbeat                                                                                         |
| `TestPhase4` | the fragile policy reaches the appliance and a cleared host is scanned; a codified false positive is suppressed by the next scan; a schedule runs a job in its window; coverage, alerts and the transparency page                                                                                                           |
| `TestPhase5` | the fingerprint pass runs only after the sign-off and enriches the inventory; the full-range option is budgeted at dispatch and on the appliance; the heartbeat reports the tools; the onboarding checklist                                                                                                                 |
| `TestPhase6` | a real scan opens a finding; a Qualys export merges with it and the parity report scores the appliance; a rescan closes the finding and the webhook receiver gets the events; summary, export and metrics                                                                                                                   |

`TestPhase3` logs `VT reload failed; rolling back` and `bundle rollout held` on purpose: it publishes a broken delta to prove the rollback and the canary hold.

Two suites need a service and skip without it:

- **Postgres.** `TEST_DATABASE_URL=postgres://cp:cp@127.0.0.1:5433/cp?sslmode=disable go test ./controlplane/pkg/store` runs the store conformance suite on Postgres as well. Use a throwaway database: the suite drops and recreates `public`.
- **S3.** `TEST_S3_ENDPOINT`, `TEST_S3_BUCKET`, `TEST_S3_ACCESS_KEY` and `TEST_S3_SECRET_KEY` point the object-store test at a real S3-compatible server. CI starts SeaweedFS with signature checks for it.

Both smoke tests enroll an appliance, dispatch a `discovery` job (and an `inventory` job when the engine is healthy), exercise directives, publish a synthetic bundle to the appliance as canary and then a delta, and run the site-governance, sign-off, full-range budget, onboarding, feed-gap and Qualys-replacement round trips. The QEMU run also drives the console over serial and scans the no-egress 10.0.3.0/24 leg in split-network mode.

| Variable                              | Effect                                                              |
| ------------------------------------- | ------------------------------------------------------------------- |
| `SMOKE_SKIP_ENGINE=1`                 | do not require a loaded VT cache (an image built without a feed)    |
| `SMOKE_KEEP=1`                        | leave the stack or the VM running afterwards                        |
| `SMOKE_NO_BUILD=1`                    | do not rebuild the container images                                 |
| `SMOKE_SKIP_BUNDLE=1`                 | skip the bundle canary and delta test                               |
| `SMOKE_BUNDLE_FEED=1`                 | add a two-VT feed to the synthetic bundle, for a real engine        |
| `WITH_NMAP=1`, `SMOKE_REQUIRE_NMAP=1` | build the image with nmap and insist that the fingerprint pass runs |
| `SMOKE_UEFI=1`, `SMOKE_SKIP_TTY=1`    | QEMU only: boot through OVMF; skip the console test                 |

The smoke run embeds the dev CA in the daemon build. Restore the placeholders afterwards with `git checkout daemon/internal/pki/roots.pem daemon/internal/pki/release-pub.pem`.

## Running the daemon on Windows

`applianced-windows-amd64.exe` is a supported build of the daemon for a Windows host: a lab VM, a jump box, a site without a hypervisor slot. It is the daemon, not the appliance. It enrolls, heartbeats, acks directives, uploads support bundles and runs `discovery` and port-scan jobs with naabu. There is no openvas on Windows, so `inventory` and `full` jobs are held by the control plane (_engine not ready_) and, if forced, rejected by the daemon with `engine`.

|                        | Linux appliance                                          | Windows host                                                                                            |
| ---------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| State                  | `/var/lib/appliance`, `/run/appliance`, `/etc/appliance` | `%ProgramData%\TPRM Appliance\{state,run,etc}` (`APPLIANCE_STATE_DIR` and `APPLIANCE_RUN_DIR` override) |
| Engine                 | `/opt/engine/naabu` and ospd-openvas                     | `engine\naabu.exe` beside the executable, or `APPLIANCE_NAABU`; no ospd                                 |
| Seed                   | OVF → volume → env → console                             | env (`APPLIANCE_CODE`, `APPLIANCE_CP_URL`, `APPLIANCE_PROXY`) or `--seed-file`                          |
| Host metrics           | `/proc`                                                  | kernel32 (uptime, free memory, free disk); no load average                                              |
| Machine identity       | `/etc/machine-id`                                        | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`                                                      |
| Wipe                   | state deleted, `systemctl poweroff`                      | state deleted, `shutdown /s /t 0`                                                                       |
| Network, time, console | systemd-networkd, htpdate, tty1                          | not applicable: the Network screen reports unsupported; `applianced tty` is a plain stdin menu          |

```powershell
# naabu: the Windows build from https://github.com/projectdiscovery/naabu/releases (v2.3.6). Host discovery and SYN
# scans use raw sockets, so install Npcap (https://npcap.com) and run from an elevated prompt; APPLIANCE_SCAN_TYPE=c
# switches the port scan to connect mode.
$env:APPLIANCE_CP_URL  = "https://appliance.tprm.example.com"     # only when it is not baked into the build
$env:APPLIANCE_CODE    = "ABCD-EFGH-JKMN-PQRS-TVWX"
$env:APPLIANCE_NAABU   = "C:\Program Files\TPRM Appliance\engine\naabu.exe"
$env:APPLIANCE_ROOT_CA = "C:\Program Files\TPRM Appliance\root.pem"    # dev and staging builds without an embedded root
.\applianced-windows-amd64.exe run
.\applianced-windows-amd64.exe status                                   # from another prompt
```

The daemon exits cleanly on Ctrl-C or a console close. It does not speak the Service Control Manager protocol yet, so to run it as a service wrap it with [WinSW](https://github.com/winsw/winsw) or NSSM, or register a scheduled task that runs at startup as SYSTEM. Build it with `make build-windows` or `ci/build.sh --targets windows/amd64`. CI vets every push for windows/amd64 and windows/arm64, where the tests compile too, and runs the Go tests natively on a Windows runner. That job is advisory until it has been seen green there.

## Contracts worth knowing

- **Enrollment code**: 20 characters, Crockford base32 (no I, L, O, U), 100 bits, shown as `XXXX-XXXX-XXXX-XXXX-XXXX`, 14-day TTL, single use. Three failed checks lock it. It is stored as a SHA-256. Wrong guesses are rate-limited per source IP.
- **Identity**: the client certificate. CN = appliance id, URI SAN `urn:tprm:appliance:<vendor>:<site>:<id>`, 1 year. The mTLS listener verifies the chain to the intermediate, then on every request checks the serial against `revoked_serial` and that the path `{id}` matches the CN.
- **Directives** are a closed set (`api/v1`): `set_interval {s:10..3600}`; `stop_all` (`{clear:true}` lifts it; while active a running job is cancelled and no job is dispatched or accepted); `run_job_now {job_id}` (the server drops the job's window and the appliance polls at once); `renew_cert`; `wipe {confirm_token:<appliance_id>}`; `update_bundle`; `update_daemon`; `reload_vts`; `noop`. Acks ride in the next heartbeat.
- **Job spec** (PLAN §11): `mode` discovery | inventory | full, `targets`, `excludes`, `ports` (`standard`, `full` or an explicit list), `modules` (`discovery`, `portscan`, `openvas`, `web`, `fingerprint`), `openvas {config, max_hosts, max_checks, fragile_ports_exclude}`, `web {min_severity, exclude_tags}`, `fingerprint {os_detection, intensity}`, `expected_hosts`, `window {cron, tz, max_duration_s}`, `rate {pps, per_host_parallel}`, `safe_checks`, `allow_public`, `iface`, `issued_at`, `sig`. The control plane signs the canonical JSON (the spec with `sig` empty) with the issuing intermediate key at dispatch. The appliance verifies it against the chain it stored at enrollment and rejects anything older than an hour or addressed to another appliance.
- **Guardrails** run twice from `internal/guard`: targets ⊆ `allowed_cidrs`; no public ranges unless the job is `allow_public` **and** the site attests them; window open, with ±5 min skew tolerance; `rate.pps ≤ max_pps`; `max_hosts × max_checks ≤ max_concurrency` (default 16); `safe_checks` unless the site is `unsafe_ok`, never for Tier 1 vendors; and the `duration` budget for port specs wider than 2048 ports. The server additionally withholds jobs while the heartbeat reports `stop_all` or an engine that is not ready. The appliance additionally checks signature, freshness, appliance id, `stop_all`, engine health and the presence of a spool key. A rejected job reports the failing check verbatim and never partially runs.
- **Results**: `POST /v1/jobs/{job}/results` with `X-Result-Seq`, `X-Result-SHA256` and `X-Result-Final`. The body is a sealed envelope whose plaintext is a `ResultBatch`: hosts with ports, os_guess and findings, and `stats` in the final chunk. The server unseals it with `spool-key.pem`, parses it with a strict schema and size limits, stores the plaintext chunk in the object store (`results/<job>/<seq>.json`), dedupes on `(job, seq)` by content hash, and ingests. The final chunk marks the job `done`. The appliance reports the terminal job status only once its chunks are flushed.
- **Correlation** (PLAN §12.3): host identity by MAC, then hostname (short name), then IP. `host.source` is agent, appliance, both or external. Agent inventory wins for packages and hostname; the appliance wins for ports. The same CVE from two sources becomes one finding with two evidence entries in state `confirmed`. openvas-only findings are `network_observed`, or `suspected` when QoD < 70 until a second scan or agent data confirms them. Per-port detail (service, product, version, CPE) survives across scan types, so a discovery-only job does not erase what an inventory learned. `POST /admin/sites/{id}/agent-inventory` is where the agent track hands over its data.
- **Finding lifecycle**: `status` is `open` or `fixed`, with `fixed_at`, `reopened_at` and `reopens`. `scope` says which scan can resolve a finding. `days_open`, `sla_days` and `overdue` are computed per vendor tier.
- **Scan configs**: `inventory` = detection families plus Web Servers, Windows, Microsoft Bulletins, SSL/TLS, Databases and Default Accounts; `full` = every unauthenticated remote family. Denial of Service, Brute force attacks and all `* Local Security Checks` families are never selectable. Hosts with an open fragile-device port (site list, default 9100, 515, 631, 161, 502, 44818) are kept out of openvas and tagged `fragile:<port>`; hosts with no open TCP port are skipped. The exact `inventory` family list is tuned on lab and pilot data (PLAN §23).
- **State on disk**: `/var/lib/appliance/{key.pem,cert.pem,state.json,spool/,nvt-cache/}`, and the live status for the console in `/run/appliance/status.json`. The spool holds only sealed chunks; the appliance cannot read them back. Wipe shreds all of it.
- **Support bundle**: never includes `key.pem` or the pending code; proxy credentials are redacted. It uploads over mTLS only.

## Known gaps and next steps

**Not built.** The openvas and ospd binaries update with the image, not with `update_daemon`. The Enterprise Feed is evaluated, not adopted ([docs/ENTERPRISE-FEED.md](docs/ENTERPRISE-FEED.md)). Authenticated scanning, web application scanning beyond nuclei's HTTP templates and patch workflows are out of scope (PLAN §1). The portal UI is the TPRM application; this repository provides the `/admin` views it renders.

**Detection content is the gap that matters for replacing Qualys.** A listing of the Community Feed taken on 2026-09-27 (95,103 test files, feed version 202609251547) shows:

- For the enterprise network vendors the feed still detects the product and version, but its vulnerability tests stop in 2017 for Fortinet, Palo Alto, Cisco, Juniper and Citrix. F5 continues to 2024.
- The flow of new tests has thinned: 6,652 files in the 2022 directory, 4,076 in 2024, 1,700 in 2025 and 37 in 2026. Greenbone has published no explanation.
- The Enterprise Feed cannot be licensed for a self-built scanner. The access key is bound to one instance of a Greenbone product and may not be passed on, and Greenbone does not sell the feed for self-built setups, so an OEM agreement is the only route.

Proposed next steps, in order. None of this is built:

1. **Detection content.** An advisory-matching evidence source in the control plane: vendor advisories with structured version ranges (Cisco, Fortinet and Palo Alto first) matched against the inventory the appliance already collects. Extend the nuclei bundle to non-destructive network-device CVE templates. Alert when the feed stops growing. In parallel, ask Greenbone about the slowdown and about an OEM agreement.
2. **Prioritization and reports.** A detection score from CVSS, EPSS, CISA KEV and exploit availability, weighted by asset criticality; end-of-life flags; generated vendor, site and scan reports.
3. **Credentialed depth.** Read-only credentials for network gear, sealed per job, used only to read exact versions. This also activates the SSH login detection scripts the feed already carries for FortiGate, Junos, NetScaler, BIG-IP and IOS XE.

The parity report against the Qualys parallel run is the acceptance gate for each step and for each site.
