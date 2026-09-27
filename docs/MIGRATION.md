# Replacing the Qualys scanner at a 3PL site

This is the runbook for taking a site from a Qualys Virtual Scanner
Appliance to this appliance without a gap in evidence. It assumes the
control plane runs Phase 6 (`cp-api version` ≥ the Phase 6 build) and the
site is onboarded to the point of the PLAN §19.2 checklist showing the
appliance online (`cp-api admin onboarding SITE`).

The principle: **run both scanners for two cycles, measure, then switch.**
The appliance never replaces evidence it has not shown it can reproduce.

## 1. Parallel run (cycle 1)

1. Keep the Qualys scanner and its schedule exactly as they are.
2. Create the appliance schedules for the same ranges and windows: weekly
   `inventory`, monthly `full`. Stagger them a few hours after the Qualys
   window so both see the same state of the network.
3. After each Qualys scan, export it and import it as external evidence:

   ```sh
   # Scan results CSV from the Qualys UI (Scans → Scan → Download, CSV), or
   # the host list detection XML from the API; the KnowledgeBase XML joins
   # QIDs to CVEs and titles when the export lacks them.
   cp-api admin import-qualys site_… qualys-scan-2026-10-04.csv
   cp-api admin import-qualys site_… host_list_detection.xml --kb knowledgebase.xml --scanned-at 2026-10-04T22:00:00Z
   ```

   Imported findings appear as source `qualys` on the same hosts (matched
   by hostname, then IP). A CVE the appliance also found becomes one
   finding with two evidence entries in state `confirmed`. Informational
   rows are skipped; rows Qualys marks `Fixed` close the corresponding
   Qualys-only finding.

4. Review fragile-device decisions and false positives as in the pilot
   (`admin fragile`, `admin review … --codify`).

## 2. Read the parity report (after cycle 1, again after cycle 2)

```sh
cp-api admin parity site_… --days-back 60 --min-severity medium
```

The report compares host×CVE pairs seen in the window:

| Field | Meaning |
|-------|---------|
| `hosts` | hosts each scanner saw, and the ones only one of them saw (a range difference or a fragile exclusion) |
| `cves.both` / `cves.external_only` / `cves.appliance_only` | pairs both found, only Qualys found, only the appliance found |
| `detection_rate` | `both / (both + external_only)`: the share of what Qualys finds that the appliance also finds |
| `external_only[]` | the Qualys-only CVEs, most severe and most widespread first, with the QID |
| `findings_without_cve` | detections that cannot be compared by CVE (configuration checks, banners) |
| `verdict` | parity (≥ 90 %), gap (≥ 70 %), not ready (below) |

Work the `external_only` list top-down. Each entry is one of:

- **Scope or exclusion**: the host is in `hosts.external_only`, or sits
  behind the fragile-device policy. Decide with the vendor (`admin
  fragile-set … --action clear`) or accept the exclusion as policy.
- **Feed coverage**: the CVE is for an enterprise product. `admin
  feed-gaps --site-id site_…` tells whether such products are common
  enough to justify the Enterprise Feed evaluation
  ([ENTERPRISE-FEED.md](ENTERPRISE-FEED.md)).
- **Detection depth**: the product is identified but the community feed
  has no test, or only a lower-QoD one. Note it; a second cycle tells
  whether it is stable.
- **Qualys false positive**: review it in Qualys; do not chase it.

`appliance_only` needs the same look from the other side: real findings
Qualys lacks are a plus, false positives get reviewed and codified.

## 3. Cycle 2 and the decision

Repeat the import after the second Qualys scan and read the report again
with `--days-back` covering both cycles. The site is ready to switch when:

- the verdict is `parity` on both cycles, or `gap` with every
  `external_only` entry explained and accepted in writing by the
  programme owner;
- `admin onboarding site_…` is complete (attested scope, both schedules,
  two cycles);
- the vendor has seen the transparency page and the appliance's summary
  (`admin summary site_…`) for their site.

## 4. Switch

1. Disable the Qualys scan schedule for the site; leave the scanner
   powered on for one more week in case a report is questioned.
2. In the portal, make the appliance the site's scanner of record: from
   now on the summary, SLA ageing (`admin summary`, `admin sla`), trend
   (`admin trend`) and exports (`admin export site_… findings --status-filter open`)
   feed the vendor reports, and webhooks feed ticketing:

   ```sh
   cp-api admin webhook add --url-hook https://tickets.example/hooks/tprm --secret … --events finding.new,findings.fixed,job.failed,alert.*
   ```

3. Decommission the Qualys scanner appliance and release its licence.
4. Keep the Qualys exports: they remain as `qualys` evidence on the
   findings they matched, which is the audit trail of the switch.

## Finding lifecycle after the switch

| Status | Set when |
|--------|----------|
| `open` | first observed by any scanner |
| `fixed` | a later scan whose scope covers the finding observed the host without it (inventory findings by an inventory or full scan, full-only findings by a full scan, web findings by a job with the web module); hosts the fragile policy kept away from detection never resolve findings |
| reopened (`open`, `reopens` + 1) | observed again after being fixed |

Agent-backed findings close through the agent track; Qualys-only
findings close through a `Fixed` row in a later import. Findings reviewed
as false positives or accepted never count as overdue.

## SLA defaults

| Severity | Tier 1-2 | Tier 3-4 |
|----------|----------|----------|
| critical | 15 days | 30 days |
| high | 30 days | 60 days |
| medium | 90 days | 180 days |
| low | 180 days | 360 days |

Override with `cp-api serve --sla critical=10,high=20`.

## Operations checklist for the scanner of record

- Object store: `--s3-endpoint … --s3-bucket …` (SigV4, MinIO or AWS);
  raw result chunks are deleted after `--retention-days` (90), support
  bundles after `--support-retention-days` (180); findings, hosts and
  job history are kept.
- Backups: Postgres (`pg_dump`), the pki directory (spool and release
  keys), and the object store bucket policy.
- Metrics: `--metrics-addr 127.0.0.1:9100` (Prometheus text) or
  `GET /admin/metrics`; alert on `cp_appliances{health="silent"}`,
  `cp_findings_overdue`, `cp_webhook_deliveries_total{result="failed"}`.
- Two control-plane instances can run against one database: the rollout,
  scheduler, retention and alert-watch loops take an advisory lock per tick.
