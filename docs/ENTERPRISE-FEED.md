# Greenbone Enterprise Feed: evaluation (PLAN §20 Phase 5, §21, §23 item 7)

**Decision at the end of Phase 5: stay on the Community Feed. Re-run this evaluation after the second and third sites have produced two inventory cycles each, using the numbers below.**

## What the Enterprise Feed would add

Greenbone sells the Enterprise Feed as the superset of the Community Feed: the same detection and CVE tests plus vulnerability tests for enterprise products (network gear and security appliances from Cisco, Fortinet, Palo Alto Networks, Juniper, F5, Check Point, SonicWall, WatchGuard, Zyxel; infrastructure from VMware, Citrix, NetApp, Dell, HPE/Aruba, IBM; business software from SAP and Oracle; industrial products from Siemens, Rockwell and Schneider), compliance policies, and a faster turnaround from CVE publication to test. Exactly which tests the community feed lacks is not published as a list; it has to be measured against what the appliances actually see.

## What it costs, beyond money

| Constraint | Consequence for this appliance |
|------------|--------------------------------|
| Licensed per scanner ("sensor") with a subscription key that is **non-redistributable** (PLAN §21) | The feed cannot be shipped in an image or bundle that a third party runs. Each vendor-run appliance would need its own key delivered out of band, or an OEM/redistribution agreement with Greenbone that covers third-party sensors. |
| Key material on the appliance | The key would have to travel in the signed bundle (encrypted to the appliance, like the spool) and be revocable per appliance: new code, a new secret to guard on a device the vendor controls. |
| Feed sync | `cp-api feed sync` mirrors an rsync module without credentials; the enterprise feed is fetched with the subscription key. The mirror would need a second, credentialed source and the bundle a `feed_source` marker so lab and vendor appliances never mix feeds. |
| Transparency (PLAN §22) | The transparency page lists the community feed and its ODbL terms. An enterprise feed changes the licence line and the "written offer" section of the OSS notices. |

None of these is hard, but all of them are only worth doing if the community feed demonstrably misses what the sites run.

## How to measure the gap

The control plane computes the input from the appliance inventory:

```sh
cp-api admin feed-gaps                # every site
cp-api admin feed-gaps --site-id S    # one site
```

The report (`GET /admin/feed-gaps`) counts, over the network-visible hosts:

- `hosts`, `open_ports`, and how many open ports carry a service/product/CPE or HTTP fingerprint (`identified_ports`) versus none (`unidentified_ports`);
- `enterprise_hosts` and a per-vendor breakdown (`enterprise[]` with hosts, ports, findings on those hosts, and examples) using a keyword heuristic over product names, CPEs, HTTP server headers and OS guesses for the vendors the Enterprise Feed is marketed for (`enterpriseVendors` in `controlplane/pkg/server/depth.go`, meant to be tuned);
- `hosts_without_findings`: hosts the community feed said nothing about.

The `recommendation` field applies these thresholds:

| Condition | Verdict |
|-----------|---------|
| no appliance inventory | run discovery and inventory scans first |
| ≥ 15 % of network-visible hosts run enterprise products, or ≥ 10 such hosts have no finding at all | **evaluate**: request a trial subscription, scan the lab segment (PLAN §18.3) with both feeds for one cycle, count the findings the enterprise feed adds on real hosts |
| ≥ 30 % of open ports unidentified | **identify first**: the fingerprint pass (after the nmap sign-off) tells what runs there; judging feed coverage before that is guesswork |
| otherwise | **stay on the community feed** |

The thresholds are deliberately coarse: the point of the report is to make the decision with the pilot's data rather than with Greenbone's brochure.

## How the trial would be run, if it comes to that

1. Greenbone trial key on the **control-plane mirror only**, never on a vendor appliance: `cp-api feed sync --source <enterprise rsync module> --dest dev/feed-enterprise` with the key configured for rsync as Greenbone documents for the subscription.
2. Build a bundle from that mirror (`cp-api bundle build --feed dev/feed-enterprise --version ent-<date>`), publish it to the **lab appliance as canary only** (`admin set-canary`, `admin publish-bundle`), and keep the rollout in `canary` (never `released`) so no vendor appliance receives it.
3. Run one `inventory` and one `full` cycle on the lab segment with each feed; compare findings per host with `admin findings SITE`, filtered to the hosts the feed-gap report listed.
4. Decide on the count of new, true findings on real vendor products, not on the size of the feed.

## What was done in Phase 5

- The measurement exists and runs on every site (`feed-gaps`); the fingerprint pass improves its input once legally cleared.
- Ingest keeps per-port detail across scan types (a discovery-only job no longer erases the product a previous inventory learned), so the report is stable between cycles.
- No enterprise key, no second feed source and no feed marker were added: the community feed stays the only feed the appliances receive, which keeps the ODbL attribution on the transparency page truthful.
