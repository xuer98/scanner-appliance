# Deploying the Scanner Appliance

This guide is for the team that runs the hypervisor or Docker host where the
appliance will live. The appliance is a small Debian-based virtual machine (or
a container) that scans the network segments you agreed with us and reports
results to our control plane over an outbound, mutually authenticated TLS
connection. It has no SSH, no local accounts, and no inbound ports.

The vulnerability-detection engine (Greenbone OpenVAS scanner with a
snapshot of the community vulnerability-test feed) and the naabu port
scanner are embedded in the image. They sit idle after deployment: no scan
runs until a job is scheduled for this appliance in the portal, within the
agreed scope and scan window. The status screen and our portal show whether
the engine is healthy (*engine ready*) and which job, if any, is running.

Three things are needed before you start:

1. **An image** from the download page: OVA (VMware), VHDX (Hyper-V), qcow2
   (KVM) or the container image. Each release ships `manifest.json` with a
   SHA-256 and a signature for every file.
2. **An enrollment code** issued in the portal for this appliance. It looks
   like `ABCD-EFGH-IJKL-MNOP-QRST`, works once, and expires after 14 days.
3. **Network placement** per the prerequisites below.

## Prerequisites

| Item | Requirement |
|------|-------------|
| Hypervisor | VMware vSphere 7+, Hyper-V 2019+, or KVM; or Docker with `NET_RAW`/`NET_ADMIN` |
| Resources | 4 vCPU, 8 GB RAM, 60 GB disk (the OVA/VHDX/qcow2 are sized this way; Docker: 8 GB memory limit) |
| Egress | `appliance.tprm.example.com` TCP 443 from the WAN NIC, direct or via HTTP proxy; **exempt from SSL inspection** |
| Placement | LAN NIC in the segment(s) to be scanned; WAN NIC anywhere with egress |
| Scope | list of target CIDRs, known exclusions, fragile devices, preferred scan window and timezone |
| Contact | technical owner for scan-impact escalation |

Notes on egress:

- Only outbound TCP 443 to the single FQDN is used. No inbound rules are needed.
- If traffic must go through an HTTP proxy, the proxy must allow `CONNECT` to
  port 443 and must **not** intercept TLS for that FQDN: the appliance
  authenticates with a client certificate, which SSL inspection breaks.
- NTP is not required; the appliance sets its clock over HTTPS.

### Network adapters

The VM images have two adapters:

| Adapter | Name inside the VM | Purpose |
|---------|--------------------|---------|
| 1 (lowest PCI address) | `wan0` | Reaches the control plane. Receives the default route. |
| 2 | `lan0` | Sits in the segment to scan. Never receives a default route. |

Single-network deployment: connect both adapters to the same port group /
switch (or leave adapter 2 disconnected). The appliance detects that both
sit on one subnet and treats them as one.

Split-network deployment (recommended for warehouse floors): put `wan0` in a
management/DMZ network with egress and `lan0` in the floor segment, which needs
no internet access at all. Enable the *split* option when seeding.

## Verify the download

```sh
sha256sum appliance-1.2.3.ova            # compare with manifest.json
cosign verify-blob \
  --signature appliance-1.2.3.ova.sig \
  --certificate appliance-1.2.3.ova.pem \
  --certificate-identity-regexp 'github.com/tprm/scanner-appliance' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  appliance-1.2.3.ova
```

## Option A: VMware vSphere (OVA)

The OVA carries OVF properties, so the appliance can be fully configured at
deploy time and enrolls on first boot without touching the console.

1. vSphere Client: **Deploy OVF Template**, select `appliance-<version>.ova`.
2. Name and folder, compute resource, storage (thin provisioning is fine).
3. **Select networks**: map `WAN` to the port group with egress, `LAN` to the
   segment to scan (or the same port group for single-network).
4. **Customize template** — the properties are:

   | Property | Required | Meaning |
   |----------|----------|---------|
   | Enrollment code (`appliance.code`) | yes* | The code from the portal |
   | HTTP proxy (`appliance.proxy`) | no | `host:port` or `user:pass@host:port` |
   | WAN IP mode (`appliance.ip.mode`) | no | `dhcp` (default) or `static` |
   | WAN IP address (`appliance.ip.cidr`) | if static | e.g. `10.20.0.50/24` |
   | WAN default gateway (`appliance.gw`) | if static | e.g. `10.20.0.1` |
   | DNS servers (`appliance.dns`) | if static | comma separated |
   | Split-network mode (`appliance.split`) | no | `true` when WAN and LAN are different networks |

   \* The code can instead be typed on the console after first boot.

5. Finish and power on. The VM console shows the status screen; within a few
   minutes it reports *Enrolled* and the appliance appears as *online* in the
   portal.

Requirements: hardware version 19 (vSphere 7.0 U2+) or the deploy wizard will
downgrade it; VMware Tools (open-vm-tools) is pre-installed and is how the
properties reach the guest — do not remove it. Do **not** enable host time
synchronisation.

### Redeploying / changing properties

Properties are read only until enrollment succeeds. To change network settings
later use the console (Network / Proxy screens). A replacement appliance needs
a new code from the portal.

## Option B: KVM (qcow2) and Hyper-V (VHDX) with a seed volume

These formats carry no OVF properties. Configuration comes from a small ISO
labelled `APPLIANCE` that contains a `seed.yaml`, attached as a CD-ROM on
first boot. Alternatively, type the code on the console. The disk image
boots both ways, BIOS and UEFI (with Secure Boot), so it runs on KVM with
SeaBIOS or OVMF and on Hyper-V Generation 2.

1. Create `seed.yaml`:

   ```yaml
   code: "ABCD-EFGH-IJKL-MNOP-QRST"
   proxy: "user:pass@proxy.vendor.local:3128"   # optional
   network:                                     # optional; default is DHCP on both
     wan0: { mode: static, cidr: 10.20.0.50/24, gw: 10.20.0.1, dns: [10.20.0.10] }
     lan0: { mode: dhcp }
   split: true                                  # WAN and LAN on different networks
   ```

2. Build the ISO (the volume label **must** be `APPLIANCE`). The KVM helper
   below does this for you; on a Windows host use `oscdimg` from the Windows
   ADK:

   ```sh
   genisoimage -o seed.iso -V APPLIANCE -r -J seed.yaml
   # Windows (Hyper-V host): oscdimg -lAPPLIANCE -n seed\ seed.iso
   ```

3. Create the VM. The release ships `appliance-<version>-hypervisor-helpers.zip`
   with the two helpers used below (they are also in the repository under
   `packer/kvm` and `packer/hyperv`).

   **KVM / libvirt** (`create-vm.sh` wraps `virt-install`: virtio devices,
   two NICs in WAN, LAN order, serial console, optional OVMF):

   ```sh
   ./create-vm.sh --name appliance-reno --image /var/lib/libvirt/images/appliance-1.2.3.qcow2 \
     --wan-bridge br-mgmt --lan-bridge br-floor --seed seed.yaml          # add --uefi for OVMF
   virsh console appliance-reno                                          # the appliance console; Ctrl-] leaves
   ```

   Without the helper: `virt-install --import --osinfo debian12 --memory 8192 --vcpus 4`
   with the qcow2 on a virtio bus, the seed ISO as a CD-ROM, and one
   `--network bridge=…,model=virtio` per adapter (the first becomes `wan0`,
   the second `lan0`).

   **Hyper-V** (`New-ApplianceVM.ps1`, run in an elevated PowerShell on the
   host; creates a **Generation 2** VM with Secure Boot on the *Microsoft
   UEFI Certificate Authority* template, static memory, time synchronisation
   and automatic checkpoints off, WAN and LAN adapters with static MACs so
   the guest names them deterministically):

   ```powershell
   .\New-ApplianceVM.ps1 -Name appliance-reno -VhdxPath C:\VMs\appliance-1.2.3.vhdx `
       -WanSwitch Management -LanSwitch Floor -SeedIso C:\VMs\seed.iso -Start
   ```

   Without the helper: `New-VM -Generation 2` with the VHDX, `Set-VMFirmware
   -SecureBootTemplate MicrosoftUEFICertificateAuthority`, one adapter per
   switch added in WAN, LAN order (the appliance orders Hyper-V adapters by
   MAC address, which Hyper-V hands out in creation order), and
   `Disable-VMIntegrationService -Name "Time Synchronization"`. Generation 1
   VMs still work (BIOS loader); Generation 2 is preferred.

4. Power on. The seed is consumed on the first successful enrollment; the ISO
   can then be detached.

## Option C: Docker

The container is for single-network deployments on a Linux host: it needs host
networking (or a macvlan interface) to scan.

```sh
docker run -d --name scanner-appliance --restart unless-stopped \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --network host \
  --memory 8g \
  -v appliance-state:/var/lib/appliance \
  -v openvas-state:/var/lib/openvas \
  -e APPLIANCE_CODE=ABCD-EFGH-IJKL-MNOP-QRST \
  -e APPLIANCE_PROXY=user:pass@proxy.vendor.local:3128 \
  ghcr.io/tprm/scanner-appliance:VERSION
```

- `appliance-state` holds the appliance's private key and certificate. It
  **must persist** across restarts and upgrades; deleting it turns the
  container into a new, un-enrolled appliance that needs a fresh code.
- `openvas-state` holds the vulnerability-test feed and the engine's cache
  (about 1.5 GB). It is pre-populated from the image on first start; keeping
  it across restarts avoids a 10-minute cache rebuild. It can be deleted
  safely when upgrading to a new image version.
- `--memory 8g`: the engine's cache lives in memory; with less than 8 GB the
  container may be OOM-killed during a scan.
- `APPLIANCE_PROXY` is optional. Other supported variables:
  `APPLIANCE_CP_URL` (only if we gave you a non-default enrollment URL),
  `APPLIANCE_IP_MODE`, `APPLIANCE_IP_CIDR`, `APPLIANCE_GW`, `APPLIANCE_DNS`
  (not used with host networking) and `APPLIANCE_SPLIT`.
- Images are multi-arch (amd64, arm64) and signed:
  `cosign verify ghcr.io/tprm/scanner-appliance:VERSION --certificate-identity-regexp 'github.com/tprm/scanner-appliance' --certificate-oidc-issuer https://token.actions.githubusercontent.com`.
- Logs: `docker logs scanner-appliance`. Status: `docker exec scanner-appliance applianced status`.

## Option D: Windows host (daemon only)

For sites without a hypervisor slot we can supply `applianced-windows-amd64.exe`, a build of the appliance daemon for a Windows machine you already run. It enrolls, reports status and runs the **discovery and port-scan** part of a job; it does not carry the vulnerability-test engine, so inventory scans still need the VM or the container.

1. Unzip to `C:\Program Files\TPRM Appliance\` with `engine\naabu.exe` beside the executable, and install [Npcap](https://npcap.com) (host discovery needs it).
2. From an elevated PowerShell prompt:

   ```powershell
   $env:APPLIANCE_CODE = "ABCD-EFGH-IJKL-MNOP-QRST"
   $env:APPLIANCE_PROXY = "user:pass@proxy.vendor.local:3128"    # optional
   & 'C:\Program Files\TPRM Appliance\applianced.exe' run
   ```

   State lives under `%ProgramData%\TPRM Appliance`; `applianced.exe status` prints what the console Status screen shows.
3. To keep it running across logins, register it with a service wrapper (WinSW or NSSM) or a scheduled task that starts at boot as SYSTEM; the daemon has no built-in Windows service mode.

Outbound requirements are the same as for the VM: TCP 443 to the single FQDN, optionally through your proxy.

## Split-network deployments

For a warehouse floor with no internet at all, give the appliance two
adapters and set `appliance.split` to `true` (OVF property, `split: true` in
`seed.yaml`, or `APPLIANCE_SPLIT=1`): `wan0` carries only the outbound
HTTPS session to us, `lan0` sits in the scanned segment and never receives a
default route. All probes leave through `lan0`. If the floor has several
subnets behind a router on the `lan0` segment, tell us the ranges and the
router address and we push them to the appliance as static routes; nothing
needs to change on your side.

## Scope changes and the fragile-device list

The ranges we scan are the ones your owner attested. Adding or removing a
range is a scope request that your owner approves in the portal; nothing
changes until then, and every change is logged with its version. We ask the
owner to re-attest the scope quarterly.

Devices with printer, PLC or SNMP ports open are discovered but kept away
from vulnerability tests until you tell us they can take it; the portal
shows the list and who cleared what. Findings you dispute are reviewed as
false positives and, once codified, no longer reported for your site.

Before deploying, your team can read what the appliance does, with which
tools, and what it collects at `https://<our FQDN>/transparency` (no login).

## What updates itself

| What | How | Your involvement |
|------|-----|------------------|
| Vulnerability tests (the feed) and scan configurations | A signed bundle we publish daily; the appliance fetches only the changed files over the existing HTTPS session and reloads them without a reboot. It goes to our lab appliances first and to yours about two days later. A day's update was about 27 MB in our lab and applied in under a minute. | None. Status shows `Updating: bundle …` while it applies. |
| The appliance daemon | The same signed channel; the daemon verifies the new build, swaps it and confirms itself within ten minutes, or reverts on its own. | None. |
| Operating-system security patches | Debian security updates from a mirror we host behind the same FQDN; the appliance installs them unattended. | None, but a kernel update needs a reboot: the appliance reboots itself between 03:00 and 04:00 local time when it is idle. Tell us if that hour is a bad time for your site. |

The container image is updated by pulling a new tag (see Option C); the
bundle and OS mechanisms above apply to it as well.

## After power-on: the console

The VM console (screen, or serial port on KVM) shows a text menu:

```
1 Status   2 Network   3 Proxy   4 Enroll   5 Support bundle   6 Wipe   0 Back
```

- **Status** shows enrollment state, control-plane reachability, adapter
  roles and addresses, version, last heartbeat, engine readiness, the
  current scan job with its phase and progress, and how many result chunks
  are still waiting to upload.
- **Network** and **Proxy** let you change addressing and proxy settings if
  the seed values were wrong; Proxy has a *test connection* option.
- **Enroll** is where you type the code if none was supplied at deploy time.
- **Support bundle** uploads logs to us over the existing secure channel
  (never to removable media) when our support asks for it.
- **Wipe** destroys the appliance's key and state after you type its ID.

There is no shell and no login; the menu is the whole interface.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Status shows *control plane unreachable* | Egress to the FQDN on TCP 443 from `wan0`; proxy address and credentials; proxy SSL inspection exemption |
| Enrollment fails with *invalid code* | Code expired (14 days), already used, or mistyped three times — request a new one in the portal |
| No IP on `wan0` | DHCP on that port group, or set a static address via the Network screen |
| Adapters swapped (`wan0` in the floor segment) | Swap the port groups / virtual switches; on VMware and KVM the first adapter is always `wan0`, on Hyper-V the adapter with the lower MAC address |
| Hyper-V Generation 2 VM does not boot | Secure Boot template must be *Microsoft UEFI Certificate Authority* (not *Microsoft Windows*); the helper script sets it |
| Clock warning in Status | Outbound HTTPS to the FQDN is also used to set the time; check the proxy |
| Portal shows *stale* | The appliance has not sent a heartbeat for three intervals; check power state and egress |
| Status shows *engine not ready* for more than 15 minutes after boot | The engine is loading its vulnerability-test cache (normal for a few minutes on first boot). If it persists: the VM has less than 8 GB RAM, or the `/var/lib/openvas` volume (Docker) is not writable |
| Portal shows a job *rejected* with `window` | The appliance clock and the site timezone disagree with the window; check the clock warning in Status and the timezone we have on file |
| Portal shows a job *rejected* with `scope` | The target ranges are outside the ranges attested for the site; ask us to update the scope |
| Status shows *Results queued* for a long time | Results are waiting for egress to the control plane; check the WAN adapter and proxy |
| Status shows *Update error* | The last bundle or daemon update did not apply and was reverted; the appliance keeps scanning on the previous version. We see the same message and follow up |
| Status shows *Updating* for more than 30 minutes | The engine is loading a new feed (normal for up to 15 minutes); if it persists, the appliance reverts on its own and reports it |

## What a scan looks like

A job is created in the portal for one appliance with the target ranges,
exclusions, a scan window (for example Saturdays 22:00 local time for up to
six hours) and a mode:

| Mode | Phases | Typical use |
|------|--------|-------------|
| `discovery` | host discovery only (ICMP/ARP/TCP-SYN probes) | first scan of a new site; builds the exclusion list |
| `inventory` | discovery, port scan, then detection checks limited to service/product/OS detection and a small set of high-value families | weekly |
| `full` | discovery, port scan, then every unauthenticated remote check family; after our legal review of nmap, also a service/OS fingerprint pass on the open ports | monthly or on request |

The appliance only accepts a job that is signed by our control plane, is
inside the ranges attested for your site, is within its window, and is
under the agreed packet-rate and concurrency caps; anything else is
rejected and shown in the portal with the reason. The port scan covers the
top ~1000 ports plus warehouse and industrial ports; a scan of all 65535
ports can be agreed for specific hosts and is only accepted when it fits
the scan window at the agreed packet rate. Denial-of-service and
brute-force checks are never run. Devices that answer on printer or
industrial-controller ports (9100, 515, 631, 161, 502, 44818 by default)
are discovered and port-scanned but kept out of the vulnerability checks
until a human clears them. A job stops by itself at its maximum duration,
and our operators can halt a running scan at any time (the *stop_all*
control), which ends the probes within seconds.

UDP checks are not part of any mode and run only in a job that asks for
them. The detection engine cannot limit them to a port list: each UDP check
probes its own well-known port on every host in the job's ranges, including
hosts with no open TCP port. In our lab that was about 90 UDP ports and
1,300 datagrams per host, most of them SNMP requests that try about 170
common community names, and the scan took about 1.7 times as long. Devices
kept out of the vulnerability checks are kept out of these as well.

A full scan also checks the web servers it finds. It reads each server's
title, server header and technology, then runs HTTP checks rated medium or
higher against it. In our lab that was about 8,800 requests per web server,
about 580 of them from checks that try vendor default passwords.

Results (open ports, detected services, operating-system guess, findings
with their detection confidence) are encrypted on the appliance before they
are written to disk and uploaded over the same mutually authenticated
channel; the appliance itself cannot read its own result queue.

## What the appliance does not do

It does not accept inbound connections, does not run commands sent from the
control plane (the directive set is fixed and documented on the transparency
page), does not scan outside the CIDRs attested in the portal, does not scan
at all until a job is scheduled for it, does not use credentials against your
systems (unauthenticated checks only) and does not store credentials. The
full software inventory (SBOM) and open-source notices (including the
Greenbone OpenVAS components under GPL/AGPL and the community feed under
ODbL) are published with every release.
