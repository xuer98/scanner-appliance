# Deploying the Scanner Appliance

This guide is for the team that runs the hypervisor or Docker host where the
appliance will live. The appliance is a small Debian-based virtual machine (or
a container) that scans the network segments you agreed with us and reports
results to our control plane over an outbound, mutually authenticated TLS
connection. It has no SSH, no local accounts, and no inbound ports.

The vulnerability-detection engine (Greenbone OpenVAS scanner with a
snapshot of the community vulnerability-test feed) is embedded in the image.
It sits idle after deployment: no scan runs until a job is scheduled for this
appliance in the portal, within the agreed scope and scan window. The status
screen and our portal show whether the engine is healthy (*engine ready*).

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
first boot. Alternatively, type the code on the console.

1. Create `seed.yaml`:

   ```yaml
   code: "ABCD-EFGH-IJKL-MNOP-QRST"
   proxy: "user:pass@proxy.vendor.local:3128"   # optional
   network:                                     # optional; default is DHCP on both
     wan0: { mode: static, cidr: 10.20.0.50/24, gw: 10.20.0.1, dns: [10.20.0.10] }
     lan0: { mode: dhcp }
   split: true                                  # WAN and LAN on different networks
   ```

2. Build the ISO (the volume label **must** be `APPLIANCE`):

   ```sh
   genisoimage -o seed.iso -V APPLIANCE -r -J seed.yaml
   # Windows (Hyper-V host): use oscdimg from the Windows ADK
   #   oscdimg -lAPPLIANCE -n seed\ seed.iso
   ```

3. Create the VM and attach the ISO.

   **KVM / libvirt** (BIOS boot, virtio devices, two NICs, serial console
   available with `virsh console`):

   ```sh
   virt-install --name appliance --memory 8192 --vcpus 4 \
     --disk path=/var/lib/libvirt/images/appliance-1.2.3.qcow2,format=qcow2,bus=virtio \
     --disk path=/var/lib/libvirt/images/seed.iso,device=cdrom \
     --network bridge=br-mgmt,model=virtio \
     --network bridge=br-floor,model=virtio \
     --os-variant debian12 --import --graphics none --noautoconsole
   ```

   The first `--network` becomes `wan0`, the second `lan0`.

   **Hyper-V** (Generation 1, two network adapters):

   ```powershell
   New-VM -Name appliance -Generation 1 -MemoryStartupBytes 8GB `
     -VHDPath C:\VMs\appliance-1.2.3.vhdx -SwitchName Management
   Set-VMProcessor appliance -Count 4
   Add-VMNetworkAdapter -VMName appliance -SwitchName Floor
   Set-VMDvdDrive -VMName appliance -Path C:\VMs\seed.iso
   Start-VM appliance
   ```

   On Hyper-V the adapter order is not tied to a PCI bus; check the Status
   screen after boot to confirm which adapter became `wan0` and swap the
   virtual switches if needed. Disable Hyper-V time synchronisation for the VM
   (Integration Services).

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

## After power-on: the console

The VM console (screen, or serial port on KVM) shows a text menu:

```
1 Status   2 Network   3 Proxy   4 Enroll   5 Support bundle   6 Wipe   0 Back
```

- **Status** shows enrollment state, control-plane reachability, adapter
  roles and addresses, version and last heartbeat.
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
| Adapters swapped (`wan0` in the floor segment) | Swap the port groups / virtual switches; on VMware the first adapter is always `wan0` |
| Clock warning in Status | Outbound HTTPS to the FQDN is also used to set the time; check the proxy |
| Portal shows *stale* | The appliance has not sent a heartbeat for three intervals; check power state and egress |
| Status shows *engine not ready* for more than 15 minutes after boot | The engine is loading its vulnerability-test cache (normal for a few minutes on first boot). If it persists: the VM has less than 8 GB RAM, or the `/var/lib/openvas` volume (Docker) is not writable |

## What the appliance does not do

It does not accept inbound connections, does not run commands sent from the
control plane (the directive set is fixed and documented on the transparency
page), does not scan outside the CIDRs attested in the portal, does not scan
at all until a job is scheduled for it, does not use credentials against your
systems (unauthenticated checks only) and does not store credentials. The
full software inventory (SBOM) and open-source notices (including the
Greenbone OpenVAS components under GPL/AGPL and the community feed under
ODbL) are published with every release.
