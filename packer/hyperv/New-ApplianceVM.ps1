<#
.SYNOPSIS
  Creates a Hyper-V Generation 2 virtual machine for the scanner appliance from the VHDX.

.DESCRIPTION
  Sizes the VM to the appliance minimum (4 vCPU, 8 GB static memory), attaches the WAN
  adapter first and the LAN adapter second with static MAC addresses (the appliance names
  Hyper-V adapters wan0/lan0 in MAC order), enables Secure Boot with the "Microsoft UEFI
  Certificate Authority" template (the image boots through Debian's Microsoft-signed shim),
  disables time synchronisation (the appliance sets its own clock over HTTPS) and automatic
  checkpoints, boots from the disk first and optionally attaches the APPLIANCE seed ISO.

  Generation 1 is not needed any more: the image carries both a BIOS and a UEFI loader.

.PARAMETER Name
  VM name.
.PARAMETER VhdxPath
  Path of appliance-<version>.vhdx (copy it per VM; the VM writes to it).
.PARAMETER WanSwitch
  Virtual switch with egress to the control plane (becomes wan0).
.PARAMETER LanSwitch
  Virtual switch of the segment to scan (becomes lan0). Omit for a single-network deployment.
.PARAMETER SeedIso
  Optional ISO labelled APPLIANCE holding seed.yaml (docs/DEPLOY.md, Option B).
.PARAMETER WanMac / LanMac
  Static MACs as 12 hex digits. Default: locally administered addresses derived from the VM
  name, WAN < LAN, so the guest naming is stable across reboots and host moves.
.PARAMETER NoSecureBoot
  Leave Secure Boot off (older hosts without the Microsoft UEFI CA template).
.PARAMETER Start
  Start the VM once created.

.EXAMPLE
  .\New-ApplianceVM.ps1 -Name appliance-reno -VhdxPath C:\VMs\appliance-1.2.3.vhdx `
      -WanSwitch Management -LanSwitch Floor -SeedIso C:\VMs\seed.iso -Start
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory = $true)][string]$Name,
  [Parameter(Mandatory = $true)][string]$VhdxPath,
  [Parameter(Mandatory = $true)][string]$WanSwitch,
  [string]$LanSwitch = '',
  [string]$SeedIso = '',
  [string]$VmPath = '',
  [int]$Cpus = 4,
  [long]$MemoryBytes = 8GB,
  [string]$WanMac = '',
  [string]$LanMac = '',
  [switch]$NoSecureBoot,
  [switch]$Start
)

$ErrorActionPreference = 'Stop'

function New-ApplianceMac {
  param([string]$Seed, [int]$Index)
  # Locally administered unicast address (first octet 0x0A), derived from the VM name;
  # the last octet is the adapter index so WAN sorts before LAN inside the guest.
  $md5 = [System.Security.Cryptography.MD5]::Create()
  $bytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Seed))
  return ('0A{0:X2}{1:X2}{2:X2}{3:X2}{4:X2}' -f $bytes[0], $bytes[1], $bytes[2], $bytes[3], $Index)
}

if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
  throw 'The Hyper-V PowerShell module is not available (Install-WindowsFeature Hyper-V-PowerShell).'
}
if (-not (Test-Path -LiteralPath $VhdxPath)) { throw "VHDX not found: $VhdxPath" }
if ($SeedIso -and -not (Test-Path -LiteralPath $SeedIso)) { throw "seed ISO not found: $SeedIso" }
if ($MemoryBytes -lt 8GB) { Write-Warning 'The appliance minimum is 8 GB: the engine keeps its vulnerability-test cache in memory.' }
if (-not $WanMac) { $WanMac = New-ApplianceMac -Seed $Name -Index 1 }
if (-not $LanMac) { $LanMac = New-ApplianceMac -Seed $Name -Index 2 }
foreach ($m in @($WanMac, $LanMac)) {
  if ($m -notmatch '^[0-9A-Fa-f]{12}$') { throw "MAC must be 12 hex digits: $m" }
}

if ($PSCmdlet.ShouldProcess($Name, 'Create Generation 2 VM')) {
  $vmArgs = @{ Name = $Name; Generation = 2; MemoryStartupBytes = $MemoryBytes; VHDPath = $VhdxPath; SwitchName = $WanSwitch }
  if ($VmPath) { $vmArgs.Path = $VmPath }
  $vm = New-VM @vmArgs

  Set-VM -VM $vm -ProcessorCount $Cpus -StaticMemory -AutomaticCheckpointsEnabled $false `
    -CheckpointType Disabled -AutomaticStartAction Start -AutomaticStopAction ShutDown

  # WAN first (created with the VM), LAN second.
  $wan = Get-VMNetworkAdapter -VM $vm | Select-Object -First 1
  Rename-VMNetworkAdapter -VMNetworkAdapter $wan -NewName 'WAN'
  Set-VMNetworkAdapter -VMNetworkAdapter $wan -StaticMacAddress $WanMac
  if ($LanSwitch) {
    Add-VMNetworkAdapter -VM $vm -SwitchName $LanSwitch -Name 'LAN' -StaticMacAddress $LanMac | Out-Null
  }

  if ($NoSecureBoot) {
    Set-VMFirmware -VM $vm -EnableSecureBoot Off
  } else {
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
  }
  # The appliance sets its clock over HTTPS (htpdate); host time sync fights it.
  Disable-VMIntegrationService -VM $vm -Name 'Time Synchronization'

  if ($SeedIso) { Add-VMDvdDrive -VM $vm -Path $SeedIso | Out-Null }
  $hdd = Get-VMHardDiskDrive -VM $vm | Select-Object -First 1
  Set-VMFirmware -VM $vm -FirstBootDevice $hdd

  Write-Host ("Created {0}: {1} vCPU, {2} GB, WAN {3} ({4}){5}, Secure Boot {6}" -f $Name, $Cpus, [int]($MemoryBytes / 1GB), $WanSwitch, $WanMac,
    $(if ($LanSwitch) { ", LAN $LanSwitch ($LanMac)" } else { '' }), $(if ($NoSecureBoot) { 'off' } else { 'on (Microsoft UEFI CA)' }))
  if ($Start) {
    Start-VM -VM $vm
    Write-Host 'Started. Open the VM console: the status screen reports enrollment; the seed ISO can be detached once the appliance is enrolled.'
  }
}
