// Scanner appliance base image: Debian 12 netinst + preseed -> hardened qcow2.
//
// Build (needs /dev/kvm for a sane build time; tcg works but is ~10x slower):
//
//   packer init  packer/
//   packer build -var version=1.2.3 -var iso_checksum=sha256:<hash> packer/
//
// The qcow2 is then converted with packer/build-ova.sh and packer/build-vhdx.sh.
// The daemon binary is expected at bin/applianced-linux-amd64 (ci/build.sh
// produces it) and the optional scan-engine binaries under bin/engine/.
//
// The detection engine (gvm-libs + openvas-scanner + ospd-openvas + redis) is
// built from the pinned Greenbone tags below (install-openvas.sh) and the VT
// feed snapshot passed as -var feed_tarball=<path> is shipped in the image
// with a pre-warmed redis cache (seed-feed.sh). Without feed_tarball the
// image has no VTs (dev builds only).

packer {
  required_version = ">= 1.9.0"
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.0"
    }
  }
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "version" {
  type        = string
  default     = "dev"
  description = "Appliance version; becomes the qcow2 file name and is passed to the provisioners."
}

variable "iso_url" {
  type = string
  # Debian keeps only the *latest* 12.x point release under release/current/
  # while 12 is stable; when 12 becomes oldstable the images move to
  # https://cdimage.debian.org/cdimage/archive/12.<x>.0/amd64/iso-cd/ . Adjust
  # the file name to the point release listed in that directory.
  default     = "https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/debian-12.12.0-amd64-netinst.iso"
  description = "Debian 12 netinst ISO URL."
}

variable "iso_checksum" {
  type = string
  # Fetch the pinned value with:
  #   curl -fsSL https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/SHA256SUMS \
  #     | grep netinst.iso | awk '{print "sha256:"$1}'
  # and pass it as -var iso_checksum=sha256:<hash>. The default below asks
  # Packer to resolve the checksum from the published SHA256SUMS file; pin it
  # explicitly for release builds so the build is reproducible.
  default     = "file:https://cdimage.debian.org/cdimage/release/current/amd64/iso-cd/SHA256SUMS"
  description = "Checksum of the ISO (sha256:<hex>, or file:<url> to look it up)."
}

variable "accelerator" {
  type        = string
  default     = "kvm"
  description = "QEMU accelerator: kvm (needs /dev/kvm) or tcg (software emulation, slow)."
  validation {
    condition     = contains(["kvm", "tcg", "hvf"], var.accelerator)
    error_message = "The accelerator must be one of kvm, tcg or hvf."
  }
}

variable "headless" {
  type    = bool
  default = true
}

variable "output_dir" {
  type        = string
  default     = ""
  description = "Where the qcow2 is written. Defaults to packer/output-<version>/ (must not already exist)."
}

variable "daemon_binary" {
  type        = string
  default     = ""
  description = "Path to the static applianced Linux/amd64 binary. Defaults to <repo>/bin/applianced-linux-amd64."
}

variable "engine_dir" {
  type        = string
  default     = ""
  description = "Optional directory of scan-engine binaries copied to /opt/engine. Defaults to <repo>/bin/engine (created empty if missing)."
}

variable "ssh_password" {
  type        = string
  default     = "packer"
  sensitive   = true
  description = "Password of the temporary build user created by the preseed. The user is deleted by cleanup.sh."
}

variable "grub_password" {
  type        = string
  default     = ""
  sensitive   = true
  description = "GRUB superuser password. Empty = random, generated inside the guest and discarded."
}

# Appliance minimum (PLAN 4.6): 4 vCPU, 8 GB RAM, 60 GB disk.
variable "disk_size" {
  type    = string
  default = "60G"
}

variable "cpus" {
  type    = number
  default = 4
}

variable "memory" {
  type    = number
  default = 8192
}

# ---------------------------------------------------------------------------
# Detection engine (packer/scripts/install-openvas.sh, seed-feed.sh)
# ---------------------------------------------------------------------------

variable "feed_tarball" {
  type        = string
  default     = ""
  description = "VT feed tarball (tree containing plugin_feed_info.inc) shipped in the image. CI fetches it from the control-plane mirror. Empty = no VTs."
}

variable "feed_sha256" {
  type        = string
  default     = ""
  description = "Optional sha256 of feed_tarball."
}

# Greenbone release tags and tarball hashes; the defaults live in
# install-openvas.sh (empty here = use the script's pins). Override for a
# bump; see the notes in that script about verification.
variable "gvm_libs_tag" {
  type    = string
  default = ""
}

variable "openvas_scanner_tag" {
  type    = string
  default = ""
}

variable "ospd_openvas_tag" {
  type    = string
  default = ""
}

variable "openvas_smb_tag" {
  type        = string
  default     = ""
  description = "Optional openvas-smb tag (authenticated SMB checks); empty = not built."
}

variable "gvm_libs_sha256" {
  type    = string
  default = ""
}

variable "openvas_scanner_sha256" {
  type    = string
  default = ""
}

variable "ospd_openvas_sha256" {
  type    = string
  default = ""
}

variable "openvas_require_checksums" {
  type        = bool
  default     = false
  description = "Fail the build when a Greenbone tarball has no pinned sha256."
}

variable "openvas_with_mqtt" {
  type        = bool
  default     = false
  description = "Install mosquitto on 127.0.0.1 for openvas. Only if the pinned release refuses to run without a broker."
}

variable "with_nmap" {
  type        = bool
  default     = false
  description = "Install Debian's nmap for the Phase 5 fingerprint pass (NPSL, PLAN 21). Only for images built after the legal sign-off is recorded on the control plane."
}

locals {
  output_dir    = var.output_dir != "" ? var.output_dir : "${path.root}/output-${var.version}"
  daemon_binary = var.daemon_binary != "" ? var.daemon_binary : "${path.root}/../bin/applianced-linux-amd64"
  engine_dir    = var.engine_dir != "" ? var.engine_dir : "${path.root}/../bin/engine"
  # The file provisioner has no "if"; a shell-local step stages either a
  # symlink to the feed tarball or an empty file here (bin/ is gitignored).
  feed_stage = "${path.root}/../bin/feed.tar"
  feed_abs   = var.feed_tarball != "" ? abspath(var.feed_tarball) : ""
}

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

source "qemu" "appliance" {
  iso_url      = var.iso_url
  iso_checksum = var.iso_checksum

  output_directory = local.output_dir
  vm_name          = "appliance-${var.version}.qcow2"
  format           = "qcow2"

  accelerator = var.accelerator
  headless    = var.headless
  cpus        = var.cpus
  memory      = var.memory
  disk_size   = var.disk_size

  # virtio disk/NIC: the installer sees /dev/vda and the preseed targets it.
  disk_interface     = "virtio"
  net_device         = "virtio-net"
  disk_discard       = "unmap" # lets fstrim in cleanup.sh shrink the qcow2
  disk_detect_zeroes = "unmap"
  disk_compression   = true

  # The preseed is served from packer/http by Packer's built-in HTTP server.
  http_directory = "${path.root}/http"

  boot_wait = "5s"
  boot_command = [
    "<esc><wait>",
    "auto priority=critical ",
    "preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
    "debian-installer/locale=en_US ",
    "keyboard-configuration/xkb-keymap=us ",
    "netcfg/get_hostname=appliance ",
    "netcfg/get_domain=localdomain ",
    "fb=false ",
    "<enter>",
  ]

  # Temporary build user created by the preseed with passwordless sudo.
  communicator           = "ssh"
  ssh_username           = "packer"
  ssh_password           = var.ssh_password
  ssh_timeout            = "45m"
  ssh_handshake_attempts = 100

  # cleanup.sh deletes the packer user and removes sshd as its last act, so
  # nothing that needs sudo can run afterwards. It schedules the power-off
  # itself (transient systemd timer); Packer only has to wait for the VM to go
  # away. Using a non-empty shutdown_command keeps Packer in "graceful" mode
  # (wait for QEMU to exit) instead of killing the process.
  shutdown_command = "true"
  shutdown_timeout = "15m"

  vnc_bind_address = "127.0.0.1"
}

# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------

build {
  name    = "appliance"
  sources = ["source.qemu.appliance"]

  # Make sure the (optional) engine directory exists so the file provisioner
  # below never fails; install-daemon.sh copes with an empty directory.
  provisioner "shell-local" {
    inline = [
      "mkdir -p '${local.engine_dir}' '${dirname(local.feed_stage)}'",
      "rm -f '${local.feed_stage}'",
      "if [ -n '${local.feed_abs}' ]; then test -s '${local.feed_abs}' || { echo 'feed_tarball not found: ${local.feed_abs}' >&2; exit 1; }; ln -s '${local.feed_abs}' '${local.feed_stage}'; else : > '${local.feed_stage}'; echo 'WARNING: no feed_tarball; the image will ship without VTs' >&2; fi",
    ]
  }

  provisioner "file" {
    source      = local.daemon_binary
    destination = "/tmp/applianced"
    generated   = true
  }

  provisioner "file" {
    source      = local.engine_dir
    destination = "/tmp/engine"
    generated   = true
  }

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E bash '{{ .Path }}'"
    environment_vars = [
      "APPLIANCE_VERSION=${var.version}",
      "GRUB_PASSWORD=${var.grub_password}",
      "WITH_NMAP=${var.with_nmap ? "1" : "0"}",
      "DEBIAN_FRONTEND=noninteractive",
    ]
    scripts = [
      "${path.root}/scripts/harden.sh",
      "${path.root}/scripts/install-daemon.sh",
    ]
  }

  # Detection engine: build from the pinned tags, then seed the VT feed and
  # pre-warm the redis cache. cleanup.sh purges the toolchain afterwards.
  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E bash '{{ .Path }}'"
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
      "GVM_LIBS_TAG=${var.gvm_libs_tag}",
      "OPENVAS_SCANNER_TAG=${var.openvas_scanner_tag}",
      "OSPD_OPENVAS_TAG=${var.ospd_openvas_tag}",
      "OPENVAS_SMB_TAG=${var.openvas_smb_tag}",
      "GVM_LIBS_SHA256=${var.gvm_libs_sha256}",
      "OPENVAS_SCANNER_SHA256=${var.openvas_scanner_sha256}",
      "OSPD_OPENVAS_SHA256=${var.ospd_openvas_sha256}",
      "OPENVAS_REQUIRE_CHECKSUMS=${var.openvas_require_checksums ? "1" : "0"}",
      "OPENVAS_WITH_MQTT=${var.openvas_with_mqtt ? "1" : "0"}",
    ]
    script = "${path.root}/scripts/install-openvas.sh"
  }

  # /var/tmp: the feed is ~1 GB and /var is the large LV. Removed by cleanup.sh.
  provisioner "file" {
    source      = local.feed_stage
    destination = "/var/tmp/feed.tar"
    generated   = true
  }

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E bash '{{ .Path }}'"
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
      "FEED_TARBALL=/var/tmp/feed.tar",
      "FEED_SHA256=${var.feed_sha256}",
    ]
    script = "${path.root}/scripts/seed-feed.sh"
  }

  provisioner "shell" {
    execute_command  = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E bash '{{ .Path }}'"
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    script           = "${path.root}/scripts/cleanup.sh"
    # cleanup.sh removes the SSH server; tolerate the session dropping.
    expect_disconnect = true
  }

  post-processor "checksum" {
    checksum_types = ["sha256"]
    output         = "${local.output_dir}/appliance-${var.version}.qcow2.sha256"
  }
}
