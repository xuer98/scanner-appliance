//go:build !windows

package platform

import "os/exec"

// Layout of the Debian image (packer/scripts/harden.sh, install-openvas.sh);
// the container and dev boxes use the same paths.

// StateDir holds the key, certificate, state.json, spool and NVT cache.
func StateDir() string { return "/var/lib/appliance" }

// RunDir holds status.json and the seed mount point.
func RunDir() string { return "/run/appliance" }

// ConfDir holds root-ca.pem (staging override) and the htpdate hint.
func ConfDir() string { return "/etc/appliance" }

// EngineDir holds the scan-engine binaries (naabu) whose hashes the
// heartbeat reports.
func EngineDir() string { return "/opt/engine" }

// PowerOff halts the machine (wipe directive, console "Power off").
func PowerOff() error { return exec.Command("systemctl", "poweroff").Run() }

// Reboot restarts the machine (maintenance-slot reboot after OS updates).
func Reboot() error { return exec.Command("systemctl", "reboot").Run() }

// PluginsDir is the openvas VT feed directory that bundles update.
func PluginsDir() string { return "/var/lib/openvas/plugins" }
