// Package fingerprint describes the machine for the control plane (PLAN §7.2).
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// Collect gathers the fingerprint. Every field is best-effort.
func Collect() v1.Fingerprint {
	fp := v1.Fingerprint{Hypervisor: Hypervisor(), CPU: cpuModel()}
	if id := machineID(); id != "" {
		h := sha256.Sum256([]byte("tprm-machine-id:" + id))
		fp.MachineIDHash = hex.EncodeToString(h[:])
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) == 0 || virtualName(i.Name) {
				continue
			}
			fp.MACs = append(fp.MACs, i.HardwareAddr.String())
		}
	}
	return fp
}

// Hypervisor guesses the platform from DMI; "container" if inside one.
func Hypervisor() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "container"
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil && (strings.Contains(string(b), "docker") || strings.Contains(string(b), "containerd") || strings.Contains(string(b), "kubepods")) {
		return "container"
	}
	vendor := strings.ToLower(readTrim("/sys/class/dmi/id/sys_vendor"))
	product := strings.ToLower(readTrim("/sys/class/dmi/id/product_name"))
	switch {
	case strings.Contains(vendor, "vmware"):
		return "vmware"
	case strings.Contains(vendor, "microsoft") || strings.Contains(product, "virtual machine"):
		return "hyperv"
	case strings.Contains(vendor, "qemu") || strings.Contains(product, "kvm") || strings.Contains(product, "qemu"):
		return "kvm"
	case strings.Contains(vendor, "xen"):
		return "xen"
	case strings.Contains(vendor, "innotek") || strings.Contains(product, "virtualbox"):
		return "virtualbox"
	case vendor == "" && product == "":
		return "unknown"
	}
	return "physical"
}

func cpuModel() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "model name") {
			if i := strings.Index(line, ":"); i > 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func virtualName(n string) bool {
	for _, p := range []string{"docker", "veth", "br-", "virbr", "vmnet", "utun", "awdl", "llw", "bridge", "tap", "tun"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}
