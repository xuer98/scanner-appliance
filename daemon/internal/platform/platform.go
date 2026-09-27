// Package platform isolates the few things applianced does differently per
// operating system.
//
// The product is the Linux appliance (Packer image and container, PLAN §4).
// Windows is a supported build target for the daemon itself, so a Windows
// host can enroll, heartbeat, take directives and run naabu discovery /
// portscan jobs. openvas + ospd-openvas, the tty1 console, systemd-networkd,
// htpdate and the OVF / volume seed sources stay Linux-only and report
// "not available" elsewhere instead of failing the daemon.
package platform

import "runtime"

// ExeName appends the platform's executable suffix (".exe" on Windows).
func ExeName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

// IsWindows is a readability helper for the callers that only need a test.
func IsWindows() bool { return runtime.GOOS == "windows" }
