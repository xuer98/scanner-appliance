//go:build !windows

package fingerprint

import (
	"os"
	"strings"
)

// machineID is systemd's /etc/machine-id (also present in the container base).
func machineID() string {
	b, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
