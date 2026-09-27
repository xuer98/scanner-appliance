//go:build linux

package heartbeat

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func diskFreeMB(path string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize) / (1024 * 1024)
}

// setClock steps the system clock. Needs CAP_SYS_TIME (root on the appliance).
func setClock(t time.Time) error {
	tv := syscall.NsecToTimeval(t.UnixNano())
	return syscall.Settimeofday(&tv)
}

func uptimeSeconds() int64 {
	v, _ := strconv.ParseFloat(firstField("/proc/uptime"), 64)
	return int64(v)
}

func load1() float64 {
	v, _ := strconv.ParseFloat(firstField("/proc/loadavg"), 64)
	return v
}

func firstField(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// rebootRequired is set by Debian's unattended-upgrades / kernel packages.
func rebootRequired() bool {
	_, err := os.Stat("/var/run/reboot-required")
	return err == nil
}

func memFreeMB() int64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			if fields := strings.Fields(line); len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb / 1024
			}
		}
	}
	return 0
}
