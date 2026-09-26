//go:build linux

package heartbeat

import (
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
