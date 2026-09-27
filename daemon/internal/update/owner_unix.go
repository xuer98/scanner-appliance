//go:build !windows

package update

import (
	"os"
	"syscall"
)

// dirOwner returns the uid/gid of a directory so installed feed files can
// be handed to the openvas user.
func dirOwner(path string) (uid, gid int, ok bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
