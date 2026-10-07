//go:build linux

package engine

import (
	"encoding/binary"
	"syscall"
)

// readNeighbors dumps the kernel's neighbor table for both address
// families. Reading it needs no privilege.
func readNeighbors() ([]neighbor, error) {
	b, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return parseNeighbors(b, binary.NativeEndian)
}
