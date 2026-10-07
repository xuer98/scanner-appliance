//go:build !linux

package engine

// readNeighbors: the neighbor table is only read on Linux, the one platform
// the scan engines run on.
func readNeighbors() ([]neighbor, error) { return nil, nil }
