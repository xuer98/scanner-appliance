package engine

import (
	"os"
	"strconv"
	"strings"
)

// rawSocketsAllowed reports whether this process may open raw sockets:
// root, or CAP_NET_RAW in the effective set (applianced.service grants it
// through AmbientCapabilities; the container runs with --cap-add NET_RAW).
func rawSocketsAllowed() bool {
	if os.Geteuid() == 0 {
		return true
	}
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return false
		}
		const capNetRaw = 13
		return v&(1<<capNetRaw) != 0
	}
	return false
}
