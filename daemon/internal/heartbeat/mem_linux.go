//go:build linux

package heartbeat

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func memFreeMB() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "MemAvailable:") {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb / 1024
			}
		}
	}
	return 0
}
