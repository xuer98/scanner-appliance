package e2e

import (
	"time"

	"github.com/tprm/scanner-appliance/daemon/internal/heartbeat"
)

// The heartbeat interval floor is a package variable the loop reads on
// every tick; lower it once, before any test starts a loop, rather than in
// each test (a write there races with the previous test's loop goroutine
// under -race).
func init() { heartbeat.MinInterval = time.Second }
