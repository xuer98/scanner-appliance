//go:build !linux && !windows

package engine

import "os"

// rawSocketsAllowed: root only outside Linux (no capability sets).
func rawSocketsAllowed() bool { return os.Geteuid() == 0 }
