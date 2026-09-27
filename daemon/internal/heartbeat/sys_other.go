//go:build !linux && !windows

package heartbeat

import (
	"errors"
	"time"
)

// Development hosts (macOS, BSD): the heartbeat carries zeros for the host
// metrics, which the control plane treats as "not reported".

func diskFreeMB(string) int64 { return 0 }

func setClock(time.Time) error { return errors.New("clock stepping unsupported on this platform") }

func uptimeSeconds() int64 { return 0 }

func load1() float64 { return 0 }

func memFreeMB() int64 { return 0 }

func rebootRequired() bool { return false }
