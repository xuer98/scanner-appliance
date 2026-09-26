//go:build !linux

package heartbeat

import (
	"errors"
	"time"
)

func diskFreeMB(string) int64 { return 0 }

func setClock(time.Time) error { return errors.New("clock stepping unsupported on this platform") }
