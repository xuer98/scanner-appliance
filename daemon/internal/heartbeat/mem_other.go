//go:build !linux

package heartbeat

func memFreeMB() int64 { return 0 }
