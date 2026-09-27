//go:build windows

package heartbeat

import (
	"errors"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpaceExW  = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

// diskFreeMB reports the space available to the caller on path's volume.
func diskFreeMB(path string) int64 {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	var avail, total, free uint64
	r, _, _ := procGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&avail)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free)))
	if r == 0 {
		return 0
	}
	return int64(avail / (1024 * 1024))
}

// setClock is left to the Windows Time service.
func setClock(time.Time) error { return errors.New("clock stepping unsupported on windows") }

func uptimeSeconds() int64 {
	ms, _, _ := procGetTickCount64.Call()
	return int64(ms / 1000)
}

// load1: Windows has no load average; 0 means "not reported" (PLAN §9.2).
func load1() float64 { return 0 }

// rebootRequired: Windows Update reboots are the host's business.
func rebootRequired() bool { return false }

// memoryStatusEx mirrors MEMORYSTATUSEX (64 bytes).
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func memFreeMB() int64 {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r == 0 {
		return 0
	}
	return int64(ms.AvailPhys / (1024 * 1024))
}
