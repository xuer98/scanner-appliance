//go:build windows

package fingerprint

import (
	"strings"
	"syscall"
	"unsafe"
)

// machineID is HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid, the stable
// per-install identifier Windows itself uses.
func machineID() string {
	sub, err := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Cryptography`)
	if err != nil {
		return ""
	}
	var h syscall.Handle
	// KEY_WOW64_64KEY: always read the 64-bit hive, whatever the build's width.
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, sub, 0, syscall.KEY_READ|syscall.KEY_WOW64_64KEY, &h); err != nil {
		return ""
	}
	defer syscall.RegCloseKey(h)
	name, _ := syscall.UTF16PtrFromString("MachineGuid")
	var typ uint32
	var buf [128]uint16
	n := uint32(len(buf) * 2)
	if err := syscall.RegQueryValueEx(h, name, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n); err != nil || typ != syscall.REG_SZ {
		return ""
	}
	return strings.TrimSpace(syscall.UTF16ToString(buf[:n/2]))
}
