//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
)

// base is %ProgramData%\TPRM Appliance, the per-machine location a service
// account can write. state\, run\ and etc\ live below it.
func base() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "TPRM Appliance")
}

// StateDir holds the key, certificate, state.json, spool and NVT cache.
func StateDir() string { return filepath.Join(base(), "state") }

// RunDir holds status.json.
func RunDir() string { return filepath.Join(base(), "run") }

// ConfDir holds root-ca.pem (staging override).
func ConfDir() string { return filepath.Join(base(), "etc") }

// EngineDir is the engine\ directory beside applianced.exe; naabu.exe goes
// there (or point APPLIANCE_NAABU at it).
func EngineDir() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(base(), "engine")
	}
	return filepath.Join(filepath.Dir(exe), "engine")
}

// PowerOff shuts the machine down (wipe directive).
func PowerOff() error { return exec.Command("shutdown", "/s", "/t", "0").Run() }

// Reboot restarts the machine.
func Reboot() error { return exec.Command("shutdown", "/r", "/t", "0").Run() }

// PluginsDir: no openvas on Windows; bundled feeds stay under the state dir.
func PluginsDir() string { return "" }
