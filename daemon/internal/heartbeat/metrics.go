package heartbeat

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/tprm/scanner-appliance/daemon/internal/platform"
)

// EngineDir holds the scan-engine binaries whose hashes are reported
// (/opt/engine on the image; engine\ beside the executable on Windows).
var EngineDir = platform.EngineDir()

// EngineTools are the optional helpers the daemon looks for, in the order
// the heartbeat lists them (Phase 5: nmap only exists on builds made after
// the legal sign-off).
var EngineTools = []string{"naabu", "httpx", "nuclei", "nmap"}

// FindTool looks for an engine helper in EngineDir, then $PATH; "" when
// absent.
func FindTool(name string) string {
	p := filepath.Join(EngineDir, platform.ExeName(name))
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// availableTools lists the helpers FindTool resolves, plus any the caller
// configured explicitly (an APPLIANCE_NAABU path outside EngineDir).
func availableTools(explicit map[string]string) []string {
	var out []string
	for _, n := range EngineTools {
		if p := explicit[n]; p != "" {
			if _, err := os.Stat(p); err == nil {
				out = append(out, n)
				continue
			}
		}
		if FindTool(n) != "" {
			out = append(out, n)
		}
	}
	return out
}

// Host metrics (uptimeSeconds, load1, diskFreeMB, memFreeMB, setClock) live
// in sys_linux.go, sys_windows.go and sys_other.go.

// binaryHashes hashes applianced itself and everything in EngineDir.
func binaryHashes() map[string]string {
	out := map[string]string{}
	if exe, err := os.Executable(); err == nil {
		if h, err := fileSHA256(exe); err == nil {
			out["applianced"] = h
		}
	}
	entries, err := os.ReadDir(EngineDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if h, err := fileSHA256(filepath.Join(EngineDir, e.Name())); err == nil {
			out[e.Name()] = h
		}
	}
	return out
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
