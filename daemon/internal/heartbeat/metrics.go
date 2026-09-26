package heartbeat

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// EngineDir holds the scan-engine binaries whose hashes are reported.
var EngineDir = "/opt/engine"

func uptimeSeconds() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return int64(v)
}

func load1() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

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
