// Package engine orchestrates a job's phases (PLAN §10): naabu discovery
// and port scan, then openvas over OSP with the port list pinned from
// naabu, and normalizes everything into the v1 result model (PLAN §12.1).
package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/bundle"
	"github.com/tprm/scanner-appliance/internal/scanconfig"
)

// ScanConfig is one openvas scan config (PLAN §10.4); the shipped set
// lives in internal/scanconfig and a signature bundle may override it.
type ScanConfig = scanconfig.Config

// ExcludedFamilies are never selectable in any config.
var ExcludedFamilies = scanconfig.ExcludedFamilies

// Configs are the shipped scan configs, by name.
var Configs = scanconfig.Defaults()

// ConfigFor returns the shipped config with policy exclusions applied.
func ConfigFor(name string) (ScanConfig, error) { return scanconfig.Lookup(name, nil) }

// configFor prefers configs from the installed bundle.
func (e *Engine) configFor(name string) (ScanConfig, error) {
	var overrides map[string]ScanConfig
	if e.BundleDir != "" {
		m, err := scanconfig.Load(filepath.Join(e.BundleDir, bundle.ConfigsDir))
		if err != nil {
			e.Log.Warn("bundled scan configs unusable; using shipped defaults", "err", err)
		} else {
			overrides = m
		}
	}
	return scanconfig.Lookup(name, overrides)
}

// fragilePorts: the site's list, else the bundle's default list, else the
// shipped default (PLAN §10.6).
func (r *run) fragilePorts() []int {
	if len(r.site.FragilePorts) > 0 {
		return r.site.FragilePorts
	}
	if r.e.BundleDir != "" {
		if b, err := os.ReadFile(filepath.Join(r.e.BundleDir, bundle.FragileFile)); err == nil {
			var ports []int
			if json.Unmarshal(b, &ports) == nil && len(ports) > 0 {
				return ports
			}
		}
	}
	return DefaultFragilePorts
}

// setConfKey sets "key = value" in a key/value config file (openvas.conf),
// replacing an existing line or appending one. A missing file is created.
func setConfKey(path, key, value string) error {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var out []string
	found := false
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		k, _, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == key {
			if found {
				continue
			}
			found = true
			line = key + " = " + value
		}
		if line != "" || len(out) > 0 {
			out = append(out, line)
		}
	}
	if !found {
		out = append(out, key+" = "+value)
	}
	text := strings.Join(out, "\n") + "\n"
	if string(b) == text {
		return nil
	}
	return os.WriteFile(path, []byte(text), 0o644)
}

// standardExtraPorts complement naabu's top-1000 list for warehouse/OT
// environments: remote access, printers, industrial protocols, databases,
// management planes.
var standardExtraPorts = []int{
	22, 23, 25, 53, 80, 88, 110, 111, 135, 137, 139, 143, 389, 443, 445, 464, 465, 587, 593, 636, 993, 995,
	1433, 1434, 1521, 1883, 2049, 2375, 2376, 3268, 3269, 3306, 3389, 4786, 5060, 5061, 5432, 5900, 5901,
	5985, 5986, 6379, 8000, 8008, 8080, 8081, 8443, 8883, 8888, 9090, 9100, 9200, 9443, 10000, 11211, 27017,
	102, 502, 515, 631, 1911, 2222, 4840, 20000, 44818, 47808, 623, 830, 161,
}

// portArgs turns a job port spec into naabu arguments.
func portArgs(spec string) ([]string, error) {
	ranges, err := v1.ParsePortSpec(spec)
	if err != nil {
		return nil, err
	}
	switch strings.TrimSpace(spec) {
	case "", v1.PortsStandard:
		return []string{"-top-ports", "1000", "-p", joinInts(standardExtraPorts)}, nil
	case v1.PortsFull:
		return []string{"-p", "-"}, nil
	}
	var parts []string
	for _, r := range ranges {
		if r.Lo == r.Hi {
			parts = append(parts, fmt.Sprint(r.Lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
		}
	}
	return []string{"-p", strings.Join(parts, ",")}, nil
}

func joinInts(in []int) string {
	s := make([]string, len(in))
	for i, v := range in {
		s[i] = fmt.Sprint(v)
	}
	return strings.Join(s, ",")
}

// openvasPortList renders the pinned port list: the union of naabu's open
// TCP ports plus the config's UDP set.
func openvasPortList(tcp map[int]bool, udp []int) string {
	var t []int
	for p := range tcp {
		t = append(t, p)
	}
	sort.Ints(t)
	var sb strings.Builder
	if len(t) > 0 {
		sb.WriteString("T:" + joinInts(t))
	}
	if len(udp) > 0 {
		if sb.Len() > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("U:" + joinInts(udp))
	}
	return sb.String()
}
