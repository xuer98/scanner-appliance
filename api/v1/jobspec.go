package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// KnownModes / KnownModules are the closed sets accepted on both sides.
var (
	KnownModes   = map[string]bool{ModeDiscovery: true, ModeInventory: true, ModeFull: true}
	KnownModules = map[string]bool{ModuleDiscovery: true, ModulePortscan: true, ModuleOpenVAS: true, ModuleWeb: true}
)

// DefaultsFor fills a spec's mode-dependent fields (PLAN §10.5, §11).
func (j *JobSpec) DefaultsFor(mode string) {
	j.Mode = mode
	switch mode {
	case ModeDiscovery:
		if len(j.Modules) == 0 {
			j.Modules = []string{ModuleDiscovery}
		}
	case ModeInventory:
		if len(j.Modules) == 0 {
			j.Modules = []string{ModuleDiscovery, ModulePortscan, ModuleOpenVAS}
		}
		if j.OpenVAS == nil {
			j.OpenVAS = &OpenVASParams{Config: "inventory", MaxHosts: 4, MaxChecks: 4, FragilePortsExclude: true}
		}
	case ModeFull:
		if len(j.Modules) == 0 {
			j.Modules = []string{ModuleDiscovery, ModulePortscan, ModuleOpenVAS}
		}
		if j.OpenVAS == nil {
			j.OpenVAS = &OpenVASParams{Config: "full", MaxHosts: 4, MaxChecks: 4, FragilePortsExclude: true}
		}
	}
	if j.Ports == "" {
		j.Ports = PortsStandard
	}
	if j.Rate.PPS == 0 {
		j.Rate.PPS = 300
	}
	if j.Rate.PerHostParallel == 0 {
		j.Rate.PerHostParallel = 2
	}
	if j.Window != nil && j.Window.MaxDurationS == 0 {
		j.Window.MaxDurationS = 6 * 3600
	}
	if j.Excludes == nil {
		j.Excludes = []string{}
	}
}

// HasModule reports whether the module is enabled.
func (j *JobSpec) HasModule(m string) bool {
	for _, x := range j.Modules {
		if x == m {
			return true
		}
	}
	return false
}

// MaxDuration returns the run cap in seconds (default 6 h).
func (j *JobSpec) MaxDuration() int {
	if j.Window != nil && j.Window.MaxDurationS > 0 {
		return j.Window.MaxDurationS
	}
	return 6 * 3600
}

// SigningBytes is the canonical form covered by Sig: the JSON encoding of
// the spec with Sig cleared. Both sides marshal the same Go type, so the
// bytes are identical as long as the receiver re-encodes what it decoded.
func (j JobSpec) SigningBytes() ([]byte, error) {
	j.Sig = ""
	return json.Marshal(j)
}

// ValidateShape checks the closed sets and value ranges that do not depend
// on site scope (those live in internal/guard).
func (j *JobSpec) ValidateShape() error {
	if j.JobID == "" || j.SiteID == "" || j.ApplianceID == "" {
		return errors.New("job_id, site_id and appliance_id are required")
	}
	if !KnownModes[j.Mode] {
		return fmt.Errorf("unknown mode %q", j.Mode)
	}
	if len(j.Targets) == 0 {
		return errors.New("targets required")
	}
	if len(j.Modules) == 0 {
		return errors.New("modules required")
	}
	seen := map[string]bool{}
	for _, m := range j.Modules {
		if !KnownModules[m] {
			return fmt.Errorf("unknown module %q", m)
		}
		if seen[m] {
			return fmt.Errorf("duplicate module %q", m)
		}
		seen[m] = true
	}
	if j.Mode == ModeDiscovery && (seen[ModuleOpenVAS] || seen[ModuleWeb]) {
		return errors.New("discovery mode cannot run openvas or web modules")
	}
	if seen[ModuleOpenVAS] {
		if j.OpenVAS == nil {
			return errors.New("openvas module needs openvas params")
		}
		if j.OpenVAS.Config != "inventory" && j.OpenVAS.Config != "full" {
			return fmt.Errorf("unknown openvas config %q", j.OpenVAS.Config)
		}
		if j.OpenVAS.MaxHosts < 1 || j.OpenVAS.MaxHosts > 64 || j.OpenVAS.MaxChecks < 1 || j.OpenVAS.MaxChecks > 32 {
			return errors.New("openvas max_hosts must be 1..64 and max_checks 1..32")
		}
		if !seen[ModulePortscan] {
			return errors.New("openvas module needs the portscan module (port list is pinned from naabu)")
		}
	}
	if seen[ModuleWeb] {
		return errors.New("web module is not available before Phase 3")
	}
	if seen[ModulePortscan] {
		if _, err := ParsePortSpec(j.Ports); err != nil {
			return err
		}
	}
	if j.Rate.PPS < 1 || j.Rate.PPS > 100000 {
		return errors.New("rate.pps must be 1..100000")
	}
	if j.Rate.PerHostParallel < 1 || j.Rate.PerHostParallel > 8 {
		return errors.New("rate.per_host_parallel must be 1..8")
	}
	if j.Window != nil {
		if j.Window.MaxDurationS < 60 || j.Window.MaxDurationS > 24*3600 {
			return errors.New("window.max_duration_s must be 60..86400")
		}
	}
	if j.Iface != "" && (strings.ContainsAny(j.Iface, " /\\;") || len(j.Iface) > 15) {
		return fmt.Errorf("bad iface %q", j.Iface)
	}
	return nil
}

// PortRange is an inclusive TCP port range.
type PortRange struct{ Lo, Hi int }

// ParsePortSpec accepts the presets and explicit lists. Presets return nil
// ranges (the engine expands them).
func ParsePortSpec(s string) ([]PortRange, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "", PortsStandard, PortsFull:
		return nil, nil
	}
	var out []PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := part, part
		if i := strings.Index(part, "-"); i > 0 {
			lo, hi = part[:i], part[i+1:]
		}
		l, err1 := strconv.Atoi(lo)
		h, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || l < 1 || h > 65535 || l > h {
			return nil, fmt.Errorf("bad port spec %q", part)
		}
		out = append(out, PortRange{Lo: l, Hi: h})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty port spec")
	}
	if len(out) > 512 {
		return nil, fmt.Errorf("port spec too long")
	}
	return out, nil
}
