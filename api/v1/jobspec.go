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
	KnownModules = map[string]bool{ModuleDiscovery: true, ModulePortscan: true, ModuleOpenVAS: true, ModuleWeb: true, ModuleFingerprint: true, ModuleUDP: true}
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
			// Phase 3: full = discovery + port + openvas full + web add-on (PLAN §10.5).
			j.Modules = []string{ModuleDiscovery, ModulePortscan, ModuleOpenVAS, ModuleWeb}
		}
		if j.OpenVAS == nil {
			j.OpenVAS = &OpenVASParams{Config: "full", MaxHosts: 4, MaxChecks: 4, FragilePortsExclude: true}
		}
	}
	if j.HasModule(ModuleWeb) && j.Web == nil {
		j.Web = DefaultWebParams()
	}
	if j.HasModule(ModuleFingerprint) && j.Fingerprint == nil {
		j.Fingerprint = DefaultFingerprintParams()
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
	if j.Mode == ModeDiscovery && (seen[ModuleOpenVAS] || seen[ModuleWeb] || seen[ModuleFingerprint] || seen[ModuleUDP]) {
		return errors.New("discovery mode cannot run openvas, web, fingerprint or udp modules")
	}
	if seen[ModuleUDP] && !seen[ModuleOpenVAS] {
		return errors.New("udp module needs the openvas module (it adds UDP tests to that phase)")
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
		if j.Web == nil {
			return errors.New("web module needs web params")
		}
		if !KnownSeverities[j.Web.MinSeverity] {
			return fmt.Errorf("web.min_severity %q is not a severity", j.Web.MinSeverity)
		}
		if !seen[ModulePortscan] {
			return errors.New("web module needs the portscan module (it targets the open HTTP ports)")
		}
	}
	if seen[ModuleFingerprint] {
		if j.Fingerprint == nil {
			return errors.New("fingerprint module needs fingerprint params")
		}
		if j.Fingerprint.Intensity < 0 || j.Fingerprint.Intensity > MaxFingerprintIntensity {
			return fmt.Errorf("fingerprint.intensity must be 0..%d", MaxFingerprintIntensity)
		}
		if !seen[ModulePortscan] {
			return errors.New("fingerprint module needs the portscan module (it probes the open ports)")
		}
	}
	if seen[ModulePortscan] {
		if _, err := ParsePortSpec(j.Ports); err != nil {
			return err
		}
	}
	if j.ExpectedHosts < 0 || j.ExpectedHosts > MaxExpectedHosts {
		return fmt.Errorf("expected_hosts must be 0..%d", MaxExpectedHosts)
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

// MaxExpectedHosts bounds the control plane's live-host hint.
const MaxExpectedHosts = 1 << 24

// StandardPortCount is the nominal size of the "standard" preset (naabu's
// top 1000 plus the warehouse/OT extras, most of which overlap).
const StandardPortCount = 1024

// PortCount is the number of TCP ports a port spec expands to; 0 for an
// invalid spec. The full-range option (Phase 5) is 65535.
func PortCount(spec string) int {
	ranges, err := ParsePortSpec(spec)
	if err != nil {
		return 0
	}
	switch strings.TrimSpace(spec) {
	case "", PortsStandard:
		return StandardPortCount
	case PortsFull:
		return 65535
	}
	n := 0
	for _, r := range ranges {
		n += r.Hi - r.Lo + 1
	}
	return n
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
