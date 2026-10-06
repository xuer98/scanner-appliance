package v1

import (
	"strings"
	"testing"
)

func TestPortCount(t *testing.T) {
	cases := map[string]int{"": StandardPortCount, PortsStandard: StandardPortCount, PortsFull: 65535, "22,80,443": 3, "1-1024": 1024, "1-1024,8000-8100": 1125, "bad": 0, "70000": 0}
	for spec, want := range cases {
		if got := PortCount(spec); got != want {
			t.Errorf("PortCount(%q) = %d, want %d", spec, got, want)
		}
	}
}

func TestFingerprintModuleShape(t *testing.T) {
	base := func() JobSpec {
		s := JobSpec{JobID: "j", SiteID: "s", ApplianceID: "a", Targets: []string{"10.0.0.0/24"}}
		s.DefaultsFor(ModeInventory)
		return s
	}
	// Defaults fill the params when the module is listed.
	s := base()
	s.Modules = append(s.Modules, ModuleFingerprint)
	s.DefaultsFor(ModeInventory)
	if s.Fingerprint == nil || !s.Fingerprint.OSDetection || s.Fingerprint.Intensity != 5 {
		t.Fatalf("defaults: %+v", s.Fingerprint)
	}
	if err := s.ValidateShape(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	// Params required, intensity bounded, portscan required, not in discovery.
	s.Fingerprint = nil
	if err := s.ValidateShape(); err == nil || !strings.Contains(err.Error(), "fingerprint params") {
		t.Fatalf("missing params: %v", err)
	}
	s.Fingerprint = &FingerprintParams{Intensity: 12}
	if err := s.ValidateShape(); err == nil || !strings.Contains(err.Error(), "intensity") {
		t.Fatalf("intensity: %v", err)
	}
	s.Fingerprint = DefaultFingerprintParams()
	s.Modules = []string{ModuleDiscovery, ModuleFingerprint}
	if err := s.ValidateShape(); err == nil || !strings.Contains(err.Error(), "portscan") {
		t.Fatalf("without portscan: %v", err)
	}
	d := JobSpec{JobID: "j", SiteID: "s", ApplianceID: "a", Targets: []string{"10.0.0.0/24"}, Modules: []string{ModuleDiscovery, ModulePortscan, ModuleFingerprint}, Fingerprint: DefaultFingerprintParams()}
	d.DefaultsFor(ModeDiscovery)
	if err := d.ValidateShape(); err == nil || !strings.Contains(err.Error(), "discovery mode") {
		t.Fatalf("discovery mode: %v", err)
	}
	// expected_hosts is bounded; the signed bytes omit it when zero.
	s = base()
	s.ExpectedHosts = -1
	if err := s.ValidateShape(); err == nil {
		t.Fatal("negative expected_hosts accepted")
	}
	s.ExpectedHosts = 0
	b, _ := s.SigningBytes()
	if strings.Contains(string(b), "expected_hosts") || strings.Contains(string(b), `"fingerprint"`) {
		t.Fatalf("zero-value Phase 5 fields leaked into the signed bytes: %s", b)
	}
}

func TestUDPModuleShape(t *testing.T) {
	for _, mode := range []string{ModeInventory, ModeFull} {
		s := JobSpec{JobID: "j", SiteID: "s", ApplianceID: "a", Targets: []string{"10.0.0.0/24"}}
		s.DefaultsFor(mode)
		// Never a default: a job has to ask for it.
		if s.HasModule(ModuleUDP) {
			t.Fatalf("%s runs udp by default", mode)
		}
		before, _ := s.SigningBytes()
		s.Modules = append(s.Modules, ModuleUDP)
		if err := s.ValidateShape(); err != nil {
			t.Fatalf("%s with udp rejected: %v", mode, err)
		}
		// The choice is part of what the control plane signs.
		after, _ := s.SigningBytes()
		if string(before) == string(after) || !strings.Contains(string(after), `"udp"`) {
			t.Fatalf("%s: udp is not covered by the signature", mode)
		}
	}
	// It adds tests to the openvas phase, so it needs that phase.
	s := JobSpec{JobID: "j", SiteID: "s", ApplianceID: "a", Targets: []string{"10.0.0.0/24"}, Modules: []string{ModuleDiscovery, ModulePortscan, ModuleUDP}}
	s.DefaultsFor(ModeInventory)
	if err := s.ValidateShape(); err == nil || !strings.Contains(err.Error(), "udp module needs the openvas module") {
		t.Fatalf("udp without openvas: %v", err)
	}
	d := JobSpec{JobID: "j", SiteID: "s", ApplianceID: "a", Targets: []string{"10.0.0.0/24"}, Modules: []string{ModuleDiscovery, ModuleUDP}}
	d.DefaultsFor(ModeDiscovery)
	if err := d.ValidateShape(); err == nil || !strings.Contains(err.Error(), "discovery mode") {
		t.Fatalf("udp in discovery mode: %v", err)
	}
	if UDPScope(ScopeInventory) == ScopeInventory || UDPScope(ScopeInventory) == UDPScope(ScopeFull) {
		t.Fatal("udp scopes must differ from the plain scopes and from each other")
	}
}
