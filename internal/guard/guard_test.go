package guard

import (
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

func base() (v1.JobSpec, v1.SiteConfig) {
	spec := v1.JobSpec{JobID: "job_1", SiteID: "site_1", ApplianceID: "apl_1", Targets: []string{"10.30.5.0/24", "10.30.6.10"}, Excludes: []string{"10.30.5.1"}, SafeChecks: true}
	spec.DefaultsFor(v1.ModeInventory)
	site := v1.SiteConfig{AllowedCIDRs: []string{"10.30.0.0/16"}, TZ: "UTC", MaxPPS: 300, MaxConcurrency: 16}
	return spec, site
}

func names(f []Failure) map[string]bool {
	m := map[string]bool{}
	for _, x := range f {
		m[x.Check] = true
	}
	return m
}

func TestGuardrails(t *testing.T) {
	spec, site := base()
	now := time.Now()
	if f := Check(Input{Spec: spec, Site: site, Now: now}); len(f) != 0 {
		t.Fatalf("clean job failed: %v", f)
	}

	s := spec
	s.Targets = []string{"10.31.0.0/24"}
	if !names(Check(Input{Spec: s, Site: site, Now: now}))[CheckScope] {
		t.Fatal("out of scope accepted")
	}
	s = spec
	s.Targets = []string{"10.0.0.0/8"} // wider than the allowed /16
	if !names(Check(Input{Spec: s, Site: site, Now: now}))[CheckScope] {
		t.Fatal("wider-than-scope accepted")
	}

	// Public range: needs both the job flag and the site attestation.
	pub := spec
	pub.Targets = []string{"203.0.113.0/24"}
	pubSite := site
	pubSite.AllowedCIDRs = []string{"203.0.113.0/24"}
	f := names(Check(Input{Spec: pub, Site: pubSite, Now: now}))
	if !f[CheckPublic] || f[CheckScope] {
		t.Fatalf("public without flag: %v", f)
	}
	pub.AllowPublic = true
	if !names(Check(Input{Spec: pub, Site: pubSite, Now: now}))[CheckPublic] {
		t.Fatal("public without site attestation accepted")
	}
	pubSite.AllowPublic = true
	if f := Check(Input{Spec: pub, Site: pubSite, Now: now}); len(f) != 0 {
		t.Fatalf("attested public rejected: %v", f)
	}

	// Window closed / open with skew tolerance.
	w := spec
	w.Window = &v1.Window{Cron: "0 22 * * 6", TZ: "America/Los_Angeles", MaxDurationS: 3600}
	la, _ := time.LoadLocation("America/Los_Angeles")
	inWin := time.Date(2026, 9, 26, 22, 30, 0, 0, la)
	if f := Check(Input{Spec: w, Site: site, Now: inWin}); len(f) != 0 {
		t.Fatalf("open window rejected: %v", f)
	}
	if !names(Check(Input{Spec: w, Site: site, Now: inWin.Add(2 * time.Hour)}))[CheckWindow] {
		t.Fatal("closed window accepted")
	}
	if f := Check(Input{Spec: w, Site: site, Now: inWin.Add(-31 * time.Minute), SkewTolerance: 2 * time.Minute}); len(f) != 0 {
		t.Fatalf("skew tolerance: %v", f)
	}

	r := spec
	r.Rate.PPS = 301
	if !names(Check(Input{Spec: r, Site: site, Now: now}))[CheckRate] {
		t.Fatal("rate cap")
	}
	c := spec
	c.OpenVAS = &v1.OpenVASParams{Config: "full", MaxHosts: 8, MaxChecks: 4}
	if !names(Check(Input{Spec: c, Site: site, Now: now}))[CheckConcurrency] {
		t.Fatal("concurrency cap")
	}
	u := spec
	u.SafeChecks = false
	if !names(Check(Input{Spec: u, Site: site, Now: now}))[CheckSafeChecks] {
		t.Fatal("unsafe accepted")
	}
	site.UnsafeOK = true
	if f := Check(Input{Spec: u, Site: site, Now: now}); len(f) != 0 {
		t.Fatalf("unsafe_ok site rejected: %v", f)
	}

	sh := spec
	sh.Mode = "nmap"
	if !names(Check(Input{Spec: sh, Site: site, Now: now}))[CheckShape] {
		t.Fatal("bad mode accepted")
	}
	if !Contains([]string{"10.30.5.0/28", "10.30.6.1"}, "10.30.5.9") || Contains([]string{"10.30.5.0/28"}, "10.30.5.16") {
		t.Fatal("Contains")
	}
}

func TestDurationBudget(t *testing.T) {
	spec, site := base()
	spec.Ports = v1.PortsFull
	spec.Targets = []string{"10.30.5.0/24"}
	spec.Rate.PPS = 300
	// 254 addresses (no inventory hint) at 300 pps: ~17 h > 6 h default.
	fails := Check(Input{Spec: spec, Site: site, Now: time.Now()})
	if !names(fails)[CheckDuration] {
		t.Fatalf("full range on a /24 without a hint accepted: %v", fails)
	}
	// The control plane's inventory hint brings it under budget.
	spec.ExpectedHosts = 40
	if fails := Check(Input{Spec: spec, Site: site, Now: time.Now()}); len(fails) != 0 {
		t.Fatalf("40 hosts full range rejected: %v", fails)
	}
	// A wider window does too.
	spec.ExpectedHosts = 0
	spec.Window = &v1.Window{MaxDurationS: 24 * 3600}
	if fails := Check(Input{Spec: spec, Site: site, Now: time.Now()}); len(fails) != 0 {
		t.Fatalf("24 h window rejected: %v", fails)
	}
	// Standard ports are never budgeted, whatever the range.
	spec.Window = nil
	spec.Ports = v1.PortsStandard
	spec.Targets = []string{"10.0.0.0/8"}
	site.AllowedCIDRs = []string{"10.0.0.0/8"}
	if fails := Check(Input{Spec: spec, Site: site, Now: time.Now()}); names(fails)[CheckDuration] {
		t.Fatalf("standard scan budgeted: %v", fails)
	}
	if n := AddressCount([]string{"10.30.5.0/24", "10.30.6.1", "10.30.7.0/30"}); n != 261 {
		t.Fatalf("AddressCount = %d", n)
	}
	if n := AddressCount([]string{"10.0.0.0/7"}); n != MaxAddressCount {
		t.Fatalf("huge range = %d", n)
	}
	if s := FormatDuration(EstimateSeconds(254, 65535, 300)); !strings.HasPrefix(s, "16h") && !strings.HasPrefix(s, "17h") {
		t.Fatalf("estimate: %s", s)
	}
}
