package engine

import (
	"log/slog"
	"strings"
	"testing"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

func TestFragileDecision(t *testing.T) {
	spec, site := inventorySpec()
	site.FragileCleared = []string{"10.30.5.21"}
	site.FragileHosts = []string{"10.30.5.30"}
	r := &run{e: &Engine{Log: slog.Default()}, spec: spec, site: site, stats: &v1.ScanStats{}, hosts: map[string]*hostAgg{}}
	printer := newHostAgg("10.30.5.21")
	printer.addPort(9100, "tcp", "naabu")
	other := newHostAgg("10.30.5.22")
	other.addPort(9100, "tcp", "naabu")
	plc := newHostAgg("10.30.5.30")
	plc.addPort(80, "tcp", "naabu")
	plain := newHostAgg("10.30.5.40")
	plain.addPort(80, "tcp", "naabu")
	fragile := site.FragilePorts
	if skip, note := r.fragileDecision(printer, fragile); skip || note != "fragile:cleared:9100" {
		t.Fatalf("cleared host: skip=%v note=%q", skip, note)
	}
	if skip, note := r.fragileDecision(other, fragile); !skip || note != "fragile:9100" {
		t.Fatalf("uncleared fragile host: skip=%v note=%q", skip, note)
	}
	if skip, note := r.fragileDecision(plc, fragile); !skip || note != "fragile:policy" {
		t.Fatalf("policy host: skip=%v note=%q", skip, note)
	}
	if skip, note := r.fragileDecision(plain, fragile); skip || note != "" {
		t.Fatalf("plain host: skip=%v note=%q", skip, note)
	}
	// With the exclusion switched off only the policy list applies.
	r.spec.OpenVAS.FragilePortsExclude = false
	if skip, _ := r.fragileDecision(other, fragile); skip {
		t.Fatal("fragile port honoured although fragile_ports_exclude=false")
	}
	if skip, _ := r.fragileDecision(plc, fragile); !skip {
		t.Fatal("policy list ignored")
	}
}

func TestVTExcludesSuppressFindings(t *testing.T) {
	spec, site := inventorySpec()
	site.VTExcludes = []string{"1.3.6.1.4.1.25623.1.0.999", "nuclei:tech-detect", "  "}
	r := &run{e: &Engine{Log: slog.Default()}, spec: spec, site: site, stats: &v1.ScanStats{}, hosts: map[string]*hostAgg{}}
	for _, tc := range []struct {
		f    v1.Finding
		want bool
	}{
		{v1.Finding{NVTOID: "1.3.6.1.4.1.25623.1.0.999"}, true},
		{v1.Finding{NVTOID: "1.3.6.1.4.1.25623.1.0.998"}, false},
		{v1.Finding{ID: "tech-detect", Source: "nuclei"}, true},
		{v1.Finding{ID: "other", Source: "nuclei"}, false},
	} {
		if got := r.vtExcluded(tc.f); got != tc.want {
			t.Fatalf("%+v: excluded=%v", tc.f, got)
		}
	}
	// emitAll drops suppressed findings and counts them in the stats.
	h := r.host("10.30.5.20")
	h.findings = []v1.Finding{{Source: "nuclei", ID: "tech-detect", Name: "x", Severity: v1.SeverityInfo}, {Source: "nuclei", ID: "keep", Name: "y", Severity: v1.SeverityHigh}}
	sink := &webSink{}
	r.sink = sink
	r.e.Now = nil
	r.e.init()
	if err := r.emitAll(t.Context(), true, nil); err != nil {
		t.Fatal(err)
	}
	final := sink.batches[len(sink.batches)-1]
	if len(final.Hosts) != 1 || len(final.Hosts[0].Findings) != 1 || final.Hosts[0].Findings[0].ID != "keep" {
		t.Fatalf("findings after suppression: %+v", final.Hosts[0].Findings)
	}
	if r.stats.Suppressed != 1 || r.stats.Findings != 1 {
		t.Fatalf("stats: %+v", r.stats)
	}
}

func TestNucleiExcludesCodifiedTemplates(t *testing.T) {
	logDir := t.TempDir()
	naabu, httpx, nuclei := webFakes(t, logDir)
	bundleDir := t.TempDir()
	tpl := bundleDir + "/nuclei-templates"
	if err := writeFile(tpl+"/x.yaml", "id: x\n"); err != nil {
		t.Fatal(err)
	}
	e := &Engine{NaabuPath: naabu, HTTPXPath: httpx, NucleiPath: nuclei, BundleDir: bundleDir, Log: slog.Default(), IfaceExists: func(string) bool { return false }}
	spec := v1.JobSpec{JobID: "job_web3", SiteID: "site_1", ApplianceID: "apl_1", Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"},
		Modules: []string{v1.ModuleDiscovery, v1.ModulePortscan, v1.ModuleWeb}, Ports: "standard", Rate: v1.Rate{PPS: 300, PerHostParallel: 2}, Web: v1.DefaultWebParams()}
	site := v1.SiteConfig{VTExcludes: []string{"nuclei:CVE-2021-41773", "1.3.6.1.4.1.25623.1.0.1", "tech-detect"}}
	stats, err := e.Run(t.Context(), spec, site, &webSink{})
	if err != nil {
		t.Fatal(err)
	}
	args := read(t, logDir+"/nuclei.args")
	if !strings.Contains(args, "-exclude-id CVE-2021-41773,tech-detect") {
		t.Fatalf("nuclei args: %s", args)
	}
	// The fake still emits the excluded match; the engine drops it and reports it.
	if stats.Findings != 0 || stats.Suppressed != 1 {
		t.Fatalf("stats: findings=%d suppressed=%d", stats.Findings, stats.Suppressed)
	}
}

func writeFile(path, body string) error {
	if err := mkdirAll(path); err != nil {
		return err
	}
	return osWriteFile(path, body)
}
