package store

import (
	"context"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

func TestCorrelation(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	vendor, _ := m.EnsureVendor(ctx, "Acme")
	site, _ := m.EnsureSite(ctx, vendor.ID, "Reno", []string{"10.30.0.0/16"}, "UTC", 300)
	correlationScenario(t, ctx, m, site.ID)
}

// correlationScenario is PLAN §12.3 end to end on any Store (also run by
// the conformance suite against Postgres).
func correlationScenario(t *testing.T, ctx context.Context, m Store, siteID string) {
	t.Helper()
	site := &Site{ID: siteID}
	t0 := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	// Results are only ever ingested for existing jobs (job_host references
	// job); create the rows the scenario refers to.
	apl, err := m.CreateAppliance(ctx, siteID)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"job_1", "job_2", "job_3"} {
		if err := m.CreateJob(ctx, &Job{ID: id, SiteID: siteID, ApplianceID: apl.ID}); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Appliance sees a host with a high-QoD and a low-QoD finding.
	sum, err := m.IngestHosts(ctx, site.ID, "job_1", []v1.Host{{
		IP: "10.30.5.20", MAC: "00:50:56:AB:CD:EF", Hostname: "wms-app-01",
		OSGuess: &v1.OSGuess{Family: "windows", Confidence: 0.7, Source: "openvas:os_detection"},
		Ports:   []v1.Port{{Port: 3389, Proto: "tcp", Service: "rdp", Source: "naabu"}},
		Findings: []v1.Finding{
			{Source: "openvas", NVTOID: "1.1", Name: "BlueKeep", Severity: "critical", CVSS: 9.8, CVE: []string{"CVE-2019-0708"}, QoD: 97, Port: 3389, Proto: "tcp", Evidence: "e1"},
			{Source: "openvas", NVTOID: "1.2", Name: "Banner guess", Severity: "medium", CVSS: 5.0, CVE: []string{"CVE-2020-1"}, QoD: 30, Port: 3389, Proto: "tcp", Evidence: "e2"},
		},
	}}, "2026", t0)
	if err != nil || sum.Created != 1 || sum.Findings != 2 {
		t.Fatalf("%+v %v", sum, err)
	}
	hosts, _ := m.ListHosts(ctx, site.ID)
	if len(hosts) != 1 || hosts[0].Source != v1.SourceAppliance || hosts[0].MAC != "00:50:56:ab:cd:ef" {
		t.Fatalf("%+v", hosts[0])
	}
	fs, _ := m.ListFindings(ctx, site.ID, "")
	if len(fs) != 2 || fs[0].State != v1.FindingNetworkObserved || fs[1].State != v1.FindingSuspected {
		t.Fatalf("states: %s %s", fs[0].State, fs[1].State)
	}

	// 2. Agent inventory for the same box (matched by MAC despite a new IP):
	//    host becomes "both", BlueKeep confirmed with two evidence entries,
	//    packages come from the agent, ports stay from the appliance.
	sum, err = m.IngestAgentHosts(ctx, site.ID, []v1.AgentHost{{
		AgentID: "wz-001", Hostname: "WMS-APP-01.corp.local", IP: "10.30.5.77", MACs: []string{"00-50-56-AB-CD-EF"}, OS: "Windows Server 2008 R2",
		Packages: []v1.AgentPackage{{Name: "openssl", Version: "1.0.2"}},
		Findings: []v1.AgentFinding{{CVE: "CVE-2019-0708", Package: "termsrv", CVSS: 9.8}, {CVE: "CVE-2021-9", Package: "openssl", CVSS: 7.5}},
	}}, t0.Add(time.Hour))
	if err != nil || sum.Merged != 1 || sum.Created != 0 {
		t.Fatalf("agent ingest: %+v %v", sum, err)
	}
	hosts, _ = m.ListHosts(ctx, site.ID)
	h := hosts[0]
	if len(hosts) != 1 || h.Source != v1.SourceBoth || h.AgentID != "wz-001" || h.Hostname != "WMS-APP-01.corp.local" || h.IP != "10.30.5.20" || len(h.Packages) != 1 || len(h.Ports) != 1 {
		t.Fatalf("merged host: %+v", h)
	}
	fs, _ = m.ListFindings(ctx, site.ID, h.ID)
	if len(fs) != 3 {
		t.Fatalf("findings after agent: %d", len(fs))
	}
	var blue, agentOnly *Finding
	for _, f := range fs {
		switch {
		case f.NVTOID == "1.1":
			blue = f
		case contains(f.CVE, "CVE-2021-9"):
			agentOnly = f
		}
	}
	if blue == nil || blue.Source != v1.SourceBoth || blue.State != v1.FindingConfirmed || len(blue.Evidence) != 2 {
		t.Fatalf("bluekeep: %+v", blue)
	}
	if agentOnly == nil || agentOnly.Source != v1.SourceAgent || agentOnly.State != v1.FindingConfirmed || agentOnly.Severity != v1.SeverityHigh {
		t.Fatalf("agent-only: %+v", agentOnly)
	}

	// 3. Second scan: the suspected finding is observed again → network_observed;
	//    a new host appears with no MAC and is matched by hostname on the third scan.
	_, _ = m.IngestHosts(ctx, site.ID, "job_2", []v1.Host{{
		IP: "10.30.5.20", MAC: "00:50:56:ab:cd:ef",
		Findings: []v1.Finding{{Source: "openvas", NVTOID: "1.2", Name: "Banner guess", Severity: "medium", CVSS: 5.0, CVE: []string{"CVE-2020-1"}, QoD: 30, Port: 3389, Proto: "tcp", Evidence: "e2b"}},
	}, {IP: "10.30.5.30", Hostname: "printer-7"}}, "2026", t0.Add(2*time.Hour))
	fs, _ = m.ListFindings(ctx, site.ID, h.ID)
	for _, f := range fs {
		if f.NVTOID == "1.2" && (f.State != v1.FindingNetworkObserved || len(f.Evidence) != 2) {
			t.Fatalf("second scan: %+v", f)
		}
		if f.NVTOID == "1.1" && len(f.Evidence) != 2 {
			t.Fatalf("bluekeep evidence changed without observation: %+v", f)
		}
	}
	_, _ = m.IngestHosts(ctx, site.ID, "job_3", []v1.Host{{IP: "10.30.5.31", Hostname: "PRINTER-7"}}, "2026", t0.Add(3*time.Hour))
	hosts, _ = m.ListHosts(ctx, site.ID)
	if len(hosts) != 2 {
		t.Fatalf("hostname match failed: %d hosts", len(hosts))
	}
	jh, _ := m.ListJobHosts(ctx, "job_3")
	if len(jh) != 1 || jh[0].IP != "10.30.5.31" {
		t.Fatalf("job hosts: %+v", jh)
	}
	// Unknown site is refused.
	if _, err := m.IngestHosts(ctx, "site_missing", "job_x", []v1.Host{{IP: "10.0.0.1"}}, "2026", t0); err != ErrNotFound {
		t.Fatalf("ingest into unknown site: %v", err)
	}
	if _, err := m.IngestAgentHosts(ctx, "site_missing", []v1.AgentHost{{AgentID: "a"}}, t0); err != ErrNotFound {
		t.Fatalf("agent ingest into unknown site: %v", err)
	}
	if _, err := m.GetHost(ctx, "host_missing"); err != ErrNotFound {
		t.Fatalf("missing host: %v", err)
	}
	if got, err := m.GetHost(ctx, h.ID); err != nil || got.IP != "10.30.5.20" || got.Source != v1.SourceBoth {
		t.Fatalf("get host: %+v %v", got, err)
	}
}

// TestMergePorts: a later port-scan-only observation keeps the detail an
// earlier inventory or fingerprint pass learned, drops closed ports and
// adds new ones (Phase 5).
func TestMergePorts(t *testing.T) {
	prev := []v1.Port{
		{Port: 3389, Proto: "tcp", Service: "rdp", Product: "Microsoft Terminal Services", CPE: "cpe:/a:microsoft:terminal_services", Source: "nmap:version_detection"},
		{Port: 8080, Proto: "tcp", Service: "http", Source: "openvas:find_service", Web: &v1.WebInfo{URL: "http://10.30.5.20:8080", Server: "Apache"}},
		{Port: 23, Proto: "tcp", Service: "telnet", Source: "openvas:find_service"},
	}
	cur := []v1.Port{
		{Port: 3389, Proto: "tcp", Source: "naabu"},
		{Port: 8080, Proto: "tcp", Service: "https", Source: "naabu"},
		{Port: 445, Proto: "tcp", Source: "naabu"},
	}
	got := mergePorts(prev, cur)
	if len(got) != 3 {
		t.Fatalf("ports: %+v", got)
	}
	if got[0].Product != "Microsoft Terminal Services" || got[0].Service != "rdp" || got[0].CPE == "" || got[0].Source != "nmap:version_detection" {
		t.Fatalf("detail not carried: %+v", got[0])
	}
	if got[1].Service != "https" || got[1].Web == nil || got[1].Web.Server != "Apache" || got[1].Source != "naabu" {
		t.Fatalf("new detail overridden or web lost: %+v", got[1])
	}
	if got[2].Port != 445 || got[2].Service != "" {
		t.Fatalf("new port: %+v", got[2])
	}
	for _, p := range got {
		if p.Port == 23 {
			t.Fatal("closed port kept")
		}
	}
}
