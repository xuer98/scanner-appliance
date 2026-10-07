package store

import (
	"context"
	"reflect"
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
	got := mergePorts(prev, cur, false)
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

	// UDP ports are only seen by the UDP tests. An observation without them
	// (udp false) carries the known ones over; one with them decides.
	snmp := v1.Port{Port: 161, Proto: "udp", Service: "snmp", Product: "Net-SNMP", Source: "openvas:product_detection"}
	ntp := v1.Port{Port: 123, Proto: "udp", Service: "ntp", Source: "openvas:find_service"}
	prev = append(prev, snmp, ntp)
	if got := mergePorts(prev, cur, false); len(got) != 5 || !reflect.DeepEqual(got[3], snmp) || !reflect.DeepEqual(got[4], ntp) {
		t.Fatalf("udp ports not carried over by a scan that tested no udp: %+v", got)
	}
	got = mergePorts(prev, append(append([]v1.Port{}, cur...), v1.Port{Port: 161, Proto: "udp", Source: "openvas:find_service"}), true)
	if len(got) != 4 || got[3].Port != 161 || got[3].Product != "Net-SNMP" || got[3].Service != "snmp" {
		t.Fatalf("udp ports after a scan that tested udp: %+v", got)
	}
	// Same number, other protocol: a TCP port does not stand in for the UDP one.
	if got := mergePorts([]v1.Port{{Port: 53, Proto: "udp", Service: "dns"}}, []v1.Port{{Port: 53, Proto: "tcp"}}, false); len(got) != 2 || got[0].Service != "" || got[1].Proto != "udp" {
		t.Fatalf("tcp and udp 53: %+v", got)
	}
	for _, p := range got {
		if p.Port == 23 {
			t.Fatal("closed port kept")
		}
	}
}

// A database written before records were folded may hold two records for
// one address: the host, and a nameless record made by a job's first chunk.
// That is what the lab held for 172.18.0.10. The next sighting has to clean
// it up, whichever way the host is matched, and must not pick the nameless
// record over the host.
func TestLeftoverDuplicateIsFolded(t *testing.T) {
	t0 := time.Date(2026, 10, 6, 2, 0, 0, 0, time.UTC)
	build := func() (*siteIndex, *Host, *Host) {
		stub := &Host{ID: "host_a_stub", SiteID: "site_1", IP: "172.18.0.10", Source: v1.SourceAppliance, FirstSeen: t0.Add(time.Hour), LastSeen: t0.Add(time.Hour)}
		host := &Host{ID: "host_b_real", SiteID: "site_1", IP: "172.18.0.10", MAC: "16:e4:3f:f7:e6:02", Hostname: "scanner-lab-snmponly-1.scannerlab",
			Source: v1.SourceAppliance, FirstSeen: t0, LastSeen: t0.Add(2 * time.Hour)}
		other := &Host{ID: "host_c_other", SiteID: "site_1", IP: "172.18.0.11", MAC: "b6:41:b7:70:8f:44", Source: v1.SourceAppliance, FirstSeen: t0}
		// The nameless record sorts first, as it did in the lab.
		return newSiteIndex("site_1", []*Host{stub, host, other}, nil), stub, host
	}

	// By address alone the host is preferred over the nameless record.
	ix, stub, host := build()
	if got := ix.match(nil, "", "172.18.0.10"); got != host {
		t.Fatalf("match by address picked %+v", got)
	}
	// With no better candidate the nameless record is still found.
	ix.hosts = []*Host{stub}
	if got := ix.match(nil, "", "172.18.0.10"); got != stub {
		t.Fatalf("lone record not matched: %+v", got)
	}

	// A sighting with the MAC the host answers with today, which is not the
	// one on record: matched by address, the MAC is brought up to date and
	// the nameless record goes.
	ix, stub, host = build()
	sum, touched := ix.ingestAppliance("job_1", []v1.Host{{IP: "172.18.0.10", MAC: "d6:20:6f:8c:8c:76", Ports: []v1.Port{}}}, "f", t0.Add(30*time.Hour), v1.ScopeFull)
	if sum.Absorbed != 1 || sum.Created != 0 || len(touched) != 1 || touched[0] != host.ID {
		t.Fatalf("summary %+v touched %v", sum, touched)
	}
	if len(ix.hosts) != 2 || ix.removed[stub.ID] == nil || ix.changed[stub.ID] != nil || host.MAC != "d6:20:6f:8c:8c:76" || !host.FirstSeen.Equal(t0) {
		t.Fatalf("after the sighting: hosts %d removed %v host %+v", len(ix.hosts), ix.removed, host)
	}

	// Matched by name instead: same outcome.
	ix, stub, host = build()
	if sum, _ := ix.ingestAppliance("job_1", []v1.Host{{IP: "172.18.0.10", Hostname: "scanner-lab-snmponly-1", Ports: []v1.Port{}}}, "f", t0.Add(30*time.Hour), v1.ScopeFull); sum.Absorbed != 1 {
		t.Fatalf("matched by name: %+v", sum)
	}
	if ix.removed[stub.ID] == nil || host.MAC != "16:e4:3f:f7:e6:02" {
		t.Fatalf("matched by name: removed %v mac %s", ix.removed, host.MAC)
	}

	// An agent vouches for the host: its MAC is not the appliance's to change.
	ix, _, host = build()
	host.AgentID = "agent-7"
	ix.ingestAppliance("job_1", []v1.Host{{IP: "172.18.0.10", MAC: "d6:20:6f:8c:8c:76", Hostname: "scanner-lab-snmponly-1", Ports: []v1.Port{}}}, "f", t0.Add(30*time.Hour), v1.ScopeFull)
	if host.MAC != "16:e4:3f:f7:e6:02" {
		t.Fatalf("agent host's MAC replaced: %s", host.MAC)
	}

	// Two hosts that are each known by more than the address are never
	// folded, even at one address: nothing says they are the same device.
	ix, _, host = build()
	rival := &Host{ID: "host_d_rival", SiteID: "site_1", IP: "172.18.0.10", Hostname: "something-else", Source: v1.SourceAppliance}
	ix.hosts = append(ix.hosts, rival)
	if sum, _ := ix.ingestAppliance("job_1", []v1.Host{{IP: "172.18.0.10", MAC: "16:e4:3f:f7:e6:02", Ports: []v1.Port{}}}, "f", t0.Add(30*time.Hour), v1.ScopeFull); sum.Absorbed != 1 || ix.removed[rival.ID] != nil {
		t.Fatalf("a named host was folded: %+v %v", sum, ix.removed)
	}
}
