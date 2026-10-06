package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/nvt"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/daemon/internal/osp/osptest"
)

// FakeNaabu writes a shell script that answers like naabu and logs its
// arguments to logPath. Exported for the e2e test via engine_export_test.
func fakeNaabu(t *testing.T, logPath string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake naabu is a POSIX shell script")
	}
	script := `#!/bin/sh
echo "$@" >> "` + logPath + `"
case " $* " in
  *" -sn "*)
    printf '%s\n' '10.30.5.20' '10.30.5.21' '{"ip":"10.30.5.99"}' '10.30.5.1' 'not an ip' ''
    ;;
  *)
    printf '%s\n' '{"host":"10.30.5.20","ip":"10.30.5.20","port":3389,"protocol":"tcp","tls":false}' '{"ip":"10.30.5.20","port":445,"protocol":"tcp"}' '{"ip":"10.30.5.21","port":{"Port":9100,"Protocol":"tcp"}}'
    ;;
esac
`
	p := filepath.Join(t.TempDir(), "naabu")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

type memSink struct {
	mu       sync.Mutex
	batches  []v1.ResultBatch
	progress []Progress
	fail     bool
}

func (m *memSink) Emit(_ context.Context, b v1.ResultBatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("spool full")
	}
	m.batches = append(m.batches, b)
	return nil
}

func (m *memSink) Progress(p Progress) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress = append(m.progress, p)
}

const bluekeep = "1.3.6.1.4.1.25623.1.0.108587"

func fakeOSPD(t *testing.T, hang bool) *osptest.Fake {
	return osptest.Start(t, &osptest.Fake{
		Hang: hang,
		VTs: map[string]osptest.VT{
			bluekeep:                       {Name: "Microsoft Windows RDP RCE (BlueKeep)", Family: "Windows", QoD: 97, QoDType: "remote_active", CVEs: []string{"CVE-2019-0708"}, CVSSv2: "AV:N/AC:L/Au:N/C:C/I:C/A:C", CVSSv3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Solution: "Apply KB4499175"},
			"1.3.6.1.4.1.25623.1.0.10330":  {Name: "Services", Family: "Service detection", QoD: 80},
			"1.3.6.1.4.1.25623.1.0.105937": {Name: "OS Detection Consolidation", Family: "General", QoD: 80},
		},
		Script: []osptest.Step{
			{Progress: 20, Results: []osp.Result{
				{Host: "10.30.5.20", Type: "Log Message", Port: "3389/tcp", TestID: "1.3.6.1.4.1.25623.1.0.10330", Name: "Services", QoD: "80", Text: "A Remote Desktop Protocol (RDP) service is running on this port."},
				{Host: "10.30.5.20", Type: "Log Message", Port: "445/tcp", TestID: "1.3.6.1.4.1.25623.1.0.10330", Name: "Services", QoD: "80", Text: "An SMB server is running on this port."},
				{Host: "10.30.5.20", Type: "Host Detail", Port: "general/tcp", TestID: "1.3.6.1.4.1.25623.1.0.105937", Name: "OS Detection", Text: "<host><detail><name>best_os_cpe</name><value>cpe:/o:microsoft:windows_server_2008:r2</value><source><type>nvt</type></source></detail><detail><name>best_os_txt</name><value>Microsoft Windows Server 2008 R2</value></detail></host>"},
				{Host: "10.30.5.20", Type: "Host Detail", Port: "general/tcp", TestID: "1.3.6.1.4.1.25623.1.0.103585", Name: "MAC", Text: "<host><detail><name>MAC</name><value>00:50:56:AB:CD:EF</value></detail></host>"},
			}},
			{Progress: 70, Results: []osp.Result{
				{Host: "10.30.5.20", Hostname: "wms-app-01", Type: "Alarm", Severity: "9.8", Port: "3389/tcp", TestID: bluekeep, Name: "Microsoft Windows RDP RCE (BlueKeep)", QoD: "97", Text: "The host is vulnerable: response to crafted MS_T120 channel."},
				{Host: "10.30.5.20", Type: "Alarm", Severity: "9.8", Port: "3389/tcp", TestID: bluekeep, Name: "dup", QoD: "97", Text: "dup"},
				{Host: "10.30.5.20", Type: "Error Message", Port: "445/tcp", TestID: "1.2.3", Name: "timeout", Text: "NVT timed out"},
			}},
		},
	})
}

func newEngine(t *testing.T, f *osptest.Fake, naabu string) *Engine {
	return &Engine{NaabuPath: naabu, OSP: osp.New(f.Socket), NVT: nvt.New(t.TempDir(), osp.New(f.Socket), nil),
		ApplianceID: "apl_1", PollInterval: 20 * time.Millisecond, ChunkHosts: 2, ScanType: "c", IfaceExists: func(string) bool { return true }}
}

func inventorySpec() (v1.JobSpec, v1.SiteConfig) {
	spec := v1.JobSpec{JobID: "job_1", SiteID: "site_1", ApplianceID: "apl_1", Targets: []string{"10.30.5.0/24"}, Excludes: []string{"10.30.5.1"}, SafeChecks: true, Iface: "lan0"}
	spec.DefaultsFor(v1.ModeInventory)
	site := v1.SiteConfig{AllowedCIDRs: []string{"10.30.0.0/16"}, FragilePorts: []int{9100, 515}}
	return spec, site
}

func TestInventoryRun(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "naabu.log")
	f := fakeOSPD(t, false)
	e := newEngine(t, f, fakeNaabu(t, logPath))
	spec, site := inventorySpec()
	sink := &memSink{}
	stats, err := e.Run(context.Background(), spec, site, sink)
	if err != nil {
		t.Fatal(err)
	}
	if stats.HostsAlive != 3 || stats.HostsScanned != 1 || stats.FragileExcluded != 1 || stats.OpenPorts != 3 || stats.Findings != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	argLog, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(argLog)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "-sn -wn -pe -arp -ps 22,80,443") || strings.Contains(lines[0], "-json") || !strings.Contains(lines[0], "-host 10.30.5.0/24") || !strings.Contains(lines[0], "-exclude-hosts 10.30.5.1") || !strings.Contains(lines[0], "-interface lan0") || !strings.Contains(lines[0], "-rate 300") {
		t.Fatalf("discovery args: %q", lines)
	}
	if !strings.Contains(lines[1], "-Pn") || !strings.Contains(lines[1], "-json") || !strings.Contains(lines[1], "-top-ports 1000") || !strings.Contains(lines[1], "-host 10.30.5.20,10.30.5.21,10.30.5.99") {
		t.Fatalf("portscan args: %q", lines[1])
	}
	start := f.Starts()[0]
	if !strings.Contains(start, "<hosts>10.30.5.20</hosts>") || !strings.Contains(start, "<ports>T:445,3389</ports>") || !strings.Contains(start, "<max_hosts>4</max_hosts>") || !strings.Contains(start, "<safe_checks>1</safe_checks>") || !strings.Contains(start, `filter="family=Service detection"`) || strings.Contains(start, "Denial of Service") {
		t.Fatalf("start_scan: %s", start)
	}
	// UDP is only touched by a job that asks for it.
	if strings.Contains(start, "unscanned_closed_udp") || strings.Contains(start, "U:") {
		t.Fatalf("start_scan enables UDP without the udp module: %s", start)
	}
	// Without one of its own port scanner tests openvas treats every port as
	// closed, whatever the config's families are.
	if !strings.Contains(start, `<vt_single id="1.3.6.1.4.1.25623.1.0.11219"/>`) {
		t.Fatalf("start_scan selects no port scanner test: %s", start)
	}
	// Interim chunk after portscan (2 hosts per chunk → 2 chunks), then final chunks.
	if len(sink.batches) != 4 || sink.batches[0].Final || sink.batches[1].Final || sink.batches[2].Final || !sink.batches[3].Final || sink.batches[3].Stats == nil {
		for _, b := range sink.batches {
			t.Logf("seq=%d final=%v hosts=%d", b.Seq, b.Final, len(b.Hosts))
		}
		t.Fatal("chunking")
	}
	var h20, h21, h99 *v1.Host
	for i := 2; i < 4; i++ {
		for j := range sink.batches[i].Hosts {
			h := &sink.batches[i].Hosts[j]
			switch h.IP {
			case "10.30.5.20":
				h20 = h
			case "10.30.5.21":
				h21 = h
			case "10.30.5.99":
				h99 = h
			}
		}
	}
	if h20 == nil || h21 == nil || h99 == nil {
		t.Fatal("hosts missing from final chunks")
	}
	if h20.Hostname != "wms-app-01" || h20.MAC != "00:50:56:ab:cd:ef" || h20.OSGuess == nil || h20.OSGuess.Family != "windows" || h20.OSGuess.Confidence != 0.7 {
		t.Fatalf("h20 identity: %+v os=%+v", h20, h20.OSGuess)
	}
	if len(h20.Ports) != 2 || h20.Ports[0].Port != 445 || h20.Ports[0].Service != "smb" || h20.Ports[1].Port != 3389 || h20.Ports[1].Service != "rdp" {
		t.Fatalf("h20 ports: %+v", h20.Ports)
	}
	if len(h20.Findings) != 1 {
		t.Fatalf("findings: %+v", h20.Findings)
	}
	fd := h20.Findings[0]
	if fd.NVTOID != bluekeep || fd.Severity != v1.SeverityCritical || fd.CVSS != 9.8 || fd.QoD != 97 || len(fd.CVE) != 1 || fd.CVE[0] != "CVE-2019-0708" || fd.Family != "Windows" || fd.Solution == "" || fd.Port != 3389 {
		t.Fatalf("finding: %+v", fd)
	}
	if len(h21.Notes) != 1 || h21.Notes[0] != "fragile:9100" || len(h21.Findings) != 0 {
		t.Fatalf("fragile host: %+v", h21)
	}
	if len(h99.Ports) != 0 || len(h99.Notes) != 1 || h99.Notes[0] != "openvas:skipped-no-open-ports" {
		t.Fatalf("alive host without ports: %+v", h99)
	}
	if sink.batches[3].FeedVersion != "202609260530" || sink.batches[3].Stats.PhaseDurationS[PhaseOpenVAS] < 0 {
		t.Fatalf("batch meta: %+v", sink.batches[3])
	}
	if len(f.DeleteIDs) != 1 {
		t.Fatal("scan not deleted after finish")
	}
	// Progress reached every phase.
	phases := map[string]bool{}
	for _, p := range sink.progress {
		phases[p.Phase] = true
	}
	for _, ph := range []string{PhaseDiscovery, PhasePortscan, PhaseOpenVAS, PhaseFinalize} {
		if !phases[ph] {
			t.Fatalf("no progress for %s", ph)
		}
	}
}

func TestDiscoveryOnly(t *testing.T) {
	f := fakeOSPD(t, false)
	e := newEngine(t, f, fakeNaabu(t, filepath.Join(t.TempDir(), "l")))
	spec := v1.JobSpec{JobID: "job_d", SiteID: "site_1", ApplianceID: "apl_1", Targets: []string{"10.30.5.0/24"}, SafeChecks: true}
	spec.DefaultsFor(v1.ModeDiscovery)
	sink := &memSink{}
	stats, err := e.Run(context.Background(), spec, v1.SiteConfig{}, sink)
	if err != nil || stats.HostsAlive != 4 || len(sink.batches) != 2 || !sink.batches[1].Final || len(f.Starts()) != 0 {
		t.Fatalf("discovery: %+v %v batches=%d", stats, err, len(sink.batches))
	}
}

func TestStopHaltsOSPScan(t *testing.T) {
	f := fakeOSPD(t, true)
	e := newEngine(t, f, fakeNaabu(t, filepath.Join(t.TempDir(), "l")))
	spec, site := inventorySpec()
	sink := &memSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := e.Run(ctx, spec, site, sink)
		done <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		sink.mu.Lock()
		running := len(sink.progress) > 0 && sink.progress[len(sink.progress)-1].Phase == PhaseOpenVAS
		sink.mu.Unlock()
		if running && len(f.Starts()) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrStopped) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("engine did not stop")
	}
	if stops := f.Stops(); len(stops) != 1 {
		t.Fatalf("stop_scan calls: %v", stops)
	}
	// Partial results were emitted (interim + abort chunks), none final.
	for _, b := range sink.batches {
		if b.Final {
			t.Fatal("final chunk after stop")
		}
	}
	if len(sink.batches) < 2 {
		t.Fatalf("partial results: %d", len(sink.batches))
	}
}

// What openvas reports for a host when none of its port scanner tests ran:
// the host-level results arrive, nothing on a port does, and the scan still
// finishes. Captured from an inventory scan before PortScannerVT existed.
func blindResults(host string) []osp.Result {
	return []osp.Result{
		{Host: host, Type: "Log Message", Name: "HOST_START", Text: "Mon Oct  5 22:23:27 2026"},
		{Host: host, Type: "Log Message", Port: "general/tcp", TestID: "1.3.6.1.4.1.25623.1.0.105937", Name: "OS Detection Consolidation and Reporting", QoD: "80", Text: "Best matching OS:\n\nOS:           Linux Kernel\nCPE:          cpe:/o:linux:kernel"},
		{Host: host, Type: "Alarm", Severity: "2.1", Port: "general/icmp", TestID: "1.3.6.1.4.1.25623.1.0.103190", Name: "ICMP Timestamp Reply Information Disclosure", QoD: "80", Text: "The remote host responded to an ICMP timestamp request."},
		{Host: host, Type: "Log Message", Port: "general/Host_Details", TestID: "1.3.6.1.4.1.25623.1.0.103997", Name: "Host Details", QoD: "80", Text: "<host><detail><name>best_os_txt</name><value>Linux Kernel</value></detail></host>"},
		{Host: host, Type: "Log Message", Name: "HOST_END", Text: "Mon Oct  5 22:25:12 2026"},
	}
}

func TestBlindEngineFailsTheJob(t *testing.T) {
	run := func(results []osp.Result) (*memSink, error) {
		f := osptest.Start(t, &osptest.Fake{Script: []osptest.Step{{Progress: 100, Results: results}}})
		e := newEngine(t, f, fakeNaabu(t, filepath.Join(t.TempDir(), "l")))
		spec, site := inventorySpec()
		sink := &memSink{}
		_, err := e.Run(context.Background(), spec, site, sink)
		return sink, err
	}

	// naabu found ports on 10.30.5.20 and the engine saw none of them: the
	// job fails, keeps the hosts and ports it has, and sends no final chunk,
	// so the control plane does not take the silence for fixed findings.
	sink, err := run(blindResults("10.30.5.20"))
	if !errors.Is(err, ErrBlind) || !strings.Contains(err.Error(), "openvas saw no open port on any host (1 had open ports)") {
		t.Fatalf("blind engine: err=%v", err)
	}
	if len(sink.batches) == 0 {
		t.Fatal("partial results were dropped")
	}
	for _, b := range sink.batches {
		if b.Final {
			t.Fatal("final chunk after a blind scan")
		}
	}

	// Either sign that the engine's port scanner worked is enough: a result
	// on a real port, or the engine's own list of open ports.
	for name, extra := range map[string]osp.Result{
		"service on a port": {Host: "10.30.5.20", Type: "Log Message", Port: "3389/tcp", TestID: "1.3.6.1.4.1.25623.1.0.10330", Name: "Services", QoD: "80", Text: "A Remote Desktop Protocol (RDP) service is running on this port."},
		"open port list":    {Host: "10.30.5.20", Type: "Log Message", Port: "general/Host_Details", TestID: "1.3.6.1.4.1.25623.1.0.103997", Name: "Host Details", QoD: "80", Text: "<host><detail><name>tcp_ports</name><value>445,3389</value></detail></host>"},
	} {
		sink, err := run(append(blindResults("10.30.5.20"), extra))
		if err != nil || len(sink.batches) == 0 || !sink.batches[len(sink.batches)-1].Final {
			t.Fatalf("%s: err=%v batches=%d", name, err, len(sink.batches))
		}
	}
}

func TestUDPModule(t *testing.T) {
	snmp := osp.Result{Host: "10.30.5.99", Type: "Log Message", Port: "161/udp", TestID: "1.3.6.1.4.1.25623.1.0.10265", Name: "An SNMP Agent is running", QoD: "80", Text: "An SNMP server is running on this host."}
	rdp := osp.Result{Host: "10.30.5.20", Type: "Log Message", Port: "3389/tcp", TestID: "1.3.6.1.4.1.25623.1.0.10330", Name: "Services", QoD: "80", Text: "A Remote Desktop Protocol (RDP) service is running on this port."}
	run := func(site v1.SiteConfig, results []osp.Result) (*osptest.Fake, *v1.ScanStats, map[string]v1.Host, error) {
		f := osptest.Start(t, &osptest.Fake{Script: []osptest.Step{{Progress: 100, Results: results}}})
		e := newEngine(t, f, fakeNaabu(t, filepath.Join(t.TempDir(), "l")))
		spec, _ := inventorySpec()
		spec.Modules = append(spec.Modules, v1.ModuleUDP)
		sink := &memSink{}
		stats, err := e.Run(context.Background(), spec, site, sink)
		hosts := map[string]v1.Host{}
		for _, b := range sink.batches {
			for _, h := range b.Hosts {
				hosts[h.IP] = h // later chunks replace the interim one
			}
		}
		return f, stats, hosts, err
	}
	hasNote := func(h v1.Host, note string) bool {
		for _, n := range h.Notes {
			if n == note {
				return true
			}
		}
		return false
	}

	// naabu: .20 has two TCP ports, .21 a fragile-device port, .99 none.
	_, site := inventorySpec()
	f, stats, hosts, err := run(site, append(blindResults("10.30.5.99"), snmp, rdp))
	if err != nil {
		t.Fatal(err)
	}
	start := f.Starts()[0]
	for _, want := range []string{"<hosts>10.30.5.20,10.30.5.99</hosts>", "<ports>T:445,3389,U:53,67,", "<unscanned_closed_udp>0</unscanned_closed_udp>"} {
		if !strings.Contains(start, want) {
			t.Fatalf("start_scan lacks %q: %s", want, start)
		}
	}
	if stats.HostsScanned != 2 || stats.FragileExcluded != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	// The host without a TCP port was tested and its UDP service recorded.
	h99 := hosts["10.30.5.99"]
	if len(h99.Ports) != 1 || h99.Ports[0].Port != 161 || h99.Ports[0].Proto != "udp" || h99.Ports[0].Service != "snmp" {
		t.Fatalf("udp-only host: %+v", h99.Ports)
	}
	if !hasNote(h99, v1.NoteUDPTested) || hasNote(h99, "openvas:skipped-no-open-ports") || !hasNote(hosts["10.30.5.20"], v1.NoteUDPTested) {
		t.Fatalf("notes: %v / %v", h99.Notes, hosts["10.30.5.20"].Notes)
	}
	// A fragile device stays away from every test, UDP included.
	if h21 := hosts["10.30.5.21"]; hasNote(h21, v1.NoteUDPTested) || !hasNote(h21, "fragile:9100") {
		t.Fatalf("fragile host: %v", h21.Notes)
	}

	// Only hosts with TCP ports can show a blind engine: when the one such
	// host says nothing on a port, the job fails even though UDP answered.
	if _, _, _, err := run(site, append(blindResults("10.30.5.20"), snmp)); !errors.Is(err, ErrBlind) {
		t.Fatalf("blind on TCP with a UDP answer: %v", err)
	}
	// The same when that UDP answer comes from the host itself.
	own := snmp
	own.Host = "10.30.5.20"
	if _, _, _, err := run(site, append(blindResults("10.30.5.20"), own)); !errors.Is(err, ErrBlind) {
		t.Fatalf("blind on TCP with a UDP answer from the same host: %v", err)
	}
	// And when no scanned host has a TCP port, silence proves nothing.
	site.FragilePorts = []int{9100, 3389}
	f, stats, hosts, err = run(site, blindResults("10.30.5.99"))
	if err != nil || stats.HostsScanned != 1 || !strings.Contains(f.Starts()[0], "<hosts>10.30.5.99</hosts><ports>U:53,") {
		t.Fatalf("udp-only job: err=%v stats=%+v start=%s", err, stats, f.Starts()[0])
	}
	if !hasNote(hosts["10.30.5.99"], v1.NoteUDPTested) {
		t.Fatalf("notes: %v", hosts["10.30.5.99"].Notes)
	}
}

func TestTimeout(t *testing.T) {
	f := fakeOSPD(t, true)
	e := newEngine(t, f, fakeNaabu(t, filepath.Join(t.TempDir(), "l")))
	spec, site := inventorySpec()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_, err := e.Run(ctx, spec, site, &memSink{})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err=%v", err)
	}
}

func TestPortArgsAndParsing(t *testing.T) {
	if a, _ := portArgs("full"); a[1] != "-" {
		t.Fatal(a)
	}
	if a, _ := portArgs("22,80,1000-1010"); a[1] != "22,80,1000-1010" {
		t.Fatal(a)
	}
	if _, err := portArgs("70000"); err == nil {
		t.Fatal("bad port accepted")
	}
	r := parseNaabu([]byte(`{"ip":"10.0.0.1","port":80,"protocol":"tcp"}` + "\n" + `{"host":"10.0.0.2","port":{"Port":443,"Protocol":"tcp"}}` + "\n" + `{"host":"name-only"}` + "\n" + `{"ip":"10.0.0.3"}` + "\n10.0.0.4\n\n[INF] banner\n"))
	if len(r.Order) != 4 || r.Hosts["10.0.0.1"][80] != "tcp" || r.Hosts["10.0.0.2"][443] != "tcp" || len(r.Hosts["10.0.0.3"]) != 0 || len(r.Hosts["10.0.0.4"]) != 0 {
		t.Fatalf("%+v", r)
	}
	if openvasPortList(map[int]bool{443: true, 22: true}, []int{53}) != "T:22,443,U:53" {
		t.Fatal("port list")
	}
	if serviceFromText("A web server is running on this port") != "http" || serviceFromText("A Foo daemon is running") != "foo" || osFamily("cpe:/o:linux:kernel", "") != "linux" {
		t.Fatal("heuristics")
	}
	cfg, _ := ConfigFor("full")
	for _, fam := range cfg.Families {
		if ExcludedFamilies[fam] || strings.Contains(fam, "Local Security Checks") {
			t.Fatalf("full config selects %q", fam)
		}
	}
}
