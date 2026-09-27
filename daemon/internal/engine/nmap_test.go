package engine

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// nmapXML is a trimmed nmap -oX document for the lab hosts: the WMS box
// with RDP/SMB identified and a confident Windows OS match, the printer
// (which the fragile policy keeps out and must be ignored if reported),
// and a host the job never targeted.
const nmapXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV" start="1" version="7.93">
<host><status state="up" reason="user-set"/>
<address addr="10.30.5.20" addrtype="ipv4"/><address addr="00:50:56:AB:CD:EF" addrtype="mac" vendor="VMware"/>
<hostnames><hostname name="wms-app-01.acme.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds" product="Windows Server 2008 R2 microsoft-ds" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows_server_2008:r2</cpe></service></port>
<port protocol="tcp" portid="3389"><state state="open" reason="syn-ack"/><service name="ms-wbt-server" product="Microsoft Terminal Services" method="probed" conf="10"><cpe>cpe:/a:microsoft:terminal_services</cpe><cpe>cpe:/o:microsoft:windows</cpe></service></port>
<port protocol="tcp" portid="8080"><state state="closed" reason="reset"/><service name="http-proxy" method="table" conf="3"/></port>
</ports>
<os><osmatch name="Microsoft Windows Server 2008 R2 SP1" accuracy="97" line="1"><osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2008" accuracy="97"><cpe>cpe:/o:microsoft:windows_server_2008:r2:sp1</cpe></osclass></osmatch>
<osmatch name="Microsoft Windows 7" accuracy="90" line="2"><osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="7" accuracy="90"/></osmatch></os>
</host>
<host><status state="up"/><address addr="10.30.5.21" addrtype="ipv4"/><ports><port protocol="tcp" portid="9100"><state state="open"/><service name="jetdirect" product="HP JetDirect" conf="10"/></port></ports></host>
<host><status state="up"/><address addr="10.30.9.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2" conf="10"/></port></ports></host>
<host><status state="up"/><address addr="10.30.5.99" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1 Debian 2" conf="10"><cpe>cpe:/a:openbsd:openssh:9.2p1</cpe></service></port></ports>
<os><osmatch name="Linux 5.10 - 6.1" accuracy="95"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="95"><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass></osmatch></os></host>
</nmaprun>
`

// fakeNmap logs its arguments and prints the canned XML; a truncated
// variant exercises the partial-output path.
func fakeNmap(t *testing.T, logPath string, truncate bool) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake nmap is a POSIX shell script")
	}
	xmlPath := filepath.Join(t.TempDir(), "out.xml")
	body := nmapXML
	if truncate {
		body = body[:strings.Index(body, "<host><status state=\"up\"/><address addr=\"10.30.9.9\"")]
	}
	if err := os.WriteFile(xmlPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho \"$@\" >> \"" + logPath + "\"\ncat \"" + xmlPath + "\"\n"
	p := filepath.Join(t.TempDir(), "nmap")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseNmap(t *testing.T) {
	r, err := parseNmap([]byte(nmapXML))
	if err != nil || len(r.Hosts) != 4 {
		t.Fatalf("parse: %v hosts=%d", err, len(r.Hosts))
	}
	h := r.Hosts[0]
	if h.ip() != "10.30.5.20" || h.mac() != "00:50:56:ab:cd:ef" || h.ptr() != "wms-app-01.acme.local" || len(h.Ports) != 3 || h.Ports[0].Service.Conf != 10 {
		t.Fatalf("host 0: ip=%s mac=%s ptr=%s ports=%d", h.ip(), h.mac(), h.ptr(), len(h.Ports))
	}
	g := bestOSMatch(h.OS.Matches)
	if g == nil || g.Confidence != 0.97 || g.Family != "windows" || g.CPE != "cpe:/o:microsoft:windows_server_2008:r2:sp1" || g.Source != sourceNmapOS {
		t.Fatalf("os: %+v", g)
	}
	if bestOSMatch([]nmapOSMatch{{Name: "guess", Accuracy: 60}}) != nil {
		t.Fatal("low-accuracy match accepted")
	}
	if l := nmapServiceLabel("http", "ssl"); l != "https" {
		t.Fatalf("ssl/http label %q", l)
	}
	if l := nmapServiceLabel("tcpwrapped", ""); l != "" {
		t.Fatalf("tcpwrapped label %q", l)
	}
	if l := nmapServiceLabel("EtherNet-IP-1", ""); l != "ethernet-ip" {
		t.Fatalf("enip label %q", l)
	}
	// A truncated document still yields the hosts decoded so far.
	cut := nmapXML[:strings.Index(nmapXML, "<host><status state=\"up\"/><address addr=\"10.30.9.9\"")]
	if r, err := parseNmap([]byte(cut)); err != nil || len(r.Hosts) != 2 {
		t.Fatalf("truncated: %v hosts=%d", err, len(r.Hosts))
	}
	if _, err := parseNmap([]byte("garbage")); err == nil {
		t.Fatal("garbage parsed")
	}
}

// TestFingerprintPass runs the full pipeline with the fake naabu, ospd and
// nmap: nmap fills products, versions, CPEs and a higher-confidence OS
// guess; the fragile printer is never handed to nmap; hosts outside the
// job are ignored.
func TestFingerprintPass(t *testing.T) {
	logDir := t.TempDir()
	f := fakeOSPD(t, false)
	e := newEngine(t, f, fakeNaabu(t, filepath.Join(logDir, "naabu.log")))
	e.NmapPath = fakeNmap(t, filepath.Join(logDir, "nmap.log"), false)
	e.Privileged = func() bool { return true }
	spec, site := inventorySpec()
	spec.Modules = append(spec.Modules, v1.ModuleFingerprint)
	spec.DefaultsFor(v1.ModeInventory)
	sink := &memSink{}
	stats, err := e.Run(context.Background(), spec, site, sink)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Fingerprinted != 1 || len(stats.Warnings) != 0 || stats.FragileExcluded != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	argLog, _ := os.ReadFile(filepath.Join(logDir, "nmap.log"))
	args := strings.TrimSpace(string(argLog))
	for _, want := range []string{"-sV", "--version-intensity 5", "-Pn", "-n", "-oX -", "--max-rate 300", "-p T:445,3389", "--privileged -sS -O --osscan-limit", "--exclude 10.30.5.1", "-e lan0"} {
		if !strings.Contains(args, want) {
			t.Fatalf("nmap args missing %q: %s", want, args)
		}
	}
	if !strings.HasSuffix(args, " 10.30.5.20") || strings.Contains(args, "10.30.5.21") || strings.Contains(args, "10.30.5.99") || strings.Contains(args, "--script") {
		t.Fatalf("nmap targets: fragile host, port-less host or scripts: %s", args)
	}
	final := sink.batches[len(sink.batches)-1]
	byIP := map[string]v1.Host{}
	for i := len(sink.batches) - 2; i < len(sink.batches); i++ {
		for _, h := range sink.batches[i].Hosts {
			byIP[h.IP] = h
		}
	}
	h20 := byIP["10.30.5.20"]
	if h20.OSGuess == nil || h20.OSGuess.Source != sourceNmapOS || h20.OSGuess.Confidence != 0.97 || h20.OSGuess.Family != "windows" {
		t.Fatalf("h20 os: %+v", h20.OSGuess)
	}
	if h20.Hostname != "wms-app-01" {
		t.Fatalf("openvas hostname overridden: %q", h20.Hostname)
	}
	var rdp, smb *v1.Port
	for i := range h20.Ports {
		switch h20.Ports[i].Port {
		case 3389:
			rdp = &h20.Ports[i]
		case 445:
			smb = &h20.Ports[i]
		}
	}
	if rdp == nil || rdp.Service != "rdp" || rdp.Product != "Microsoft Terminal Services" || rdp.CPE != "cpe:/a:microsoft:terminal_services" || rdp.Source != sourceNmapVersion {
		t.Fatalf("rdp port: %+v", rdp)
	}
	if smb == nil || smb.Service != "smb" || smb.Product != "Windows Server 2008 R2 microsoft-ds" || smb.CPE != "" {
		t.Fatalf("smb port: %+v", smb)
	}
	if len(h20.Ports) != 2 {
		t.Fatalf("closed port added: %+v", h20.Ports)
	}
	// Hosts without an open port are not handed to nmap, so whatever the
	// output says about them is ignored; so is anything the job never targeted.
	h99 := byIP["10.30.5.99"]
	if len(h99.Ports) != 0 || h99.OSGuess != nil {
		t.Fatalf("port-less host merged from nmap output: %+v", h99)
	}
	h21 := byIP["10.30.5.21"]
	if len(h21.Ports) != 1 || h21.Ports[0].Product != "" {
		t.Fatalf("fragile host merged from nmap output: %+v", h21.Ports)
	}
	if _, ok := byIP["10.30.9.9"]; ok {
		t.Fatal("untargeted host reported")
	}
	if final.Stats.PhaseDurationS[PhaseFingerprint] < 0 {
		t.Fatal("no fingerprint phase timing")
	}
	phases := map[string]bool{}
	for _, p := range sink.progress {
		phases[p.Phase] = true
	}
	if !phases[PhaseFingerprint] {
		t.Fatal("no progress for the fingerprint phase")
	}
}

func TestFingerprintDegradesGracefully(t *testing.T) {
	logDir := t.TempDir()
	f := fakeOSPD(t, false)
	spec, site := inventorySpec()
	spec.Modules = append(spec.Modules, v1.ModuleFingerprint)
	spec.DefaultsFor(v1.ModeInventory)

	// No nmap: warning, job still done with openvas results.
	e := newEngine(t, f, fakeNaabu(t, filepath.Join(logDir, "naabu.log")))
	sink := &memSink{}
	stats, err := e.Run(context.Background(), spec, site, sink)
	if err != nil || len(stats.Warnings) != 1 || !strings.Contains(stats.Warnings[0], "nmap not installed") || stats.Findings != 1 || stats.Fingerprinted != 0 {
		t.Fatalf("without nmap: %v %+v", err, stats)
	}

	// Unprivileged: connect scan, no OS detection.
	f2 := fakeOSPD(t, false)
	e = newEngine(t, f2, fakeNaabu(t, filepath.Join(logDir, "naabu2.log")))
	e.NmapPath = fakeNmap(t, filepath.Join(logDir, "nmap2.log"), true)
	e.Privileged = func() bool { return false }
	sink = &memSink{}
	if stats, err = e.Run(context.Background(), spec, site, sink); err != nil || stats.Fingerprinted != 1 {
		t.Fatalf("truncated output: %v %+v", err, stats)
	}
	args, _ := os.ReadFile(filepath.Join(logDir, "nmap2.log"))
	if !strings.Contains(string(args), "--unprivileged -sT") || strings.Contains(string(args), "-O") {
		t.Fatalf("unprivileged args: %s", args)
	}

	// A failing nmap is a warning, not a failed job.
	f3 := fakeOSPD(t, false)
	e = newEngine(t, f3, fakeNaabu(t, filepath.Join(logDir, "naabu3.log")))
	bad := filepath.Join(t.TempDir(), "nmap")
	_ = os.WriteFile(bad, []byte("#!/bin/sh\necho 'nmap: broken' >&2\nexit 1\n"), 0o755)
	e.NmapPath = bad
	sink = &memSink{}
	if stats, err = e.Run(context.Background(), spec, site, sink); err != nil || len(stats.Warnings) != 1 || !strings.Contains(stats.Warnings[0], "broken") || stats.Findings != 1 {
		t.Fatalf("broken nmap: %v %+v", err, stats)
	}
}

// TestFullRangeBudget: the appliance refuses a full-range port scan that
// cannot finish inside what is left of max_duration_s, before any port
// probe leaves, and reports why; discovery results are still emitted.
func TestFullRangeBudget(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "naabu.log")
	f := fakeOSPD(t, false)
	e := newEngine(t, f, fakeNaabu(t, logPath))
	spec, site := inventorySpec()
	spec.Ports = v1.PortsFull
	spec.Window = &v1.Window{MaxDurationS: 600}
	sink := &memSink{}
	_, err := e.Run(context.Background(), spec, site, sink)
	if !errors.Is(err, ErrBudget) || !strings.Contains(err.Error(), "65535-port scan of 3 live hosts at 300 pps") {
		t.Fatalf("budget: %v", err)
	}
	argLog, _ := os.ReadFile(logPath)
	if lines := strings.Split(strings.TrimSpace(string(argLog)), "\n"); len(lines) != 1 {
		t.Fatalf("port scan ran despite the budget: %q", lines)
	}
	if len(sink.batches) == 0 || sink.batches[len(sink.batches)-1].Final || len(sink.batches[0].Hosts) != 2 {
		t.Fatalf("discovery results not emitted as partial: %d batches", len(sink.batches))
	}
	// Enough time: the scan runs with -p -.
	f2 := fakeOSPD(t, false)
	e = newEngine(t, f2, fakeNaabu(t, logPath))
	spec.Window = &v1.Window{MaxDurationS: 24 * 3600}
	spec.Rate.PPS = 5000
	sink = &memSink{}
	if _, err := e.Run(context.Background(), spec, site, sink); err != nil {
		t.Fatal(err)
	}
	argLog, _ = os.ReadFile(logPath)
	if !strings.Contains(string(argLog), "-p -") {
		t.Fatalf("full range not requested: %s", argLog)
	}
	// The deadline of the job context counts too.
	f3 := fakeOSPD(t, false)
	e = newEngine(t, f3, fakeNaabu(t, logPath))
	e.Now = time.Now
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := e.Run(ctx, spec, site, &memSink{}); !errors.Is(err, ErrBudget) {
		t.Fatalf("context deadline ignored: %v", err)
	}
	_ = slog.Default()
}
