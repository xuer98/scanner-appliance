package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/tprm/scanner-appliance/internal/bundle"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/ca"
	"github.com/tprm/scanner-appliance/controlplane/pkg/server"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/daemon/internal/engine"
	"github.com/tprm/scanner-appliance/daemon/internal/heartbeat"
	"github.com/tprm/scanner-appliance/daemon/internal/jobs"
	"github.com/tprm/scanner-appliance/daemon/internal/nvt"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/daemon/internal/osp/osptest"
	"github.com/tprm/scanner-appliance/daemon/internal/spool"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
	"github.com/tprm/scanner-appliance/daemon/internal/tty"
)

const bluekeep = "1.3.6.1.4.1.25623.1.0.108587"

// labNaabu answers like naabu against the "fake warehouse" segment of PLAN §18.3.
func labNaabu(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake naabu is a POSIX shell script")
	}
	script := `#!/bin/sh
case " $* " in
  *" -sn "*) printf '%s\n' 10.30.5.20 10.30.5.21 10.30.5.99 10.30.5.1 ;;
  *) printf '%s\n' '{"ip":"10.30.5.20","port":3389,"protocol":"tcp"}' '{"ip":"10.30.5.20","port":445,"protocol":"tcp"}' '{"ip":"10.30.5.21","port":9100,"protocol":"tcp"}' ;;
esac
`
	p := filepath.Join(t.TempDir(), "naabu")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// labOSPD seeds one host with a known CVE the way the lab's vulnerable
// service would be detected (PLAN §18.2: qod ≥ 70).
func labOSPD(t *testing.T) *osptest.Fake {
	return osptest.Start(t, &osptest.Fake{
		VTs: map[string]osptest.VT{
			bluekeep:                       {Name: "Microsoft Windows RDP RCE (BlueKeep)", Family: "Windows", QoD: 97, QoDType: "remote_active", CVEs: []string{"CVE-2019-0708"}, CVSSv2: "AV:N/AC:L/Au:N/C:C/I:C/A:C", Solution: "Apply KB4499175"},
			"1.3.6.1.4.1.25623.1.0.10330":  {Name: "Services", Family: "Service detection", QoD: 80},
			"1.3.6.1.4.1.25623.1.0.105937": {Name: "OS Detection Consolidation", Family: "General", QoD: 80},
		},
		Script: []osptest.Step{
			{Progress: 30, Results: []osp.Result{
				{Host: "10.30.5.20", Type: "Log Message", Port: "3389/tcp", TestID: "1.3.6.1.4.1.25623.1.0.10330", Name: "Services", QoD: "80", Text: "A Remote Desktop Protocol (RDP) service is running on this port."},
				{Host: "10.30.5.20", Type: "Host Detail", Port: "general/tcp", TestID: "1.3.6.1.4.1.25623.1.0.105937", Name: "OS Detection", Text: "<host><detail><name>best_os_cpe</name><value>cpe:/o:microsoft:windows_server_2008:r2</value></detail><detail><name>MAC</name><value>00:50:56:AB:CD:EF</value></detail></host>"},
			}},
			{Progress: 80, Results: []osp.Result{
				{Host: "10.30.5.20", Hostname: "wms-app-01", Type: "Alarm", Severity: "9.8", Port: "3389/tcp", TestID: bluekeep, Name: "Microsoft Windows RDP RCE (BlueKeep)", QoD: "97", Text: "The host is vulnerable."},
			}},
		},
	})
}

type cp struct {
	mem        *store.Memory
	mtls       *httptest.Server
	enroll     *httptest.Server
	roots      *x509.CertPool
	srv        *server.Server
	releaseKey *ecdsa.PrivateKey
	adminFn    func(method, path string, body, out any) int
	rawAdminFn func(method, path string, body []byte, headers map[string]string) (int, []byte)
}

func newCP(t *testing.T) *cp {
	t.Helper()
	pkiDir := t.TempDir()
	if err := ca.Init(pkiDir, "E2E"); err != nil {
		t.Fatal(err)
	}
	issuer, err := ca.Load(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := issuer.IssueServer([]string{"127.0.0.1"})
	serverCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	roots := x509.NewCertPool()
	rootPEM, _ := os.ReadFile(pkiDir + "/root.pem")
	roots.AppendCertsFromPEM(rootPEM)
	mem := store.NewMemory()
	mtls := httptest.NewUnstartedServer(nil)
	mtls.TLS = server.TLSConfigMTLS(serverCert, issuer)
	mtls.Config.Handler = http.NotFoundHandler()
	mtls.StartTLS()
	relKey, err := bundle.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Phase 3: a release key, a real object store and a short canary period.
	srv := server.New(server.Config{Store: mem, CA: issuer, PublicURL: mtls.URL, AdminToken: "tok", Logger: slog.Default(),
		Objects: server.DirObjects{Root: t.TempDir()}, ReleaseKeys: []*ecdsa.PublicKey{&relKey.PublicKey}, CanaryPeriod: time.Millisecond})
	mtls.Config.Handler = srv.MTLSHandler()
	enrollSrv := httptest.NewUnstartedServer(srv.EnrollHandler())
	enrollSrv.TLS = server.TLSConfigEnroll(serverCert)
	enrollSrv.StartTLS()
	t.Cleanup(func() { mtls.Close(); enrollSrv.Close() })
	c := &cp{mem: mem, mtls: mtls, enroll: enrollSrv, roots: roots, srv: srv, releaseKey: relKey}
	c.rawAdminFn = func(method, path string, body []byte, headers map[string]string) (int, []byte) {
		req, _ := http.NewRequest(method, mtls.URL+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	c.adminFn = func(method, path string, body, out any) int {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req, _ := http.NewRequest(method, mtls.URL+path, &buf)
		req.Header.Set("Authorization", "Bearer tok")
		resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	return c
}

func TestPhase2(t *testing.T) {
	c := newCP(t)
	admin := c.adminFn
	var created v1.AdminCreateApplianceResponse
	if st := admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme", Site: "Reno", AllowedCIDRs: []string{"10.30.0.0/16"}}, &created); st != 201 {
		t.Fatalf("create %d", st)
	}

	// Daemon with the lab engine: fake ospd on a socket, fake naabu on disk.
	fake := labOSPD(t)
	st := state.New(t.TempDir(), t.TempDir())
	s, _ := st.Load()
	s.EnrollURL = c.enroll.URL
	s.PendingCode = created.Code
	s.IntervalOverrideS = 1
	_ = st.Save(s)
	ospc := osp.New(fake.Socket)
	eng := &engine.Engine{NaabuPath: labNaabu(t), OSP: ospc, NVT: nvt.New(filepath.Join(st.Dir, "nvt-cache"), ospc, nil), Log: slog.Default(),
		PollInterval: 50 * time.Millisecond, ScanType: "c", IfaceExists: func(string) bool { return true }}
	runner := &jobs.Runner{Store: st, Engine: eng, Spool: &spool.Spool{Dir: filepath.Join(st.Dir, "spool")}, Roots: c.roots, Log: slog.Default()}
	loop := &heartbeat.Loop{Store: st, Roots: c.roots, Version: "e2e", Log: slog.Default(), PowerOff: func() error { return nil }, OSPSocket: fake.Socket, Jobs: runner}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go loop.Run(ctx)

	var view v1.AdminApplianceView
	waitFor(t, 20*time.Second, func() bool {
		admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &view)
		return view.Status == v1.StatusEnrolled && view.Online && view.LastHeartbeat != nil && view.LastHeartbeat.Engine.Ready()
	}, "appliance online with engine ready")
	if view.FeedVersion != "202609260530" || view.LastHeartbeat.StopAll {
		t.Fatalf("heartbeat: %+v", view.LastHeartbeat)
	}
	local, _ := st.Load()
	if local.SpoolPubKey == "" || local.SpoolKID == "" || local.Site.MaxConcurrency != 16 {
		t.Fatalf("spool key / site config not stored: %+v", local)
	}

	// DoD: a discovery job runs against the lab and reports done.
	var job1 v1.AdminJobView
	if st := admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeDiscovery, Targets: []string{"10.30.5.0/24"}, Excludes: []string{"10.30.5.1"}}, &job1); st != 201 {
		t.Fatalf("job1 %d", st)
	}
	waitFor(t, 30*time.Second, func() bool {
		admin("GET", "/admin/jobs/"+job1.ID, nil, &job1)
		return job1.Status == v1.JobDone
	}, "discovery job done")
	if job1.Stats == nil || job1.Stats.HostsAlive != 3 || job1.StartedAt == nil || job1.Batches == 0 {
		t.Fatalf("job1: %+v", job1)
	}
	var hosts []v1.AdminHostView
	admin("GET", "/admin/jobs/"+job1.ID+"/hosts", nil, &hosts)
	if len(hosts) != 3 || hosts[0].Source != v1.SourceAppliance {
		t.Fatalf("job1 hosts: %+v", hosts)
	}

	// DoD: an inventory job detects the seeded CVE with qod ≥ 70.
	var job2 v1.AdminJobView
	if st := admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}, Excludes: []string{"10.30.5.1"}}, &job2); st != 201 {
		t.Fatalf("job2 %d", st)
	}
	waitFor(t, 40*time.Second, func() bool {
		admin("GET", "/admin/jobs/"+job2.ID, nil, &job2)
		return job2.Status == v1.JobDone
	}, "inventory job done")
	if job2.Stats == nil || job2.Stats.Findings != 1 || job2.Stats.FragileExcluded != 1 || job2.Stats.HostsScanned != 1 {
		t.Fatalf("job2 stats: %+v", job2.Stats)
	}
	admin("GET", "/admin/jobs/"+job2.ID+"/hosts", nil, &hosts)
	var wms, printer *v1.AdminHostView
	for i := range hosts {
		switch hosts[i].IP {
		case "10.30.5.20":
			wms = &hosts[i]
		case "10.30.5.21":
			printer = &hosts[i]
		}
	}
	if wms == nil || printer == nil {
		t.Fatalf("hosts: %+v", hosts)
	}
	if len(wms.Findings) != 1 || wms.Findings[0].CVE[0] != "CVE-2019-0708" || wms.Findings[0].QoD < 70 || wms.Findings[0].State != v1.FindingNetworkObserved || wms.Findings[0].Severity != v1.SeverityCritical || wms.Findings[0].Family != "Windows" {
		t.Fatalf("seeded CVE not detected: %+v", wms.Findings)
	}
	if wms.OSGuess == nil || wms.OSGuess.Family != "windows" || wms.MAC != "00:50:56:ab:cd:ef" || wms.Hostname != "wms-app-01" || len(wms.Ports) != 2 {
		t.Fatalf("wms host: %+v", wms)
	}
	if len(printer.Notes) != 1 || printer.Notes[0] != "fragile:9100" {
		t.Fatalf("fragile policy: %+v", printer)
	}
	if n := c.mem.NVT(bluekeep); n == nil || n.Family != "Windows" {
		t.Fatal("nvt mirror missing")
	}

	// DoD: results correlate with agent data (MAC match → both, finding confirmed).
	var inv v1.AdminAgentInventoryResponse
	if st := admin("POST", "/admin/sites/"+job2.SiteID+"/agent-inventory", v1.AdminAgentInventoryRequest{Hosts: []v1.AgentHost{{AgentID: "wz-7", Hostname: "WMS-APP-01", MACs: []string{"00-50-56-AB-CD-EF"}, IP: "10.30.5.44",
		Packages: []v1.AgentPackage{{Name: "termsrv", Version: "6.1"}}, Findings: []v1.AgentFinding{{CVE: "CVE-2019-0708", Package: "termsrv", CVSS: 9.8}}}}}, &inv); st != 200 || inv.Merged != 1 {
		t.Fatalf("agent inventory: %d %+v", st, inv)
	}
	admin("GET", "/admin/sites/"+job2.SiteID+"/hosts", nil, &hosts)
	for _, h := range hosts {
		if h.IP == "10.30.5.20" {
			if h.Source != v1.SourceBoth || h.AgentID != "wz-7" || h.Findings[0].State != v1.FindingConfirmed || len(h.Findings[0].Evidence) != 2 || h.Findings[0].Source != v1.SourceBoth {
				t.Fatalf("correlation: %+v", h)
			}
		}
	}

	// DoD: stop_all halts an in-flight OSP scan.
	fake.SetHang(true)
	var job3 v1.AdminJobView
	if st := admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"}, Excludes: []string{"10.30.5.1"}}, &job3); st != 201 {
		t.Fatalf("job3 %d", st)
	}
	waitFor(t, 30*time.Second, func() bool {
		admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &view)
		return view.LastHeartbeat != nil && view.LastHeartbeat.CurrentJob != nil && view.LastHeartbeat.CurrentJob.ID == job3.ID && view.LastHeartbeat.CurrentJob.Phase == engine.PhaseOpenVAS
	}, "openvas phase in flight")
	if view.LastHeartbeat.State != heartbeat.StateScanning {
		t.Fatalf("state %s", view.LastHeartbeat.State)
	}
	live, _ := st.ReadStatus()
	if live.CurrentJob == nil || live.CurrentJob.ID != job3.ID {
		t.Fatalf("status.json: %+v", live)
	}
	admin("POST", "/admin/appliances/"+created.ApplianceID+"/directives", v1.AdminDirectiveRequest{Type: v1.DirectiveStopAll}, nil)
	waitFor(t, 30*time.Second, func() bool {
		admin("GET", "/admin/jobs/"+job3.ID, nil, &job3)
		return job3.Status == v1.JobFailed
	}, "job halted")
	if !strings.Contains(job3.RejectReason, "stop_all") || len(fake.Stops()) != 1 {
		t.Fatalf("halt: reason=%q stops=%v", job3.RejectReason, fake.Stops())
	}
	waitFor(t, 10*time.Second, func() bool {
		admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &view)
		return view.LastHeartbeat != nil && view.LastHeartbeat.CurrentJob == nil && view.LastHeartbeat.StopAll && view.LastHeartbeat.PendingResults == 0
	}, "idle after stop with spool flushed")
	// Partial results (ports from the portscan phase) still arrived.
	admin("GET", "/admin/jobs/"+job3.ID+"/hosts", nil, &hosts)
	if len(hosts) == 0 {
		t.Fatal("no partial results after stop")
	}
	// While stop_all is active nothing is dispatched; clearing it resumes.
	var job4 v1.AdminJobView
	admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeDiscovery, Targets: []string{"10.30.5.0/24"}}, &job4)
	time.Sleep(2500 * time.Millisecond)
	admin("GET", "/admin/jobs/"+job4.ID, nil, &job4)
	if job4.Status != v1.JobQueued {
		t.Fatalf("dispatched under stop_all: %s", job4.Status)
	}
	admin("POST", "/admin/appliances/"+created.ApplianceID+"/directives", v1.AdminDirectiveRequest{Type: v1.DirectiveStopAll, Payload: map[string]any{"clear": true}}, nil)
	waitFor(t, 30*time.Second, func() bool {
		admin("GET", "/admin/jobs/"+job4.ID, nil, &job4)
		return job4.Status == v1.JobDone
	}, "job after stop_all cleared")

	// Console shows engine and no current job.
	var out bytes.Buffer
	con := &tty.Console{In: strings.NewReader("1\n"), Out: &out, Store: st, Roots: c.roots, Version: "e2e", Idle: time.Second, PowerOff: func() error { return nil }}
	_ = con.Run(ctx)
	if !strings.Contains(out.String(), "Engine:          ready") {
		t.Fatalf("console:\n%s", out.String())
	}
}

// tlsConfig trusts the e2e control plane's root.
func (c *cp) tlsConfig() *tls.Config { return &tls.Config{RootCAs: c.roots} }
