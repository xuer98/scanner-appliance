package e2e

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/server"
	"github.com/tprm/scanner-appliance/daemon/internal/engine"
	"github.com/tprm/scanner-appliance/daemon/internal/heartbeat"
	"github.com/tprm/scanner-appliance/daemon/internal/jobs"
	"github.com/tprm/scanner-appliance/daemon/internal/nvt"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/daemon/internal/osp/osptest"
	"github.com/tprm/scanner-appliance/daemon/internal/spool"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

// TestPhase6 walks the Qualys replacement path end to end: a real scan
// through the daemon opens a finding, a Qualys export imported as
// external evidence merges with it and the parity report scores the
// appliance, a rescan of the same scope that no longer sees the finding
// closes it and the webhook receiver gets the events, and the summary,
// export and metrics endpoints reflect it all.
func TestPhase6(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses shell-script fakes")
	}
	c := newCP(t)
	admin := c.adminFn
	var created v1.AdminCreateApplianceResponse
	if st := admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme", Site: "Fresno", AllowedCIDRs: []string{"10.30.0.0/16"}}, &created); st != 201 {
		t.Fatalf("create %d", st)
	}
	// Webhook receiver.
	var mu sync.Mutex
	events := map[string]int{}
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !server.VerifyWebhookSignature("e2e", r.Header.Get("X-Webhook-Signature"), body, time.Now(), time.Minute) {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		events[r.Header.Get("X-Webhook-Event")]++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer rcv.Close()
	if st := admin("POST", "/admin/webhooks", v1.AdminWebhookRequest{URL: rcv.URL, Secret: "e2e"}, nil); st != 201 {
		t.Fatalf("webhook: %d", st)
	}
	wctx, wcancel := context.WithCancel(context.Background())
	defer wcancel()
	go c.srv.RunWebhooks(wctx)

	// The lab ospd finds BlueKeep on the first scan and nothing on the
	// second (the host was patched).
	fake := osptest.Start(t, &osptest.Fake{
		VTs: map[string]osptest.VT{bluekeep: {Name: "Microsoft Windows RDP RCE (BlueKeep)", Family: "Windows", QoD: 97, QoDType: "remote_active", CVEs: []string{"CVE-2019-0708"}, CVSSv3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		Script: []osptest.Step{{Progress: 100, Results: []osp.Result{
			{Host: "10.30.5.20", Type: "Alarm", Severity: "9.8", Port: "3389/tcp", TestID: bluekeep, Name: "Microsoft Windows RDP RCE (BlueKeep)", QoD: "97", Text: "vulnerable"},
		}}},
	})
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
	loop := &heartbeat.Loop{Store: st, Roots: c.roots, Version: "e2e", Log: slog.Default(), PowerOff: func() error { return nil }, Reboot: func() error { return nil },
		OSPSocket: fake.Socket, Jobs: runner}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go loop.Run(ctx)
	waitFor(t, 20*time.Second, func() bool {
		var v v1.AdminApplianceView
		admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &v)
		return v.Status == v1.StatusEnrolled && v.Online && v.LastHeartbeat != nil && v.LastHeartbeat.Engine.Ready()
	}, "appliance online")
	runInventory := func() v1.AdminJobView {
		t.Helper()
		var job v1.AdminJobView
		if stc := admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}, Excludes: []string{"10.30.5.1"}}, &job); stc != 201 {
			t.Fatalf("job %d", stc)
		}
		waitFor(t, 40*time.Second, func() bool {
			var j v1.AdminJobView
			admin("GET", "/admin/jobs/"+job.ID, nil, &j)
			job = j
			return j.Status == v1.JobDone
		}, "inventory job done")
		return job
	}
	findings := func() map[string]v1.AdminFindingView {
		var list []v1.AdminFindingView
		admin("GET", "/admin/sites/"+created.SiteID+"/findings", nil, &list)
		out := map[string]v1.AdminFindingView{}
		for _, f := range list {
			out[f.NVTOID+"|"+f.ExternalID] = f
		}
		return out
	}

	// Cycle 1: the appliance opens BlueKeep with inventory scope.
	job1 := runInventory()
	if job1.Stats.Findings != 1 {
		t.Fatalf("cycle 1: %+v", job1.Stats)
	}
	var bk v1.AdminFindingView
	for _, f := range findings() {
		if f.NVTOID == bluekeep {
			bk = f
		}
	}
	if bk.ID == "" || bk.Status != v1.FindingOpen || bk.Scope != v1.ScopeInventory || bk.Overdue || bk.SLADays == 0 {
		t.Fatalf("bluekeep after cycle 1: %+v", bk)
	}

	// Qualys saw the same CVE plus one the appliance did not.
	csvExport := "IP,DNS,OS,QID,Title,Type,Severity,Port,Protocol,CVE ID,CVSS3 Base,Solution,Results\n" +
		"10.30.5.20,wms-app-01,Windows Server 2008 R2,91534,Microsoft RDP RCE (BlueKeep),Vuln,5,3389,tcp,CVE-2019-0708,9.8,Apply KB4499175,vulnerable\n" +
		"10.30.5.20,wms-app-01,Windows Server 2008 R2,90007,SMBv1 Enabled,Practice,3,445,tcp,\"CVE-2017-0144\",5.0,Disable SMBv1,negotiated\n"
	req, _ := http.NewRequest("POST", c.mtls.URL+"/admin/sites/"+created.SiteID+"/external-scans/qualys", bytes.NewReader([]byte(csvExport)))
	stc, body := c.rawAdminFn("POST", "/admin/sites/"+created.SiteID+"/external-scans/qualys", []byte(csvExport), map[string]string{"Content-Type": "text/csv"})
	_ = req
	var imp v1.ExternalScanResponse
	_ = json.Unmarshal(body, &imp)
	if stc != 200 || imp.Hosts != 1 || imp.HostsMerged != 1 || imp.Findings != 2 || imp.FindingsNew != 1 {
		t.Fatalf("import: %d %s", stc, body)
	}
	var par v1.AdminParityReport
	if stc := admin("GET", "/admin/sites/"+created.SiteID+"/parity?days=7&min_severity=low", nil, &par); stc != 200 || par.CVEs.Both != 1 || par.CVEs.ExternalOnly != 1 || par.DetectionRate != 0.5 || par.Hosts.Both != 1 {
		t.Fatalf("parity: %d %+v", stc, par)
	}
	if len(par.ExternalOnly) != 1 || par.ExternalOnly[0].CVE != "CVE-2017-0144" || par.ExternalOnly[0].ExternalID != "90007" {
		t.Fatalf("external-only list: %+v", par.ExternalOnly)
	}
	for _, f := range findings() {
		if f.NVTOID == bluekeep && (f.State != v1.FindingConfirmed || f.ExternalID != "91534" || len(f.Evidence) != 2) {
			t.Fatalf("bluekeep after import: %+v", f)
		}
	}

	// Cycle 2: the host is patched; the same scope no longer sees BlueKeep → fixed.
	fake.Script = []osptest.Step{{Progress: 100}}
	job2 := runInventory()
	if job2.Stats.Findings != 0 {
		t.Fatalf("cycle 2: %+v", job2.Stats)
	}
	waitFor(t, 10*time.Second, func() bool {
		for _, f := range findings() {
			if f.NVTOID == bluekeep {
				return f.Status == v1.FindingFixed && f.FixedAt != nil
			}
		}
		return false
	}, "bluekeep fixed by the rescan")
	var sum v1.AdminSummary
	if stc := admin("GET", "/admin/sites/"+created.SiteID+"/summary", nil, &sum); stc != 200 || sum.FixedLast30 != 1 || sum.Open[v1.SeverityCritical] != 0 || sum.Open[v1.SeverityMedium] != 1 || sum.LastInventory == nil {
		t.Fatalf("summary: %d %+v", stc, sum)
	}
	stc, body = c.rawAdminFn("GET", "/admin/sites/"+created.SiteID+"/export/findings.csv", nil, nil)
	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil || stc != 200 || len(rows) != 3 {
		t.Fatalf("export: %d %v rows=%d", stc, err, len(rows))
	}
	waitFor(t, 10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return events[server.EventJobCompleted] >= 2 && events[server.EventFindingNew] >= 1 && events[server.EventFindingsFixed] >= 1 && events[server.EventImportDone] >= 1
	}, "webhook events delivered")
	stc, body = c.rawAdminFn("GET", "/admin/metrics", nil, nil)
	if stc != 200 || !strings.Contains(string(body), "cp_findings_fixed_total 1") || !strings.Contains(string(body), `cp_appliances{health="online"} 1`) {
		t.Fatalf("metrics: %d %s", stc, body)
	}
	cancel()
	runner.Wait()
}
