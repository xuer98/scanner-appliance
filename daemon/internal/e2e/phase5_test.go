package e2e

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/engine"
	"github.com/tprm/scanner-appliance/daemon/internal/heartbeat"
	"github.com/tprm/scanner-appliance/daemon/internal/jobs"
	"github.com/tprm/scanner-appliance/daemon/internal/nvt"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/daemon/internal/spool"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
)

// labNmap answers like nmap -oX for the lab WMS host and logs its
// arguments.
func labNmap(t *testing.T, logPath string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake nmap is a POSIX shell script")
	}
	script := `#!/bin/sh
echo "$@" >> "` + logPath + `"
cat <<'XML'
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.93">
<host><status state="up"/><address addr="10.30.5.20" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows Server 2008 R2 microsoft-ds" conf="10"/></port>
<port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server" product="Microsoft Terminal Services" conf="10"><cpe>cpe:/a:microsoft:terminal_services</cpe></service></port>
</ports>
<os><osmatch name="Microsoft Windows Server 2008 R2 SP1" accuracy="97"><osclass type="general purpose" vendor="Microsoft" osfamily="Windows" accuracy="97"><cpe>cpe:/o:microsoft:windows_server_2008:r2:sp1</cpe></osclass></osmatch></os>
</host>
</nmaprun>
XML
`
	p := filepath.Join(t.TempDir(), "nmap")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPhase5 covers the software side of the depth phase (PLAN §20 Phase
// 5): the nmap fingerprint pass runs only after the legal sign-off and
// enriches the inventory, the full-range port option is budgeted at
// dispatch and on the appliance, the heartbeat reports the tools a build
// carries, and the onboarding checklist tracks the site.
func TestPhase5(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses shell-script fakes")
	}
	c := newCP(t)
	admin := c.adminFn
	var created v1.AdminCreateApplianceResponse
	if st := admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme", Site: "Boise", AllowedCIDRs: []string{"10.30.0.0/16"}}, &created); st != 201 {
		t.Fatalf("create %d", st)
	}
	fake := labOSPD(t)
	st := state.New(t.TempDir(), t.TempDir())
	s, _ := st.Load()
	s.EnrollURL = c.enroll.URL
	s.PendingCode = created.Code
	s.IntervalOverrideS = 1
	_ = st.Save(s)
	ospc := osp.New(fake.Socket)
	nmapLog := filepath.Join(t.TempDir(), "nmap.log")
	nmapPath := labNmap(t, nmapLog)
	eng := &engine.Engine{NaabuPath: labNaabu(t), OSP: ospc, NVT: nvt.New(filepath.Join(st.Dir, "nvt-cache"), ospc, nil), Log: slog.Default(),
		PollInterval: 50 * time.Millisecond, ScanType: "c", IfaceExists: func(string) bool { return true }, NmapPath: nmapPath, Privileged: func() bool { return true }}
	runner := &jobs.Runner{Store: st, Engine: eng, Spool: &spool.Spool{Dir: filepath.Join(st.Dir, "spool")}, Roots: c.roots, Log: slog.Default()}
	loop := &heartbeat.Loop{Store: st, Roots: c.roots, Version: "e2e", Log: slog.Default(), PowerOff: func() error { return nil }, Reboot: func() error { return nil },
		OSPSocket: fake.Socket, Jobs: runner, ToolPaths: map[string]string{"naabu": eng.NaabuPath, "nmap": nmapPath}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go loop.Run(ctx)

	getView := func() v1.AdminApplianceView {
		var v v1.AdminApplianceView
		admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &v)
		return v
	}
	var view v1.AdminApplianceView
	waitFor(t, 20*time.Second, func() bool {
		view = getView()
		return view.Status == v1.StatusEnrolled && view.Online && view.LastHeartbeat != nil && view.LastHeartbeat.Engine.Ready()
	}, "appliance online")
	tools := strings.Join(view.Tools, ",")
	if !strings.HasPrefix(tools, "naabu,") || !strings.HasSuffix(tools, ",nmap") {
		t.Fatalf("heartbeat tools: %v", view.Tools)
	}
	runJob := func(req v1.AdminJobRequest, wantStatus int) v1.AdminJobView {
		t.Helper()
		req.ApplianceID = created.ApplianceID
		var job v1.AdminJobView
		var errResp map[string]any
		stc := admin("POST", "/admin/jobs", req, &job)
		if stc != wantStatus {
			admin("POST", "/admin/jobs", req, &errResp)
			t.Fatalf("job: %d (want %d) %v", stc, wantStatus, errResp)
		}
		if stc != 201 {
			return job
		}
		waitFor(t, 40*time.Second, func() bool {
			var j v1.AdminJobView
			admin("GET", "/admin/jobs/"+job.ID, nil, &j)
			job = j
			switch j.Status {
			case v1.JobDone, v1.JobFailed, v1.JobRejected, v1.JobCancelled:
				return true
			}
			return false
		}, "job terminal")
		return job
	}

	// Without the sign-off the module is refused at creation.
	inv := v1.AdminJobRequest{Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}, Excludes: []string{"10.30.5.1"}, Fingerprint: v1.DefaultFingerprintParams()}
	runJob(inv, 403)
	var so v1.AdminSignoffView
	if stc := admin("PUT", "/admin/signoffs/nmap", v1.AdminSignoffRequest{Reference: "LEGAL-2026-014"}, &so); stc != 200 || !so.Approved {
		t.Fatalf("signoff: %d %+v", stc, so)
	}
	// With it, the pass enriches the WMS host and skips the printer.
	job := runJob(inv, 201)
	if job.Status != v1.JobDone || job.Stats.Fingerprinted != 1 || len(job.Stats.Warnings) != 0 {
		t.Fatalf("fingerprint job: %s %+v", job.Status, job.Stats)
	}
	args, _ := os.ReadFile(nmapLog)
	if !strings.Contains(string(args), "-sV") || !strings.Contains(string(args), "-O") || strings.Contains(string(args), "10.30.5.21") || !strings.HasSuffix(strings.TrimSpace(string(args)), "10.30.5.20") {
		t.Fatalf("nmap args: %s", args)
	}
	var hosts []v1.AdminHostView
	admin("GET", "/admin/jobs/"+job.ID+"/hosts", nil, &hosts)
	var wms *v1.AdminHostView
	for i := range hosts {
		if hosts[i].IP == "10.30.5.20" {
			wms = &hosts[i]
		}
	}
	if wms == nil || wms.OSGuess == nil || wms.OSGuess.Source != "nmap:os_detection" || wms.OSGuess.Confidence != 0.97 {
		t.Fatalf("wms os: %+v", wms)
	}
	rdp := false
	for _, p := range wms.Ports {
		if p.Port == 3389 && p.Product == "Microsoft Terminal Services" && p.CPE == "cpe:/a:microsoft:terminal_services" && p.Service == "rdp" {
			rdp = true
		}
	}
	if !rdp {
		t.Fatalf("rdp port not enriched: %+v", wms.Ports)
	}

	// Full-range option: budgeted from the inventory at dispatch (3 live
	// hosts → fits the default window; a 2-minute window does not).
	fullReq := v1.AdminJobRequest{Mode: v1.ModeDiscovery, Targets: []string{"10.30.5.0/24"}, Ports: v1.PortsFull, Modules: []string{v1.ModuleDiscovery, v1.ModulePortscan}}
	fullReq.Window = &v1.Window{MaxDurationS: 120}
	runJob(fullReq, 400)
	fullReq.Window = nil
	fj := runJob(fullReq, 201)
	if fj.Status != v1.JobDone || fj.Spec.ExpectedHosts != 3 || fj.Spec.Ports != v1.PortsFull {
		t.Fatalf("full-range job: %s expected_hosts=%d reason=%s", fj.Status, fj.Spec.ExpectedHosts, fj.RejectReason)
	}
	// The appliance's own budget check: a rate the spec passes at dispatch
	// (server hint 3 hosts) but that cannot finish in a 5-minute window
	// once the appliance counts the same 3 hosts at 1 pps... the guardrail
	// catches it on both sides, so the job is rejected by the server first.
	fullReq.Rate = &v1.Rate{PPS: 1, PerHostParallel: 1}
	runJob(fullReq, 400)

	// Onboarding checklist for this site after the runs.
	var ob v1.AdminOnboardingView
	if stc := admin("GET", "/admin/sites/"+created.SiteID+"/onboarding", nil, &ob); stc != 200 || len(ob.Steps) != 9 || ob.Complete {
		t.Fatalf("onboarding: %d %+v", stc, ob)
	}
	steps := map[string]bool{}
	for _, s := range ob.Steps {
		steps[s.Key] = s.Done
	}
	if !steps["appliance_online"] || !steps["discovery_done"] || steps["scope_attested"] || steps["exclusions_reviewed"] {
		t.Fatalf("onboarding steps: %+v", ob.Steps)
	}
	var gaps v1.AdminFeedGapReport
	if stc := admin("GET", "/admin/feed-gaps?site="+created.SiteID, nil, &gaps); stc != 200 || gaps.Hosts < 2 || gaps.IdentifiedPorts < 2 {
		t.Fatalf("feed gaps: %d %+v", stc, gaps)
	}
	// Revoking the sign-off stops new fingerprint jobs.
	admin("DELETE", "/admin/signoffs/nmap", nil, &so)
	runJob(inv, 403)
	cancel()
	runner.Wait()
}
