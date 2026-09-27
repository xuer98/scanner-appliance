package e2e

import (
	"context"
	"io"
	"log/slog"
	"net/http"
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

// TestPhase4 covers the software side of the pilot phase (PLAN §20 Phase
// 4): the versioned fragile-device policy reaches the appliance and lets a
// cleared host be scanned, a false positive reviewed on the control plane
// is codified and suppressed by the next scan, a schedule runs a job in its
// window, coverage and alerts reflect the site, and the transparency page
// is served without credentials.
func TestPhase4(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses shell-script fakes")
	}
	c := newCP(t)
	admin := c.adminFn
	var created v1.AdminCreateApplianceResponse
	if st := admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme", Site: "Reno", AllowedCIDRs: []string{"10.30.0.0/16"}}, &created); st != 201 {
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
	eng := &engine.Engine{NaabuPath: labNaabu(t), OSP: ospc, NVT: nvt.New(filepath.Join(st.Dir, "nvt-cache"), ospc, nil), Log: slog.Default(),
		PollInterval: 50 * time.Millisecond, ScanType: "c", IfaceExists: func(string) bool { return true }}
	runner := &jobs.Runner{Store: st, Engine: eng, Spool: &spool.Spool{Dir: filepath.Join(st.Dir, "spool")}, Roots: c.roots, Log: slog.Default()}
	loop := &heartbeat.Loop{Store: st, Roots: c.roots, Version: "e2e", Log: slog.Default(), PowerOff: func() error { return nil }, Reboot: func() error { return nil },
		OSPSocket: fake.Socket, Jobs: runner}
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
	if view.Health != v1.HealthOnline {
		t.Fatalf("health %s", view.Health)
	}
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

	// Baseline: the printer on 9100 is kept away from openvas, BlueKeep found.
	job1 := runInventory()
	if job1.Stats.FragileExcluded != 1 || job1.Stats.HostsScanned != 1 || job1.Stats.Findings != 1 {
		t.Fatalf("baseline stats: %+v", job1.Stats)
	}
	var fr v1.AdminFragileView
	if stc := admin("GET", "/admin/sites/"+job1.SiteID+"/fragile", nil, &fr); stc != 200 || len(fr.Hosts) != 1 || fr.Hosts[0].IP != "10.30.5.21" || !fr.Hosts[0].Excluded {
		t.Fatalf("fragile view: %d %+v", stc, fr)
	}

	// DoD (fragile-device policy): a human clears the printer; the next scan
	// carries the versioned policy and scans it.
	if stc := admin("POST", "/admin/sites/"+job1.SiteID+"/fragile", v1.AdminFragileRequest{IP: "10.30.5.21", Action: "clear", Reason: "vendor confirmed during the pilot"}, &fr); stc != 200 {
		t.Fatalf("clear: %d", stc)
	}
	job2 := runInventory()
	if job2.Stats.FragileExcluded != 0 || job2.Stats.HostsScanned != 2 {
		t.Fatalf("after clearance: %+v", job2.Stats)
	}
	var hosts []v1.AdminHostView
	admin("GET", "/admin/jobs/"+job2.ID+"/hosts", nil, &hosts)
	var bluekeep v1.AdminFindingView
	for _, h := range hosts {
		if h.IP == "10.30.5.21" && (len(h.Notes) != 1 || h.Notes[0] != "fragile:cleared:9100") {
			t.Fatalf("printer notes: %v", h.Notes)
		}
		for _, f := range h.Findings {
			if f.NVTOID == bluekeep_oid {
				bluekeep = f
			}
		}
	}
	if bluekeep.ID == "" || bluekeep.State != v1.FindingNetworkObserved || !bluekeep.NetworkReachable {
		t.Fatalf("bluekeep finding: %+v", bluekeep)
	}
	local, _ := st.Load()
	if local.Site.Version < 1 || len(local.Site.FragileCleared) != 1 {
		t.Fatalf("policy not on the appliance: %+v", local.Site)
	}

	// DoD (exclusions codified): review as a false positive with codify; the
	// next scan suppresses it on the appliance and the finding stays reviewed.
	var reviewed v1.AdminFindingView
	if stc := admin("PATCH", "/admin/findings/"+bluekeep.ID, v1.AdminFindingReview{Review: v1.ReviewFalsePositive, Reason: "lab host is a honeypot", Codify: true}, &reviewed); stc != 200 || reviewed.Review != v1.ReviewFalsePositive {
		t.Fatalf("review: %d %+v", stc, reviewed)
	}
	job3 := runInventory()
	if job3.Stats.Findings != 0 || job3.Stats.Suppressed != 1 {
		t.Fatalf("after codified exclusion: %+v", job3.Stats)
	}
	var detail v1.AdminFindingDetail
	admin("GET", "/admin/findings/"+bluekeep.ID, nil, &detail)
	if detail.Finding.Review != v1.ReviewFalsePositive || detail.NVT == nil || detail.NVT.Family != "Windows" || detail.Host.IP != "10.30.5.20" {
		t.Fatalf("finding detail: %+v", detail)
	}
	var rep v1.AdminTuningReport
	admin("GET", "/admin/sites/"+job1.SiteID+"/tuning", nil, &rep)
	if rep.Findings != 1 || rep.FalsePositives != 1 || len(rep.Exclusions) != 1 || rep.Exclusions[0] != bluekeep_oid {
		t.Fatalf("tuning: %+v", rep)
	}

	// DoD (job calendar): a schedule whose window is open now runs a job.
	var sc v1.AdminScheduleView
	if stc := admin("POST", "/admin/schedules", v1.AdminScheduleRequest{ApplianceID: created.ApplianceID, Name: "every minute discovery", Mode: v1.ModeDiscovery, Targets: []string{"10.30.5.0/24"}, Excludes: []string{"10.30.5.1"}, Cron: "* * * * *", TZ: "UTC", MaxDurationS: 120}, &sc); stc != 201 || sc.NextJobID == "" {
		t.Fatalf("schedule: %d %+v", stc, sc)
	}
	var sjob v1.AdminJobView
	waitFor(t, 40*time.Second, func() bool {
		admin("GET", "/admin/jobs/"+sc.NextJobID, nil, &sjob)
		return sjob.Status == v1.JobDone
	}, "scheduled job done")
	if sjob.ScheduleID != sc.ID || sjob.Stats == nil || sjob.Stats.HostsAlive != 3 {
		t.Fatalf("scheduled job: %+v", sjob)
	}
	if err := c.srv.SchedulerTick(ctx); err != nil {
		t.Fatal(err)
	}
	var sc2 v1.AdminScheduleView
	admin("GET", "/admin/schedules/"+sc.ID, nil, &sc2)
	if sc2.LastJobID != sjob.ID || sc2.NextJobID == "" || sc2.NextJobID == sjob.ID {
		t.Fatalf("schedule after run: %+v", sc2)
	}
	var cal []v1.AdminCalendarEntry
	admin("GET", "/admin/sites/"+job1.SiteID+"/calendar?days=1", nil, &cal)
	if len(cal) < 5 {
		t.Fatalf("calendar: %d entries", len(cal))
	}
	off := false
	admin("PATCH", "/admin/schedules/"+sc.ID, v1.AdminScheduleRequest{Enabled: &off}, &sc2)

	// Coverage and alerts for a healthy pilot site.
	var cov v1.AdminCoverage
	admin("GET", "/admin/sites/"+job1.SiteID+"/coverage", nil, &cov)
	if cov.Score < 60 || cov.Components["appliance"] != 40 || cov.Components["freshness"] != 40 || cov.Hosts.ApplianceSeen < 3 {
		t.Fatalf("coverage: %d %+v reasons=%v", cov.Score, cov.Components, cov.Reasons)
	}
	var alerts []v1.AdminAlert
	admin("GET", "/admin/alerts", nil, &alerts)
	for _, a := range alerts {
		if a.Kind == "silent" || a.Kind == "stale" || a.Kind == "degraded" || a.Kind == "scan_failed" {
			t.Fatalf("unexpected alert: %+v", a)
		}
	}
	var changes []v1.AdminSiteChangeView
	admin("GET", "/admin/sites/"+job1.SiteID+"/changes", nil, &changes)
	if len(changes) != 2 || changes[0].Kind != "exclusion" || changes[1].Kind != "fragile" {
		t.Fatalf("audit log: %+v", changes)
	}

	// The transparency page needs no credentials.
	resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: c.tlsConfig()}}).Get(c.enroll.URL + "/transparency")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Guardrails") {
		t.Fatalf("transparency: %d", resp.StatusCode)
	}
}

const bluekeep_oid = bluekeep
