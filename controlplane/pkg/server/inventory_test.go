package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
)

func (h *harness) jobStatus(t *testing.T, jobID string, req v1.JobStatusRequest) int {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := h.client(&h.applCert).Post(h.mtls.URL+"/v1/jobs/"+jobID+"/status", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// The appliance posts a job's status when it starts and when it ends. In
// between only the heartbeat moves, so the job record follows it; in the
// lab a job read "discovery, 0 percent" until it was done, and a finished
// one still said "discovery".
func TestJobPhaseFollowsTheHeartbeat(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	pub := h.srv.cfg.SpoolKey.PublicString()
	ready := v1.Heartbeat{Version: "test", State: "idle", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true, VTCount: 95103}}
	h.heartbeat(ready)
	var job v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"}}, &job); st != 201 {
		t.Fatalf("create job: %d", st)
	}
	if _, st := h.pollJobs(t); st != 200 {
		t.Fatalf("dispatch: %d", st)
	}
	view := func() v1.AdminJobView {
		t.Helper()
		var v v1.AdminJobView
		h.admin("GET", "/admin/jobs/"+job.ID, nil, &v)
		return v
	}
	beat := func(phase string, pct int) {
		t.Helper()
		hb := ready
		hb.State = "scanning"
		hb.CurrentJob = &v1.JobProgress{ID: job.ID, Phase: phase, ProgressPct: pct, StartedAt: h.now.Unix()}
		if _, st := h.heartbeat(hb); st != 200 {
			t.Fatalf("heartbeat: %d", st)
		}
	}

	// The "running" status never arrived: the heartbeat alone shows that
	// the job is under way, so it is not offered again after the lease.
	beat("portscan", 0)
	if v := view(); v.Status != v1.JobRunning || v.Phase != "portscan" || v.ProgressPct != 0 || v.StartedAt == nil {
		t.Fatalf("after the first heartbeat: %+v", v)
	}
	h.now = h.now.Add(DispatchLease + time.Minute)
	if _, st := h.pollJobs(t); st != 204 {
		t.Fatalf("a job the appliance is running was dispatched again: %d", st)
	}
	beat("openvas", 37)
	if v := view(); v.Phase != "openvas" || v.ProgressPct != 37 {
		t.Fatalf("after the second heartbeat: %+v", v)
	}
	// Out of range or absurd values do not reach the record as they are.
	beat("openvas", 250)
	if v := view(); v.ProgressPct != 100 {
		t.Fatalf("progress not clamped: %+v", v)
	}
	beat(strings.Repeat("x", 200), 10)
	if v := view(); v.Phase != "openvas" {
		t.Fatalf("an oversized phase was stored: %q", v.Phase)
	}
	// An idle heartbeat changes nothing.
	h.heartbeat(ready)
	if v := view(); v.Status != v1.JobRunning || v.Phase != "openvas" {
		t.Fatalf("after an idle heartbeat: %+v", v)
	}

	// The last chunk makes the job done; the status that follows it names
	// the phase it ended in.
	batch := v1.ResultBatch{JobID: job.ID, ApplianceID: created.ApplianceID, SiteID: job.SiteID, FeedVersion: "f1", StartedAt: 1, FinishedAt: 2, Seq: 1, Final: true,
		Stats: &v1.ScanStats{HostsAlive: 1, Rejected: []string{}}, Hosts: []v1.Host{{IP: "10.30.5.20", Ports: []v1.Port{}, Findings: []v1.Finding{}}}}
	if st, ack, raw := h.upload(t, job.ID, batch, pub); st != 200 || !ack.Complete {
		t.Fatalf("upload: %d %s", st, raw)
	}
	if st := h.jobStatus(t, job.ID, v1.JobStatusRequest{Status: v1.JobDone, ProgressPct: 100, Phase: "finalize"}); st != 204 {
		t.Fatalf("terminal status: %d", st)
	}
	done := view()
	if done.Status != v1.JobDone || done.Phase != "finalize" || done.ProgressPct != 100 || done.Stats == nil || done.FinishedAt == nil {
		t.Fatalf("finished job: %+v", done)
	}
	// A heartbeat that was sent while the job still ran arrives late.
	beat("web", 50)
	if v := view(); v.Status != v1.JobDone || v.Phase != "finalize" || v.ProgressPct != 100 || v.Stats == nil {
		t.Fatalf("a late heartbeat moved a finished job: %+v", v)
	}
	// Repeating the status is harmless, and a different one is refused.
	if st := h.jobStatus(t, job.ID, v1.JobStatusRequest{Status: v1.JobDone, ProgressPct: 100, Phase: "finalize"}); st != 204 {
		t.Fatalf("repeat: %d", st)
	}
	if st := h.jobStatus(t, job.ID, v1.JobStatusRequest{Status: v1.JobFailed, Reason: "late", Phase: "web"}); st != 409 {
		t.Fatalf("a finished job accepted another status: %d", st)
	}
	if v := view(); v.Status != v1.JobDone || v.Phase != "finalize" {
		t.Fatalf("after the refused status: %+v", v)
	}

	// A job of another appliance is not moved by this one's heartbeat.
	other := &store.Job{ID: "job_foreign", SiteID: job.SiteID, ApplianceID: created.ApplianceID, Status: v1.JobRunning, Phase: "discovery"}
	other.Spec.DefaultsFor(v1.ModeDiscovery)
	if err := h.srv.cfg.Store.CreateJob(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	if changed, err := h.srv.cfg.Store.NoteJobProgress(t.Context(), other.ID, "apl_someone_else", "openvas", 80, h.now); err != nil || changed {
		t.Fatalf("foreign appliance: %v %v", changed, err)
	}
}

// Which findings a finished job may call fixed, with the web phase in mind.
func TestWebScopes(t *testing.T) {
	scopes := func(stats *v1.ScanStats, mods ...string) string {
		j := &store.Job{Spec: v1.JobSpec{Modules: mods}}
		j.Spec.DefaultsFor(v1.ModeFull)
		return strings.Join(jobScopes(j, stats), ",")
	}
	if got := scopes(nil); got != "inventory,full,web" {
		t.Fatalf("full job: %q", got)
	}
	if got := scopes(&v1.ScanStats{}, "discovery", "portscan", "openvas", "web", "default_logins"); got != "inventory,full,web,web+logins" {
		t.Fatalf("full job with default logins: %q", got)
	}
	// The appliance skipped or cut the web phase short: it did not look, so
	// it resolves no web finding. Other warnings do not matter here.
	for _, w := range []string{"web: httpx/nuclei not installed", "web: no nuclei templates in the installed bundle", "web: 6000 HTTP targets, probing the first 5000"} {
		if got := scopes(&v1.ScanStats{Warnings: []string{w}}, "discovery", "portscan", "openvas", "web", "default_logins"); got != "inventory,full" {
			t.Fatalf("%q: scopes %q", w, got)
		}
	}
	if got := scopes(&v1.ScanStats{Warnings: []string{"fingerprint: nmap not installed"}}); got != "inventory,full,web" {
		t.Fatalf("unrelated warning: %q", got)
	}
}

// A web phase that did not run must not close what an earlier one found.
func TestSkippedWebPhaseFixesNothing(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	h.heartbeat(v1.Heartbeat{Version: "test", State: "idle", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}})
	const ip = "10.30.5.50"
	port := v1.Port{Port: 8080, Proto: "tcp", Service: "http", Source: "naabu"}
	traversal := v1.Finding{Source: "nuclei", ID: "CVE-2021-41773", Name: "Path traversal", Family: v1.FamilyWeb, Severity: "critical", CVSS: 9.8, QoD: 80, Port: 8080, Proto: "tcp", CVE: []string{"CVE-2021-41773"}}
	login := v1.Finding{Source: "nuclei", ID: "tomcat-default-login", Name: "Tomcat default login", Family: v1.FamilyWebDefaultLogin, Severity: "high", CVSS: 8.1, QoD: 80, Port: 8080, Proto: "tcp", CVE: []string{}}
	run := func(defaultLogins bool, warnings []string, findings ...v1.Finding) {
		t.Helper()
		var job v1.AdminJobView
		if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"}, DefaultLogins: defaultLogins}, &job); st != 201 {
			t.Fatalf("create job: %d", st)
		}
		if jr, st := h.pollJobs(t); st != 200 || jr.Job.HasModule(v1.ModuleDefaultLogins) != defaultLogins {
			t.Fatalf("dispatch: %d", st)
		}
		if findings == nil {
			findings = []v1.Finding{}
		}
		batch := v1.ResultBatch{JobID: job.ID, ApplianceID: created.ApplianceID, SiteID: job.SiteID, FeedVersion: "f1", StartedAt: 1, FinishedAt: 2, Seq: 1, Final: true,
			Stats: &v1.ScanStats{HostsAlive: 1, HostsScanned: 1, Findings: len(findings), Rejected: []string{}, Warnings: warnings},
			Hosts: []v1.Host{{IP: ip, Ports: []v1.Port{port}, Findings: findings}}}
		if st, ack, raw := h.upload(t, job.ID, batch, h.srv.cfg.SpoolKey.PublicString()); st != 200 || !ack.Complete {
			t.Fatalf("upload: %d %s", st, raw)
		}
		h.now = h.now.Add(time.Hour)
	}
	state := func() string {
		t.Helper()
		var fs []v1.AdminFindingView
		h.admin("GET", "/admin/sites/"+created.SiteID+"/findings", nil, &fs)
		out := map[string]string{}
		for _, f := range fs {
			out[f.TemplateID] = f.Scope + "/" + f.Status
		}
		return out["CVE-2021-41773"] + " " + out["tomcat-default-login"]
	}

	run(true, nil, traversal, login)
	if got := state(); got != "web/open web+logins/open" {
		t.Fatalf("after the first job: %s", got)
	}
	// The next job's bundle had no templates: its web phase never ran.
	run(true, []string{"web: no nuclei templates in the installed bundle"})
	if got := state(); got != "web/open web+logins/open" {
		t.Fatalf("a skipped web phase closed findings: %s", got)
	}
	// A weekly job without the default-login checks finds the traversal
	// gone. It did not try the login, so that one stays. A few templates
	// that did not load do not make the phase one that did not look.
	run(false, []string{"nuclei: 8 templates did not load"})
	if got := state(); got != "web/fixed web+logins/open" {
		t.Fatalf("after a plain web job: %s", got)
	}
	// A job that runs those checks no longer gets in.
	run(true, nil)
	if got := state(); got != "web/fixed web+logins/fixed" {
		t.Fatalf("after a job with the default-login checks: %s", got)
	}
}

func TestDefaultLoginsModuleJobs(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	target := []string{"10.30.5.0/24"}
	modules := func(req v1.AdminJobRequest) (string, int) {
		var job v1.AdminJobView
		st := h.admin("POST", "/admin/jobs", req, &job)
		return strings.Join(job.Spec.Modules, ","), st
	}
	// Off unless asked for, in every mode.
	for _, mode := range []string{v1.ModeDiscovery, v1.ModeInventory, v1.ModeFull} {
		if m, st := modules(v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: mode, Targets: target}); st != 201 || strings.Contains(m, v1.ModuleDefaultLogins) {
			t.Fatalf("default %s job: %d %q", mode, st, m)
		}
	}
	if m, st := modules(v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeFull, Targets: target, DefaultLogins: true}); st != 201 || m != "discovery,portscan,openvas,web,default_logins" {
		t.Fatalf("full job with default logins: %d %q", st, m)
	}
	if m, st := modules(v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeFull, Targets: target, DefaultLogins: true, UDP: true}); st != 201 || m != "discovery,portscan,openvas,web,udp,default_logins" {
		t.Fatalf("full job with both: %d %q", st, m)
	}
	// It belongs to the web phase: refused where there is none.
	if _, st := modules(v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeInventory, Targets: target, DefaultLogins: true}); st != 400 {
		t.Fatalf("inventory job with default logins accepted: %d", st)
	}
	if _, st := modules(v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeDiscovery, Targets: target, DefaultLogins: true}); st != 400 {
		t.Fatalf("discovery job with default logins accepted: %d", st)
	}
	// A schedule opts in through its module list.
	var sched v1.AdminScheduleView
	if st := h.admin("POST", "/admin/schedules", v1.AdminScheduleRequest{ApplianceID: created.ApplianceID, Name: "quarterly logins", Mode: v1.ModeFull, Targets: target,
		Cron: "0 22 1 */3 *", Modules: []string{"discovery", "portscan", "openvas", "web", "default_logins"}}, &sched); st != 201 || !strings.HasSuffix(strings.Join(sched.Modules, ","), ",default_logins") {
		t.Fatalf("schedule with default logins: %d %+v", st, sched.Modules)
	}
	// The vendor-facing page says the checks exist and that they are off.
	resp, err := h.client(nil).Get(h.mtls.URL + "/transparency.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var page struct {
		Phases []string `json:"phases"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil || resp.StatusCode != 200 {
		t.Fatalf("transparency: %d %v", resp.StatusCode, err)
	}
	web, logins := "", ""
	for _, p := range page.Phases {
		switch {
		case strings.HasPrefix(p, "web add-on"):
			web = p
		case strings.HasPrefix(p, "default-login templates"):
			logins = p
		}
	}
	if !strings.Contains(web, "without its default-login templates") || !strings.Contains(logins, "never by default") {
		t.Fatalf("the transparency page does not say the default-login templates are off: %q / %q", web, logins)
	}
	// What does run by default is said as well: the engine's own tests for
	// a product's default password are part of every scan config.
	if !strings.Contains(strings.Join(page.Phases, "\n"), "Default Accounts family") {
		t.Fatalf("the transparency page is silent about the engine's default-account tests: %v", page.Phases)
	}
}

// What the appliance sends for a host is kept: every CPE of a port and the
// host's whole inventory, bounded in size.
func TestProductInventoryIsStored(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	h.heartbeat(v1.Heartbeat{Version: "test", State: "idle", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}})
	var job v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}}, &job); st != 201 {
		t.Fatalf("create job: %d", st)
	}
	if _, st := h.pollJobs(t); st != 200 {
		t.Fatalf("dispatch: %d", st)
	}
	many := make([]string, 0, maxCPEsPort+20)
	for i := 0; i < maxCPEsPort+20; i++ {
		many = append(many, "cpe:/a:vendor:product:"+strings.Repeat("9", i%7+1))
	}
	host := v1.Host{IP: "10.30.5.60", MAC: "ee:43:b4:5a:f9:ad", Findings: []v1.Finding{},
		CPEs: []string{"cpe:/a:f5:nginx:1.16.1", "cpe:/a:nginx:nginx:1.16.1", "cpe:/o:linux:kernel"},
		Ports: []v1.Port{
			{Port: 80, Proto: "tcp", Service: "http", Product: "Nginx", Version: "1.16.1", CPE: "cpe:/a:nginx:nginx:1.16.1", CPEs: []string{"cpe:/a:nginx:nginx:1.16.1", "cpe:/a:f5:nginx:1.16.1"}, Source: "openvas:product_detection"},
			{Port: 8080, Proto: "tcp", CPE: many[0], CPEs: many, Source: "openvas:product_detection"},
			{Port: 22, Proto: "tcp", Service: "ssh", Source: "naabu"},
		}}
	batch := v1.ResultBatch{JobID: job.ID, ApplianceID: created.ApplianceID, SiteID: job.SiteID, FeedVersion: "f1", StartedAt: 1, FinishedAt: 2, Seq: 1, Final: true,
		Stats: &v1.ScanStats{HostsAlive: 1, HostsScanned: 1, Rejected: []string{}}, Hosts: []v1.Host{host}}
	if st, ack, raw := h.upload(t, job.ID, batch, h.srv.cfg.SpoolKey.PublicString()); st != 200 || !ack.Complete {
		t.Fatalf("upload: %d %s", st, raw)
	}
	var hosts []v1.AdminHostView
	h.admin("GET", "/admin/sites/"+created.SiteID+"/hosts", nil, &hosts)
	if len(hosts) != 1 || hosts[0].MAC != "ee:43:b4:5a:f9:ad" || strings.Join(hosts[0].CPEs, " ") != "cpe:/a:f5:nginx:1.16.1 cpe:/a:nginx:nginx:1.16.1 cpe:/o:linux:kernel" {
		t.Fatalf("host: %+v", hosts)
	}
	byPort := map[int]v1.Port{}
	for _, p := range hosts[0].Ports {
		byPort[p.Port] = p
	}
	if p := byPort[80]; strings.Join(p.AllCPEs(), " ") != "cpe:/a:nginx:nginx:1.16.1 cpe:/a:f5:nginx:1.16.1" {
		t.Fatalf("port 80: %+v", p)
	}
	if p := byPort[8080]; len(p.CPEs) != maxCPEsPort {
		t.Fatalf("port 8080 keeps %d CPEs, want the cap of %d", len(p.CPEs), maxCPEsPort)
	}
	if p := byPort[22]; p.CPEs != nil || p.AllCPEs() != nil {
		t.Fatalf("port 22: %+v", p)
	}
}
