package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

const ownerTok = "owner-secret"

func (h *harness) adminAs(token, method, path string, body any, out any) int {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, h.mtls.URL+path, &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Actor", token+"@test")
	resp, err := h.client(nil).Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		b, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(b, out)
	}
	return resp.StatusCode
}

func (h *harness) site(t *testing.T, id string) v1.AdminSiteView {
	t.Helper()
	var v v1.AdminSiteView
	if st := h.admin("GET", "/admin/sites/"+id, nil, &v); st != 200 {
		t.Fatalf("get site: %d", st)
	}
	return v
}

func TestScopeApprovalAndAttestation(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.VendorOwnerToken = ownerTok
	created := h.enrolled(t)
	siteID := created.SiteID
	v0 := h.site(t, siteID)
	if v0.PendingScope != 0 || !v0.AttestionStale {
		t.Fatalf("initial site view: %+v", v0)
	}

	// The operator cannot change allowed_cidrs directly (PLAN §16).
	cidrs := []string{"10.30.0.0/16", "10.31.0.0/16"}
	var errResp map[string]any
	if st := h.admin("PATCH", "/admin/sites/"+siteID, v1.AdminSiteUpdate{AllowedCIDRs: &cidrs}, &errResp); st != 409 || errResp["code"] != "scope_approval_required" {
		t.Fatalf("operator scope edit: %d %v", st, errResp)
	}
	// Other fields are audited policy changes.
	fp := []int{9100, 161}
	var sv v1.AdminSiteView
	if st := h.admin("PATCH", "/admin/sites/"+siteID, v1.AdminSiteUpdate{FragilePorts: &fp}, &sv); st != 200 || sv.Config.Version != 1 {
		t.Fatalf("policy edit: %d version=%d", st, sv.Config.Version)
	}
	// Scope request → pending; the operator may not approve it; the owner may.
	var sr v1.AdminScopeRequestView
	if st := h.admin("POST", "/admin/sites/"+siteID+"/scope-requests", v1.AdminScopeRequest{AllowedCIDRs: cidrs, Reason: "new floor"}, &sr); st != 201 || sr.Status != v1.ScopePending {
		t.Fatalf("scope request: %d %+v", st, sr)
	}
	if h.site(t, siteID).PendingScope != 1 {
		t.Fatal("pending count")
	}
	if st := h.admin("POST", "/admin/sites/"+siteID+"/scope-requests/"+sr.ID+"/approve", v1.AdminDecision{Reason: "x"}, nil); st != 403 {
		t.Fatalf("operator approved: %d", st)
	}
	if st := h.adminAs("bogus", "POST", "/admin/sites/"+siteID+"/scope-requests/"+sr.ID+"/approve", nil, nil); st != 401 {
		t.Fatalf("bogus token: %d", st)
	}
	var decided v1.AdminScopeRequestView
	if st := h.adminAs(ownerTok, "POST", "/admin/sites/"+siteID+"/scope-requests/"+sr.ID+"/approve", v1.AdminDecision{Reason: "attested on the call"}, &decided); st != 200 || decided.Status != v1.ScopeApproved || decided.DecidedBy != ownerTok+"@test" {
		t.Fatalf("owner approve: %d %+v", st, decided)
	}
	sv = h.site(t, siteID)
	if strings.Join(sv.Config.AllowedCIDRs, ",") != "10.30.0.0/16,10.31.0.0/16" || sv.Config.Version != 2 || sv.PendingScope != 0 {
		t.Fatalf("scope after approval: %+v", sv.Config)
	}
	if st := h.adminAs(ownerTok, "POST", "/admin/sites/"+siteID+"/scope-requests/"+sr.ID+"/approve", nil, nil); st != 409 {
		t.Fatalf("re-approve: %d", st)
	}
	// Rejection leaves the scope alone.
	var sr2 v1.AdminScopeRequestView
	h.admin("POST", "/admin/sites/"+siteID+"/scope-requests", v1.AdminScopeRequest{AllowedCIDRs: []string{"0.0.0.0/0"}, Reason: "everything"}, &sr2)
	if st := h.adminAs(ownerTok, "POST", "/admin/sites/"+siteID+"/scope-requests/"+sr2.ID+"/reject", v1.AdminDecision{Reason: "no"}, &decided); st != 200 || decided.Status != v1.ScopeRejected {
		t.Fatalf("reject: %d %+v", st, decided)
	}
	if got := h.site(t, siteID).Config.AllowedCIDRs; len(got) != 2 {
		t.Fatalf("scope changed by a rejected request: %v", got)
	}
	// The owner's own edit applies directly, with an audit entry.
	direct := []string{"10.30.0.0/16"}
	if st := h.adminAs(ownerTok, "PATCH", "/admin/sites/"+siteID, v1.AdminSiteUpdate{AllowedCIDRs: &direct}, &sv); st != 200 || len(sv.Config.AllowedCIDRs) != 1 || sv.Config.Version != 3 {
		t.Fatalf("owner direct edit: %d %+v", st, sv.Config)
	}
	// Attestation: owner only; clears the stale flag and the alert.
	if st := h.admin("POST", "/admin/sites/"+siteID+"/attest", nil, nil); st != 403 {
		t.Fatalf("operator attest: %d", st)
	}
	if st := h.adminAs(ownerTok, "POST", "/admin/sites/"+siteID+"/attest", v1.AdminDecision{Reason: "quarterly review"}, &sv); st != 200 || sv.AttestedAt == nil || sv.AttestionStale || sv.AttestedBy != ownerTok+"@test" {
		t.Fatalf("attest: %d %+v", st, sv)
	}
	var changes []v1.AdminSiteChangeView
	h.admin("GET", "/admin/sites/"+siteID+"/changes", nil, &changes)
	kinds := []string{}
	for _, c := range changes {
		kinds = append(kinds, c.Kind)
	}
	if strings.Join(kinds, ",") != "attest,scope,scope,fragile" || changes[0].Version != 4 || changes[3].Actor != h.adminTok+"@test" && changes[3].Actor != v1.RoleOperator {
		t.Fatalf("audit log: %v %+v", kinds, changes)
	}
	var alerts []v1.AdminAlert
	h.admin("GET", "/admin/alerts", nil, &alerts)
	for _, a := range alerts {
		if a.Kind == "attestation_stale" || a.Kind == "scope_pending" {
			t.Fatalf("stale alert after attestation: %+v", a)
		}
	}
	// The dispatched site config carries the versioned policy to the appliance.
	var job v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: h.applID, Mode: v1.ModeDiscovery, Targets: []string{"10.30.5.0/24"}}, &job); st != 201 {
		t.Fatalf("job: %d", st)
	}
	jr, st := h.pollJobs(t)
	if st != 200 || jr.Site.Version != 4 || len(jr.Site.FragilePorts) != 2 {
		t.Fatalf("dispatched site config: %d %+v", st, jr)
	}
}

func TestFragilePolicyExclusionsAndReview(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.VendorOwnerToken = ownerTok
	created := h.enrolled(t)
	siteID := created.SiteID
	ctx := t.Context()
	// Results of a discovery + inventory: a printer on 9100, a WMS host with two findings.
	if _, err := h.st.IngestHosts(ctx, siteID, "job_a", []v1.Host{
		{IP: "10.30.5.21", Hostname: "printer-1", Ports: []v1.Port{{Port: 9100, Proto: "tcp", Source: "naabu"}}, Notes: []string{"fragile:9100"}},
		{IP: "10.30.5.20", Hostname: "wms-app-01", Ports: []v1.Port{{Port: 3389, Proto: "tcp", Source: "naabu"}, {Port: 8080, Proto: "tcp", Source: "naabu"}}, Findings: []v1.Finding{
			{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.108587", Name: "BlueKeep", Family: "Windows", Severity: v1.SeverityCritical, CVSS: 9.8, CVE: []string{"CVE-2019-0708"}, QoD: 97, Port: 3389, Proto: "tcp"},
			{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.4242", Name: "Noisy banner check", Family: "General", Severity: v1.SeverityMedium, CVSS: 5, CVE: []string{}, QoD: 30, Port: 8080, Proto: "tcp"},
			{Source: "nuclei", ID: "tech-detect", Name: "Wappalyzer", Severity: v1.SeverityInfo, CVE: []string{}, QoD: 80, Port: 8080, Proto: "tcp"},
		}},
	}, "202609260530", h.now); err != nil {
		t.Fatal(err)
	}

	var fr v1.AdminFragileView
	if st := h.admin("GET", "/admin/sites/"+siteID+"/fragile", nil, &fr); st != 200 || len(fr.Hosts) != 1 || fr.Hosts[0].IP != "10.30.5.21" || !fr.Hosts[0].Excluded || fr.Hosts[0].Reason != "port 9100" {
		t.Fatalf("fragile view: %d %+v", st, fr)
	}
	if st := h.admin("POST", "/admin/sites/"+siteID+"/fragile", v1.AdminFragileRequest{IP: "10.30.5.21", Action: "clear"}, nil); st != 400 {
		t.Fatalf("clear without reason: %d", st)
	}
	if st := h.admin("POST", "/admin/sites/"+siteID+"/fragile", v1.AdminFragileRequest{IP: "10.30.5.21", Action: "clear", Reason: "vendor confirmed the printer survives probing"}, &fr); st != 200 {
		t.Fatalf("clear: %d", st)
	}
	if fr.Hosts[0].Excluded || !fr.Hosts[0].Cleared || fr.Hosts[0].Reason != "cleared" || fr.Version != 1 || len(fr.Cleared) != 1 {
		t.Fatalf("after clear: %+v", fr)
	}
	if st := h.admin("POST", "/admin/sites/"+siteID+"/fragile", v1.AdminFragileRequest{IP: "10.30.5.20", Action: "mark", Reason: "PLC behind the WMS host"}, &fr); st != 200 || len(fr.Hosts) != 2 {
		t.Fatalf("mark: %d %+v", st, fr)
	}
	for _, hv := range fr.Hosts {
		if hv.IP == "10.30.5.20" && (!hv.Excluded || hv.Reason != "policy" || !hv.Marked) {
			t.Fatalf("marked host: %+v", hv)
		}
	}
	if st := h.admin("POST", "/admin/sites/"+siteID+"/fragile", v1.AdminFragileRequest{IP: "10.30.5.20", Action: "unmark", Reason: "wrong host"}, &fr); st != 200 || len(fr.Marked) != 0 {
		t.Fatalf("unmark: %d %+v", st, fr)
	}
	sv := h.site(t, siteID)
	if sv.Config.Version != 3 || len(sv.Config.FragileCleared) != 1 || sv.Config.FragileCleared[0] != "10.30.5.21" {
		t.Fatalf("site policy: %+v", sv.Config)
	}

	// Findings: review the noisy one as a false positive and codify it.
	var hosts []v1.AdminHostView
	h.admin("GET", "/admin/sites/"+siteID+"/hosts", nil, &hosts)
	var noisy, real, tech v1.AdminFindingView
	for _, hv := range hosts {
		for _, f := range hv.Findings {
			switch f.NVTOID + f.TemplateID {
			case "1.3.6.1.4.1.25623.1.0.4242":
				noisy = f
			case "1.3.6.1.4.1.25623.1.0.108587":
				real = f
			case "tech-detect":
				tech = f
			}
		}
	}
	if noisy.ID == "" || real.ID == "" || tech.ID == "" || noisy.State != v1.FindingSuspected || !real.NetworkReachable || real.ExposureMultiplier != v1.ExposureMultiplier {
		t.Fatalf("findings: noisy=%+v real=%+v tech=%+v", noisy, real, tech)
	}
	if st := h.admin("PATCH", "/admin/findings/"+noisy.ID, v1.AdminFindingReview{Review: "bogus"}, nil); st != 400 {
		t.Fatalf("bad review accepted: %d", st)
	}
	var reviewed v1.AdminFindingView
	if st := h.admin("PATCH", "/admin/findings/"+noisy.ID, v1.AdminFindingReview{Review: v1.ReviewFalsePositive, Reason: "banner only, service patched", Codify: true}, &reviewed); st != 200 || reviewed.Review != v1.ReviewFalsePositive || reviewed.ReviewedAt == nil {
		t.Fatalf("review: %d %+v", st, reviewed)
	}
	var ex map[string]any
	h.admin("GET", "/admin/sites/"+siteID+"/exclusions", nil, &ex)
	if got, _ := json.Marshal(ex["vt_excludes"]); string(got) != `["1.3.6.1.4.1.25623.1.0.4242"]` {
		t.Fatalf("exclusions after codify: %s", got)
	}
	// A later scan reporting it again keeps it a reviewed false positive.
	sum, err := h.st.IngestHosts(ctx, siteID, "job_b", []v1.Host{{IP: "10.30.5.20", Ports: []v1.Port{{Port: 8080, Proto: "tcp"}}, Findings: []v1.Finding{
		{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.4242", Name: "Noisy banner check", Severity: v1.SeverityMedium, CVSS: 5, CVE: []string{}, QoD: 30, Port: 8080, Proto: "tcp"}}}}, "202609270530", h.now.Add(time.Hour))
	if err != nil || sum.Suppressed != 0 { // already reviewed: nothing new to suppress
		t.Fatalf("re-ingest: %v %+v", err, sum)
	}
	var detail v1.AdminFindingDetail
	if st := h.admin("GET", "/admin/findings/"+noisy.ID, nil, &detail); st != 200 || detail.Finding.Review != v1.ReviewFalsePositive || detail.Host.IP != "10.30.5.20" || len(detail.Finding.Evidence) != 2 {
		t.Fatalf("detail: %d %+v", st, detail)
	}
	// Exclude the nuclei template explicitly, then remove the exclusion.
	var exResp map[string]any
	if st := h.admin("POST", "/admin/sites/"+siteID+"/exclusions", v1.AdminExclusionRequest{VT: "nuclei:tech-detect", Reason: "informational"}, &exResp); st != 200 || exResp["reviewed"].(float64) != 1 {
		t.Fatalf("exclude template: %d %v", st, exResp)
	}
	if st := h.admin("DELETE", "/admin/sites/"+siteID+"/exclusions/nuclei:tech-detect?reason=needed+after+all", nil, &exResp); st != 200 || len(exResp["vt_excludes"].([]any)) != 1 {
		t.Fatalf("unexclude: %d %v", st, exResp)
	}
	if st := h.admin("DELETE", "/admin/sites/"+siteID+"/exclusions/nope", nil, nil); st != 404 {
		t.Fatalf("unexclude unknown: %d", st)
	}
	// Tuning report.
	var rep v1.AdminTuningReport
	if st := h.admin("GET", "/admin/sites/"+siteID+"/tuning", nil, &rep); st != 200 || rep.Findings != 3 || rep.FalsePositives != 2 || rep.FalsePositiveRate < 0.66 || rep.Suspected != 0 || len(rep.ByDetector) != 3 || !rep.ByDetector[0].Excluded && rep.ByDetector[0].FalsePositives == 0 {
		t.Fatalf("tuning: %d %+v", st, rep)
	}
	// Accepting the real finding takes it out of the open count; reopening puts it back.
	if st := h.admin("PATCH", "/admin/findings/"+real.ID, v1.AdminFindingReview{Review: v1.ReviewAccepted, Reason: "compensating control"}, &reviewed); st != 200 || reviewed.Review != v1.ReviewAccepted {
		t.Fatalf("accept: %d", st)
	}
	var cov v1.AdminCoverage
	h.admin("GET", "/admin/sites/"+siteID+"/coverage", nil, &cov)
	if cov.Findings.Open != 0 || cov.Findings.FalsePositives != 2 {
		t.Fatalf("coverage findings: %+v", cov.Findings)
	}
	var reopened v1.AdminFindingView // fresh: omitempty fields do not clear a reused struct
	if st := h.admin("PATCH", "/admin/findings/"+real.ID, v1.AdminFindingReview{Review: ""}, &reopened); st != 200 || reopened.Review != "" || reopened.ReviewedAt != nil {
		t.Fatalf("reopen: %d %+v", st, reopened)
	}
	var hv v1.AdminHostView
	var hvs []v1.AdminHostView
	if st := h.admin("GET", "/admin/hosts/"+detail.Host.ID, nil, &hvs); st != 200 || len(hvs) != 1 || hvs[0].IP != "10.30.5.20" {
		t.Fatalf("host detail: %d %+v", st, hvs)
	}
	_ = hv
}

func TestSchedulesAndCalendar(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	siteID := created.SiteID
	// A known point in time: Wednesday 2026-09-23 10:00 UTC.
	h.now = time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	var sc v1.AdminScheduleView
	if st := h.admin("POST", "/admin/schedules", v1.AdminScheduleRequest{ApplianceID: h.applID, Name: "weekly inventory", Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}, Cron: "0 22 * * 6", TZ: "UTC", MaxDurationS: 4 * 3600}, &sc); st != 201 {
		t.Fatalf("create schedule: %d %+v", st, sc)
	}
	sat := time.Date(2026, 9, 26, 22, 0, 0, 0, time.UTC)
	if sc.NextOccurrence == nil || !sc.NextOccurrence.Equal(sat) || sc.NextJobID == "" || !sc.Enabled {
		t.Fatalf("materialized: %+v", sc)
	}
	var job v1.AdminJobView
	h.admin("GET", "/admin/jobs/"+sc.NextJobID, nil, &job)
	if job.Status != v1.JobQueued || job.ScheduledFor == nil || !job.ScheduledFor.Equal(sat) || job.ScheduleID != sc.ID || job.Spec.Window == nil || job.Spec.Window.Cron != "0 22 * * 6" {
		t.Fatalf("occurrence job: %+v", job)
	}
	// Ticks are idempotent.
	for i := 0; i < 3; i++ {
		if err := h.srv.SchedulerTick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var jobs []v1.AdminJobView
	h.admin("GET", "/admin/jobs?site="+siteID, nil, &jobs)
	if len(jobs) != 1 {
		t.Fatalf("duplicate occurrence jobs: %d", len(jobs))
	}
	// Not dispatchable before the window; dispatched once it opens.
	if _, st := h.pollJobs(t); st != 204 {
		t.Fatalf("dispatched before the window: %d", st)
	}
	h.now = sat.Add(30 * time.Minute)
	h.heartbeat(v1.Heartbeat{Version: "1.4.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true, FeedVersion: "202609260530"}})
	jr, st := h.pollJobs(t)
	if st != 200 || jr.Job.JobID != sc.NextJobID {
		t.Fatalf("dispatch in window: %d", st)
	}
	// The calendar shows the dispatched job and the following occurrences.
	var cal []v1.AdminCalendarEntry
	if st := h.admin("GET", "/admin/sites/"+siteID+"/calendar?days=21", nil, &cal); st != 200 || len(cal) < 3 || cal[0].Kind != "job" || cal[0].JobID != sc.NextJobID || cal[1].Kind != "occurrence" || !cal[1].At.Equal(sat.Add(7*24*time.Hour)) {
		t.Fatalf("calendar: %d %+v", st, cal)
	}
	// After the job finishes the scheduler queues the next Saturday.
	h.admin("GET", "/admin/jobs/"+sc.NextJobID, nil, &job)
	h.st.UpdateJobStatusForTest(t, job.ID, v1.JobDone, h.now)
	if err := h.srv.SchedulerTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.admin("GET", "/admin/schedules/"+sc.ID, nil, &sc)
	if sc.LastJobID != job.ID || sc.NextJobID == job.ID || sc.NextOccurrence == nil || !sc.NextOccurrence.Equal(sat.Add(7*24*time.Hour)) {
		t.Fatalf("rolled forward: %+v", sc)
	}
	// Disabling cancels the queued occurrence; deleting removes it.
	off := false
	var disabled v1.AdminScheduleView // fresh: omitempty fields do not clear a reused struct
	h.admin("PATCH", "/admin/schedules/"+sc.ID, v1.AdminScheduleRequest{Enabled: &off}, &disabled)
	jobs = nil
	h.admin("GET", "/admin/jobs?site="+siteID, nil, &jobs)
	cancelled := 0
	for _, j := range jobs {
		if j.Status == v1.JobCancelled {
			cancelled++
		}
	}
	if disabled.Enabled || disabled.NextJobID != "" || disabled.NextOccurrence != nil || cancelled != 1 {
		t.Fatalf("disable: %+v cancelled=%d", disabled, cancelled)
	}
	if st := h.admin("POST", "/admin/schedules", v1.AdminScheduleRequest{ApplianceID: h.applID, Mode: "nope", Targets: []string{"10.30.5.0/24"}, Cron: "0 22 * * 6"}, nil); st != 400 {
		t.Fatalf("bad mode: %d", st)
	}
	if st := h.admin("POST", "/admin/schedules", v1.AdminScheduleRequest{ApplianceID: h.applID, Mode: v1.ModeDiscovery, Targets: []string{"10.99.0.0/16"}, Cron: "0 22 * * 6"}, nil); st != 400 {
		t.Fatalf("out-of-scope schedule accepted: %d", st)
	}
	if st := h.admin("DELETE", "/admin/schedules/"+sc.ID, nil, nil); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if st := h.admin("GET", "/admin/schedules/"+sc.ID, nil, nil); st != 404 {
		t.Fatalf("after delete: %d", st)
	}
}

func TestCoverageHealthAlertsAndTransparency(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	siteID := created.SiteID
	h.now = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	ready := v1.Heartbeat{Version: "1.4.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true, FeedVersion: "202609260530"}}
	h.heartbeat(ready)
	var av v1.AdminApplianceView
	h.admin("GET", "/admin/appliances/"+h.applID, nil, &av)
	if av.Health != v1.HealthOnline {
		t.Fatalf("health: %+v", av.Health)
	}
	// Hosts: two seen by the appliance, one of them also by an agent.
	if _, err := h.st.IngestHosts(t.Context(), siteID, "job_x", []v1.Host{{IP: "10.30.5.20", MAC: "00:50:56:ab:cd:ef"}, {IP: "10.30.5.21"}}, "f", h.now); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.IngestAgentHosts(t.Context(), siteID, []v1.AgentHost{{AgentID: "wz-7", Hostname: "wms", MACs: []string{"00:50:56:ab:cd:ef"}}}, h.now); err != nil {
		t.Fatal(err)
	}
	var cov v1.AdminCoverage
	h.admin("GET", "/admin/sites/"+siteID+"/coverage", nil, &cov)
	// online (40) + no inventory (0) + hosts 1/2 (10) - attestation (10) = 40
	if cov.Score != 40 || cov.Components["appliance"] != 40 || cov.Components["freshness"] != 0 || cov.Components["hosts"] != 10 || cov.Hosts.Agentless != 1 || !cov.Freshness.Overdue {
		t.Fatalf("coverage: score=%d %+v reasons=%v", cov.Score, cov.Components, cov.Reasons)
	}
	// A completed inventory scan two days ago.
	var job v1.AdminJobView
	h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: h.applID, Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}}, &job)
	h.st.UpdateJobStatusForTest(t, job.ID, v1.JobDone, h.now.Add(-48*time.Hour))
	h.admin("GET", "/admin/sites/"+siteID+"/coverage", nil, &cov)
	if cov.Score != 80 || cov.Components["freshness"] != 40 || cov.Freshness.LastInventory == nil || cov.Freshness.Overdue {
		t.Fatalf("coverage with inventory: score=%d %+v", cov.Score, cov.Components)
	}
	var vcov v1.AdminCoverage
	if st := h.admin("GET", "/admin/vendors/"+created.SiteID[:0]+"nope/coverage", nil, nil); st != 404 {
		t.Fatalf("unknown vendor: %d", st)
	}
	var sv v1.AdminSiteView
	h.admin("GET", "/admin/sites/"+siteID, nil, &sv)
	if st := h.admin("GET", "/admin/vendors/"+sv.VendorID+"/coverage", nil, &vcov); st != 200 || vcov.Score != 80 || len(vcov.Sites) != 1 {
		t.Fatalf("vendor coverage: %d %+v", st, vcov)
	}
	// Degraded after 15 minutes of a not-ready engine; silent after 24 h.
	notReady := ready
	notReady.Engine.VTCacheLoaded = false
	h.heartbeat(notReady)
	h.now = h.now.Add(16 * time.Minute)
	h.heartbeat(notReady)
	h.admin("GET", "/admin/appliances/"+h.applID, nil, &av)
	if av.Health != v1.HealthDegraded || av.EngineDownSince == nil {
		t.Fatalf("degraded: %+v", av.Health)
	}
	var alerts []v1.AdminAlert
	h.admin("GET", "/admin/alerts", nil, &alerts)
	kinds := map[string]int{}
	for _, a := range alerts {
		kinds[a.Kind]++
	}
	if kinds["degraded"] != 1 || kinds["attestation_stale"] != 1 || kinds["silent"] != 0 {
		t.Fatalf("alerts: %+v", alerts)
	}
	h.now = h.now.Add(25 * time.Hour)
	h.admin("GET", "/admin/appliances/"+h.applID, nil, &av)
	h.admin("GET", "/admin/alerts", nil, &alerts)
	kinds = map[string]int{}
	for _, a := range alerts {
		kinds[a.Kind]++
	}
	if av.Health != v1.HealthSilent || kinds["silent"] != 1 {
		t.Fatalf("silent: health=%s alerts=%+v", av.Health, alerts)
	}
	var cov2 v1.AdminCoverage
	h.admin("GET", "/admin/sites/"+siteID+"/coverage", nil, &cov2)
	if cov2.Components["appliance"] != 0 || cov2.Appliance.Silent != 1 || cov2.Score != 40 {
		t.Fatalf("coverage while silent: %+v", cov2)
	}
	// Appliance list filters.
	var list []v1.AdminApplianceView
	h.admin("GET", "/admin/appliances?site="+siteID, nil, &list)
	if len(list) != 1 {
		t.Fatalf("site filter: %d", len(list))
	}
	h.admin("GET", "/admin/appliances?vendor=vnd_nope", nil, &list)
	if len(list) != 0 {
		t.Fatalf("vendor filter: %d", len(list))
	}
	// Transparency page: no authentication, on the enroll listener too.
	resp, err := h.client(nil).Get(h.enroll.URL + "/transparency")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(body)
	for _, want := range []string{"what this appliance does", "<strong>inventory</strong>", "Denial of Service", "Open-source notices", "openvas-scanner", "stop_all", "Never collected"} {
		if resp.StatusCode != 200 || !strings.Contains(page, want) {
			t.Fatalf("transparency page (%d) missing %q", resp.StatusCode, want)
		}
	}
	resp, err = h.client(nil).Get(h.mtls.URL + "/transparency.json")
	if err != nil {
		t.Fatal(err)
	}
	var tj map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&tj)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(tj["tools"].([]any)) != 8 || len(tj["scan_configs"].([]any)) != 2 {
		t.Fatalf("transparency json: %d %v", resp.StatusCode, tj)
	}
}
