package server

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// TestFingerprintSignoffGate: the nmap module is refused until the legal
// sign-off is recorded (PLAN §21); once it is, full-mode jobs carry it by
// default, explicit module lists are respected, and revoking it stops new
// jobs again. The transparency page tells the vendor either way.
func TestFingerprintSignoffGate(t *testing.T) {
	h := newHarness(t)
	h.enrolled(t)
	h.now = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	var so v1.AdminSignoffView
	if st := h.admin("GET", "/admin/signoffs/nmap", nil, &so); st != 200 || so.Approved {
		t.Fatalf("initial signoff: %d %+v", st, so)
	}
	if st := h.admin("GET", "/admin/signoffs/masscan", nil, nil); st != 404 {
		t.Fatalf("unknown tool: %d", st)
	}
	var errResp map[string]any
	req := v1.AdminJobRequest{ApplianceID: h.applID, Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}, Fingerprint: v1.DefaultFingerprintParams()}
	if st := h.admin("POST", "/admin/jobs", req, &errResp); st != 403 || errResp["code"] != "fingerprint_not_approved" {
		t.Fatalf("fingerprint before signoff: %d %v", st, errResp)
	}
	// full mode without the sign-off: the usual four modules.
	var job v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: h.applID, Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"}}, &job); st != 201 || job.Spec.HasModule(v1.ModuleFingerprint) || job.Spec.Fingerprint != nil {
		t.Fatalf("full before signoff: %d %v", st, job.Spec.Modules)
	}
	// Record it (reference required).
	if st := h.admin("PUT", "/admin/signoffs/nmap", v1.AdminSignoffRequest{Reference: " "}, &errResp); st != 400 {
		t.Fatalf("empty reference: %d", st)
	}
	if st := h.adminAs(h.adminTok, "PUT", "/admin/signoffs/nmap", v1.AdminSignoffRequest{Reference: "LEGAL-2026-014", Note: "NPSL review, commercial redistribution cleared"}, &so); st != 200 || !so.Approved || so.By != h.adminTok+"@test" || so.At == nil || so.Reference != "LEGAL-2026-014" {
		t.Fatalf("record signoff: %d %+v", st, so)
	}
	var job2 v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", req, &job2); st != 201 || !job2.Spec.HasModule(v1.ModuleFingerprint) || job2.Spec.Fingerprint == nil || job2.Spec.Fingerprint.Intensity != 5 {
		t.Fatalf("fingerprint after signoff: %d %+v", st, job2.Spec)
	}
	var full v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: h.applID, Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"}}, &full); st != 201 || !full.Spec.HasModule(v1.ModuleFingerprint) || !full.Spec.HasModule(v1.ModuleWeb) {
		t.Fatalf("full after signoff: %d %v", st, full.Spec.Modules)
	}
	var explicit v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: h.applID, Mode: v1.ModeFull, Targets: []string{"10.30.5.0/24"}, Modules: []string{v1.ModuleDiscovery, v1.ModulePortscan, v1.ModuleOpenVAS}}, &explicit); st != 201 || explicit.Spec.HasModule(v1.ModuleFingerprint) {
		t.Fatalf("explicit modules: %d %v", st, explicit.Spec.Modules)
	}
	// The dispatched spec is signed with the new fields and verifies.
	h.heartbeat(v1.Heartbeat{Version: "1.5.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true, Tools: []string{"naabu", "httpx", "nuclei", "nmap"}}})
	var av v1.AdminApplianceView
	h.admin("GET", "/admin/appliances/"+h.applID, nil, &av)
	if strings.Join(av.Tools, ",") != "naabu,httpx,nuclei,nmap" {
		t.Fatalf("tools in view: %v", av.Tools)
	}
	// Schedules carry an explicit module set.
	var sc v1.AdminScheduleView
	if st := h.admin("POST", "/admin/schedules", v1.AdminScheduleRequest{ApplianceID: h.applID, Name: "fp", Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}, Cron: "0 3 * * 0", TZ: "UTC",
		Modules: []string{v1.ModuleDiscovery, v1.ModulePortscan, v1.ModuleFingerprint}}, &sc); st != 201 || len(sc.Modules) != 3 || sc.NextJobID == "" {
		t.Fatalf("schedule with modules: %d %+v", st, sc)
	}
	var sjob v1.AdminJobView
	h.admin("GET", "/admin/jobs/"+sc.NextJobID, nil, &sjob)
	if !sjob.Spec.HasModule(v1.ModuleFingerprint) || sjob.Spec.HasModule(v1.ModuleOpenVAS) || sjob.Spec.Fingerprint == nil {
		t.Fatalf("scheduled job modules: %v", sjob.Spec.Modules)
	}
	// Transparency reflects the sign-off.
	resp, err := h.client(nil).Get(h.enroll.URL + "/transparency")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "NPSL-0.95") || !strings.Contains(string(body), "enabled since 2026-10-01 under review LEGAL-2026-014") {
		t.Fatalf("transparency after signoff: %s", body)
	}
	// Revoke: new jobs are refused again, the schedule cannot materialize.
	if st := h.admin("DELETE", "/admin/signoffs/nmap", nil, &so); st != 200 || so.Approved {
		t.Fatalf("revoke: %d %+v", st, so)
	}
	if st := h.admin("POST", "/admin/jobs", req, &errResp); st != 403 {
		t.Fatalf("fingerprint after revoke: %d", st)
	}
	resp, _ = h.client(nil).Get(h.mtls.URL + "/transparency.json")
	var tj map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&tj)
	resp.Body.Close()
	found := false
	for _, tool := range tj["tools"].([]any) {
		m := tool.(map[string]any)
		if m["Name"] == "nmap" && strings.Contains(m["Role"].(string), "NOT enabled") {
			found = true
		}
	}
	if !found {
		t.Fatalf("transparency json after revoke: %v", tj["tools"])
	}
}

// TestFullRangeBudgetAtDispatch: the full-range port option is budgeted
// against the site inventory (PLAN §10.2 Phase 5). Without an inventory
// the address count is used, with one the live hosts inside the targets.
func TestFullRangeBudgetAtDispatch(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	h.now = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	var errResp map[string]any
	req := v1.AdminJobRequest{ApplianceID: h.applID, Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}, Ports: v1.PortsFull}
	if st := h.admin("POST", "/admin/jobs", req, &errResp); st != 400 || errResp["code"] != "guardrail_duration" {
		t.Fatalf("full range without inventory: %d %v", st, errResp)
	}
	// Twelve live hosts in the range (one of them excluded), plus one stale.
	var hosts []v1.Host
	for i := 10; i < 22; i++ {
		hosts = append(hosts, v1.Host{IP: "10.30.5." + itoa(i), Ports: []v1.Port{{Port: 22, Proto: "tcp"}}})
	}
	if _, err := h.st.IngestHosts(t.Context(), created.SiteID, "job_seed", hosts, "f", h.now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.IngestHosts(t.Context(), created.SiteID, "job_old", []v1.Host{{IP: "10.30.5.200"}}, "f", h.now.Add(-60*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	req.Excludes = []string{"10.30.5.10"}
	var job v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", req, &job); st != 201 || job.Spec.ExpectedHosts != 11 || job.Spec.Ports != v1.PortsFull {
		t.Fatalf("full range with inventory: %d expected_hosts=%d", st, job.Spec.ExpectedHosts)
	}
	// A short window still fails, and the message says what to change.
	req.Window = &v1.Window{MaxDurationS: 600}
	errResp = map[string]any{}
	if st := h.admin("POST", "/admin/jobs", req, &errResp); st != 400 || !strings.Contains(errResp["error"].(string), "ports=standard") {
		t.Fatalf("short window: %d %v", st, errResp)
	}
	req.Window = nil
	// Standard scans of the same range are not budgeted and carry no hint.
	req.Ports = v1.PortsStandard
	var std v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", req, &std); st != 201 || std.Spec.ExpectedHosts != 0 {
		t.Fatalf("standard: %d %+v", st, std.Spec)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// TestOnboardingChecklist walks a site through PLAN §19.2 and watches the
// checklist follow.
func TestOnboardingChecklist(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.VendorOwnerToken = ownerTok
	created := h.enrolled(t)
	siteID := created.SiteID
	h.now = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	get := func() v1.AdminOnboardingView {
		var v v1.AdminOnboardingView
		if st := h.admin("GET", "/admin/sites/"+siteID+"/onboarding", nil, &v); st != 200 {
			t.Fatalf("onboarding: %d", st)
		}
		return v
	}
	done := func(v v1.AdminOnboardingView) map[string]bool {
		m := map[string]bool{}
		for _, s := range v.Steps {
			m[s.Key] = s.Done
		}
		return m
	}
	v := get()
	d := done(v)
	if v.Complete || len(v.Steps) != 9 || !d["appliance_enrolled"] || d["scope_attested"] || d["appliance_online"] || v.Next != "Vendor owner attested the scope" {
		t.Fatalf("fresh site: %+v", v)
	}
	if st := h.adminAs(ownerTok, "POST", "/admin/sites/"+siteID+"/attest", v1.AdminDecision{Reason: "onboarding call"}, nil); st != 200 {
		t.Fatalf("attest: %d", st)
	}
	h.heartbeat(v1.Heartbeat{Version: "1.5.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}})
	d = done(get())
	if !d["scope_attested"] || !d["appliance_online"] || !d["attestation_current"] || d["discovery_done"] {
		t.Fatalf("after attest + heartbeat: %+v", d)
	}
	// Discovery done, but a printer awaits a fragile decision.
	var job v1.AdminJobView
	h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: h.applID, Mode: v1.ModeDiscovery, Targets: []string{"10.30.5.0/24"}}, &job)
	h.st.UpdateJobStatusForTest(t, job.ID, v1.JobDone, h.now)
	if _, err := h.st.IngestHosts(t.Context(), siteID, job.ID, []v1.Host{{IP: "10.30.5.21", Ports: []v1.Port{{Port: 9100, Proto: "tcp"}}}, {IP: "10.30.5.20", Ports: []v1.Port{{Port: 3389, Proto: "tcp"}}}}, "f", h.now); err != nil {
		t.Fatal(err)
	}
	v = get()
	d = done(v)
	if !d["discovery_done"] || d["exclusions_reviewed"] || !strings.Contains(v.Steps[4].Detail, "1 host(s)") {
		t.Fatalf("pending fragile decision: %+v", v.Steps[4])
	}
	if st := h.admin("POST", "/admin/sites/"+siteID+"/fragile", v1.AdminFragileRequest{IP: "10.30.5.21", Action: "mark", Reason: "label printer"}, nil); st != 200 {
		t.Fatalf("mark: %d", st)
	}
	d = done(get())
	if !d["exclusions_reviewed"] || d["inventory_scheduled"] || d["full_scheduled"] || d["two_cycles"] {
		t.Fatalf("after fragile decision: %+v", d)
	}
	for _, mode := range []string{v1.ModeInventory, v1.ModeFull} {
		if st := h.admin("POST", "/admin/schedules", v1.AdminScheduleRequest{ApplianceID: h.applID, Name: mode, Mode: mode, Targets: []string{"10.30.5.0/24"}, Cron: "0 22 * * 6", TZ: "UTC"}, nil); st != 201 {
			t.Fatalf("schedule %s: %d", mode, st)
		}
	}
	for i := 0; i < 2; i++ {
		var j v1.AdminJobView
		h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: h.applID, Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}}, &j)
		h.st.UpdateJobStatusForTest(t, j.ID, v1.JobDone, h.now.Add(time.Duration(i)*7*24*time.Hour))
	}
	v = get()
	if !v.Complete || v.Next != "" {
		t.Fatalf("not complete: %+v", v)
	}
	// Ninety-one days later the attestation is stale again.
	h.now = h.now.Add(91 * 24 * time.Hour)
	h.heartbeat(v1.Heartbeat{Version: "1.5.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}})
	v = get()
	if v.Complete || !strings.Contains(v.Next, "re-attestation") {
		t.Fatalf("stale attestation: %+v", v)
	}
}

// TestFeedGapReport classifies what the appliances saw for the Enterprise
// Feed evaluation.
func TestFeedGapReport(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	h.now = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	var rep v1.AdminFeedGapReport
	if st := h.admin("GET", "/admin/feed-gaps", nil, &rep); st != 200 || rep.Hosts != 0 || !strings.Contains(rep.Recommendation, "no appliance inventory") {
		t.Fatalf("empty report: %d %+v", st, rep)
	}
	hosts := []v1.Host{
		{IP: "10.30.5.1", Hostname: "fw-reno", Ports: []v1.Port{{Port: 443, Proto: "tcp", Service: "https", Product: "FortiGate", CPE: "cpe:/a:fortinet:fortios"}}},
		{IP: "10.30.5.2", Ports: []v1.Port{{Port: 22, Proto: "tcp", Service: "ssh", Product: "Cisco SSH"}, {Port: 23, Proto: "tcp"}}},
		{IP: "10.30.5.20", Ports: []v1.Port{{Port: 3389, Proto: "tcp", Service: "rdp"}}, Findings: []v1.Finding{{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.1", Name: "x", Severity: v1.SeverityHigh, CVSS: 7.5, QoD: 80, CVE: []string{}}}},
		{IP: "10.30.5.21", Ports: []v1.Port{{Port: 9100, Proto: "tcp"}}},
		{IP: "10.30.5.30", OSGuess: &v1.OSGuess{Family: "other", Name: "VMware ESXi 7.0", CPE: "cpe:/o:vmware:esxi:7.0", Source: "nmap:os_detection", Confidence: 0.96}, Ports: []v1.Port{{Port: 443, Proto: "tcp", Web: &v1.WebInfo{URL: "https://10.30.5.30", Server: "VMware"}}}},
	}
	if _, err := h.st.IngestHosts(t.Context(), created.SiteID, "job_1", hosts, "f", h.now); err != nil {
		t.Fatal(err)
	}
	if st := h.admin("GET", "/admin/feed-gaps?site="+created.SiteID, nil, &rep); st != 200 {
		t.Fatalf("report: %d", st)
	}
	if rep.Hosts != 5 || rep.OpenPorts != 6 || rep.UnidentifiedPorts != 2 || rep.IdentifiedPorts != 4 || rep.EnterpriseHosts != 3 || rep.HostsNoFindings != 4 {
		t.Fatalf("counts: %+v", rep)
	}
	vendors := map[string]v1.AdminFeedGapEntry{}
	for _, e := range rep.Enterprise {
		vendors[e.Vendor] = e
	}
	if len(vendors) != 3 || vendors["Fortinet"].Hosts != 1 || vendors["Cisco"].Ports != 1 || vendors["VMware"].Hosts != 1 || len(vendors["Fortinet"].Examples) != 1 {
		t.Fatalf("vendors: %+v", rep.Enterprise)
	}
	if !strings.HasPrefix(rep.Recommendation, "evaluate the Enterprise Feed") {
		t.Fatalf("recommendation: %s", rep.Recommendation)
	}
	if st := h.admin("GET", "/admin/feed-gaps?site=site_nope", nil, nil); st != 404 {
		t.Fatalf("unknown site: %d", st)
	}
	if r := feedRecommendation(v1.AdminFeedGapReport{Hosts: 100, OpenPorts: 100, UnidentifiedPorts: 40}); !strings.HasPrefix(r, "identify first") {
		t.Fatalf("identify-first branch: %s", r)
	}
	if r := feedRecommendation(v1.AdminFeedGapReport{Hosts: 100, OpenPorts: 100, IdentifiedPorts: 90, UnidentifiedPorts: 10, EnterpriseHosts: 3}); !strings.HasPrefix(r, "stay on the community feed") {
		t.Fatalf("stay branch: %s", r)
	}
}
