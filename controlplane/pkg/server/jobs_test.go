package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/seal"
)

func (h *harness) enrolled(t *testing.T) v1.AdminCreateApplianceResponse {
	t.Helper()
	var created v1.AdminCreateApplianceResponse
	if st := h.admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme 3PL", Site: "Reno DC", AllowedCIDRs: []string{"10.30.0.0/16"}}, &created); st != 201 {
		t.Fatalf("create: %d", st)
	}
	if _, st := h.doEnroll(created.Code); st != 200 {
		t.Fatalf("enroll: %d", st)
	}
	return created
}

func (h *harness) pollJobs(t *testing.T) (*v1.JobsResponse, int) {
	t.Helper()
	resp, err := h.client(&h.applCert).Get(h.mtls.URL + "/v1/appliances/" + h.applID + "/jobs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode
	}
	var jr v1.JobsResponse
	_ = json.NewDecoder(resp.Body).Decode(&jr)
	return &jr, 200
}

func (h *harness) upload(t *testing.T, jobID string, batch v1.ResultBatch, pub string) (int, v1.ResultAck, string) {
	t.Helper()
	pk, err := seal.ParsePublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	body, err := seal.SealJSON(pk, batch, seal.AAD(jobID, batch.Seq))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	req, _ := http.NewRequest("POST", h.mtls.URL+"/v1/jobs/"+jobID+"/results", bytes.NewReader(body))
	req.Header.Set("Content-Type", v1.ContentTypeSealed)
	req.Header.Set(v1.HeaderResultSeq, strconv.Itoa(batch.Seq))
	req.Header.Set(v1.HeaderResultSHA256, hex.EncodeToString(sum[:]))
	resp, err := h.client(&h.applCert).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var ack v1.ResultAck
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &ack)
	return resp.StatusCode, ack, string(b)
}

func TestJobDispatchAndResults(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	// Fetch the spool key the way the daemon does (enroll response).
	var view v1.AdminApplianceView
	h.admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &view)
	pub := h.srv.cfg.SpoolKey.PublicString()

	// Guardrails at creation: out-of-scope target is refused.
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: "inventory", Targets: []string{"10.31.0.0/24"}}, nil); st != 400 {
		t.Fatalf("out of scope accepted: %d", st)
	}
	// Tier 1 vendor cannot get unsafe checks (default tier is 3, so this passes shape but the site is not unsafe_ok).
	f := false
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: "full", Targets: []string{"10.30.5.0/24"}, SafeChecks: &f}, nil); st != 400 {
		t.Fatalf("unsafe accepted: %d", st)
	}
	var job v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: "inventory", Targets: []string{"10.30.5.0/24"}, Excludes: []string{"10.30.5.1"}}, &job); st != 201 {
		t.Fatalf("create job: %d", st)
	}
	if job.Status != v1.JobQueued || job.Spec.OpenVAS == nil || job.Spec.OpenVAS.Config != "inventory" || len(job.Spec.Modules) != 3 || job.Spec.Iface != "lan0" {
		t.Fatalf("job defaults: %+v", job)
	}

	// No heartbeat yet → engine unknown → openvas job is withheld.
	if _, st := h.pollJobs(t); st != 204 {
		t.Fatalf("withheld job dispatched: %d", st)
	}
	h.heartbeat(v1.Heartbeat{Version: "test", State: "idle", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true, VTCount: 10}})
	jr, st := h.pollJobs(t)
	if st != 200 {
		t.Fatalf("dispatch: %d", st)
	}
	spec := jr.Job
	if spec.JobID != job.ID || spec.ApplianceID != created.ApplianceID || spec.Sig == "" || spec.IssuedAt != h.now.Unix() || len(jr.Site.AllowedCIDRs) != 1 || jr.Site.MaxConcurrency != 16 {
		t.Fatalf("dispatched spec: %+v site=%+v", spec, jr.Site)
	}
	// Signature verifies against the intermediate.
	body, _ := spec.SigningBytes()
	sum := sha256.Sum256(body)
	if !verifyWith(h.ca, sum[:], spec.Sig) {
		t.Fatal("signature does not verify against the issuing CA")
	}
	// Same job is not offered twice within the lease; after the lease it is.
	if _, st := h.pollJobs(t); st != 204 {
		t.Fatalf("re-dispatched inside lease: %d", st)
	}
	h.admin("GET", "/admin/jobs/"+job.ID, nil, &job)
	if job.Status != v1.JobDispatched {
		t.Fatalf("status %s", job.Status)
	}

	// Appliance reports running, then uploads two chunks; the second is final.
	sb, _ := json.Marshal(v1.JobStatusRequest{Status: v1.JobRunning, Phase: "discovery"})
	resp, _ := h.client(&h.applCert).Post(h.mtls.URL+"/v1/jobs/"+job.ID+"/status", "application/json", bytes.NewReader(sb))
	if resp.StatusCode != 204 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	b1 := v1.ResultBatch{JobID: job.ID, ApplianceID: created.ApplianceID, SiteID: job.SiteID, FeedVersion: "202609260530", StartedAt: 1, Seq: 1,
		Hosts: []v1.Host{{IP: "10.30.5.20", MAC: "00:50:56:ab:cd:ef", Hostname: "wms-app-01", Ports: []v1.Port{{Port: 3389, Proto: "tcp", Source: "naabu"}}, Findings: []v1.Finding{}}}}
	st1, ack, raw := h.upload(t, job.ID, b1, pub)
	if st1 != 200 || ack.Hosts != 1 || ack.Duplicate {
		t.Fatalf("upload 1: %d %s", st1, raw)
	}
	// Idempotent re-upload.
	if st, ack, _ := h.upload(t, job.ID, b1, pub); st != 200 || !ack.Duplicate {
		t.Fatalf("duplicate: %d %+v", st, ack)
	}
	// Wrong seq in the envelope → refused (AAD binds job+seq).
	bad := b1
	bad.Seq = 2
	pk, _ := seal.ParsePublic(pub)
	env, _ := seal.SealJSON(pk, bad, seal.AAD(job.ID, 1))
	req, _ := http.NewRequest("POST", h.mtls.URL+"/v1/jobs/"+job.ID+"/results", bytes.NewReader(env))
	req.Header.Set(v1.HeaderResultSeq, "2")
	resp, _ = h.client(&h.applCert).Do(req)
	if resp.StatusCode != 400 {
		t.Fatalf("mis-bound chunk accepted: %d", resp.StatusCode)
	}
	b2 := v1.ResultBatch{JobID: job.ID, ApplianceID: created.ApplianceID, SiteID: job.SiteID, FeedVersion: "202609260530", StartedAt: 1, FinishedAt: 2, Seq: 2, Final: true,
		Stats: &v1.ScanStats{HostsAlive: 1, HostsScanned: 1, Findings: 1, Rejected: []string{}},
		Hosts: []v1.Host{{IP: "10.30.5.20", MAC: "00:50:56:ab:cd:ef", Hostname: "wms-app-01", OSGuess: &v1.OSGuess{Family: "windows", Confidence: 0.7, Source: "openvas:os_detection"},
			Ports:    []v1.Port{{Port: 3389, Proto: "tcp", Service: "rdp", Source: "openvas:find_service"}},
			Findings: []v1.Finding{{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.108587", Name: "BlueKeep", Family: "Windows", Severity: "critical", CVSS: 9.8, CVE: []string{"CVE-2019-0708"}, QoD: 97, Port: 3389, Proto: "tcp", Evidence: "vulnerable", Solution: "patch"}}}}}
	if st, ack, raw := h.upload(t, job.ID, b2, pub); st != 200 || !ack.Complete {
		t.Fatalf("upload 2: %d %s", st, raw)
	}
	h.admin("GET", "/admin/jobs/"+job.ID, nil, &job)
	if job.Status != v1.JobDone || job.Batches != 2 || job.Stats == nil || job.Stats.Findings != 1 || job.FinishedAt == nil {
		t.Fatalf("job after final: %+v", job)
	}
	var hosts []v1.AdminHostView
	h.admin("GET", "/admin/jobs/"+job.ID+"/hosts", nil, &hosts)
	if len(hosts) != 1 || hosts[0].Source != v1.SourceAppliance || len(hosts[0].Findings) != 1 || hosts[0].Findings[0].State != v1.FindingNetworkObserved || hosts[0].Ports[0].Service != "rdp" {
		t.Fatalf("job hosts: %+v", hosts)
	}
	if n := h.st.NVT("1.3.6.1.4.1.25623.1.0.108587"); n == nil || n.Family != "Windows" || len(n.CVEs) != 1 {
		t.Fatalf("nvt mirror: %+v", n)
	}
	// Status after done: same status is idempotent, another is a conflict.
	sb, _ = json.Marshal(v1.JobStatusRequest{Status: v1.JobDone})
	resp, _ = h.client(&h.applCert).Post(h.mtls.URL+"/v1/jobs/"+job.ID+"/status", "application/json", bytes.NewReader(sb))
	if resp.StatusCode != 204 {
		t.Fatalf("idempotent done: %d", resp.StatusCode)
	}
	sb, _ = json.Marshal(v1.JobStatusRequest{Status: v1.JobFailed, Reason: "late"})
	resp, _ = h.client(&h.applCert).Post(h.mtls.URL+"/v1/jobs/"+job.ID+"/status", "application/json", bytes.NewReader(sb))
	if resp.StatusCode != 409 {
		t.Fatalf("terminal transition: %d", resp.StatusCode)
	}

	// Agent inventory correlates: host becomes both, finding confirmed.
	var inv v1.AdminAgentInventoryResponse
	if st := h.admin("POST", "/admin/sites/"+job.SiteID+"/agent-inventory", v1.AdminAgentInventoryRequest{Hosts: []v1.AgentHost{{AgentID: "wz-1", Hostname: "wms-app-01", MACs: []string{"00:50:56:AB:CD:EF"}, Findings: []v1.AgentFinding{{CVE: "CVE-2019-0708", Package: "termsrv"}}}}}, &inv); st != 200 || inv.Merged != 1 {
		t.Fatalf("agent inventory: %d %+v", st, inv)
	}
	h.admin("GET", "/admin/sites/"+job.SiteID+"/hosts", nil, &hosts)
	if hosts[0].Source != v1.SourceBoth || hosts[0].Findings[0].State != v1.FindingConfirmed || hosts[0].Findings[0].Source != v1.SourceBoth || len(hosts[0].Findings[0].Evidence) != 2 {
		t.Fatalf("correlated: %+v", hosts[0].Findings[0])
	}

	// Window scheduling: a job with a closed window is queued for the next start and not dispatched.
	var wjob v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: "discovery", Targets: []string{"10.30.6.0/24"}, Window: &v1.Window{Cron: "0 22 * * 6", MaxDurationS: 3600}}, &wjob); st != 201 {
		t.Fatalf("window job: %d", st)
	}
	if wjob.ScheduledFor == nil || !wjob.ScheduledFor.After(h.now) || wjob.Spec.Window.TZ != "UTC" {
		t.Fatalf("scheduled_for: %+v", wjob)
	}
	if _, st := h.pollJobs(t); st != 204 {
		t.Fatalf("future job dispatched: %d", st)
	}
	// run-now drops the window and queues a run_job_now directive.
	if st := h.admin("POST", "/admin/jobs/"+wjob.ID+"/run-now", nil, &wjob); st != 200 || wjob.Spec.Window != nil {
		t.Fatalf("run-now: %d %+v", st, wjob)
	}
	var dirs []v1.AdminDirectiveView
	h.admin("GET", "/admin/appliances/"+created.ApplianceID+"/directives", nil, &dirs)
	if len(dirs) != 1 || dirs[0].Type != v1.DirectiveRunJobNow || dirs[0].Payload["job_id"] != wjob.ID {
		t.Fatalf("directive: %+v", dirs)
	}
	if jr, st := h.pollJobs(t); st != 200 || jr.Job.JobID != wjob.ID {
		t.Fatalf("run-now dispatch: %d", st)
	}
	// stop_all reported in the heartbeat withholds jobs; cancel works on dispatched jobs.
	h.heartbeat(v1.Heartbeat{Version: "test", State: "idle", StopAll: true, Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}})
	h.now = h.now.Add(DispatchLease + time.Minute)
	if _, st := h.pollJobs(t); st != 204 {
		t.Fatalf("stop_all did not withhold: %d", st)
	}
	if st := h.admin("POST", "/admin/jobs/"+wjob.ID+"/cancel", nil, &wjob); st != 200 || wjob.Status != v1.JobCancelled {
		t.Fatalf("cancel: %d %s", st, wjob.Status)
	}
	// Scope change is reflected at dispatch: shrink the site, the queued job is rejected server-side.
	var j3 v1.AdminJobView
	h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: "discovery", Targets: []string{"10.30.7.0/24"}}, &j3)
	cidrs := []string{"10.30.5.0/24"}
	if st := h.admin("PATCH", "/admin/sites/"+job.SiteID, v1.AdminSiteUpdate{AllowedCIDRs: &cidrs}, nil); st != 200 {
		t.Fatalf("site update: %d", st)
	}
	h.heartbeat(v1.Heartbeat{Version: "test", State: "idle", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}})
	if _, st := h.pollJobs(t); st != 204 {
		t.Fatalf("out-of-scope job dispatched: %d", st)
	}
	h.admin("GET", "/admin/jobs/"+j3.ID, nil, &j3)
	if j3.Status != v1.JobRejected || j3.RejectReason == "" {
		t.Fatalf("scope rejection: %+v", j3)
	}
}
