package server

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
)

// results uploads one final chunk for a fresh job of the given mode and
// returns the job id (the lifecycle hook runs on the final chunk).
func (h *harness) runScan(t *testing.T, mode string, hosts []v1.Host) v1.AdminJobView {
	t.Helper()
	var job v1.AdminJobView
	if st := h.admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: h.applID, Mode: mode, Targets: []string{"10.30.5.0/24"}}, &job); st != 201 {
		t.Fatalf("create job: %d", st)
	}
	h.admin("POST", "/admin/jobs/"+job.ID+"/run-now", nil, nil)
	jr, st := h.pollJobs(t)
	if st != 200 || jr.Job.JobID != job.ID {
		t.Fatalf("poll: %d", st)
	}
	h.now = h.now.Add(time.Minute)
	if st, _, body := h.upload(t, job.ID, v1.ResultBatch{JobID: job.ID, ApplianceID: h.applID, SiteID: job.SiteID, FeedVersion: "f", Seq: 1, Final: true, Hosts: hosts,
		Stats: &v1.ScanStats{HostsAlive: len(hosts)}}, h.spoolPub(t)); st != 200 {
		t.Fatalf("upload: %d %s", st, body)
	}
	h.admin("GET", "/admin/jobs/"+job.ID, nil, &job)
	return job
}

func (h *harness) spoolPub(t *testing.T) string {
	t.Helper()
	return h.srv.cfg.SpoolKey.PublicString()
}

func (h *harness) findings(t *testing.T, siteID string) map[string]v1.AdminFindingView {
	t.Helper()
	var list []v1.AdminFindingView
	if st := h.admin("GET", "/admin/sites/"+siteID+"/findings", nil, &list); st != 200 {
		t.Fatalf("findings: %d", st)
	}
	out := map[string]v1.AdminFindingView{}
	for _, f := range list {
		out[f.Name] = f
	}
	return out
}

var (
	bkFinding  = v1.Finding{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.108587", Name: "BlueKeep", Severity: v1.SeverityCritical, CVSS: 9.8, QoD: 97, Port: 3389, Proto: "tcp", CVE: []string{"CVE-2019-0708"}, Evidence: "x"}
	smbFinding = v1.Finding{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.777", Name: "SMBv1", Severity: v1.SeverityMedium, CVSS: 5.0, QoD: 80, Port: 445, Proto: "tcp", CVE: []string{"CVE-2017-0144"}, Evidence: "x"}
)

// TestLifecycleAndSummary: findings open, fix on a covering rescan, reopen
// when back; the summary, SLA ageing, trend and CSV export follow.
func TestLifecycleAndSummary(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	h.now = time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	h.heartbeat(v1.Heartbeat{Version: "1.6.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}})
	// Receiver for webhook events.
	var mu sync.Mutex
	var got []v1.WebhookEvent
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !VerifyWebhookSignature("s3cret", r.Header.Get("X-Webhook-Signature"), body, time.Now(), 0) {
			w.WriteHeader(401)
			return
		}
		var ev v1.WebhookEvent
		_ = json.Unmarshal(body, &ev)
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer rcv.Close()
	var hook v1.AdminWebhookView
	if st := h.admin("POST", "/admin/webhooks", v1.AdminWebhookRequest{URL: rcv.URL, Secret: "s3cret", Events: []string{"finding.*", "findings.*", "job.*"}}, &hook); st != 201 || !hook.HasSecret {
		t.Fatalf("webhook: %d %+v", st, hook)
	}
	if st := h.admin("POST", "/admin/webhooks", v1.AdminWebhookRequest{URL: "ftp://x"}, nil); st != 400 {
		t.Fatalf("bad url: %d", st)
	}

	host := v1.Host{IP: "10.30.5.20", Ports: []v1.Port{{Port: 3389, Proto: "tcp"}, {Port: 445, Proto: "tcp"}}, Findings: []v1.Finding{bkFinding, smbFinding}}
	j1 := h.runScan(t, v1.ModeInventory, []v1.Host{host})
	if j1.Status != v1.JobDone {
		t.Fatalf("job1: %s", j1.Status)
	}
	fs := h.findings(t, created.SiteID)
	// The harness vendor is Tier 3: SLAs are doubled (critical 30 days).
	if fs["BlueKeep"].Status != v1.FindingOpen || fs["BlueKeep"].Scope != v1.ScopeInventory || fs["BlueKeep"].SLADays != 30 || fs["BlueKeep"].Overdue {
		t.Fatalf("after scan 1: %+v", fs["BlueKeep"])
	}
	// Rescan 20 days later without SMBv1: fixed; BlueKeep ages but is inside its SLA.
	h.now = h.now.Add(20 * 24 * time.Hour)
	host.Ports, host.Findings = host.Ports[:1], []v1.Finding{bkFinding}
	h.runScan(t, v1.ModeInventory, []v1.Host{host})
	fs = h.findings(t, created.SiteID)
	if fs["SMBv1"].Status != v1.FindingFixed || fs["SMBv1"].FixedAt == nil || fs["SMBv1"].DaysOpen != 20 || fs["SMBv1"].Overdue {
		t.Fatalf("smb after rescan: %+v", fs["SMBv1"])
	}
	if fs["BlueKeep"].Overdue || fs["BlueKeep"].DaysOpen != 20 {
		t.Fatalf("bluekeep ageing: %+v", fs["BlueKeep"])
	}
	// SMBv1 comes back: reopened. Ten more days on, BlueKeep is overdue.
	h.now = h.now.Add(24 * time.Hour)
	host.Ports = append(host.Ports, v1.Port{Port: 445, Proto: "tcp"})
	host.Findings = []v1.Finding{bkFinding, smbFinding}
	h.runScan(t, v1.ModeInventory, []v1.Host{host})
	fs = h.findings(t, created.SiteID)
	if fs["SMBv1"].Status != v1.FindingOpen || fs["SMBv1"].Reopens != 1 || fs["SMBv1"].ReopenedAt == nil {
		t.Fatalf("smb reopened: %+v", fs["SMBv1"])
	}
	h.now = h.now.Add(10 * 24 * time.Hour)
	fs = h.findings(t, created.SiteID)
	if !fs["BlueKeep"].Overdue || fs["BlueKeep"].DaysOpen != 31 || fs["SMBv1"].Overdue {
		t.Fatalf("ageing at 31 days: %+v %+v", fs["BlueKeep"], fs["SMBv1"])
	}

	// Summary.
	var sum v1.AdminSummary
	if st := h.admin("GET", "/admin/sites/"+created.SiteID+"/summary", nil, &sum); st != 200 {
		t.Fatalf("summary: %d", st)
	}
	if sum.Open[v1.SeverityCritical] != 1 || sum.Open[v1.SeverityMedium] != 1 || sum.Overdue[v1.SeverityCritical] != 1 || sum.Overdue[v1.SeverityMedium] != 0 ||
		sum.ReopenedLast30 != 1 || sum.FixedLast30 != 0 || sum.Hosts.WithOpenFindings != 1 || sum.OldestDays != 31 || len(sum.Top) != 2 || sum.Top[0].Name != "BlueKeep" ||
		sum.RiskPoints != 18 || sum.LastInventory == nil || sum.SLADays[v1.SeverityHigh] != 60 {
		t.Fatalf("summary: %+v", sum)
	}
	// FixedLast30 counts fixes, and the SMBv1 fix was undone by the reopen
	// (fixed_at cleared), so 0 is right; a still-fixed finding counts.
	var vsum v1.AdminSummary
	var sv v1.AdminSiteView
	h.admin("GET", "/admin/sites/"+created.SiteID, nil, &sv)
	if st := h.admin("GET", "/admin/vendors/"+sv.VendorID+"/summary", nil, &vsum); st != 200 || len(vsum.Sites) != 1 || vsum.Open[v1.SeverityCritical] != 1 || vsum.SLADays[v1.SeverityCritical] != 30 {
		t.Fatalf("vendor summary (tier 3 doubles the SLA): %d %+v", st, vsum)
	}
	// Trend: the current week has both open; eight weeks ago nothing existed.
	var tr []v1.AdminTrendPoint
	if st := h.admin("GET", "/admin/sites/"+created.SiteID+"/trend?weeks=8", nil, &tr); st != 200 || len(tr) != 8 || tr[7].Open != 2 || tr[0].Open != 0 || tr[7].OpenBySeverity[v1.SeverityCritical] != 1 {
		t.Fatalf("trend: %d %+v", st, tr)
	}
	// Exports.
	req, _ := http.NewRequest("GET", h.mtls.URL+"/admin/sites/"+created.SiteID+"/export/findings.csv?status=open", nil)
	req.Header.Set("Authorization", "Bearer "+h.adminTok)
	resp, err := h.client(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(resp.Body).ReadAll()
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || len(rows) != 3 || rows[0][0] != "site_id" || !strings.Contains(resp.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("findings csv: %v %d rows=%d", err, resp.StatusCode, len(rows))
	}
	req, _ = http.NewRequest("GET", h.mtls.URL+"/admin/sites/"+created.SiteID+"/export/hosts.csv", nil)
	req.Header.Set("Authorization", "Bearer "+h.adminTok)
	resp, _ = h.client(nil).Do(req)
	rows, _ = csv.NewReader(resp.Body).ReadAll()
	resp.Body.Close()
	if len(rows) != 2 || rows[1][3] != "10.30.5.20" || rows[1][13] != "2" {
		t.Fatalf("hosts csv: %v", rows)
	}
	// Webhook events: finding.new for both criticals/highs? BlueKeep only
	// (critical); findings.fixed once; job.completed three times.
	h.srv.Events().Drain(context.Background())
	mu.Lock()
	kinds := map[string]int{}
	for _, ev := range got {
		kinds[ev.Event]++
	}
	mu.Unlock()
	if kinds[EventJobCompleted] != 3 || kinds[EventFindingNew] != 1 || kinds[EventFindingsFixed] != 1 {
		t.Fatalf("events: %v", kinds)
	}
	var hooks []v1.AdminWebhookView
	h.admin("GET", "/admin/webhooks", nil, &hooks)
	if len(hooks) != 1 || hooks[0].LastDelivery == nil || !hooks[0].LastDelivery.OK {
		t.Fatalf("hook view: %+v", hooks)
	}
	var test v1.AdminWebhookDelivery
	if st := h.admin("POST", "/admin/webhooks/"+hook.ID+"/test", nil, &test); st != 200 || !test.OK || test.Event != EventWebhookTest {
		t.Fatalf("test delivery: %d %+v", st, test)
	}
	if st := h.admin("DELETE", "/admin/webhooks/"+hook.ID, nil, nil); st != 204 {
		t.Fatalf("delete hook: %d", st)
	}
	// Metrics (a fresh heartbeat so the appliance is online at h.now).
	h.heartbeat(v1.Heartbeat{Version: "1.6.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}})
	req, _ = http.NewRequest("GET", h.mtls.URL+"/admin/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+h.adminTok)
	resp, _ = h.client(nil).Do(req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{"cp_findings_open{severity=\"critical\"} 1", "cp_findings_fixed_total 1", "cp_jobs_finished_total{status=\"done\"} 3", "cp_appliances{health=\"online\"} 1", "cp_webhook_deliveries_total{result=\"ok\"}"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
}

// TestExternalImportAndParity: a Qualys export merges by CVE, the parity
// report scores the appliance against it, both raw and JSON imports work.
func TestExternalImportAndParity(t *testing.T) {
	h := newHarness(t)
	created := h.enrolled(t)
	h.now = time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	h.heartbeat(v1.Heartbeat{Version: "1.6.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}})
	host := v1.Host{IP: "10.30.5.20", Hostname: "wms-app-01", Ports: []v1.Port{{Port: 3389, Proto: "tcp"}}, Findings: []v1.Finding{bkFinding}}
	h.runScan(t, v1.ModeInventory, []v1.Host{host})

	var par v1.AdminParityReport
	if st := h.admin("GET", "/admin/sites/"+created.SiteID+"/parity", nil, &par); st != 200 || par.Hosts.External != 0 || !strings.Contains(par.Verdict, "no qualys findings") {
		t.Fatalf("parity before import: %d %+v", st, par)
	}
	// Raw CSV import (the CLI path posts JSON; the portal may post the file).
	data, err := os.ReadFile("../../../internal/qualys/testdata/scan-results.csv")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", h.mtls.URL+"/admin/sites/"+created.SiteID+"/external-scans/qualys", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+h.adminTok)
	req.Header.Set("Content-Type", "text/csv")
	resp, err := h.client(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var imp v1.ExternalScanResponse
	_ = json.NewDecoder(resp.Body).Decode(&imp)
	resp.Body.Close()
	// 3 hosts: wms (merged), fw and printer (created); 5 rows: the info row skipped.
	if resp.StatusCode != 200 || imp.Scanner != "qualys" || imp.Hosts != 3 || imp.HostsMerged != 1 || imp.HostsCreated != 2 || imp.Findings != 4 || imp.FindingsNew != 3 || imp.Skipped != 1 {
		t.Fatalf("import: %d %+v", resp.StatusCode, imp)
	}
	fs := h.findings(t, created.SiteID)
	bk := fs["BlueKeep"]
	if bk.State != v1.FindingConfirmed || bk.ExternalID != "91534" || len(bk.Evidence) != 2 {
		t.Fatalf("merged bluekeep: %+v", bk)
	}
	if st := h.admin("GET", "/admin/sites/"+created.SiteID+"/parity?days=30&min_severity=low", nil, &par); st != 200 {
		t.Fatalf("parity: %d", st)
	}
	// Host×CVE pairs: BlueKeep both (1); qualys-only: SMBv1 (2 CVEs on wms), FortiOS (1) = 3; appliance-only 0.
	if par.CVEs.Both != 1 || par.CVEs.ExternalOnly != 3 || par.CVEs.ApplianceOnly != 0 || par.Hosts.Both != 1 || par.Hosts.External != 3 || len(par.Hosts.ExternalOnly) != 2 ||
		len(par.ExternalOnly) != 3 || par.ExternalOnly[0].Severity != v1.SeverityCritical || par.ExternalOnly[0].CVE != "CVE-2022-42475" || par.NoCVE["external"] != 1 {
		t.Fatalf("parity: %+v", par)
	}
	if par.DetectionRate != 0.25 || !strings.HasPrefix(par.Verdict, "not ready") {
		t.Fatalf("verdict: %.2f %s", par.DetectionRate, par.Verdict)
	}
	// JSON import of a fixed row closes the qualys-only finding; a bad scanner name is refused.
	if st := h.admin("POST", "/admin/sites/"+created.SiteID+"/external-scans", v1.ExternalScanRequest{Scanner: "openvas"}, nil); st != 400 {
		t.Fatalf("bad scanner: %d", st)
	}
	fixedReq := v1.ExternalScanRequest{Scanner: "qualys", Hosts: []v1.ExternalHost{{IP: "10.30.9.50", Findings: []v1.ExternalFinding{{ID: "44444", Name: "x", Severity: v1.SeverityCritical, CVE: []string{"CVE-2022-42475"}, Port: 443, Proto: "tcp", Status: "fixed"}}}}}
	if st := h.admin("POST", "/admin/sites/"+created.SiteID+"/external-scans", fixedReq, &imp); st != 200 || imp.Fixed != 1 {
		t.Fatalf("fixed import: %d %+v", st, imp)
	}
	h.admin("GET", "/admin/sites/"+created.SiteID+"/parity?days=30&min_severity=low", nil, &par)
	if par.CVEs.ExternalOnly != 3 {
		t.Fatalf("fixed findings still count as seen in the window: %+v", par.CVEs)
	}
	// The feed-gap report sees the FortiOS host (port 443 from its finding) as an enterprise product.
	var gaps v1.AdminFeedGapReport
	h.admin("GET", "/admin/feed-gaps?site="+created.SiteID, nil, &gaps)
	if gaps.EnterpriseHosts != 1 || gaps.Hosts != 3 {
		t.Fatalf("feed gaps after import: %+v", gaps)
	}
}

// TestRetentionAndS3: raw chunks past retention are deleted from the
// object store (an S3 fake here) and marked purged; a dry run only counts.
func TestRetentionAndS3(t *testing.T) {
	fake := newFakeS3(t)
	defer fake.Close()
	h := newHarness(t)
	h.srv.cfg.Objects = S3Objects{Endpoint: fake.URL, Region: "us-east-1", Bucket: "cp", Prefix: "prod", AccessKey: "AKIA", SecretKey: "secret", PathStyle: true, Now: func() time.Time { return h.now }}
	h.srv.cfg.RawRetention = 24 * time.Hour
	created := h.enrolled(t)
	h.now = time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	h.heartbeat(v1.Heartbeat{Version: "1.6.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}})
	job := h.runScan(t, v1.ModeDiscovery, []v1.Host{{IP: "10.30.5.20"}})
	key := "prod/results/" + job.ID + "/000001.json"
	if _, ok := fake.get(key); !ok {
		t.Fatalf("chunk not in s3: %v", fake.keys())
	}
	if !strings.HasPrefix(fake.lastAuth, "AWS4-HMAC-SHA256 Credential=AKIA/20261005/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=") {
		t.Fatalf("authorization: %s", fake.lastAuth)
	}
	var res v1.AdminRetentionResult
	if st := h.admin("POST", "/admin/retention/run?dry_run=1", nil, &res); st != 200 || res.RawBatches != 0 {
		t.Fatalf("nothing to purge yet: %d %+v", st, res)
	}
	h.now = h.now.Add(48 * time.Hour)
	if st := h.admin("POST", "/admin/retention/run?dry_run=1", nil, &res); st != 200 || res.RawBatches != 1 || !res.DryRun {
		t.Fatalf("dry run: %d %+v", st, res)
	}
	if _, ok := fake.get(key); !ok {
		t.Fatal("dry run deleted the object")
	}
	if st := h.admin("POST", "/admin/retention/run", nil, &res); st != 200 || res.RawBatches != 1 || res.Errors != 0 {
		t.Fatalf("purge: %d %+v", st, res)
	}
	if _, ok := fake.get(key); ok {
		t.Fatal("object not deleted")
	}
	if st := h.admin("POST", "/admin/retention/run", nil, &res); st != 200 || res.RawBatches != 0 {
		t.Fatalf("second purge: %+v", res)
	}
	// Findings and hosts survive retention.
	var hosts []v1.AdminHostView
	h.admin("GET", "/admin/sites/"+created.SiteID+"/hosts", nil, &hosts)
	if len(hosts) != 1 {
		t.Fatalf("hosts after retention: %d", len(hosts))
	}
	// Get of a missing key.
	if _, _, err := h.srv.cfg.Objects.Get(context.Background(), "prod/nope"); err != ErrObjectNotFound {
		t.Fatalf("missing object: %v", err)
	}
	// Optional: the same store against a real S3 endpoint (MinIO) when TEST_S3_ENDPOINT is set.
	if ep := os.Getenv("TEST_S3_ENDPOINT"); ep != "" {
		real := S3Objects{Endpoint: ep, Region: envOr("TEST_S3_REGION", "us-east-1"), Bucket: os.Getenv("TEST_S3_BUCKET"), AccessKey: os.Getenv("TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("TEST_S3_SECRET_KEY"), PathStyle: true}
		ctx := context.Background()
		if err := real.EnsureBucket(ctx); err != nil {
			t.Fatalf("real s3 bucket: %v", err)
		}
		if _, err := real.Put(ctx, "results/test/x.json", strings.NewReader(`{"ok":true}`)); err != nil {
			t.Fatalf("real s3 put: %v", err)
		}
		rc, n, err := real.Get(ctx, "results/test/x.json")
		if err != nil || n != 11 {
			t.Fatalf("real s3 get: %v %d", err, n)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if string(b) != `{"ok":true}` {
			t.Fatalf("real s3 body: %s", b)
		}
		if err := real.Delete(ctx, "results/test/x.json"); err != nil {
			t.Fatalf("real s3 delete: %v", err)
		}
		if _, _, err := real.Get(ctx, "results/test/x.json"); err != ErrObjectNotFound {
			t.Fatalf("real s3 after delete: %v", err)
		}
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// fakeS3 answers PUT/GET/DELETE for path-style keys and records the last
// Authorization header.
type fakeS3 struct {
	*httptest.Server
	mu       sync.Mutex
	objects  map[string][]byte
	lastAuth string
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{objects: map[string][]byte{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastAuth = r.Header.Get("Authorization")
		if r.Header.Get("x-amz-date") == "" || r.Header.Get("x-amz-content-sha256") == "" {
			w.WriteHeader(400)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/cp/")
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			f.objects[key] = b
			w.WriteHeader(200)
		case http.MethodGet:
			b, ok := f.objects[key]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Length", string(rune('0'+len(b)%10)))
			w.Header().Del("Content-Length")
			_, _ = w.Write(b)
		case http.MethodDelete:
			delete(f.objects, key)
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	}))
	return f
}

func (f *fakeS3) get(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[key]
	return b, ok
}

func (f *fakeS3) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.objects {
		out = append(out, k)
	}
	return out
}

func TestWebhookSignatureAndMatching(t *testing.T) {
	body := []byte(`{"event":"x"}`)
	sig := sign("k", 1700000000, body)
	if !VerifyWebhookSignature("k", sig, body, time.Unix(1700000010, 0), time.Minute) {
		t.Fatal("valid signature rejected")
	}
	if VerifyWebhookSignature("k", sig, body, time.Unix(1700009000, 0), time.Minute) {
		t.Fatal("stale signature accepted")
	}
	if VerifyWebhookSignature("other", sig, body, time.Unix(1700000010, 0), time.Minute) {
		t.Fatal("wrong secret accepted")
	}
	if !matches(nil, "job.completed") || !matches([]string{"job.*"}, "job.failed") || matches([]string{"job.*"}, "finding.new") || !matches([]string{"finding.new"}, "finding.new") {
		t.Fatal("event matching")
	}
	// Retention of deliveries for a hook that fails.
	st := store.NewMemory()
	d := newDispatcher(st, discardLog{}, time.Now, []time.Duration{0, 0}, newMetrics(time.Now()))
	rec := d.deliver(context.Background(), webhookRec{ID: "w", URL: "http://127.0.0.1:1/x", Enabled: true}, v1.WebhookEvent{ID: "e", Event: "x"})
	if rec.OK || rec.Attempts != 2 || rec.Error == "" {
		t.Fatalf("failed delivery: %+v", rec)
	}
}

type discardLog struct{}

func (discardLog) Info(string, ...any) {}
func (discardLog) Warn(string, ...any) {}
