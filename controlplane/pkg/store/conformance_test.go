package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// The conformance suite runs the same scenarios against the in-memory
// store and, when TEST_DATABASE_URL points at a throwaway database, the
// Postgres store (migrations included). The database is wiped first.
func stores(t *testing.T) map[string]Store {
	t.Helper()
	out := map[string]Store{"memory": NewMemory()}
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Log("TEST_DATABASE_URL not set; Postgres conformance skipped")
		return out
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect %s: %v", url, err)
	}
	if _, err := conn.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
	pg, err := OpenPostgres(ctx, url)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	out["postgres"] = pg
	return out
}

func TestStoreConformance(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			vendor, site, apl := phase1Scenario(t, ctx, st)
			jobsScenario(t, ctx, st, vendor, site, apl)
			correlationScenario(t, ctx, st, site.ID)
			sitesScenario(t, ctx, st, vendor, site)
		})
	}
}

func phase1Scenario(t *testing.T, ctx context.Context, st Store) (*Vendor, *Site, *Appliance) {
	t.Helper()
	vendor, err := st.EnsureVendor(ctx, "Acme 3PL")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := st.EnsureVendor(ctx, "Acme 3PL")
	if again.ID != vendor.ID || vendor.Tier != 3 {
		t.Fatalf("vendor idempotency: %+v %+v", vendor, again)
	}
	site, err := st.EnsureSite(ctx, vendor.ID, "Reno DC", []string{"10.30.0.0/16"}, "America/Los_Angeles", 0)
	if err != nil {
		t.Fatal(err)
	}
	if site.MaxPPS != 300 || site.MaxConcurrency != 16 || len(site.FragilePorts) != 6 || site.TZ != "America/Los_Angeles" {
		t.Fatalf("site defaults: %+v", site)
	}
	site2, _ := st.EnsureSite(ctx, vendor.ID, "Reno DC", []string{"10.30.0.0/16", "10.31.0.0/16"}, "", 500)
	if site2.ID != site.ID || len(site2.AllowedCIDRs) != 2 || site2.MaxPPS != 500 {
		t.Fatalf("site update: %+v", site2)
	}
	if _, err := st.EnsureSite(ctx, "vnd_missing", "X", nil, "", 0); err == nil {
		t.Fatal("site under unknown vendor accepted")
	}
	got, err := st.GetSite(ctx, site.ID)
	if err != nil || got.VendorID != vendor.ID || got.AllowedCIDRs[1] != "10.31.0.0/16" {
		t.Fatalf("get site: %+v %v", got, err)
	}
	if _, err := st.GetSite(ctx, "site_missing"); err != ErrNotFound {
		t.Fatalf("missing site: %v", err)
	}

	apl, err := st.CreateAppliance(ctx, site.ID)
	if err != nil || apl.Status != v1.StatusPending {
		t.Fatalf("create appliance: %+v %v", apl, err)
	}
	if _, err := st.CreateAppliance(ctx, "site_missing"); err != ErrNotFound {
		t.Fatalf("appliance under unknown site: %v", err)
	}
	list, _ := st.ListAppliances(ctx)
	if len(list) != 1 || list[0].ID != apl.ID {
		t.Fatalf("list: %+v", list)
	}

	exp := time.Now().Add(14 * 24 * time.Hour).Truncate(time.Microsecond)
	if err := st.PutEnrollmentCode(ctx, EnrollmentCode{ApplianceID: apl.ID, CodeHash: "h1", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	// Re-issue replaces the live code.
	if err := st.PutEnrollmentCode(ctx, EnrollmentCode{ApplianceID: apl.ID, CodeHash: "h2", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetEnrollmentCodeByHash(ctx, "h1"); err != ErrNotFound {
		t.Fatalf("old code still live: %v", err)
	}
	code, err := st.GetEnrollmentCodeByHash(ctx, "h2")
	if err != nil || code.ApplianceID != apl.ID || !code.ExpiresAt.Equal(exp) || code.Attempts != 0 {
		t.Fatalf("code: %+v %v", code, err)
	}
	if n, _ := st.BumpCodeAttempts(ctx, "h2"); n != 1 {
		t.Fatalf("attempts %d", n)
	}
	if err := st.PutEnrollmentCode(ctx, EnrollmentCode{ApplianceID: "apl_missing", CodeHash: "h3", ExpiresAt: exp}); err != ErrNotFound {
		t.Fatalf("code for unknown appliance: %v", err)
	}
	_ = st.LogEnrollAttempt(ctx, EnrollAttempt{At: time.Now(), SourceIP: "10.0.0.1", ApplianceID: apl.ID, OK: false, Reason: "test"})
	_ = st.LogEnrollAttempt(ctx, EnrollAttempt{At: time.Now(), SourceIP: "10.0.0.1", Reason: "unknown_code"})

	notAfter := time.Now().Add(365 * 24 * time.Hour).Truncate(time.Microsecond)
	upd := EnrollUpdate{ApplianceID: apl.ID, CodeHash: "h2", CertSerial: "serial-1", CertNotAfter: notAfter, Version: "1.0", Fingerprint: v1.Fingerprint{Hypervisor: "kvm", MACs: []string{"aa:bb"}}}
	if err := st.CompleteEnrollment(ctx, upd); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteEnrollment(ctx, upd); err != ErrConflict {
		t.Fatalf("second enrollment: %v", err)
	}
	apl, _ = st.GetAppliance(ctx, apl.ID)
	if apl.Status != v1.StatusEnrolled || apl.CertSerial != "serial-1" || apl.Fingerprint == nil || apl.Fingerprint.Hypervisor != "kvm" || apl.EnrolledAt == nil || !apl.CertNotAfter.Equal(notAfter) {
		t.Fatalf("enrolled appliance: %+v", apl)
	}
	bySerial, err := st.GetApplianceBySerial(ctx, "serial-1")
	if err != nil || bySerial.ID != apl.ID {
		t.Fatalf("by serial: %v", err)
	}
	if _, err := st.GetApplianceBySerial(ctx, ""); err != ErrNotFound {
		t.Fatal("empty serial matched")
	}

	hbAt := time.Now().Truncate(time.Microsecond)
	hb := &v1.Heartbeat{Version: "1.1", BundleVersion: "b1", FeedVersion: "f1", SkewS: 3, State: "idle", StopAll: true,
		Ifaces: []v1.Iface{{Name: "wan0", Role: "wan", MAC: "aa:bb", IPv4: "10.0.0.5"}}, BinarySHA256: map[string]string{"applianced": "abc"},
		Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true, VTCount: 5}, CurrentJob: &v1.JobProgress{ID: "job_x", Phase: "portscan", ProgressPct: 40}, AckedDirectiveIDs: []string{}}
	if err := st.RecordHeartbeat(ctx, apl.ID, hbAt, hb); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordHeartbeat(ctx, "apl_missing", hbAt, hb); err != ErrNotFound {
		t.Fatalf("heartbeat for unknown appliance: %v", err)
	}
	apl, _ = st.GetAppliance(ctx, apl.ID)
	if apl.Version != "1.1" || apl.BundleVersion != "b1" || apl.SkewS != 3 || !apl.LastHeartbeatAt.Equal(hbAt) || apl.LastHeartbeat == nil || !apl.LastHeartbeat.StopAll ||
		apl.LastHeartbeat.CurrentJob == nil || apl.LastHeartbeat.CurrentJob.ID != "job_x" || apl.LastHeartbeat.FeedVersion != "f1" || len(apl.Ifaces) != 1 || apl.BinaryHashes["applianced"] != "abc" {
		t.Fatalf("after heartbeat: %+v hb=%+v", apl, apl.LastHeartbeat)
	}

	d1, err := st.CreateDirective(ctx, apl.ID, v1.DirectiveSetInterval, map[string]any{"s": 30.0})
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := st.CreateDirective(ctx, apl.ID, v1.DirectiveStopAll, nil)
	if _, err := st.CreateDirective(ctx, "apl_missing", v1.DirectiveNoop, nil); err != ErrNotFound {
		t.Fatalf("directive for unknown appliance: %v", err)
	}
	pending, _ := st.PendingDirectives(ctx, apl.ID, true)
	if len(pending) != 2 || pending[0].ID != d1.ID || pending[0].Payload["s"] != 30.0 || pending[1].ID != d2.ID || pending[0].DeliveredAt == nil {
		t.Fatalf("pending: %+v", pending)
	}
	ackAt := time.Now().Truncate(time.Microsecond)
	if err := st.AckDirectives(ctx, apl.ID, []string{d1.ID, "dir_bogus"}, ackAt); err != nil {
		t.Fatal(err)
	}
	pending, _ = st.PendingDirectives(ctx, apl.ID, false)
	if len(pending) != 1 || pending[0].ID != d2.ID {
		t.Fatalf("after ack: %+v", pending)
	}
	all, _ := st.ListDirectives(ctx, apl.ID)
	if len(all) != 2 || all[0].AckedAt == nil || !all[0].AckedAt.Equal(ackAt) || all[1].AckedAt != nil {
		t.Fatalf("list directives: %+v", all)
	}

	if err := st.UpdateCert(ctx, apl.ID, "serial-2", notAfter.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetApplianceBySerial(ctx, "serial-1"); err != ErrNotFound {
		t.Fatal("old serial still bound")
	}
	if err := st.Revoke(ctx, "serial-1", "test"); err != nil {
		t.Fatal(err)
	}
	_ = st.Revoke(ctx, "serial-1", "again") // idempotent
	if rev, _ := st.IsRevoked(ctx, "serial-1"); !rev {
		t.Fatal("not revoked")
	}
	if rev, _ := st.IsRevoked(ctx, "serial-2"); rev {
		t.Fatal("wrong serial revoked")
	}
	if err := st.RecordSupportBundle(ctx, apl.ID, "support/x.tar.gz", 100); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordSupportBundle(ctx, "apl_missing", "k", 1); err != ErrNotFound {
		t.Fatalf("support bundle for unknown appliance: %v", err)
	}
	if err := st.SetStatus(ctx, "apl_missing", v1.StatusRevoked); err != ErrNotFound {
		t.Fatalf("set status unknown: %v", err)
	}
	if v, err := st.GetVendor(ctx, vendor.ID); err != nil || v.Name != "Acme 3PL" {
		t.Fatalf("get vendor: %+v %v", v, err)
	}
	return vendor, site, apl
}

func jobsScenario(t *testing.T, ctx context.Context, st Store, vendor *Vendor, site *Site, apl *Appliance) {
	t.Helper()
	now := time.Now().Truncate(time.Microsecond)
	spec := v1.JobSpec{JobID: NewID("job"), SiteID: site.ID, ApplianceID: apl.ID, Targets: []string{"10.30.5.0/24"}, Excludes: []string{}, SafeChecks: true, Iface: "lan0"}
	spec.DefaultsFor(v1.ModeInventory)
	j1 := &Job{ID: spec.JobID, SiteID: site.ID, ApplianceID: apl.ID, Spec: spec}
	if err := st.CreateJob(ctx, j1); err != nil {
		t.Fatal(err)
	}
	if j1.Status != v1.JobQueued || j1.CreatedAt.IsZero() {
		t.Fatalf("created: %+v", j1)
	}
	if err := st.CreateJob(ctx, &Job{SiteID: site.ID, ApplianceID: "apl_missing", Spec: spec}); err != ErrNotFound {
		t.Fatalf("job for unknown appliance: %v", err)
	}
	future := now.Add(time.Hour)
	j2 := &Job{SiteID: site.ID, ApplianceID: apl.ID, Spec: spec, ScheduledFor: &future}
	_ = st.CreateJob(ctx, j2)
	got, err := st.GetJob(ctx, j1.ID)
	if err != nil || got.Spec.Mode != v1.ModeInventory || got.Spec.OpenVAS == nil || got.Spec.OpenVAS.MaxHosts != 4 || got.Spec.Iface != "lan0" {
		t.Fatalf("get job: %+v %v", got, err)
	}
	if _, err := st.GetJob(ctx, "job_missing"); err != ErrNotFound {
		t.Fatalf("missing job: %v", err)
	}
	if l, _ := st.ListJobs(ctx, site.ID, ""); len(l) != 2 {
		t.Fatalf("list by site: %d", len(l))
	}
	if l, _ := st.ListJobs(ctx, "", "apl_other"); len(l) != 0 {
		t.Fatalf("list by other appliance: %d", len(l))
	}
	disp, err := st.DispatchableJobs(ctx, apl.ID, now, 10*time.Minute)
	if err != nil || len(disp) != 1 || disp[0].ID != j1.ID {
		t.Fatalf("dispatchable: %+v %v", disp, err)
	}
	// Dispatch j1; inside the lease it is not offered again, after it is.
	j1.Status = v1.JobDispatched
	j1.DispatchedAt = &now
	j1.Spec.IssuedAt = now.Unix()
	j1.Spec.Sig = "sig"
	if err := st.UpdateJob(ctx, j1); err != nil {
		t.Fatal(err)
	}
	if disp, _ := st.DispatchableJobs(ctx, apl.ID, now.Add(time.Minute), 10*time.Minute); len(disp) != 0 {
		t.Fatalf("re-offered inside lease: %+v", disp)
	}
	if disp, _ := st.DispatchableJobs(ctx, apl.ID, now.Add(11*time.Minute), 10*time.Minute); len(disp) != 1 || disp[0].Spec.Sig != "sig" {
		t.Fatalf("lease expiry: %+v", disp)
	}
	if disp, _ := st.DispatchableJobs(ctx, apl.ID, now.Add(2*time.Hour), 10*time.Minute); len(disp) != 2 || disp[0].ID != j1.ID || disp[1].ID != j2.ID {
		t.Fatalf("scheduled job due: %+v", disp)
	}
	if err := st.UpdateJob(ctx, &Job{ID: "job_missing"}); err != ErrNotFound {
		t.Fatalf("update missing: %v", err)
	}

	if dup, err := st.RecordResultBatch(ctx, ResultBatchRec{JobID: j1.ID, Seq: 1, ReceivedAt: now, ObjectKey: "k1", SHA256: "a", Hosts: 2}); err != nil || dup {
		t.Fatalf("batch 1: %v %v", dup, err)
	}
	if dup, err := st.RecordResultBatch(ctx, ResultBatchRec{JobID: j1.ID, Seq: 1, ReceivedAt: now, ObjectKey: "k1", SHA256: "a"}); err != nil || !dup {
		t.Fatalf("batch dup: %v %v", dup, err)
	}
	if _, err := st.RecordResultBatch(ctx, ResultBatchRec{JobID: j1.ID, Seq: 1, ReceivedAt: now, ObjectKey: "k1", SHA256: "b"}); err != ErrConflict {
		t.Fatalf("batch conflict: %v", err)
	}
	if _, err := st.RecordResultBatch(ctx, ResultBatchRec{JobID: "job_missing", Seq: 1, ReceivedAt: now}); err != ErrNotFound {
		t.Fatalf("batch unknown job: %v", err)
	}
	_, _ = st.RecordResultBatch(ctx, ResultBatchRec{JobID: j1.ID, Seq: 2, ReceivedAt: now, ObjectKey: "k2", SHA256: "c", Final: true})
	j1, _ = st.GetJob(ctx, j1.ID)
	if j1.Batches != 2 {
		t.Fatalf("batches: %d", j1.Batches)
	}
	fin := now.Add(time.Minute)
	j1.Status, j1.FinishedAt, j1.ProgressPct, j1.Phase = v1.JobDone, &fin, 100, "finalize"
	j1.Stats = &v1.ScanStats{HostsAlive: 3, Findings: 1, Rejected: []string{}, PhaseDurationS: map[string]int64{"discovery": 4}}
	if err := st.UpdateJob(ctx, j1); err != nil {
		t.Fatal(err)
	}
	j1, _ = st.GetJob(ctx, j1.ID)
	if j1.Status != v1.JobDone || j1.Batches != 2 || j1.Stats == nil || j1.Stats.HostsAlive != 3 || j1.Stats.PhaseDurationS["discovery"] != 4 || !j1.FinishedAt.Equal(fin) {
		t.Fatalf("done job: %+v stats=%+v", j1, j1.Stats)
	}
	if err := st.UpsertNVTs(ctx, []NVT{{OID: "1.1", Name: "A", Family: "F", CVSS: 9.8, CVEs: []string{"CVE-1"}, QoD: 97, FeedVersion: "f1"}, {OID: "1.1", Name: "A2", Family: "F", CVSS: 9.8, CVEs: nil, QoD: 97}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNVTs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	_ = vendor
}

func sitesScenario(t *testing.T, ctx context.Context, st Store, vendor *Vendor, site *Site) {
	t.Helper()
	site.AllowedCIDRs = []string{"10.30.5.0/24"}
	site.Excludes = []string{"10.30.5.1/32"}
	site.FragilePorts = []int{9100}
	site.MaxPPS, site.MaxConcurrency, site.UnsafeOK, site.AllowPublic, site.TZ = 100, 8, true, true, "UTC"
	if err := st.UpdateSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSite(ctx, &Site{ID: "site_missing"}); err != ErrNotFound {
		t.Fatalf("update missing site: %v", err)
	}
	got, _ := st.GetSite(ctx, site.ID)
	cfg := got.Config()
	if len(cfg.AllowedCIDRs) != 1 || cfg.Excludes[0] != "10.30.5.1/32" || cfg.FragilePorts[0] != 9100 || cfg.MaxPPS != 100 || cfg.MaxConcurrency != 8 || !cfg.UnsafeOK || !cfg.AllowPublic || cfg.TZ != "UTC" {
		t.Fatalf("site config: %+v", cfg)
	}
	sites, _ := st.ListSites(ctx)
	if len(sites) != 1 || sites[0].VendorID != vendor.ID {
		t.Fatalf("list sites: %+v", sites)
	}
}
