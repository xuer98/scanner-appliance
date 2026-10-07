package store

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
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
			opsScenario(t, ctx, st, site, apl)
			pilotScenario(t, ctx, st, site, apl)
			replaceScenario(t, ctx, st, site, apl)
			udpScenario(t, ctx, st, vendor, apl)
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

func opsScenario(t *testing.T, ctx context.Context, st Store, site *Site, apl *Appliance) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	later := now.Add(48 * time.Hour)
	b1 := &Bundle{Version: "20260901T000000Z", FeedVersion: "202609010000", ObjectKey: "bundles/20260901T000000Z/manifest.json",
		SHA256: "aa", Sig: "sig1", Files: 3, Bytes: 300, Status: v1.RolloutReleased, PublishedAt: now.Add(-time.Hour)}
	b2 := &Bundle{Version: "20260926T000000Z", FeedVersion: "202609260530", ObjectKey: "bundles/20260926T000000Z/manifest.json",
		SHA256: "bb", Sig: "sig2", Files: 4, Bytes: 400, Status: v1.RolloutCanary, PublishedAt: now, CanaryUntil: &later}
	for _, b := range []*Bundle{b1, b2} {
		if err := st.PutBundle(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.GetBundle(ctx, b2.Version)
	if err != nil || got.FeedVersion != b2.FeedVersion || got.CanaryUntil == nil || !got.CanaryUntil.Equal(later) || got.Status != v1.RolloutCanary {
		t.Fatalf("get bundle: %v %+v", err, got)
	}
	if _, err := st.GetBundle(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("missing bundle: %v", err)
	}
	list, _ := st.ListBundles(ctx)
	if len(list) != 2 || list[0].Version != b2.Version {
		t.Fatalf("list bundles newest first: %+v", list)
	}
	if err := st.SetBundleStatus(ctx, b2.Version, v1.RolloutHeld, "canary apl_x reported reload failure"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBundleStatus(ctx, "nope", v1.RolloutHeld, ""); err != ErrNotFound {
		t.Fatalf("status of missing bundle: %v", err)
	}
	got, _ = st.GetBundle(ctx, b2.Version)
	if got.Status != v1.RolloutHeld || got.HeldReason == "" {
		t.Fatalf("held: %+v", got)
	}
	// The first confirmation by a canary appliance is kept.
	first, second := now.Add(time.Hour), now.Add(30*time.Hour)
	if got.ConfirmedAt != nil {
		t.Fatalf("confirmed before any canary reported it: %+v", got)
	}
	for _, at := range []time.Time{first, second} {
		if err := st.ConfirmBundle(ctx, b2.Version, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.ConfirmBundle(ctx, "nope", first); err != ErrNotFound {
		t.Fatalf("confirming a missing bundle: %v", err)
	}
	got, _ = st.GetBundle(ctx, b2.Version)
	if got.ConfirmedAt == nil || !got.ConfirmedAt.Equal(first) {
		t.Fatalf("confirmed_at: %+v, want %s", got.ConfirmedAt, first)
	}
	if list, _ = st.ListBundles(ctx); list[0].ConfirmedAt == nil || !list[0].ConfirmedAt.Equal(first) || list[1].ConfirmedAt != nil {
		t.Fatalf("confirmed_at in the listing: %+v %+v", list[0].ConfirmedAt, list[1].ConfirmedAt)
	}
	// Re-put keeps the row unique (upsert).
	b2.Status = v1.RolloutReleased
	if err := st.PutBundle(ctx, b2); err != nil {
		t.Fatal(err)
	}
	if list, _ = st.ListBundles(ctx); len(list) != 2 {
		t.Fatalf("upsert duplicated the bundle: %d", len(list))
	}

	files := []BundleFileRec{{SHA256: "f1", Size: 10, ObjectKey: "bundles/files/f1"}, {SHA256: "f2", Size: 20, ObjectKey: "bundles/files/f2"}}
	if err := st.PutBundleFiles(ctx, files); err != nil {
		t.Fatal(err)
	}
	if err := st.PutBundleFiles(ctx, files[:1]); err != nil { // idempotent
		t.Fatal(err)
	}
	has, err := st.HasBundleFiles(ctx, []string{"f1", "f2", "f3"})
	if err != nil || !has["f1"] || !has["f2"] || has["f3"] {
		t.Fatalf("has files: %v %v", err, has)
	}
	if has, _ := st.HasBundleFiles(ctx, nil); len(has) != 0 {
		t.Fatal("empty query")
	}

	r := &Release{Component: "applianced-linux-amd64", Version: "1.3.0", ObjectKey: "releases/applianced-linux-amd64/1.3.0",
		SHA256: "cc", Sig: "sig3", Bytes: 8_000_000, Status: v1.RolloutCanary, PublishedAt: now, CanaryUntil: &later}
	if err := st.PutRelease(ctx, r); err != nil {
		t.Fatal(err)
	}
	r2 := *r
	r2.Component = "applianced-linux-arm64"
	if err := st.PutRelease(ctx, &r2); err != nil {
		t.Fatal(err)
	}
	gr, err := st.GetRelease(ctx, r.Component, r.Version)
	if err != nil || gr.SHA256 != "cc" || gr.Bytes != 8_000_000 {
		t.Fatalf("get release: %v %+v", err, gr)
	}
	if _, err := st.GetRelease(ctx, r.Component, "0.0.0"); err != ErrNotFound {
		t.Fatalf("missing release: %v", err)
	}
	if rl, _ := st.ListReleases(ctx); len(rl) != 2 {
		t.Fatalf("list releases: %+v", rl)
	}
	if err := st.SetReleaseStatus(ctx, r.Component, r.Version, v1.RolloutReleased, ""); err != nil {
		t.Fatal(err)
	}
	if gr, _ = st.GetRelease(ctx, r.Component, r.Version); gr.Status != v1.RolloutReleased {
		t.Fatalf("release status: %+v", gr)
	}

	if err := st.SetApplianceCanary(ctx, apl.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetApplianceCanary(ctx, "apl_missing", true); err != ErrNotFound {
		t.Fatalf("canary on missing appliance: %v", err)
	}
	hb := &v1.Heartbeat{Version: "1.3.0", BundleVersion: b2.Version, FeedVersion: "202609260530", OS: "linux", Arch: "amd64",
		UpdateError: "bundle 20260926T000000Z: ospd did not load feed", RebootRequired: true, Engine: v1.EngineHealth{OSPDUp: true}}
	if err := st.RecordHeartbeat(ctx, apl.ID, now, hb); err != nil {
		t.Fatal(err)
	}
	ga, _ := st.GetAppliance(ctx, apl.ID)
	if !ga.Canary || ga.OS != "linux" || ga.Arch != "amd64" || ga.FeedVersion != "202609260530" || ga.UpdateError == "" || !ga.RebootRequired || ga.BundleVersion != b2.Version {
		t.Fatalf("appliance after heartbeat: %+v", ga)
	}

	site.LANRoutes = []v1.LANRoute{{CIDR: "10.31.0.0/16", Via: "10.30.5.1"}}
	if err := st.UpdateSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	gs, _ := st.GetSite(ctx, site.ID)
	if cfg := gs.Config(); len(cfg.LANRoutes) != 1 || cfg.LANRoutes[0].Via != "10.30.5.1" {
		t.Fatalf("lan routes: %+v", cfg)
	}
	site.LANRoutes = nil
	if err := st.UpdateSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	if gs, _ = st.GetSite(ctx, site.ID); len(gs.Config().LANRoutes) != 0 {
		t.Fatalf("lan routes not cleared: %+v", gs.Config())
	}
}

func pilotScenario(t *testing.T, ctx context.Context, st Store, site *Site, apl *Appliance) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)

	// Versioned site policy: cleared/marked fragile hosts, VT exclusions, attestation.
	site.FragileCleared = []string{"10.30.5.21"}
	site.FragileHosts = []string{"10.30.5.90"}
	site.VTExcludes = []string{"1.3.6.1.4.1.25623.1.0.999", "nuclei:tech-detect"}
	site.Version = 7
	site.AttestedAt, site.AttestedBy = &now, "owner@acme"
	if err := st.UpdateSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	gs, _ := st.GetSite(ctx, site.ID)
	cfg := gs.Config()
	if cfg.Version != 7 || len(cfg.FragileCleared) != 1 || cfg.FragileHosts[0] != "10.30.5.90" || len(cfg.VTExcludes) != 2 || gs.AttestedAt == nil || !gs.AttestedAt.Equal(now) || gs.AttestedBy != "owner@acme" {
		t.Fatalf("site policy: %+v attested=%v", cfg, gs.AttestedAt)
	}

	// Audit log, newest first.
	for i, kind := range []string{"scope", "fragile"} {
		c := &SiteChange{SiteID: site.ID, Version: 5 + i, At: now.Add(time.Duration(i) * time.Minute), Actor: "op", Kind: kind, Field: "x", Old: "a", New: "b", Reason: "pilot"}
		if err := st.RecordSiteChange(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordSiteChange(ctx, &SiteChange{SiteID: "site_missing", At: now, Kind: "scope"}); err != ErrNotFound {
		t.Fatalf("change on missing site: %v", err)
	}
	changes, _ := st.ListSiteChanges(ctx, site.ID)
	if len(changes) != 2 || changes[0].Kind != "fragile" || changes[1].Version != 5 {
		t.Fatalf("changes: %+v", changes)
	}

	// Scope requests.
	req := &ScopeRequest{SiteID: site.ID, Status: v1.ScopePending, AllowedCIDRs: []string{"10.30.0.0/16", "10.31.0.0/16"}, Reason: "new floor", RequestedAt: now, RequestedBy: "op"}
	if err := st.CreateScopeRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateScopeRequest(ctx, &ScopeRequest{SiteID: "site_missing", Status: v1.ScopePending, RequestedAt: now}); err != ErrNotFound {
		t.Fatalf("request on missing site: %v", err)
	}
	pending, _ := st.ListScopeRequests(ctx, site.ID, v1.ScopePending)
	if len(pending) != 1 || pending[0].ID != req.ID || len(pending[0].AllowedCIDRs) != 2 {
		t.Fatalf("pending: %+v", pending)
	}
	req.Status, req.DecidedAt, req.DecidedBy, req.Decision = v1.ScopeApproved, &now, "owner", "ok"
	if err := st.UpdateScopeRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetScopeRequest(ctx, req.ID); got.Status != v1.ScopeApproved || got.DecidedBy != "owner" {
		t.Fatalf("approved: %+v", got)
	}
	if l, _ := st.ListScopeRequests(ctx, site.ID, v1.ScopePending); len(l) != 0 {
		t.Fatal("still pending")
	}
	if _, err := st.GetScopeRequest(ctx, "scr_missing"); err != ErrNotFound {
		t.Fatalf("missing request: %v", err)
	}

	// Schedules.
	sc := &Schedule{SiteID: site.ID, ApplianceID: apl.ID, Name: "weekly inventory", Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}, Cron: "0 22 * * 6", TZ: "UTC", MaxDurationS: 3600, Enabled: true}
	if err := st.CreateSchedule(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSchedule(ctx, &Schedule{SiteID: site.ID, ApplianceID: "apl_missing", Mode: v1.ModeDiscovery, Cron: "* * * * *"}); err != ErrNotFound {
		t.Fatalf("schedule on missing appliance: %v", err)
	}
	next := now.Add(time.Hour)
	sc.NextOccurrence, sc.NextJobID, sc.Enabled = &next, "job_next", false
	if err := st.UpdateSchedule(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSchedule(ctx, sc.ID)
	if err != nil || got.NextJobID != "job_next" || got.Enabled || got.NextOccurrence == nil || !got.NextOccurrence.Equal(next) || got.Targets[0] != "10.30.5.0/24" {
		t.Fatalf("schedule: %v %+v", err, got)
	}
	if l, _ := st.ListSchedules(ctx, site.ID); len(l) != 1 {
		t.Fatalf("list schedules: %+v", l)
	}
	if err := st.DeleteSchedule(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSchedule(ctx, sc.ID); err != ErrNotFound {
		t.Fatalf("double delete: %v", err)
	}

	// Jobs remember their schedule.
	job := &Job{ID: NewID("job"), SiteID: site.ID, ApplianceID: apl.ID, Status: v1.JobQueued, ScheduleID: "sch_x",
		Spec: v1.JobSpec{JobID: "x", SiteID: site.ID, ApplianceID: apl.ID, Mode: v1.ModeDiscovery, Targets: []string{"10.30.5.0/24"}, Modules: []string{v1.ModuleDiscovery}, Rate: v1.Rate{PPS: 1, PerHostParallel: 1}}}
	if err := st.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if gj, _ := st.GetJob(ctx, job.ID); gj.ScheduleID != "sch_x" {
		t.Fatalf("schedule id lost: %+v", gj)
	}

	// Finding review and codified exclusions at ingest.
	hosts := []v1.Host{{IP: "10.30.5.77", Ports: []v1.Port{{Port: 80, Proto: "tcp"}}, Findings: []v1.Finding{
		{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.555", Name: "real", Severity: v1.SeverityHigh, CVSS: 7.5, QoD: 80, Port: 80, Proto: "tcp", CVE: []string{}},
		{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.999", Name: "noise", Severity: v1.SeverityMedium, CVSS: 5, QoD: 80, Port: 80, Proto: "tcp", CVE: []string{}},
		{Source: "nuclei", ID: "tech-detect", Name: "tech", Severity: v1.SeverityInfo, QoD: 80, Port: 80, Proto: "tcp", CVE: []string{}},
	}}}
	sum, err := st.IngestHosts(ctx, site.ID, job.ID, hosts, "202609260530", now)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Findings != 3 || sum.Suppressed != 2 {
		t.Fatalf("ingest with exclusions: %+v", sum)
	}
	var hostID string
	if hl, _ := st.ListHosts(ctx, site.ID); true {
		for _, h := range hl {
			if h.IP == "10.30.5.77" {
				hostID = h.ID
			}
		}
	}
	list, _ := st.ListFindings(ctx, site.ID, hostID)
	if hostID == "" || len(list) != 3 {
		t.Fatalf("ingested host findings: host=%q n=%d", hostID, len(list))
	}
	var real *Finding
	for _, f := range list {
		switch f.Detector() {
		case "1.3.6.1.4.1.25623.1.0.555":
			real = f
			if f.Review != "" {
				t.Fatalf("real finding reviewed: %+v", f)
			}
		default:
			if f.Review != v1.ReviewFalsePositive || f.ReviewedBy != "policy" {
				t.Fatalf("excluded finding not suppressed: %+v", f)
			}
		}
	}
	if real == nil {
		t.Fatal("real finding missing")
	}
	if err := st.ReviewFinding(ctx, real.ID, v1.ReviewAccepted, "analyst", "compensating control", now); err != nil {
		t.Fatal(err)
	}
	gf, err := st.GetFinding(ctx, real.ID)
	if err != nil || gf.Review != v1.ReviewAccepted || gf.ReviewedAt == nil || gf.ReviewedBy != "analyst" {
		t.Fatalf("review: %v %+v", err, gf)
	}
	// A re-observation keeps the review.
	if _, err := st.IngestHosts(ctx, site.ID, job.ID, hosts[:1], "202609260530", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if gf, _ = st.GetFinding(ctx, real.ID); gf.Review != v1.ReviewAccepted {
		t.Fatalf("review lost on re-ingest: %+v", gf)
	}
	if err := st.ReviewFinding(ctx, real.ID, "", "analyst", "reopened", now); err != nil {
		t.Fatal(err)
	}
	if gf, _ = st.GetFinding(ctx, real.ID); gf.Review != "" || gf.ReviewedAt != nil {
		t.Fatalf("reopen: %+v", gf)
	}
	if n, err := st.ReviewByDetector(ctx, site.ID, "1.3.6.1.4.1.25623.1.0.555", "analyst", "codified", now); err != nil || n != 1 {
		t.Fatalf("review by detector: %v %d", err, n)
	}
	if n, _ := st.ReviewByDetector(ctx, site.ID, "1.3.6.1.4.1.25623.1.0.555", "analyst", "codified", now); n != 0 {
		t.Fatalf("already reviewed findings touched: %d", n)
	}
	if _, err := st.GetFinding(ctx, "fnd_missing"); err != ErrNotFound {
		t.Fatalf("missing finding: %v", err)
	}
	if err := st.ReviewFinding(ctx, "fnd_missing", v1.ReviewAccepted, "x", "", now); err != ErrNotFound {
		t.Fatalf("review missing: %v", err)
	}

	// NVT mirror lookup.
	if err := st.UpsertNVTs(ctx, []NVT{{OID: "1.3.6.1.4.1.25623.1.0.555", Name: "real", Family: "Web Servers", CVSS: 7.5, CVEs: []string{"CVE-2024-0001"}, QoD: 80, FeedVersion: "202609260530"}}); err != nil {
		t.Fatal(err)
	}
	if n, err := st.GetNVT(ctx, "1.3.6.1.4.1.25623.1.0.555"); err != nil || n.Family != "Web Servers" || n.CVEs[0] != "CVE-2024-0001" {
		t.Fatalf("nvt: %v %+v", err, n)
	}
	if _, err := st.GetNVT(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("missing nvt: %v", err)
	}

	// Phase 5: settings (the nmap sign-off) and explicit schedule modules.
	if _, err := st.GetSetting(ctx, "signoff:nmap"); err != ErrNotFound {
		t.Fatalf("absent setting: %v", err)
	}
	if err := st.PutSetting(ctx, "signoff:nmap", `{"reference":"LEGAL-1"}`); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSetting(ctx, "signoff:nmap", `{"reference":"LEGAL-2"}`); err != nil {
		t.Fatal(err)
	}
	if v, err := st.GetSetting(ctx, "signoff:nmap"); err != nil || v != `{"reference":"LEGAL-2"}` {
		t.Fatalf("setting: %v %q", err, v)
	}
	if err := st.DeleteSetting(ctx, "signoff:nmap"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSetting(ctx, "signoff:nmap"); err != ErrNotFound {
		t.Fatalf("delete absent: %v", err)
	}
	fp := &Schedule{SiteID: site.ID, ApplianceID: apl.ID, Name: "fingerprint weekly", Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"},
		Modules: []string{v1.ModuleDiscovery, v1.ModulePortscan, v1.ModuleFingerprint}, Cron: "0 1 * * 2", TZ: "UTC", MaxDurationS: 3600, Enabled: true, CreatedAt: now}
	if err := st.CreateSchedule(ctx, fp); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetSchedule(ctx, fp.ID); len(got.Modules) != 3 || got.Modules[2] != v1.ModuleFingerprint {
		t.Fatalf("schedule modules: %+v", got.Modules)
	}
	fp.Modules = nil
	if err := st.UpdateSchedule(ctx, fp); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetSchedule(ctx, fp.ID); len(got.Modules) != 0 {
		t.Fatalf("cleared modules: %+v", got.Modules)
	}
	_ = st.DeleteSchedule(ctx, fp.ID)

	// Engine-down tracking across heartbeats.
	down := &v1.Heartbeat{Version: "1.3.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: false}}
	if err := st.RecordHeartbeat(ctx, apl.ID, now, down); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordHeartbeat(ctx, apl.ID, now.Add(time.Minute), down); err != nil {
		t.Fatal(err)
	}
	ga, _ := st.GetAppliance(ctx, apl.ID)
	if ga.EngineDownSince == nil || !ga.EngineDownSince.Equal(now) {
		t.Fatalf("engine down since: %v", ga.EngineDownSince)
	}
	if err := st.RecordHeartbeat(ctx, apl.ID, now.Add(2*time.Minute), &v1.Heartbeat{Version: "1.3.0", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}}); err != nil {
		t.Fatal(err)
	}
	if ga, _ = st.GetAppliance(ctx, apl.ID); ga.EngineDownSince != nil {
		t.Fatalf("engine down not cleared: %v", ga.EngineDownSince)
	}
}

// replaceScenario (Phase 6): the finding lifecycle across scans of
// different scope, external scanner imports correlated by CVE, retention
// bookkeeping and singleton locks.
func replaceScenario(t *testing.T, ctx context.Context, st Store, site *Site, apl *Appliance) {
	t.Helper()
	now := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	mk := func(id string, at time.Time) *Job {
		j := &Job{ID: id, SiteID: site.ID, ApplianceID: apl.ID, Status: v1.JobRunning, StartedAt: &at}
		j.Spec.DefaultsFor(v1.ModeInventory)
		if err := st.CreateJob(ctx, j); err != nil {
			t.Fatal(err)
		}
		return j
	}
	bluekeep := v1.Finding{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.108587", Name: "BlueKeep", Severity: v1.SeverityCritical, CVSS: 9.8, QoD: 97, Port: 3389, Proto: "tcp", CVE: []string{"CVE-2019-0708"}}
	smb := v1.Finding{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.777", Name: "SMBv1 enabled", Severity: v1.SeverityMedium, CVSS: 5.0, QoD: 80, Port: 445, Proto: "tcp", CVE: []string{"CVE-2017-0144"}}
	web := v1.Finding{Source: "nuclei", ID: "CVE-2021-41773", Name: "Apache traversal", Severity: v1.SeverityCritical, CVSS: 9.8, QoD: 80, Port: 8080, Proto: "tcp", CVE: []string{"CVE-2021-41773"}}
	host := "10.30.9.20"
	// Scan 1 (inventory scope): three findings, all open.
	j1 := mk("job_r1", now)
	sum, err := st.IngestScan(ctx, ScanIngest{SiteID: site.ID, JobID: j1.ID, FeedVersion: "f1", At: now.Add(time.Minute), Scope: v1.ScopeInventory,
		Hosts: []v1.Host{{IP: host, Ports: []v1.Port{{Port: 3389, Proto: "tcp"}, {Port: 445, Proto: "tcp"}, {Port: 8080, Proto: "tcp"}}, Findings: []v1.Finding{bluekeep, smb, web}}}})
	if err != nil || sum.NewFindings != 3 || sum.NewBySeverity[v1.SeverityCritical] != 2 || len(sum.New) != 2 {
		t.Fatalf("scan 1: %v %+v", err, sum)
	}
	var hostID string
	for _, h := range must(st.ListHosts(ctx, site.ID)) {
		if h.IP == host {
			hostID = h.ID
		}
	}
	byName := func() map[string]*Finding {
		m := map[string]*Finding{}
		for _, f := range must(st.ListFindings(ctx, site.ID, hostID)) {
			m[f.Name] = f
		}
		return m
	}
	fs := byName()
	if fs["BlueKeep"].Scope != v1.ScopeInventory || fs["Apache traversal"].Scope != v1.ScopeWeb || !fs["BlueKeep"].IsOpen() {
		t.Fatalf("scopes: %+v %+v", fs["BlueKeep"], fs["Apache traversal"])
	}
	// Scan 2 (inventory, host observed without SMBv1): SMBv1 fixed, the web
	// finding (web scope) untouched, BlueKeep re-observed stays open.
	j2 := mk("job_r2", now.Add(time.Hour))
	if _, err := st.IngestScan(ctx, ScanIngest{SiteID: site.ID, JobID: j2.ID, FeedVersion: "f1", At: now.Add(time.Hour + time.Minute), Scope: v1.ScopeInventory,
		Hosts: []v1.Host{{IP: host, Ports: []v1.Port{{Port: 3389, Proto: "tcp"}, {Port: 8080, Proto: "tcp"}}, Findings: []v1.Finding{bluekeep}}}}); err != nil {
		t.Fatal(err)
	}
	fixed, err := st.ResolveFindings(ctx, site.ID, j2.ID, []string{v1.ScopeInventory}, *j2.StartedAt, now.Add(time.Hour+2*time.Minute))
	if err != nil || len(fixed) != 1 || fixed[0].Name != "SMBv1 enabled" || fixed[0].Status != v1.FindingFixed || fixed[0].FixedAt == nil {
		t.Fatalf("resolve after scan 2: %v %+v", err, fixed)
	}
	fs = byName()
	if !fs["BlueKeep"].IsOpen() || !fs["Apache traversal"].IsOpen() || fs["SMBv1 enabled"].IsOpen() {
		t.Fatalf("lifecycle after scan 2: bk=%s web=%s smb=%s", fs["BlueKeep"].Status, fs["Apache traversal"].Status, fs["SMBv1 enabled"].Status)
	}
	// Scan 3 (full scope with the web module, host observed with nothing): the
	// web finding is fixed; a fragile-kept-away host is never resolved.
	j3 := mk("job_r3", now.Add(2*time.Hour))
	if _, err := st.IngestScan(ctx, ScanIngest{SiteID: site.ID, JobID: j3.ID, FeedVersion: "f1", At: now.Add(2*time.Hour + time.Minute), Scope: v1.ScopeFull,
		Hosts: []v1.Host{{IP: host, Ports: []v1.Port{{Port: 8080, Proto: "tcp"}}}, {IP: "10.30.9.21", Notes: []string{"fragile:9100"}, Ports: []v1.Port{{Port: 9100, Proto: "tcp"}}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IngestScan(ctx, ScanIngest{SiteID: site.ID, JobID: j1.ID, FeedVersion: "f1", At: now.Add(2*time.Hour + time.Minute), Scope: v1.ScopeInventory,
		Hosts: []v1.Host{{IP: "10.30.9.21", Notes: []string{"fragile:9100"}, Ports: []v1.Port{{Port: 9100, Proto: "tcp"}}, Findings: []v1.Finding{{Source: "openvas", NVTOID: "1.2.3", Name: "printer", Severity: v1.SeverityLow, CVSS: 3, QoD: 80, CVE: []string{}}}}}}); err != nil {
		t.Fatal(err)
	}
	fixed, err = st.ResolveFindings(ctx, site.ID, j3.ID, []string{v1.ScopeInventory, v1.ScopeFull, v1.ScopeWeb}, *j3.StartedAt, now.Add(2*time.Hour+2*time.Minute))
	if err != nil || len(fixed) != 2 {
		t.Fatalf("resolve after scan 3: %v %d fixed", err, len(fixed))
	}
	names := map[string]bool{}
	for _, f := range fixed {
		names[f.Name] = true
	}
	if !names["BlueKeep"] || !names["Apache traversal"] || names["printer"] {
		t.Fatalf("fixed set: %v", names)
	}
	// Scan 4: BlueKeep is back → reopened.
	j4 := mk("job_r4", now.Add(3*time.Hour))
	if _, err := st.IngestScan(ctx, ScanIngest{SiteID: site.ID, JobID: j4.ID, FeedVersion: "f2", At: now.Add(3*time.Hour + time.Minute), Scope: v1.ScopeInventory,
		Hosts: []v1.Host{{IP: host, Ports: []v1.Port{{Port: 3389, Proto: "tcp"}}, Findings: []v1.Finding{bluekeep}}}}); err != nil {
		t.Fatal(err)
	}
	fs = byName()
	if bk := fs["BlueKeep"]; !bk.IsOpen() || bk.Reopens != 1 || bk.ReopenedAt == nil || bk.FixedAt != nil {
		t.Fatalf("reopen: %+v", bk)
	}

	// External scanner import (Qualys): the same CVE merges into the
	// appliance finding with a second evidence source and confirms it; a new
	// host and finding are created; info rows skipped; a fixed row closes an
	// external-only finding.
	ts := now.Add(4 * time.Hour)
	ext := []v1.ExternalHost{
		{IP: host, Hostname: "wms-app-09", OS: "Windows Server 2008 R2", Findings: []v1.ExternalFinding{
			{ID: "91534", Name: "Microsoft RDP RCE (BlueKeep)", Type: "confirmed", Severity: v1.SeverityCritical, CVSS: 9.8, CVE: []string{"cve-2019-0708"}, Port: 3389, Proto: "tcp", Status: "active"},
			{ID: "45038", Name: "Host scan time", Type: "info", Severity: v1.SeverityInfo, CVE: []string{}},
		}},
		{IP: "10.30.9.50", Hostname: "fw-reno", OS: "FortiOS 7.2", Findings: []v1.ExternalFinding{
			{ID: "44444", Name: "FortiOS SSL-VPN heap overflow", Type: "confirmed", Severity: v1.SeverityCritical, CVSS: 9.8, CVE: []string{"CVE-2022-42475"}, Port: 443, Proto: "tcp", Status: "active"},
			{ID: "55555", Name: "Old TLS", Type: "potential", Severity: v1.SeverityMedium, CVE: []string{}, Port: 443, Proto: "tcp", Status: "active"},
		}},
	}
	esum, err := st.IngestExternal(ctx, site.ID, "qualys", ext, ts)
	if err != nil || esum.Hosts != 2 || esum.Created != 1 || esum.Merged != 1 || esum.Findings != 3 || esum.NewFindings != 2 || esum.Skipped != 1 {
		t.Fatalf("external import: %v %+v", err, esum)
	}
	fs = byName()
	bk := fs["BlueKeep"]
	if bk.State != v1.FindingConfirmed || len(bk.Evidence) < 2 || bk.ExternalID != "91534" || bk.Source != "openvas" {
		t.Fatalf("merged external: %+v", bk)
	}
	srcs := map[string]bool{}
	for _, e := range bk.Evidence {
		srcs[e.Source] = true
	}
	if !srcs["qualys"] || !srcs["openvas"] {
		t.Fatalf("evidence sources: %v", srcs)
	}
	var fw *Host
	for _, h := range must(st.ListHosts(ctx, site.ID)) {
		if h.IP == "10.30.9.50" {
			fw = h
		}
	}
	if fw == nil || fw.Source != v1.SourceExternal || fw.Hostname != "fw-reno" || fw.OSGuess == nil || fw.OSGuess.Family != "network" {
		t.Fatalf("external host: %+v", fw)
	}
	fwf := must(st.ListFindings(ctx, site.ID, fw.ID))
	if len(fwf) != 2 {
		t.Fatalf("external findings: %d", len(fwf))
	}
	for _, f := range fwf {
		if f.Source != "qualys" || f.Scope != "qualys" || f.ExternalID == "" || !f.IsOpen() {
			t.Fatalf("external finding: %+v", f)
		}
		if f.ExternalID == "55555" && f.State != v1.FindingSuspected {
			t.Fatalf("potential should be suspected: %+v", f)
		}
	}
	esum, err = st.IngestExternal(ctx, site.ID, "qualys", []v1.ExternalHost{{IP: "10.30.9.50", Findings: []v1.ExternalFinding{
		{ID: "44444", Name: "FortiOS SSL-VPN heap overflow", Severity: v1.SeverityCritical, CVE: []string{"CVE-2022-42475"}, Port: 443, Proto: "tcp", Status: "fixed"}}}}, ts.Add(time.Hour))
	if err != nil || esum.Fixed != 1 {
		t.Fatalf("external fixed: %v %+v", err, esum)
	}
	for _, f := range must(st.ListFindings(ctx, site.ID, fw.ID)) {
		if f.ExternalID == "44444" && (f.IsOpen() || f.FixedAt == nil) {
			t.Fatalf("not fixed by import: %+v", f)
		}
	}
	// A later appliance scan of the merged finding's host does not touch
	// the external-only finding (different host) and re-observes BlueKeep.
	if _, err := st.IngestExternal(ctx, "site_missing", "qualys", ext, ts); err != ErrNotFound {
		t.Fatalf("missing site: %v", err)
	}

	// Retention bookkeeping.
	old := now.Add(-100 * 24 * time.Hour)
	if _, err := st.RecordResultBatch(ctx, ResultBatchRec{JobID: j1.ID, Seq: 7, ReceivedAt: old, ObjectKey: "results/job_r1/000007.json", SHA256: "s7", Hosts: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordResultBatch(ctx, ResultBatchRec{JobID: j1.ID, Seq: 8, ReceivedAt: now, ObjectKey: "results/job_r1/000008.json", SHA256: "s8", Hosts: 1}); err != nil {
		t.Fatal(err)
	}
	batches := must(st.ListResultBatches(ctx, now.Add(-90*24*time.Hour), 100))
	found := false
	for _, b := range batches {
		if b.JobID == j1.ID && b.Seq == 8 {
			t.Fatal("fresh batch listed for retention")
		}
		if b.JobID == j1.ID && b.Seq == 7 {
			found = true
		}
	}
	if !found {
		t.Fatalf("old batch not listed: %+v", batches)
	}
	if err := st.MarkResultBatchPurged(ctx, j1.ID, 7); err != nil {
		t.Fatal(err)
	}
	for _, b := range must(st.ListResultBatches(ctx, now.Add(-90*24*time.Hour), 100)) {
		if b.JobID == j1.ID && b.Seq == 7 {
			t.Fatal("purged batch still listed")
		}
	}
	if err := st.MarkResultBatchPurged(ctx, j1.ID, 99); err != ErrNotFound {
		t.Fatalf("purge missing: %v", err)
	}
	if err := st.RecordSupportBundle(ctx, apl.ID, "support/r.tar.gz", 10); err != nil {
		t.Fatal(err)
	}
	sb := must(st.ListSupportBundles(ctx, time.Now().Add(time.Hour), 100))
	if len(sb) == 0 {
		t.Fatal("support bundles not listed")
	}
	if err := st.MarkSupportBundlePurged(ctx, sb[0].ID); err != nil {
		t.Fatal(err)
	}
	if len(must(st.ListSupportBundles(ctx, time.Now().Add(time.Hour), 100))) != len(sb)-1 {
		t.Fatal("purged support bundle still listed")
	}

	// Singleton locks.
	release, ok, err := st.TryLock(ctx, "rollout")
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", err, ok)
	}
	if _, ok2, _ := st.TryLock(ctx, "rollout"); ok2 {
		t.Fatal("lock taken twice")
	}
	release3, ok3, _ := st.TryLock(ctx, "scheduler")
	if !ok3 {
		t.Fatal("unrelated lock refused")
	}
	release3()
	release()
	release2, ok4, _ := st.TryLock(ctx, "rollout")
	if !ok4 {
		t.Fatal("lock not released")
	}
	release2()
}

// udpScenario: the UDP tests only run in jobs with the udp module. What
// such a job finds is resolvable only by such a job until a job without
// the module has seen it too, and its UDP ports outlast jobs that could
// not have seen them.
func udpScenario(t *testing.T, ctx context.Context, st Store, vendor *Vendor, apl *Appliance) {
	t.Helper()
	site, err := st.EnsureSite(ctx, vendor.ID, "UDP lab", []string{"10.40.0.0/16"}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	n := 0
	// scan ingests one final chunk for the host and resolves with the scopes
	// a job of that kind covers; it returns the names it fixed.
	scan := func(config string, udp bool, ports []v1.Port, findings ...v1.Finding) string {
		t.Helper()
		n++
		at := now.Add(time.Duration(n) * time.Hour)
		j := &Job{ID: fmt.Sprintf("job_u%d", n), SiteID: site.ID, ApplianceID: apl.ID, Status: v1.JobRunning, StartedAt: &at}
		j.Spec.DefaultsFor(v1.ModeInventory)
		if err := st.CreateJob(ctx, j); err != nil {
			t.Fatal(err)
		}
		host := v1.Host{IP: "10.40.0.9", Ports: ports, Findings: findings}
		scopes := []string{v1.ScopeInventory}
		if config == v1.ScopeFull {
			scopes = append(scopes, v1.ScopeFull)
		}
		if udp {
			host.Notes = []string{v1.NoteUDPTested}
			for _, sc := range append([]string{}, scopes...) {
				scopes = append(scopes, v1.UDPScope(sc))
			}
		}
		if _, err := st.IngestScan(ctx, ScanIngest{SiteID: site.ID, JobID: j.ID, FeedVersion: "f1", At: at.Add(time.Minute), Scope: config, Hosts: []v1.Host{host}}); err != nil {
			t.Fatal(err)
		}
		fixed, err := st.ResolveFindings(ctx, site.ID, j.ID, scopes, at, at.Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, f := range fixed {
			names = append(names, f.Name)
		}
		sort.Strings(names)
		return strings.Join(names, ",")
	}
	// state renders the host's UDP ports and every finding as name=scope/status.
	state := func() string {
		t.Helper()
		var host *Host
		for _, h := range must(st.ListHosts(ctx, site.ID)) {
			if h.IP == "10.40.0.9" {
				host = h
			}
		}
		if host == nil {
			t.Fatal("host missing")
		}
		var out []string
		for _, p := range host.Ports {
			if p.Proto == "udp" {
				out = append(out, fmt.Sprintf("%d/udp:%s", p.Port, p.Service))
			}
		}
		for _, f := range must(st.ListFindings(ctx, site.ID, host.ID)) {
			out = append(out, fmt.Sprintf("%s=%s/%s", f.Name, f.Scope, f.Status))
		}
		sort.Strings(out)
		return strings.Join(out, " ")
	}
	expect := func(step, fixed, wantFixed, want string) {
		t.Helper()
		if got := state(); fixed != wantFixed || got != want {
			t.Fatalf("%s:\n fixed %q, want %q\n state %s\n  want %s", step, fixed, wantFixed, got, want)
		}
	}
	dns := v1.Finding{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.9001", Name: "dns", Severity: v1.SeverityMedium, CVSS: 5.0, QoD: 80, Port: 53, Proto: "tcp"}
	snmp := v1.Finding{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.9002", Name: "snmp", Severity: v1.SeverityHigh, CVSS: 7.5, QoD: 99, Port: 161, Proto: "udp"}
	ntp := v1.Finding{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.9003", Name: "ntp", Severity: v1.SeverityMedium, CVSS: 5.0, QoD: 80, Port: 123, Proto: "udp"}
	// A version read over SNMP puts this one on no port at all.
	gear := v1.Finding{Source: "openvas", NVTOID: "1.3.6.1.4.1.25623.1.0.9004", Name: "gear", Severity: v1.SeverityHigh, CVSS: 8.0, QoD: 80, Port: 0, Proto: "tcp"}
	tcp53 := v1.Port{Port: 53, Proto: "tcp", Service: "dns", Source: "naabu"}
	udp161 := v1.Port{Port: 161, Proto: "udp", Service: "snmp", Source: "openvas:find_service"}
	udp123 := v1.Port{Port: 123, Proto: "udp", Service: "ntp", Source: "openvas:find_service"}

	// A full job with the udp module: everything it finds is, for now,
	// only known to be visible to such a job.
	fixed := scan(v1.ScopeFull, true, []v1.Port{tcp53, udp161, udp123}, dns, snmp, ntp, gear)
	expect("full+udp", fixed, "", "123/udp:ntp 161/udp:snmp dns=full+udp/open gear=full+udp/open ntp=full+udp/open snmp=full+udp/open")

	// An inventory job with the module sees two of them again: those become
	// resolvable by such a job. It did not look for the other two.
	fixed = scan(v1.ScopeInventory, true, []v1.Port{tcp53, udp161, udp123}, dns, snmp)
	expect("inventory+udp", fixed, "", "123/udp:ntp 161/udp:snmp dns=inventory+udp/open gear=full+udp/open ntp=full+udp/open snmp=inventory+udp/open")

	// A plain full job tests no UDP port and reads nothing over SNMP. It
	// sees the TCP finding, which a plain inventory job is still not known
	// to see, so that scope stays. The UDP ports stay, and nothing that
	// needed UDP is resolved, the portless finding included.
	fixed = scan(v1.ScopeFull, false, []v1.Port{tcp53}, dns)
	expect("plain full", fixed, "", "123/udp:ntp 161/udp:snmp dns=inventory+udp/open gear=full+udp/open ntp=full+udp/open snmp=inventory+udp/open")

	// A plain inventory job sees it: from now on any inventory job resolves it.
	fixed = scan(v1.ScopeInventory, false, []v1.Port{tcp53}, dns)
	expect("plain inventory", fixed, "", "123/udp:ntp 161/udp:snmp dns=inventory/open gear=full+udp/open ntp=full+udp/open snmp=inventory+udp/open")

	// An inventory job with the module finds SNMP gone: the port goes and
	// its finding is fixed. The two a full config found are not its to judge.
	fixed = scan(v1.ScopeInventory, true, []v1.Port{tcp53, udp123}, dns)
	expect("inventory+udp, snmp gone", fixed, "snmp", "123/udp:ntp dns=inventory/open gear=full+udp/open ntp=full+udp/open snmp=inventory+udp/fixed")

	// A full job with the module no longer finds those two either.
	fixed = scan(v1.ScopeFull, true, []v1.Port{tcp53}, dns)
	expect("full+udp, all gone", fixed, "gear,ntp", "dns=inventory/open gear=full+udp/fixed ntp=full+udp/fixed snmp=inventory+udp/fixed")
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
