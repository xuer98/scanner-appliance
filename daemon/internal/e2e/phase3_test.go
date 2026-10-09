package e2e

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/engine"
	"github.com/tprm/scanner-appliance/daemon/internal/heartbeat"
	"github.com/tprm/scanner-appliance/daemon/internal/jobs"
	"github.com/tprm/scanner-appliance/daemon/internal/nvt"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/daemon/internal/osp/osptest"
	"github.com/tprm/scanner-appliance/daemon/internal/spool"
	"github.com/tprm/scanner-appliance/daemon/internal/state"
	"github.com/tprm/scanner-appliance/daemon/internal/update"
	"github.com/tprm/scanner-appliance/internal/bundle"
)

// publishBundle builds a bundle from files, uploads what the control plane
// lacks and publishes the signed manifest (what `cp-api bundle build` +
// `admin publish-bundle` do).
func (c *cp) publishBundle(t *testing.T, files map[string]string, version string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(body), 0o644)
	}
	m, err := bundle.Build(root, version, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var shas []string
	for _, f := range m.Files {
		shas = append(shas, f.SHA256)
	}
	var missing v1.AdminMissingFilesResponse
	if st := c.adminFn("POST", "/admin/bundles/missing", v1.AdminMissingFilesRequest{SHA256: shas}, &missing); st != 200 {
		t.Fatalf("missing: %d", st)
	}
	need := map[string]bool{}
	for _, s := range missing.Missing {
		need[s] = true
	}
	for _, f := range m.Files {
		if !need[f.SHA256] {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.Path)))
		if st, out := c.rawAdminFn("PUT", "/admin/bundles/files/"+f.SHA256, b, nil); st != 201 {
			t.Fatalf("upload %s: %d %s", f.Path, st, out)
		}
	}
	mb, _ := bundle.EncodeManifest(m)
	sig, _ := bundle.Sign(mb, c.releaseKey)
	req, _ := json.Marshal(v1.AdminPublishBundleRequest{Manifest: mb, Sig: sig})
	st, out := c.rawAdminFn("POST", "/admin/bundles", req, map[string]string{"Content-Type": "application/json"})
	if st != 201 {
		t.Fatalf("publish %s: %d %s", version, st, out)
	}
	return version
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

// TestPhase3 is the Phase 3 definition of done (PLAN §20): a feed delta
// applies without a reboot, and the canary rollout works: the canary gets
// bundles and daemon releases first, a failing bundle is rolled back on the
// appliance and held on the control plane, and a daemon self-update swaps
// the binary and is confirmed by the new version's heartbeat.
func TestPhase3(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses shell-script fakes")
	}
	c := newCP(t)
	admin := c.adminFn
	var created v1.AdminCreateApplianceResponse
	if st := admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme", Site: "Reno", AllowedCIDRs: []string{"10.30.0.0/16"}}, &created); st != 201 {
		t.Fatalf("create %d", st)
	}

	// The image shipped a feed; ospd (fake) follows the plugins directory.
	plugins := t.TempDir()
	_ = os.WriteFile(filepath.Join(plugins, "plugin_feed_info.inc"), []byte("PLUGIN_SET = \"202609010000\";\n"), 0o644)
	_ = os.WriteFile(filepath.Join(plugins, "old.nasl"), []byte("old"), 0o644)
	// Like a real engine, every scan reports at least a service on an open port.
	fake := osptest.Start(t, &osptest.Fake{PluginsDir: plugins, Script: []osptest.Step{{Progress: 100, Results: []osp.Result{
		{Host: "10.30.5.20", Type: "Log Message", Port: "3389/tcp", TestID: "1.3.6.1.4.1.25623.1.0.10330", Name: "Services", QoD: "80", Text: "A Remote Desktop Protocol (RDP) service is running on this port."},
	}}}})

	st := state.New(t.TempDir(), t.TempDir())
	s, _ := st.Load()
	s.EnrollURL = c.enroll.URL
	s.PendingCode = created.Code
	s.IntervalOverrideS = 1
	_ = st.Save(s)
	ospc := osp.New(fake.Socket)
	eng := &engine.Engine{NaabuPath: labNaabu(t), OSP: ospc, NVT: nvt.New(filepath.Join(st.Dir, "nvt-cache"), ospc, nil), Log: slog.Default(),
		PollInterval: 50 * time.Millisecond, ScanType: "c", IfaceExists: func(string) bool { return true }, BundleDir: filepath.Join(st.Dir, "bundle")}
	runner := &jobs.Runner{Store: st, Engine: eng, Spool: &spool.Spool{Dir: filepath.Join(st.Dir, "spool")}, Roots: c.roots, Log: slog.Default()}
	exe := filepath.Join(t.TempDir(), "applianced")
	_ = os.WriteFile(exe, []byte("#!/bin/sh\necho e2e\n"), 0o755)
	upd := &update.Manager{StateDir: st.Dir, PluginsDir: plugins, Keys: []*ecdsa.PublicKey{&c.releaseKey.PublicKey}, OSP: ospc, Log: slog.Default(),
		Version: "e2e", ExePath: exe, ReloadTimeout: 5 * time.Second, ReloadPoll: 50 * time.Millisecond}
	loop := &heartbeat.Loop{Store: st, Roots: c.roots, Version: "e2e", Log: slog.Default(), PowerOff: func() error { return nil }, Reboot: func() error { return nil },
		OSPSocket: fake.Socket, Jobs: runner, Update: upd}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { loop.Run(ctx); close(done) }()

	// Decode into a fresh value every time: omitempty fields (update_error)
	// would otherwise survive in a reused struct.
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
	if view.FeedVersion != "202609010000" || view.OS != runtime.GOOS || view.Arch != runtime.GOARCH {
		t.Fatalf("heartbeat: feed=%s os=%s arch=%s", view.FeedVersion, view.OS, view.Arch)
	}
	canary := true
	if stc := admin("PATCH", "/admin/appliances/"+created.ApplianceID, v1.AdminApplianceUpdate{Canary: &canary}, &view); stc != 200 || !view.Canary {
		t.Fatalf("canary: %d", stc)
	}

	// DoD: a bundle (feed + a scan config) reaches the canary and the feed
	// is live in the engine without a reboot.
	cfg := `{"name":"inventory","families":["Web Servers"],"udp_ports":[161],"params":{"optimize_test":"1"}}`
	v1ver := c.publishBundle(t, map[string]string{
		"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n", "nasl/a.nasl": "a1", "configs/inventory.json": cfg,
	}, "20260926T000000Z")
	waitFor(t, 30*time.Second, func() bool {
		view = getView()
		return view.BundleVersion == v1ver && view.FeedVersion == "202609260530" && view.UpdateError == ""
	}, "bundle v1 applied and feed reloaded")
	if readFile(t, filepath.Join(plugins, "a.nasl")) != "a1" || readFile(t, filepath.Join(plugins, "old.nasl")) != "<missing>" {
		t.Fatal("plugins directory not updated")
	}
	if live, _ := st.ReadStatus(); live.BundleVersion != v1ver || live.Updating != "" || live.UpdateError != "" {
		t.Fatalf("status.json: %+v", live)
	}

	// The bundled scan config is what openvas gets: an inventory job selects
	// only Web Servers (+ detection), not the shipped Windows families.
	var job v1.AdminJobView
	if stc := admin("POST", "/admin/jobs", v1.AdminJobRequest{ApplianceID: created.ApplianceID, Mode: v1.ModeInventory, Targets: []string{"10.30.5.0/24"}}, &job); stc != 201 {
		t.Fatalf("job %d", stc)
	}
	waitFor(t, 40*time.Second, func() bool {
		admin("GET", "/admin/jobs/"+job.ID, nil, &job)
		return job.Status == v1.JobDone
	}, "inventory job done on the bundled config")
	if starts := fake.Starts(); len(starts) != 1 || !strings.Contains(starts[0], "Web Servers") || strings.Contains(starts[0], "Microsoft Bulletins") {
		t.Fatalf("start_scan did not use the bundled config: %d starts", len(starts))
	}

	// DoD: a delta (one changed, one new file) fetches and applies.
	v2ver := c.publishBundle(t, map[string]string{
		"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609270530\";\n", "nasl/a.nasl": "a2", "nasl/b.nasl": "b2", "configs/inventory.json": cfg,
	}, "20260927T000000Z")
	waitFor(t, 30*time.Second, func() bool {
		view = getView()
		return view.BundleVersion == v2ver && view.FeedVersion == "202609270530"
	}, "delta applied")
	if readFile(t, filepath.Join(plugins, "a.nasl")) != "a2" || readFile(t, filepath.Join(plugins, "b.nasl")) != "b2" {
		t.Fatal("delta not on disk")
	}

	// A broken feed (no PLUGIN_SET, so ospd never reports it loaded) is
	// rolled back on the appliance and holds the rollout on the control plane.
	v3ver := c.publishBundle(t, map[string]string{
		"nasl/plugin_feed_info.inc": "PLUGIN_FEED = \"broken\";\n", "nasl/a.nasl": "a3", "configs/inventory.json": cfg,
	}, "20260928T000000Z")
	waitFor(t, 60*time.Second, func() bool {
		view = getView()
		return strings.HasPrefix(view.UpdateError, "bundle "+v3ver+":")
	}, "broken bundle reported")
	if view.BundleVersion != v2ver || view.FeedVersion != "202609270530" || readFile(t, filepath.Join(plugins, "a.nasl")) != "a2" {
		t.Fatalf("rollback: bundle=%s feed=%s a.nasl=%q", view.BundleVersion, view.FeedVersion, readFile(t, filepath.Join(plugins, "a.nasl")))
	}
	var bundles []v1.AdminBundleView
	admin("GET", "/admin/bundles", nil, &bundles)
	var held *v1.AdminBundleView
	for i := range bundles {
		if bundles[i].Version == v3ver {
			held = &bundles[i]
		}
	}
	if held == nil || held.Status != v1.RolloutHeld || !strings.Contains(held.HeldReason, created.ApplianceID) {
		t.Fatalf("v3 not held: %+v", bundles)
	}

	// reload_vts re-checks the feed on disk and clears the error.
	admin("POST", "/admin/appliances/"+created.ApplianceID+"/directives", v1.AdminDirectiveRequest{Type: v1.DirectiveReloadVTs}, nil)
	waitFor(t, 30*time.Second, func() bool {
		view = getView()
		return view.UpdateError == "" && view.BundleVersion == v2ver
	}, "reload_vts cleared the error")

	// DoD: canary rollout of a daemon release. The artifact is a script that
	// reports the new version; the daemon verifies it, swaps its binary and
	// exits for the supervisor.
	artifact := []byte("#!/bin/sh\necho e2e-next\n")
	sig, _ := bundle.Sign(artifact, c.releaseKey)
	component := v1.ReleaseComponent(runtime.GOOS, runtime.GOARCH)
	if stc, out := c.rawAdminFn("PUT", "/admin/releases/"+component+"/e2e-next", artifact,
		map[string]string{v1.HeaderReleaseSHA256: bundle.SHA256Hex(artifact), v1.HeaderReleaseSig: sig}); stc != 201 {
		t.Fatalf("publish release: %d %s", stc, out)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("daemon did not exit for the update")
	}
	if !loop.RestartRequested() || readFile(t, exe) != string(artifact) || readFile(t, exe+".prev") != "#!/bin/sh\necho e2e\n" {
		t.Fatal("binary swap did not happen")
	}
	if pend, _ := upd.LoadPending(); pend == nil || pend.Version != "e2e-next" {
		t.Fatalf("pending record: %+v", pend)
	}
	// The "new binary" starts, confirms itself with a heartbeat, and the
	// release leaves canary once the canary reports the version.
	upd2 := *upd
	upd2.Version = "e2e-next"
	loop2 := &heartbeat.Loop{Store: st, Roots: c.roots, Version: "e2e-next", Log: slog.Default(), PowerOff: func() error { return nil }, Reboot: func() error { return nil },
		OSPSocket: fake.Socket, Jobs: runner, Update: &upd2}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go loop2.Run(ctx2)
	waitFor(t, 20*time.Second, func() bool {
		view = getView()
		pend, _ := upd2.LoadPending()
		return view.Version == "e2e-next" && view.UpdateError == "" && pend == nil
	}, "new daemon confirmed")
	if err := c.srv.RolloutTick(ctx2); err != nil {
		t.Fatal(err)
	}
	var rels []v1.AdminReleaseView
	admin("GET", "/admin/releases", nil, &rels)
	if len(rels) != 1 || rels[0].Status != v1.RolloutReleased || rels[0].Installed != 1 {
		t.Fatalf("release after canary: %+v", rels)
	}
}

// logTimes notes when a log message was first written, and passes every
// record on.
type logTimes struct {
	slog.Handler
	seen *sync.Map // message -> time.Time
}

func (h logTimes) Handle(ctx context.Context, r slog.Record) error {
	h.seen.LoadOrStore(r.Message, time.Now())
	return h.Handler.Handle(ctx, r)
}

func (h logTimes) WithAttrs(a []slog.Attr) slog.Handler {
	return logTimes{Handler: h.Handler.WithAttrs(a), seen: h.seen}
}

func (h logTimes) WithGroup(name string) slog.Handler {
	return logTimes{Handler: h.Handler.WithGroup(name), seen: h.seen}
}

// TestFinishedUpdateIsReportedAtOnce: a finished update is not left for the
// next regular heartbeat. The heartbeat that brings the bundle here also
// stretches the appliance's interval to twenty seconds. The control plane
// must learn of the new bundle right when it is applied, from a heartbeat
// that calls the appliance idle, and not an interval later from one that
// still says "updating": until then the appliance starts no job either.
//
// What is measured is the time from "bundle applied" to that heartbeat, not
// how long the update takes: on a busy Windows runner the few file
// operations of an update have stalled for many seconds. For the same
// reason there is no engine here, whose fake needs Unix sockets.
func TestFinishedUpdateIsReportedAtOnce(t *testing.T) {
	c := newCP(t)
	admin := c.adminFn
	var created v1.AdminCreateApplianceResponse
	if st := admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme", Site: "Reno", AllowedCIDRs: []string{"10.30.0.0/16"}}, &created); st != 201 {
		t.Fatalf("create %d", st)
	}
	st := state.New(t.TempDir(), t.TempDir())
	s, _ := st.Load()
	s.EnrollURL = c.enroll.URL
	s.PendingCode = created.Code
	s.IntervalOverrideS = 1
	_ = st.Save(s)
	seen := &sync.Map{}
	upd := &update.Manager{StateDir: st.Dir, Keys: []*ecdsa.PublicKey{&c.releaseKey.PublicKey}, Version: "e2e",
		Log: slog.New(logTimes{Handler: slog.Default().Handler(), seen: seen})}
	loop := &heartbeat.Loop{Store: st, Roots: c.roots, Version: "e2e", Log: slog.Default(), PowerOff: func() error { return nil }, Reboot: func() error { return nil }, Update: upd}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go loop.Run(ctx)

	getView := func() v1.AdminApplianceView {
		var v v1.AdminApplianceView
		admin("GET", "/admin/appliances/"+created.ApplianceID, nil, &v)
		return v
	}
	waitFor(t, 30*time.Second, func() bool { return getView().Online }, "appliance online")
	canary := true
	if stc := admin("PATCH", "/admin/appliances/"+created.ApplianceID, v1.AdminApplianceUpdate{Canary: &canary}, nil); stc != 200 {
		t.Fatalf("canary: %d", stc)
	}
	// Queued first, so that it never arrives after the bundle: from the
	// heartbeat that brings the bundle on, the next regular one is twenty
	// seconds away.
	const interval = 20 * time.Second
	if stc := admin("POST", "/admin/appliances/"+created.ApplianceID+"/directives", v1.AdminDirectiveRequest{Type: v1.DirectiveSetInterval, Payload: map[string]any{"s": interval.Seconds()}}, nil); stc != 201 {
		t.Fatalf("set_interval: %d", stc)
	}
	ver := c.publishBundle(t, map[string]string{"configs/inventory.json": `{"name":"inventory","families":["Web Servers"]}`, "fragile-ports.json": "[9100]\n"}, "20260926T000000Z")

	// The first heartbeat that carries the new bundle version.
	var view v1.AdminApplianceView
	deadline := time.Now().Add(90 * time.Second)
	for view = getView(); view.BundleVersion != ver; view = getView() {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Logf("goroutines:\n%s", buf[:runtime.Stack(buf, true)])
			t.Fatalf("bundle not reported: bundle=%q error=%q", view.BundleVersion, view.UpdateError)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if view.LastHeartbeat == nil || view.LastHeartbeatAt == nil {
		t.Fatalf("no heartbeat in the view that shows the bundle: %+v", view)
	}
	if got := view.LastHeartbeat.State; got != heartbeat.StateIdle {
		t.Fatalf("the heartbeat that reports the new bundle says %q, want an idle appliance", got)
	}
	applied, ok := seen.Load("bundle applied")
	if !ok {
		t.Fatal("the update manager never logged that the bundle was applied")
	}
	if took := view.LastHeartbeatAt.Sub(applied.(time.Time)); took > interval/2 {
		t.Fatalf("the update was reported %s after it was applied; the heartbeat interval is %s", took.Round(10*time.Millisecond), interval)
	}
	if local, _ := st.Load(); local.IntervalOverrideS != int(interval/time.Second) {
		t.Fatalf("interval on the appliance: %d s, want %s", local.IntervalOverrideS, interval)
	}
	if live, _ := st.ReadStatus(); live == nil || live.State != heartbeat.StateIdle || live.Updating != "" {
		t.Fatalf("status.json after the update: %+v", live)
	}
}
