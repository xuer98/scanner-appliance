package update

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/daemon/internal/osp/osptest"
	"github.com/tprm/scanner-appliance/internal/bundle"
)

// cpFake serves bundles and releases like cp-api, counting file fetches.
type cpFake struct {
	mu        sync.Mutex
	manifests map[string][]byte
	files     map[string][]byte
	releases  map[string][]byte
	fileReqs  int
	srv       *httptest.Server
}

func newCPFake(t *testing.T) *cpFake {
	f := &cpFake{manifests: map[string][]byte{}, files: map[string][]byte{}, releases: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundles/{version}/manifest", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b, ok := f.manifests[r.PathValue("version")]
		if !ok {
			http.Error(w, `{"error":"no such bundle"}`, 404)
			return
		}
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /v1/bundles/{version}/files/{sha256}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.fileReqs++
		b, ok := f.files[r.PathValue("sha256")]
		if !ok {
			http.Error(w, `{"error":"missing"}`, 404)
			return
		}
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /v1/releases/{component}/{version}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b, ok := f.releases[r.PathValue("component")+"/"+r.PathValue("version")]
		if !ok {
			http.Error(w, `{"error":"no such release"}`, 404)
			return
		}
		_, _ = w.Write(b)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *cpFake) fetcher() Fetcher {
	return FetchFunc(func(ctx context.Context, path string, w io.Writer, max int64) (http.Header, int64, error) {
		req, _ := http.NewRequestWithContext(ctx, "GET", f.srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return resp.Header, 0, io.ErrUnexpectedEOF
		}
		n, err := io.Copy(w, io.LimitReader(resp.Body, max))
		return resp.Header, n, err
	})
}

// publish builds a bundle from files and registers it; returns the directive payload.
func (f *cpFake) publish(t *testing.T, key signer, files map[string]string, version string) Payload {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(c), 0o644)
	}
	m, err := bundle.Build(root, version, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := bundle.EncodeManifest(m)
	sig, _ := bundle.Sign(mb, key.key)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manifests[version] = mb
	for _, fl := range m.Files {
		b, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(fl.Path)))
		f.files[fl.SHA256] = b
	}
	return Payload{URL: "/v1/bundles/" + version + "/manifest", SHA256: bundle.SHA256Hex(mb), Sig: sig, Version: version, FeedVersion: m.FeedVersion}
}

func (f *cpFake) reqs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fileReqs
}

func newManager(t *testing.T, f *cpFake, key signer, plugins string, fake *osptest.Fake) *Manager {
	t.Helper()
	m := &Manager{StateDir: t.TempDir(), PluginsDir: plugins, Fetch: f.fetcher(), Log: slog.Default(),
		ReloadTimeout: 3 * time.Second, ReloadPoll: 20 * time.Millisecond, Version: "1.2.0"}
	k := key
	m.Keys = k.pubs()
	if fake != nil {
		m.OSP = osp.New(fake.Socket)
	}
	return m
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func TestBundleFirstInstallDeltaAndRemoval(t *testing.T) {
	cp := newCPFake(t)
	key := newSigner(t)
	plugins := t.TempDir()
	// The image seeded a feed before any bundle existed.
	_ = os.WriteFile(filepath.Join(plugins, "plugin_feed_info.inc"), []byte("PLUGIN_SET = \"202609010000\";\n"), 0o644)
	_ = os.WriteFile(filepath.Join(plugins, "old.nasl"), []byte("old"), 0o644)
	fake := osptest.Start(t, &osptest.Fake{PluginsDir: plugins})
	m := newManager(t, cp, key, plugins, fake)

	v1files := map[string]string{
		"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n",
		"nasl/a.nasl":               "a1",
		"nasl/sub/b.nasl":           "b1",
		"configs/inventory.json":    `{"name":"inventory","families":["Web Servers"],"udp_ports":[161],"params":{}}`,
		"fragile-ports.json":        "[9100]",
	}
	p1 := cp.publish(t, key, v1files, "20260926T000000Z")
	mf, err := m.ApplyBundle(t.Context(), p1)
	if err != nil {
		t.Fatal(err)
	}
	if mf.Version != p1.Version || cp.reqs() != 5 {
		t.Fatalf("first install: %+v reqs=%d", mf, cp.reqs())
	}
	if read(t, filepath.Join(plugins, "sub", "b.nasl")) != "b1" || read(t, filepath.Join(plugins, "old.nasl")) != "<missing>" {
		t.Fatal("feed not installed / seeded file not removed")
	}
	if read(t, filepath.Join(m.ConfigsDir(), "inventory.json")) == "<missing>" || read(t, m.Target("fragile-ports.json")) != "[9100]" {
		t.Fatal("non-feed parts not installed")
	}
	if inst, _ := m.Installed(); inst == nil || inst.Version != p1.Version || inst.FeedVersion != "202609260530" {
		t.Fatalf("installed manifest: %+v", inst)
	}
	if prev := read(t, m.prevManifestPath()); !strings.Contains(prev, "seed-202609010000") {
		t.Fatalf("seed not retained as previous: %s", prev)
	}
	// Idempotent.
	if _, err := m.ApplyBundle(t.Context(), p1); err != nil || cp.reqs() != 5 {
		t.Fatalf("re-apply: %v reqs=%d", err, cp.reqs())
	}

	// Delta: change a, add c, drop b (and its now-empty directory).
	v2files := map[string]string{
		"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609270530\";\n",
		"nasl/a.nasl":               "a2",
		"nasl/c.nasl":               "c2",
		"configs/inventory.json":    v1files["configs/inventory.json"],
		"fragile-ports.json":        "[9100]",
	}
	p2 := cp.publish(t, key, v2files, "20260927T000000Z")
	if _, err := m.ApplyBundle(t.Context(), p2); err != nil {
		t.Fatal(err)
	}
	if got := cp.reqs(); got != 5+3 {
		t.Fatalf("delta fetched %d files, want 3", got-5)
	}
	if read(t, filepath.Join(plugins, "a.nasl")) != "a2" || read(t, filepath.Join(plugins, "c.nasl")) != "c2" || read(t, filepath.Join(plugins, "sub", "b.nasl")) != "<missing>" {
		t.Fatal("delta not applied")
	}
	if _, err := os.Stat(filepath.Join(plugins, "sub")); err == nil {
		t.Fatal("empty feed directory not pruned")
	}
	if h := m.OSP.Health(t.Context()); h.FeedVersion != "202609270530" || !h.VTCacheLoaded {
		t.Fatalf("engine health after delta: %+v", h)
	}
	// GC keeps current + previous only.
	entries, _ := os.ReadDir(m.casDir())
	if len(entries) != 7 { // v1 (5 files) ∪ v2 (5 files): a1,a2,b1,c2,inc1,inc2,config(shared),fragile(shared) = 8? see below
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name()[:8])
		}
		t.Logf("cas entries: %v", names)
	}
	live := map[string]bool{}
	for _, mf := range []*bundle.Manifest{mustInstalled(t, m), mustManifest(t, m.prevManifestPath())} {
		for _, f := range mf.Files {
			live[f.SHA256] = true
		}
	}
	for _, e := range entries {
		if !live[e.Name()] {
			t.Fatalf("cas entry %s not referenced", e.Name())
		}
	}
	if len(entries) != len(live) {
		t.Fatalf("cas has %d entries, %d live", len(entries), len(live))
	}
}

func mustInstalled(t *testing.T, m *Manager) *bundle.Manifest {
	t.Helper()
	mf, err := m.Installed()
	if err != nil || mf == nil {
		t.Fatalf("installed: %v", err)
	}
	return mf
}

func mustManifest(t *testing.T, path string) *bundle.Manifest {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mf, err := bundle.DecodeManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	return mf
}

func TestBundleRollbackWhenFeedDoesNotLoad(t *testing.T) {
	cp := newCPFake(t)
	key := newSigner(t)
	plugins := t.TempDir()
	_ = os.WriteFile(filepath.Join(plugins, "plugin_feed_info.inc"), []byte("PLUGIN_SET = \"202609010000\";\n"), 0o644)
	_ = os.WriteFile(filepath.Join(plugins, "keep.nasl"), []byte("keep"), 0o644)
	// This ospd never reloads: it keeps reporting the seeded version.
	fake := osptest.Start(t, &osptest.Fake{VTsVersion: "202609010000"})
	m := newManager(t, cp, key, plugins, fake)
	m.ReloadTimeout = 300 * time.Millisecond

	p := cp.publish(t, key, map[string]string{"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n", "nasl/new.nasl": "new"}, "20260926T000000Z")
	_, err := m.ApplyBundle(t.Context(), p)
	if err == nil || !strings.HasPrefix(err.Error(), "bundle 20260926T000000Z: ospd did not load feed 202609260530") {
		t.Fatalf("expected reload failure, got %v", err)
	}
	if read(t, filepath.Join(plugins, "new.nasl")) != "<missing>" || read(t, filepath.Join(plugins, "keep.nasl")) != "keep" {
		t.Fatal("rollback did not restore the plugins directory")
	}
	if got := read(t, filepath.Join(plugins, "plugin_feed_info.inc")); !strings.Contains(got, "202609010000") {
		t.Fatalf("feed info not restored: %s", got)
	}
	if inst := mustInstalled(t, m); inst.Version != "seed-202609010000" {
		t.Fatalf("installed after rollback: %s", inst.Version)
	}
	if _, err := os.Stat(filepath.Join(m.bundleDir(), "manifest.failed.json")); err != nil {
		t.Fatal("failed manifest not kept for support")
	}
	// reload_vts against the restored feed succeeds (the fake reports it).
	if err := m.ReloadVTs(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestBundleRefusesBadSignatureAndDigest(t *testing.T) {
	cp := newCPFake(t)
	key := newSigner(t)
	m := newManager(t, cp, key, "", nil)
	p := cp.publish(t, key, map[string]string{"configs/full.json": `{"name":"full","families":["Web Servers"],"params":{}}`}, "20260926T000000Z")
	bad := p
	bad.SHA256 = strings.Repeat("0", 64)
	if _, err := m.ApplyBundle(t.Context(), bad); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("digest mismatch accepted: %v", err)
	}
	other := newSigner(t)
	m2 := newManager(t, cp, other, "", nil)
	if _, err := m2.ApplyBundle(t.Context(), p); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("wrong key accepted: %v", err)
	}
	if inst, _ := m.Installed(); inst != nil {
		t.Fatal("refused bundle left a manifest behind")
	}
	if cp.reqs() != 0 {
		t.Fatal("files fetched before verification")
	}
	// No engine at all: the apply succeeds without a reload wait.
	if mf, err := m.ApplyBundle(t.Context(), p); err != nil || mf.Version != p.Version {
		t.Fatalf("apply without engine: %v", err)
	}
	for _, tc := range []map[string]any{
		{"url": "https://evil.example/x", "sha256": p.SHA256, "sig": p.Sig, "version": p.Version},
		{"url": "/v1/bundles/../x", "sha256": p.SHA256, "sig": p.Sig, "version": p.Version},
		{"url": p.URL, "sha256": "zz", "sig": p.Sig, "version": p.Version},
		{"url": p.URL, "sha256": p.SHA256, "sig": "", "version": p.Version},
		{"url": p.URL, "sha256": p.SHA256, "sig": p.Sig, "version": "v 1; rm -rf /"},
	} {
		if _, err := PayloadFrom(tc); err == nil {
			t.Fatalf("payload accepted: %v", tc)
		}
	}
	if got, err := PayloadFrom(map[string]any{"url": p.URL, "sha256": strings.ToUpper(p.SHA256), "sig": p.Sig, "version": p.Version, "feed_version": "1"}); err != nil || got.SHA256 != p.SHA256 || got.FeedVersion != "1" {
		t.Fatalf("payload: %v %+v", err, got)
	}
}

func TestDaemonUpdateSwapConfirmRollback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake binary is a shell script")
	}
	cp := newCPFake(t)
	key := newSigner(t)
	m := newManager(t, cp, key, "", nil)
	bin := t.TempDir()
	exe := filepath.Join(bin, "applianced")
	_ = os.WriteFile(exe, []byte("#!/bin/sh\necho 1.2.0\n"), 0o755)
	m.ExePath = exe
	artifact := []byte("#!/bin/sh\necho 1.3.0\n")
	sig, _ := bundle.Sign(artifact, key.key)
	cp.mu.Lock()
	cp.releases["applianced-linux-amd64/1.3.0"] = artifact
	cp.mu.Unlock()
	p := Payload{URL: "/v1/releases/applianced-linux-amd64/1.3.0", SHA256: bundle.SHA256Hex(artifact), Sig: sig, Version: "1.3.0"}

	// A binary that reports the wrong version is not installed.
	wrong := Payload{URL: p.URL, SHA256: p.SHA256, Sig: p.Sig, Version: "1.4.0"}
	if err := m.ApplyDaemon(t.Context(), wrong); err == nil || !strings.Contains(err.Error(), "reports version") {
		t.Fatalf("wrong version accepted: %v", err)
	}
	if read(t, exe) != "#!/bin/sh\necho 1.2.0\n" {
		t.Fatal("binary touched by a refused update")
	}
	m.Container = true
	if err := m.ApplyDaemon(t.Context(), p); err != ErrNotApplicable {
		t.Fatalf("container: %v", err)
	}
	m.Container = false
	if err := m.ApplyDaemon(t.Context(), p); err != ErrRestartRequired {
		t.Fatalf("apply: %v", err)
	}
	if read(t, exe) != string(artifact) || read(t, exe+".prev") != "#!/bin/sh\necho 1.2.0\n" {
		t.Fatal("swap did not happen")
	}
	pend, err := m.LoadPending()
	if err != nil || pend == nil || pend.Version != "1.3.0" || pend.PrevVersion != "1.2.0" || pend.Prev != exe+".prev" || pend.Exe != exe || pend.Starts != 0 {
		t.Fatalf("pending: %v %+v", err, pend)
	}
	// The old binary running again (guard rolled back) reports it.
	old := *m
	old.Version = "1.2.0"
	if await, report := old.Startup(); await || !strings.HasPrefix(report, "daemon 1.3.0: not running after update") {
		t.Fatalf("old binary startup: %v %q", await, report)
	}
	// Re-stage and walk the happy path: new binary starts, confirms.
	_ = os.WriteFile(exe, []byte("#!/bin/sh\necho 1.2.0\n"), 0o755)
	if err := m.ApplyDaemon(t.Context(), p); err != ErrRestartRequired {
		t.Fatalf("re-apply: %v", err)
	}
	nu := *m
	nu.Version = "1.3.0"
	if await, report := nu.Startup(); !await || report != "" {
		t.Fatalf("new binary startup: %v %q", await, report)
	}
	if err := nu.Confirm(); err != nil {
		t.Fatal(err)
	}
	if pend, _ := nu.LoadPending(); pend != nil {
		t.Fatal("pending not cleared after confirm")
	}
	// Rollback path: no heartbeat in time.
	_ = os.WriteFile(exe, []byte("#!/bin/sh\necho 1.2.0\n"), 0o755)
	if err := m.ApplyDaemon(t.Context(), p); err != ErrRestartRequired {
		t.Fatalf("re-apply: %v", err)
	}
	if err := nu.Rollback("no heartbeat within 10m0s"); err != ErrRestartRequired {
		t.Fatalf("rollback: %v", err)
	}
	if read(t, exe) != "#!/bin/sh\necho 1.2.0\n" {
		t.Fatal("rollback did not restore the previous binary")
	}
	if await, report := old.Startup(); await || !strings.Contains(report, "no heartbeat within") {
		t.Fatalf("startup after rollback: %v %q", await, report)
	}
	if pend, _ := old.LoadPending(); pend != nil {
		t.Fatal("pending not cleared after report")
	}
	// The record is shell-sourceable with awkward values.
	_ = m.savePending(&Pending{Version: "1.3.0", Prev: "/x/it's.prev", Exe: exe, Reason: "a 'quoted' reason"})
	pend, _ = m.LoadPending()
	if pend.Prev != "/x/it's.prev" || pend.Reason != "a 'quoted' reason" {
		t.Fatalf("quoting round-trip: %+v", pend)
	}
}
