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
	"strconv"
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

// ospd starts loading the feed the moment the version file names a newer
// version. In the lab it did so while the daemon was still placing files,
// so the version file has to be the last one to change.
func TestBundleVersionFileGoesLast(t *testing.T) {
	cp := newCPFake(t)
	key := newSigner(t)
	plugins := t.TempDir()
	old := "PLUGIN_SET = \"202609010000\";\n"
	_ = os.WriteFile(filepath.Join(plugins, "plugin_feed_info.inc"), []byte(old), 0o644)
	_ = os.WriteFile(filepath.Join(plugins, "dropped.nasl"), []byte("dropped"), 0o644)
	m := newManager(t, cp, key, plugins, nil)
	m.init()
	seed, err := m.adoptSeed()
	if err != nil {
		t.Fatal(err)
	}
	// One file sorts before the version file and one after it.
	cp.publish(t, key, map[string]string{
		"nasl/a_first.nasl":         "first",
		"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n",
		"nasl/zz_late/late.nasl":    "late",
	}, "20260926T000000Z")
	next, err := bundle.DecodeManifest(cp.manifests["20260926T000000Z"])
	if err != nil {
		t.Fatal(err)
	}
	fetch, remove := bundle.Diff(seed, next)
	for _, f := range fetch {
		if err := m.ensureCAS(t.Context(), "/v1/bundles/20260926T000000Z", f); err != nil {
			t.Fatal(err)
		}
	}
	// The late file cannot be placed: a regular file sits where its
	// directory belongs. Whatever was placed before the failure shows the
	// order.
	blocker := filepath.Join(plugins, "zz_late")
	_ = os.WriteFile(blocker, []byte("in the way"), 0o644)
	if err := m.place(next, fetch, remove); err == nil {
		t.Fatal("placing over a blocked path succeeded")
	}
	if read(t, filepath.Join(plugins, "a_first.nasl")) != "first" {
		t.Fatal("the file before the version file was not placed")
	}
	if got := read(t, filepath.Join(plugins, "plugin_feed_info.inc")); got != old {
		t.Fatalf("the version file changed before every feed file was in place: %q", got)
	}

	// With the path clear everything lands, dropped files go, and only then
	// does the version change.
	_ = os.Remove(blocker)
	if err := m.place(next, fetch, remove); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(plugins, "zz_late", "late.nasl")) != "late" || read(t, filepath.Join(plugins, "dropped.nasl")) != "<missing>" {
		t.Fatal("feed files not in their final state")
	}
	if got := read(t, filepath.Join(plugins, "plugin_feed_info.inc")); !strings.Contains(got, "202609260530") {
		t.Fatalf("version file not updated: %q", got)
	}
}

// The engine only loads a feed newer than the one it has. In the lab a
// bundle with an older feed kept the appliance in "updating", unable to
// scan, for the whole reload timeout before it was rolled back. It is
// refused at once, with nothing on disk touched.
func TestBundleRefusesOlderFeed(t *testing.T) {
	cp := newCPFake(t)
	key := newSigner(t)
	plugins := t.TempDir()
	_ = os.WriteFile(filepath.Join(plugins, "plugin_feed_info.inc"), []byte("PLUGIN_SET = \"202609260530\";\n"), 0o644)
	_ = os.WriteFile(filepath.Join(plugins, "keep.nasl"), []byte("keep"), 0o644)
	fake := osptest.Start(t, &osptest.Fake{PluginsDir: plugins})
	m := newManager(t, cp, key, plugins, fake)

	older := cp.publish(t, key, map[string]string{"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609010000\";\n", "nasl/old.nasl": "old"}, "20260901T000000Z")
	_, err := m.ApplyBundle(t.Context(), older)
	if err == nil || !strings.Contains(err.Error(), "bundle 20260901T000000Z: carries feed 202609010000, older than the installed feed 202609260530") {
		t.Fatalf("older feed: %v", err)
	}
	// Refused before any file was fetched, so before anything was placed and
	// before any wait for a reload. (A bound in wall time said the same less
	// reliably: on a busy Windows runner a few file operations take seconds.)
	if cp.reqs() != 0 {
		t.Fatalf("%d files fetched for a bundle that cannot be applied", cp.reqs())
	}
	if read(t, filepath.Join(plugins, "old.nasl")) != "<missing>" || read(t, filepath.Join(plugins, "keep.nasl")) != "keep" ||
		!strings.Contains(read(t, filepath.Join(plugins, "plugin_feed_info.inc")), "202609260530") {
		t.Fatal("the plugins directory changed")
	}
	if inst := mustInstalled(t, m); inst.Version != "seed-202609260530" {
		t.Fatalf("installed: %s", inst.Version)
	}

	// The same feed version (only configs or templates changed) and a newer
	// one still apply.
	same := cp.publish(t, key, map[string]string{"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n", "nasl/keep.nasl": "keep", "configs/full.json": `{"name":"full","families":["Web Servers"],"params":{}}`}, "20260926T000000Z")
	if _, err := m.ApplyBundle(t.Context(), same); err != nil {
		t.Fatalf("same feed version: %v", err)
	}
	newer := cp.publish(t, key, map[string]string{"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609270530\";\n", "nasl/keep.nasl": "keep"}, "20260927T000000Z")
	if _, err := m.ApplyBundle(t.Context(), newer); err != nil {
		t.Fatalf("newer feed: %v", err)
	}
	for _, c := range []struct {
		a, b string
		want bool
	}{{"202609010000", "202609260530", true}, {"202609260530", "202609260530", false}, {"202609270530", "202609260530", false}, {"", "202609260530", false}, {"202609010000", "", false}, {"abc", "202609260530", false}} {
		if got := feedOlder(c.a, c.b); got != c.want {
			t.Fatalf("feedOlder(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

// A rollback has to stay quick at the size of the real feed. It used to
// rebuild the manifest index for every file, which is quadratic: with
// 105,000 files the lab's rollback took over six minutes.
func TestRollbackScalesWithTheFeed(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Creating and removing 12,000 files keeps a Windows runner's file
		// system busy for tens of seconds, in which tests of other packages
		// stall. What is checked here is restore's own work, which does not
		// depend on the platform.
		t.Skip("file-system heavy; the check is the same on every platform")
	}
	const files = 12000
	plugins := t.TempDir()
	m := newManager(t, newCPFake(t), newSigner(t), plugins, nil)
	m.init()
	body := []byte("script")
	sha := bundle.SHA256Hex(body)
	if err := os.MkdirAll(m.casDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.casPath(sha), body, 0o644); err != nil {
		t.Fatal(err)
	}
	prev, next := &bundle.Manifest{Version: "prev"}, &bundle.Manifest{Version: "next"}
	for i := 0; i < files; i++ {
		name := "gb_test_" + strconv.Itoa(i) + ".nasl"
		if err := os.WriteFile(filepath.Join(plugins, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
		f := bundle.File{Path: "nasl/" + name, SHA256: sha, Size: int64(len(body))}
		prev.Files = append(prev.Files, f)
		next.Files = append(next.Files, f)
	}
	// next added one file that the rollback has to take away again.
	_ = os.WriteFile(filepath.Join(plugins, "zz_new.nasl"), body, 0o644)
	next.Files = append(next.Files, bundle.File{Path: "nasl/zz_new.nasl", SHA256: sha, Size: int64(len(body))})

	// What the file system alone costs: restore looks at every file once.
	start := time.Now()
	for _, f := range prev.Files {
		if _, err := os.Stat(m.Target(f.Path)); err != nil {
			t.Fatal(err)
		}
	}
	look := time.Since(start)

	start = time.Now()
	if err := m.restore(prev, next); err != nil {
		t.Fatal(err)
	}
	d := time.Since(start)
	t.Logf("restore of %d unchanged files: %s (looking at each once: %s)", files, d, look)
	// The bound is for the work restore adds, which was seconds when it
	// rebuilt the index per file. Where looking at the files is itself
	// slow, as on a Windows CI runner, a bound in wall time says nothing.
	if look > 250*time.Millisecond {
		t.Logf("slow file system: the time bound is not checked")
	} else if d > 1500*time.Millisecond {
		t.Fatalf("restoring %d unchanged files took %s", files, d)
	}
	if read(t, filepath.Join(plugins, "zz_new.nasl")) != "<missing>" || read(t, filepath.Join(plugins, "gb_test_0.nasl")) != "script" {
		t.Fatal("restore did not put the previous file set back")
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
