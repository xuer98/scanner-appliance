package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/bundle"
)

type applianceCreds struct {
	id   string
	cert tls.Certificate
}

func (h *harness) heartbeatAs(t *testing.T, c applianceCreds, hb v1.Heartbeat) *v1.HeartbeatResponse {
	t.Helper()
	body, _ := json.Marshal(hb)
	resp, err := h.client(&c.cert).Post(h.mtls.URL+"/v1/appliances/"+c.id+"/heartbeat", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("heartbeat %s: %d %s", c.id, resp.StatusCode, b)
	}
	var out v1.HeartbeatResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return &out
}

func (h *harness) rawAdmin(t *testing.T, method, path string, body []byte, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, h.mtls.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+h.adminTok)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func (h *harness) getAs(t *testing.T, c applianceCreds, path string) (int, []byte, http.Header) {
	t.Helper()
	resp, err := h.client(&c.cert).Get(h.mtls.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func directivesOf(t *testing.T, h *harness, id, typ, version string) []v1.AdminDirectiveView {
	t.Helper()
	var list []v1.AdminDirectiveView
	if st := h.admin("GET", "/admin/appliances/"+id+"/directives", nil, &list); st != 200 {
		t.Fatalf("list directives: %d", st)
	}
	var out []v1.AdminDirectiveView
	for _, d := range list {
		if d.Type == typ && (version == "" || d.Payload[v1.PayloadVersion] == version) {
			out = append(out, d)
		}
	}
	return out
}

// publishBundle builds a bundle from files, uploads the missing blobs and
// publishes the signed manifest; returns the manifest bytes and signature.
func (h *harness) publishBundle(t *testing.T, files map[string]string, version string, key interface{ Sign([]byte) string }) (*bundle.Manifest, []byte, string, int, []byte) {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(c), 0o644)
	}
	m, err := bundle.Build(root, version, h.now)
	if err != nil {
		t.Fatal(err)
	}
	var shas []string
	for _, f := range m.Files {
		shas = append(shas, f.SHA256)
	}
	var missing v1.AdminMissingFilesResponse
	if st := h.admin("POST", "/admin/bundles/missing", v1.AdminMissingFilesRequest{SHA256: shas}, &missing); st != 200 {
		t.Fatalf("missing: %d", st)
	}
	for _, f := range m.Files {
		want := false
		for _, s := range missing.Missing {
			if s == f.SHA256 {
				want = true
			}
		}
		if !want {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.Path)))
		if st, body, _ := h.rawAdmin(t, "PUT", "/admin/bundles/files/"+f.SHA256, b, nil); st != 201 {
			t.Fatalf("put file %s: %d %s", f.Path, st, body)
		}
	}
	mb, _ := bundle.EncodeManifest(m)
	sig := key.Sign(mb)
	req, _ := json.Marshal(v1.AdminPublishBundleRequest{Manifest: mb, Sig: sig})
	st, body, _ := h.rawAdmin(t, "POST", "/admin/bundles", req, map[string]string{"Content-Type": "application/json"})
	return m, mb, sig, st, body
}

// A manifest of the real feed lists about 95,000 files and weighs about
// 14 MB. Publishing must not be bound by the 1 MiB limit of ordinary admin
// requests, and a body that is over a limit must say so.
func TestPublishFeedSizedManifest(t *testing.T) {
	h := newHarness(t)
	key, _ := bundle.GenerateKey()
	h.srv.cfg.ReleaseKeys = append(h.srv.cfg.ReleaseKeys, &key.PublicKey)
	h.srv.cfg.Objects = DirObjects{Root: t.TempDir()}

	blob := []byte("script_oid(\"1.3.6.1.4.1.25623.1.0.1\");")
	sha := bundle.SHA256Hex(blob)
	if st, body, _ := h.rawAdmin(t, "PUT", "/admin/bundles/files/"+sha, blob, nil); st != 201 {
		t.Fatalf("put file: %d %s", st, body)
	}
	m := &bundle.Manifest{Version: "20261006T000000Z", CreatedAt: h.now.UTC().Truncate(time.Second)}
	for i := 0; i < 20000; i++ {
		m.Files = append(m.Files, bundle.File{Path: fmt.Sprintf("nasl/2025/gb_some_product_detect_%05d.nasl", i), SHA256: sha, Size: int64(len(blob))})
	}
	mb, err := bundle.EncodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(mb) <= maxJSONBody {
		t.Fatalf("manifest is only %d bytes: the test would not cross the default limit", len(mb))
	}
	sig, _ := bundle.Sign(mb, key)
	req, _ := json.Marshal(v1.AdminPublishBundleRequest{Manifest: mb, Sig: sig})
	st, body, _ := h.rawAdmin(t, "POST", "/admin/bundles", req, map[string]string{"Content-Type": "application/json"})
	if st != 201 {
		t.Fatalf("publish of a %d byte manifest: %d %s", len(mb), st, body)
	}
	var bv v1.AdminBundleView
	_ = json.Unmarshal(body, &bv)
	if bv.Files != 20000 || bv.SHA256 != bundle.SHA256Hex(mb) {
		t.Fatalf("bundle view: %+v", bv)
	}

	// Ordinary admin requests keep the small limit and name it.
	shas := make([]string, 20000)
	for i := range shas {
		shas[i] = sha
	}
	big, _ := json.Marshal(v1.AdminMissingFilesRequest{SHA256: shas})
	if len(big) <= maxJSONBody {
		t.Fatalf("request is only %d bytes", len(big))
	}
	if st, body, _ := h.rawAdmin(t, "POST", "/admin/bundles/missing", big, nil); st != 400 || !strings.Contains(string(body), "larger than") {
		t.Fatalf("oversized request: %d %s", st, body)
	}
}

// The documented cadence is one bundle a day with a 48-hour canary period.
// The newest bundle is then always still in canary, so the fleet has to be
// given the newest bundle that has left it. And a bundle has to leave
// canary on the confirmation it got while the canaries ran it: by the end
// of its period they have moved on to newer bundles.
func TestBundleRolloutDailyCadence(t *testing.T) {
	h := newHarness(t)
	key, _ := bundle.GenerateKey()
	h.srv.cfg.ReleaseKeys = append(h.srv.cfg.ReleaseKeys, &key.PublicKey)
	h.srv.cfg.Objects = DirObjects{Root: t.TempDir()}
	h.srv.cfg.CanaryPeriod = 48 * time.Hour
	sign := signFn(func(b []byte) string { s, _ := bundle.Sign(b, key); return s })

	h.enrolled(t)
	a := applianceCreds{id: h.applID, cert: h.applCert} // the lab appliance
	var created v1.AdminCreateApplianceResponse
	if st := h.admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme 3PL", Site: "Reno DC"}, &created); st != 201 {
		t.Fatalf("create B: %d", st)
	}
	if _, st := h.doEnroll(created.Code); st != 200 {
		t.Fatalf("enroll B: %d", st)
	}
	b := applianceCreds{id: h.applID, cert: h.applCert} // a vendor's appliance
	canary := true
	if st := h.admin("PATCH", "/admin/appliances/"+a.id, v1.AdminApplianceUpdate{Canary: &canary}, nil); st != 200 {
		t.Fatalf("set canary: %d", st)
	}

	// beat reports what the appliance runs and installs any bundle it is
	// offered; it returns the offered version.
	installed := map[string]string{}
	beat := func(c applianceCreds) string {
		t.Helper()
		hb := v1.Heartbeat{Version: "1.2.0", OS: "linux", Arch: "amd64", State: "idle", BundleVersion: installed[c.id],
			Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}}
		offered := ""
		for _, d := range h.heartbeatAs(t, c, hb).Directives {
			if d.Type == v1.DirectiveUpdateBundle {
				offered, _ = d.Payload[v1.PayloadVersion].(string)
				hb.AckedDirectiveIDs = append(hb.AckedDirectiveIDs, d.ID)
			}
		}
		if offered != "" {
			installed[c.id] = offered
			hb.BundleVersion = offered
			h.heartbeatAs(t, c, hb)
		}
		return offered
	}
	tick := func() {
		t.Helper()
		if err := h.srv.RolloutTick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	day := func(n int) string { return fmt.Sprintf("2026100%dT060000Z", n) }

	var fleetGot []string
	for d := 1; d <= 6; d++ {
		files := map[string]string{"nasl/plugin_feed_info.inc": fmt.Sprintf("PLUGIN_SET = \"2026100%d0600\";\n", d), "nasl/a.nasl": fmt.Sprintf("day %d", d)}
		if _, _, _, st, body := h.publishBundle(t, files, day(d), sign); st != 201 {
			t.Fatalf("publish day %d: %d %s", d, st, body)
		}
		if got := beat(a); got != day(d) {
			t.Fatalf("day %d: the canary was offered %q", d, got)
		}
		if got := beat(b); got != "" {
			t.Fatalf("day %d: the fleet was offered %s at the moment day %d was published", d, got, d)
		}
		h.now = h.now.Add(24 * time.Hour)
		tick()
		if got := beat(a); got != "" {
			t.Fatalf("day %d: the canary runs the newest bundle and was offered %s", d, got)
		}
		if got := beat(b); got != "" {
			fleetGot = append(fleetGot, got)
		}
	}
	// Six days in, the bundles of days 1 to 5 are past their 48 hours and
	// each reached the fleet in turn.
	want := []string{day(1), day(2), day(3), day(4), day(5)}
	if strings.Join(fleetGot, ",") != strings.Join(want, ",") {
		t.Fatalf("the fleet received %v, want %v", fleetGot, want)
	}

	// Holding the newest bundle must not push the appliances that run it
	// back to an older one: the engine only ever loads a newer feed, so the
	// downgrade would fail after the reload timeout on every one of them.
	if st := h.admin("POST", "/admin/bundles/"+day(6)+"/rollout", v1.AdminRolloutRequest{Status: v1.RolloutHeld, Reason: "test"}, nil); st != 200 {
		t.Fatalf("hold: %d", st)
	}
	tick()
	if got := beat(a); got != "" {
		t.Fatalf("after the hold the canary, which runs %s, was offered the older %s", day(6), got)
	}
}

func TestBundleRolloutCanaryToRelease(t *testing.T) {
	h := newHarness(t)
	key, _ := bundle.GenerateKey()
	h.srv.cfg.ReleaseKeys = append(h.srv.cfg.ReleaseKeys, &key.PublicKey)
	h.srv.cfg.Objects = DirObjects{Root: t.TempDir()}
	h.srv.cfg.CanaryPeriod = 48 * time.Hour
	sign := signFn(func(b []byte) string { s, _ := bundle.Sign(b, key); return s })

	// Two enrolled appliances: A becomes the canary, B is the fleet.
	h.enrolled(t)
	a := applianceCreds{id: h.applID, cert: h.applCert}
	var created v1.AdminCreateApplianceResponse
	if st := h.admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme 3PL", Site: "Reno DC"}, &created); st != 201 {
		t.Fatalf("create B: %d", st)
	}
	if _, st := h.doEnroll(created.Code); st != 200 {
		t.Fatalf("enroll B: %d", st)
	}
	b := applianceCreds{id: h.applID, cert: h.applCert}
	linux := v1.Heartbeat{Version: "1.2.0", OS: "linux", Arch: "amd64", State: "idle", Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true, FeedVersion: "202609010000"}}
	h.heartbeatAs(t, a, linux)
	h.heartbeatAs(t, b, linux)

	canary := true
	var av v1.AdminApplianceView
	if st := h.admin("PATCH", "/admin/appliances/"+a.id, v1.AdminApplianceUpdate{Canary: &canary}, &av); st != 200 || !av.Canary {
		t.Fatalf("set canary: %d %+v", st, av)
	}

	files := map[string]string{
		"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n",
		"nasl/a.nasl":               "script_oid(\"1.3.6.1.4.1.25623.1.0.1\");",
		"configs/inventory.json":    `{"name":"inventory","families":["Web Servers"],"udp_ports":[161],"params":{}}`,
	}
	// Bad signature is refused before anything is stored.
	other, _ := bundle.GenerateKey()
	if _, _, _, st, body := h.publishBundle(t, files, "20260926T000000Z", signFn(func(b []byte) string { s, _ := bundle.Sign(b, other); return s })); st != 400 || !strings.Contains(string(body), "signature") {
		t.Fatalf("bad signature accepted: %d %s", st, body)
	}
	m, mb, sig, st, body := h.publishBundle(t, files, "20260926T000000Z", sign)
	if st != 201 {
		t.Fatalf("publish: %d %s", st, body)
	}
	var bv v1.AdminBundleView
	_ = json.Unmarshal(body, &bv)
	if bv.Status != v1.RolloutCanary || bv.FeedVersion != "202609260530" || bv.Files != 3 || bv.Fleet != 2 || bv.Installed != 0 || bv.CanaryUntil == nil {
		t.Fatalf("bundle view: %+v", bv)
	}
	if _, _, _, st, _ := h.publishBundle(t, files, "20260926T000000Z", sign); st != 409 {
		t.Fatalf("duplicate publish: %d", st)
	}
	// A manifest referencing an un-uploaded file is refused.
	m2 := *m
	m2.Version = "20260927T000000Z"
	m2.Files = append(append([]bundle.File{}, m.Files...), bundle.File{Path: "nasl/ghost.nasl", SHA256: strings.Repeat("ab", 32), Size: 1})
	mb2, _ := bundle.EncodeManifest(&m2)
	req, _ := json.Marshal(v1.AdminPublishBundleRequest{Manifest: mb2, Sig: sign.Sign(mb2)})
	if st, body, _ := h.rawAdmin(t, "POST", "/admin/bundles", req, nil); st != 409 || !strings.Contains(string(body), "files_missing") {
		t.Fatalf("ghost file accepted: %d %s", st, body)
	}

	// Canary: only A gets the directive.
	resp := h.heartbeatAs(t, a, linux)
	var upd *v1.Directive
	for i := range resp.Directives {
		if resp.Directives[i].Type == v1.DirectiveUpdateBundle {
			upd = &resp.Directives[i]
		}
	}
	if upd == nil || upd.Payload[v1.PayloadVersion] != m.Version || upd.Payload[v1.PayloadSHA256] != bundle.SHA256Hex(mb) || upd.Payload[v1.PayloadSig] != sig || upd.Payload[v1.PayloadFeedVersion] != "202609260530" {
		t.Fatalf("canary directive: %+v", resp.Directives)
	}
	if len(directivesOf(t, h, b.id, v1.DirectiveUpdateBundle, "")) != 0 {
		t.Fatal("fleet appliance got the canary bundle")
	}
	// Not re-queued while pending.
	if err := h.srv.RolloutTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(directivesOf(t, h, a.id, v1.DirectiveUpdateBundle, m.Version)); n != 1 {
		t.Fatalf("directive re-queued while pending: %d", n)
	}

	// A fetches the manifest and a file over mTLS.
	st, got, hdr := h.getAs(t, a, upd.Payload[v1.PayloadURL].(string))
	if st != 200 || !bytes.Equal(got, mb) || hdr.Get(HeaderBundleSig) != sig || hdr.Get(HeaderBundleSHA256) != bundle.SHA256Hex(mb) {
		t.Fatalf("manifest fetch: %d %s", st, hdr)
	}
	for _, f := range m.Files {
		st, got, _ := h.getAs(t, a, "/v1/bundles/"+m.Version+"/files/"+f.SHA256)
		if st != 200 || bundle.SHA256Hex(got) != f.SHA256 {
			t.Fatalf("file fetch %s: %d", f.Path, st)
		}
	}
	if st, _, _ := h.getAs(t, a, "/v1/bundles/"+m.Version+"/files/"+strings.Repeat("00", 32)); st != 404 {
		t.Fatalf("missing file: %d", st)
	}
	if st, _, _ := h.getAs(t, a, "/v1/bundles/nope/manifest"); st != 404 {
		t.Fatalf("missing bundle: %d", st)
	}

	// A acks and reports the bundle; the period passes; B gets it.
	ack := linux
	ack.AckedDirectiveIDs = []string{upd.ID}
	ack.BundleVersion = m.Version
	ack.FeedVersion = "202609260530"
	h.heartbeatAs(t, a, ack)
	if err := h.srv.RolloutTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if bvs := listBundles(t, h); bvs[0].Status != v1.RolloutCanary || bvs[0].Installed != 1 {
		t.Fatalf("still canary before period: %+v", bvs[0])
	}
	h.now = h.now.Add(49 * time.Hour)
	if err := h.srv.RolloutTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if bvs := listBundles(t, h); bvs[0].Status != v1.RolloutReleased {
		t.Fatalf("not released after canary period: %+v", bvs[0])
	}
	resp = h.heartbeatAs(t, b, linux)
	if len(resp.Directives) != 1 || resp.Directives[0].Type != v1.DirectiveUpdateBundle || resp.Directives[0].Payload[v1.PayloadVersion] != m.Version {
		t.Fatalf("fleet directive after release: %+v", resp.Directives)
	}

	// Second bundle: the canary fails → held, the fleet never sees it.
	files["nasl/plugin_feed_info.inc"] = "PLUGIN_SET = \"202609270530\";\n"
	files["nasl/b.nasl"] = "new"
	m3, _, _, st, body := h.publishBundle(t, files, "20260927T000000Z", sign)
	if st != 201 {
		t.Fatalf("publish v2: %d %s", st, body)
	}
	resp = h.heartbeatAs(t, a, ack)
	if len(directivesOf(t, h, a.id, v1.DirectiveUpdateBundle, m3.Version)) != 1 {
		t.Fatalf("canary did not get v2: %+v", resp.Directives)
	}
	fail := ack
	fail.AckedDirectiveIDs = []string{resp.Directives[0].ID}
	fail.UpdateError = "bundle " + m3.Version + ": ospd did not load feed 202609270530 within 30m"
	h.heartbeatAs(t, a, fail)
	bvs := listBundles(t, h)
	if bvs[0].Version != m3.Version || bvs[0].Status != v1.RolloutHeld || !strings.Contains(bvs[0].HeldReason, a.id) {
		t.Fatalf("v2 not held: %+v", bvs[0])
	}
	h.now = h.now.Add(49 * time.Hour)
	if err := h.srv.RolloutTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(directivesOf(t, h, b.id, v1.DirectiveUpdateBundle, m3.Version)) != 0 {
		t.Fatal("held bundle reached the fleet")
	}
	// The failed canary is not re-queued for v2 either.
	if n := len(directivesOf(t, h, a.id, v1.DirectiveUpdateBundle, m3.Version)); n != 1 {
		t.Fatalf("failed canary re-queued: %d", n)
	}
	// An operator can release it explicitly.
	var rv v1.AdminBundleView
	if st := h.admin("POST", "/admin/bundles/"+m3.Version+"/rollout", v1.AdminRolloutRequest{Status: v1.RolloutReleased, Reason: "lab verified"}, &rv); st != 200 || rv.Status != v1.RolloutReleased {
		t.Fatalf("manual release: %d %+v", st, rv)
	}
	if len(directivesOf(t, h, b.id, v1.DirectiveUpdateBundle, m3.Version)) != 1 {
		t.Fatal("manual release did not reach the fleet")
	}
}

func listBundles(t *testing.T, h *harness) []v1.AdminBundleView {
	t.Helper()
	var out []v1.AdminBundleView
	if st := h.admin("GET", "/admin/bundles", nil, &out); st != 200 {
		t.Fatalf("list bundles: %d", st)
	}
	return out
}

type signFn func([]byte) string

func (f signFn) Sign(b []byte) string { return f(b) }

func TestReleaseRolloutAndApt(t *testing.T) {
	h := newHarness(t)
	key, _ := bundle.GenerateKey()
	h.srv.cfg.ReleaseKeys = append(h.srv.cfg.ReleaseKeys, &key.PublicKey)
	h.srv.cfg.Objects = DirObjects{Root: t.TempDir()}
	apt := t.TempDir()
	_ = os.MkdirAll(filepath.Join(apt, "dists", "bookworm-security"), 0o755)
	_ = os.WriteFile(filepath.Join(apt, "dists", "bookworm-security", "Release"), []byte("Origin: Debian\n"), 0o644)
	h.srv.cfg.AptDir = apt

	h.enrolled(t)
	a := applianceCreds{id: h.applID, cert: h.applCert}
	canary := true
	if st := h.admin("PATCH", "/admin/appliances/"+a.id, v1.AdminApplianceUpdate{Canary: &canary}, nil); st != 200 {
		t.Fatalf("set canary: %d", st)
	}
	h.heartbeatAs(t, a, v1.Heartbeat{Version: "1.2.0", OS: "linux", Arch: "amd64"})

	artifact := bytes.Repeat([]byte("applianced-binary-"), 1000)
	sha := bundle.SHA256Hex(artifact)
	sig, _ := bundle.Sign(artifact, key)
	hdr := map[string]string{v1.HeaderReleaseSHA256: sha, v1.HeaderReleaseSig: sig, v1.HeaderCanaryHours: "1"}
	if st, body, _ := h.rawAdmin(t, "PUT", "/admin/releases/applianced-linux-amd64/1.3.0", artifact, map[string]string{v1.HeaderReleaseSHA256: strings.Repeat("0", 64), v1.HeaderReleaseSig: sig}); st != 400 {
		t.Fatalf("wrong digest accepted: %d %s", st, body)
	}
	st, body, _ := h.rawAdmin(t, "PUT", "/admin/releases/applianced-linux-amd64/1.3.0", artifact, hdr)
	if st != 201 {
		t.Fatalf("publish release: %d %s", st, body)
	}
	var rv v1.AdminReleaseView
	_ = json.Unmarshal(body, &rv)
	if rv.Status != v1.RolloutCanary || rv.Bytes != int64(len(artifact)) || rv.Fleet != 1 {
		t.Fatalf("release view: %+v", rv)
	}
	resp := h.heartbeatAs(t, a, v1.Heartbeat{Version: "1.2.0", OS: "linux", Arch: "amd64"})
	if len(resp.Directives) != 1 || resp.Directives[0].Type != v1.DirectiveUpdateDaemon || resp.Directives[0].Payload[v1.PayloadVersion] != "1.3.0" {
		t.Fatalf("update_daemon directive: %+v", resp.Directives)
	}
	st, got, rh := h.getAs(t, a, resp.Directives[0].Payload[v1.PayloadURL].(string))
	if st != 200 || !bytes.Equal(got, artifact) || rh.Get(HeaderReleaseSigV1) != sig || rh.Get(v1.HeaderReleaseSHA256) != sha {
		t.Fatalf("release fetch: %d", st)
	}
	// An arm64 appliance never sees the amd64 release.
	var created v1.AdminCreateApplianceResponse
	h.admin("POST", "/admin/appliances", v1.AdminCreateApplianceRequest{Vendor: "Acme 3PL", Site: "Reno DC"}, &created)
	h.doEnroll(created.Code)
	arm := applianceCreds{id: h.applID, cert: h.applCert}
	h.heartbeatAs(t, arm, v1.Heartbeat{Version: "1.2.0", OS: "linux", Arch: "arm64"})
	h.now = h.now.Add(2 * time.Hour)
	if err := h.srv.RolloutTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(directivesOf(t, h, arm.id, v1.DirectiveUpdateDaemon, "")) != 0 {
		t.Fatal("arm64 appliance got the amd64 release")
	}
	var rels []v1.AdminReleaseView
	h.admin("GET", "/admin/releases", nil, &rels)
	if len(rels) != 1 || rels[0].Status != v1.RolloutCanary { // canary never confirmed 1.3.0
		t.Fatalf("releases: %+v", rels)
	}
	h.heartbeatAs(t, a, v1.Heartbeat{Version: "1.3.0", OS: "linux", Arch: "amd64"})
	if err := h.srv.RolloutTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.admin("GET", "/admin/releases", nil, &rels)
	if rels[0].Status != v1.RolloutReleased || rels[0].Installed != 1 {
		t.Fatalf("release after canary confirmed: %+v", rels[0])
	}

	// apt mirror over mTLS: files only, no traversal, no listings.
	if st, got, _ := h.getAs(t, a, "/apt/dists/bookworm-security/Release"); st != 200 || string(got) != "Origin: Debian\n" {
		t.Fatalf("apt file: %d %q", st, got)
	}
	for _, p := range []string{"/apt/dists/bookworm-security/", "/apt/nope"} {
		if st, _, _ := h.getAs(t, a, p); st != 404 {
			t.Fatalf("%s: %d", p, st)
		}
	}
	// A traversal attempt is redirected to the clean path by the mux (301)
	// or refused; it must never be served as-is.
	cl := h.client(&a.cert)
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if resp, err := cl.Get(h.mtls.URL + "/apt/dists/../dists/bookworm-security/Release"); err != nil || resp.StatusCode == 200 {
		t.Fatalf("traversal: %v", err)
	}
	// Without a client certificate nothing is served.
	resp2, err := h.client(nil).Get(h.mtls.URL + "/apt/dists/bookworm-security/Release")
	if err == nil && resp2.StatusCode == 200 {
		t.Fatal("apt served without mTLS")
	}
}
