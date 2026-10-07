package server

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/bundle"
)

// The daily build makes a bundle every day. On a day without a new feed its
// files are the ones the newest bundle already has, and publishing it under
// a new name would make every appliance fetch the whole file list, 16 MB
// for the real feed, to find nothing to do.
func TestUnchangedBundleIsNotPublished(t *testing.T) {
	h := newHarness(t)
	key, _ := bundle.GenerateKey()
	h.srv.cfg.ReleaseKeys = append(h.srv.cfg.ReleaseKeys, &key.PublicKey)
	h.srv.cfg.Objects = DirObjects{Root: t.TempDir()}
	h.srv.cfg.CanaryPeriod = 48 * time.Hour
	sign := signFn(func(b []byte) string { s, _ := bundle.Sign(b, key); return s })
	h.enrolled(t)
	a := applianceCreds{id: h.applID, cert: h.applCert}
	canary := true
	if st := h.admin("PATCH", "/admin/appliances/"+a.id, v1.AdminApplianceUpdate{Canary: &canary}, nil); st != 200 {
		t.Fatalf("set canary: %d", st)
	}
	installed := ""
	// beat reports what the appliance runs and installs what it is offered.
	beat := func() string {
		t.Helper()
		hb := v1.Heartbeat{Version: "1.2.0", OS: "linux", Arch: "amd64", State: "idle", BundleVersion: installed, Engine: v1.EngineHealth{OSPDUp: true, VTCacheLoaded: true}}
		offered := ""
		for _, d := range h.heartbeatAs(t, a, hb).Directives {
			if d.Type == v1.DirectiveUpdateBundle {
				offered, _ = d.Payload[v1.PayloadVersion].(string)
				hb.AckedDirectiveIDs = append(hb.AckedDirectiveIDs, d.ID)
			}
		}
		if offered != "" {
			installed, hb.BundleVersion = offered, offered
			h.heartbeatAs(t, a, hb)
		}
		return offered
	}
	publish := func(version string, files map[string]string) (int, v1.AdminPublishBundleResponse) {
		t.Helper()
		_, _, _, st, body := h.publishBundle(t, files, version, sign)
		var out v1.AdminPublishBundleResponse
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("publish %s: %d %s", version, st, body)
		}
		h.now = h.now.Add(24 * time.Hour)
		return st, out
	}
	friday := map[string]string{"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202610020600\";\n", "nasl/a.nasl": "friday", "configs/inventory.json": `{"name":"inventory"}`}

	st, fri := publish("20261002T110000Z", friday)
	if st != 201 || fri.Unchanged || fri.Version != "20261002T110000Z" || len(fri.ContentSHA256) != 64 {
		t.Fatalf("first publish: %d %+v", st, fri)
	}
	if got := beat(); got != fri.Version {
		t.Fatalf("the canary was offered %q", got)
	}

	// Saturday: no new feed. Nothing is published and nothing is offered.
	st, sat := publish("20261003T110000Z", friday)
	if st != 200 || !sat.Unchanged || sat.Version != fri.Version || sat.ContentSHA256 != fri.ContentSHA256 {
		t.Fatalf("publish of the same files: %d %+v, want 200 and the bundle of Friday", st, sat)
	}
	if list := listBundles(t, h); len(list) != 1 || list[0].Version != fri.Version {
		t.Fatalf("bundles after an unchanged day: %+v", list)
	}
	if got := beat(); got != "" {
		t.Fatalf("the appliance was offered %s on a day without changes", got)
	}
	if n := len(directivesOf(t, h, a.id, v1.DirectiveUpdateBundle, "")); n != 1 {
		t.Fatalf("%d update directives, want the one of Friday", n)
	}

	// Sunday: the newest bundle is on hold. The same files under a new
	// name would be offered again to the canary that just failed on them.
	if st := h.admin("POST", "/admin/bundles/"+fri.Version+"/rollout", v1.AdminRolloutRequest{Status: v1.RolloutHeld, Reason: "canary failed"}, nil); st != 200 {
		t.Fatalf("hold: %d", st)
	}
	st, sun := publish("20261004T110000Z", friday)
	if st != 200 || !sun.Unchanged || sun.Version != fri.Version || sun.Status != v1.RolloutHeld || sun.HeldReason != "canary failed" {
		t.Fatalf("publish of the files of a held bundle: %d %+v", st, sun)
	}
	if list := listBundles(t, h); len(list) != 1 {
		t.Fatalf("a held bundle came back under a new name: %+v", list)
	}

	// Monday: one script changed. That is a new bundle.
	monday := map[string]string{"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202610050600\";\n", "nasl/a.nasl": "monday", "configs/inventory.json": `{"name":"inventory"}`}
	st, mon := publish("20261005T110000Z", monday)
	if st != 201 || mon.Unchanged || mon.Version != "20261005T110000Z" || mon.ContentSHA256 == fri.ContentSHA256 {
		t.Fatalf("publish of a changed feed: %d %+v", st, mon)
	}
	if got := beat(); got != mon.Version {
		t.Fatalf("the canary was offered %q, want the bundle of Monday", got)
	}
	// The comparison is with the newest bundle only: files that differ
	// from it are published even when an older bundle had the same ones.
	monday["configs/inventory.json"] = `{"name":"inventory","families":["Web Servers"]}`
	if st, tue := publish("20261006T110000Z", monday); st != 201 || tue.Unchanged {
		t.Fatalf("publish of a changed scan config: %d %+v", st, tue)
	}
	monday["configs/inventory.json"] = `{"name":"inventory"}`
	if st, wed := publish("20261007T110000Z", monday); st != 201 || wed.Unchanged || wed.ContentSHA256 != mon.ContentSHA256 {
		t.Fatalf("publish of files that differ from the newest bundle: %d %+v", st, wed)
	}
	if list := listBundles(t, h); len(list) != 4 {
		t.Fatalf("%d bundles, want 4", len(list))
	}
}

// Every appliance fetches the manifest whole for every bundle. It names
// each file of the feed and compresses to about a third, so the control
// plane serves the copy it compressed at publish time to a client that
// asks for it, which the appliance's HTTP client does on its own.
func TestManifestDownloadIsCompressed(t *testing.T) {
	h := newHarness(t)
	key, _ := bundle.GenerateKey()
	h.srv.cfg.ReleaseKeys = append(h.srv.cfg.ReleaseKeys, &key.PublicKey)
	objects := t.TempDir()
	h.srv.cfg.Objects = DirObjects{Root: objects}
	h.enrolled(t)

	blob := []byte("script_oid(\"1.3.6.1.4.1.25623.1.0.1\");")
	sha := bundle.SHA256Hex(blob)
	if st, body, _ := h.rawAdmin(t, "PUT", "/admin/bundles/files/"+sha, blob, nil); st != 201 {
		t.Fatalf("put file: %d %s", st, body)
	}
	m := &bundle.Manifest{Version: "20261007T110000Z", FeedVersion: "202610070608", CreatedAt: h.now.UTC().Truncate(time.Second)}
	for i := 0; i < 5000; i++ {
		m.Files = append(m.Files, bundle.File{Path: fmt.Sprintf("nasl/2026/gb_some_product_detect_%05d.nasl", i), SHA256: sha, Size: int64(len(blob))})
	}
	mb, _ := bundle.EncodeManifest(m)
	sig, _ := bundle.Sign(mb, key)
	req, _ := json.Marshal(v1.AdminPublishBundleRequest{Manifest: mb, Sig: sig})
	if st, body, _ := h.rawAdmin(t, "POST", "/admin/bundles", req, map[string]string{"Content-Type": "application/json"}); st != 201 {
		t.Fatalf("publish: %d %s", st, body)
	}

	// get asks with exactly this Accept-Encoding and returns the body as it
	// came over the wire.
	get := func(acceptEncoding string) (*http.Response, []byte) {
		t.Helper()
		cl := &http.Client{Transport: &http.Transport{DisableCompression: true,
			TLSClientConfig: &tls.Config{RootCAs: h.rootPool, Certificates: []tls.Certificate{h.applCert}}}}
		rq, _ := http.NewRequest("GET", h.mtls.URL+"/v1/bundles/"+m.Version+"/manifest", nil)
		if acceptEncoding != "" {
			rq.Header.Set("Accept-Encoding", acceptEncoding)
		}
		resp, err := cl.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("manifest with Accept-Encoding %q: %d %v", acceptEncoding, resp.StatusCode, err)
		}
		if resp.Header.Get(HeaderBundleSHA256) != bundle.SHA256Hex(mb) || resp.Header.Get(HeaderBundleSig) != sig {
			t.Fatalf("manifest headers with Accept-Encoding %q: %v", acceptEncoding, resp.Header)
		}
		if n, _ := strconv.Atoi(resp.Header.Get("Content-Length")); n != len(body) {
			t.Fatalf("Content-Length %s for a body of %d bytes", resp.Header.Get("Content-Length"), len(body))
		}
		return resp, body
	}
	for _, ae := range []string{"gzip", "br, gzip;q=0.8", "GZIP"} {
		resp, body := get(ae)
		if resp.Header.Get("Content-Encoding") != "gzip" || len(body) > len(mb)/2 {
			t.Fatalf("Accept-Encoding %q: Content-Encoding %q, %d bytes for a manifest of %d", ae, resp.Header.Get("Content-Encoding"), len(body), len(mb))
		}
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if plain, err := io.ReadAll(zr); err != nil || !bytes.Equal(plain, mb) {
			t.Fatalf("Accept-Encoding %q: the body does not unpack to the signed manifest: %v", ae, err)
		}
	}
	// A client that does not ask gets the signed bytes themselves.
	for _, ae := range []string{"", "identity", "gzip;q=0", "br"} {
		if resp, body := get(ae); resp.Header.Get("Content-Encoding") != "" || !bytes.Equal(body, mb) {
			t.Fatalf("Accept-Encoding %q: Content-Encoding %q, %d bytes", ae, resp.Header.Get("Content-Encoding"), len(body))
		}
	}
	// Go's client, which the appliance uses, asks and unpacks by itself.
	resp, err := h.client(&h.applCert).Get(h.mtls.URL + "/v1/bundles/" + m.Version + "/manifest")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !resp.Uncompressed || !bytes.Equal(body, mb) {
		t.Fatalf("default client: uncompressed=%v, %d bytes", resp.Uncompressed, len(body))
	}
	// A bundle published before the compressed copy existed goes out plain.
	if err := os.Remove(filepath.Join(objects, filepath.FromSlash(bundleManifestKey(m.Version)+gzSuffix))); err != nil {
		t.Fatalf("the compressed copy was not stored: %v", err)
	}
	if resp, body := get("gzip"); resp.Header.Get("Content-Encoding") != "" || !bytes.Equal(body, mb) {
		t.Fatalf("bundle without a compressed copy: Content-Encoding %q, %d bytes", resp.Header.Get("Content-Encoding"), len(body))
	}
}
