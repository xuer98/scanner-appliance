package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

func testManifest() v1.ReleaseManifest {
	h := func(c byte) string { return strings.Repeat(string(c), 64) }
	return v1.ReleaseManifest{
		Version: "1.2.3", BuiltAt: time.Date(2026, 10, 14, 0, 35, 0, 0, time.UTC),
		Artifacts: []v1.ReleaseArtifact{
			{Name: "applianced-linux-amd64", SHA256: h('1'), Size: 8716450, Sig: "applianced-linux-amd64.sig", SBOM: "applianced-linux-amd64.sbom.spdx.json"},
			{Name: "appliance-1.2.3-hypervisor-helpers.zip", SHA256: h('2'), Size: 13464, Sig: "appliance-1.2.3-hypervisor-helpers.zip.sig"},
			{Name: "appliance-1.2.3.qcow2", SHA256: h('3'), Size: 930086912, Sig: "appliance-1.2.3.qcow2.sig"},
			{Name: "appliance-1.2.3.vhdx.zip", SHA256: h('4'), Size: 798011960, Sig: "appliance-1.2.3.vhdx.zip.sig"},
			{Name: "appliance-1.2.3.ova", SHA256: h('5'), Size: 840110080, Sig: "appliance-1.2.3.ova.sig"},
			{Name: "cp-api-linux-amd64", SHA256: h('6'), Size: 15708322, Sig: "cp-api-linux-amd64.sig"},
		},
		Container: &v1.ReleaseContainer{Image: "ghcr.io/org/scanner-appliance:1.2.3", Digest: "sha256:" + h('7')},
	}
}

func (h *harness) public(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := h.client(nil).Get(h.enroll.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestImagesDownloadPage(t *testing.T) {
	h := newHarness(t)

	// Without an object store the set could not be kept: say so.
	if st := h.admin("PUT", "/admin/images", v1.AdminImagesPublish{BaseURL: "https://x/", Manifest: testManifest()}, nil); st != http.StatusServiceUnavailable {
		t.Fatalf("publish without object store: %d", st)
	}
	h.srv.cfg.Objects = DirObjects{Root: t.TempDir()}

	// Nothing published yet: the portal gets 404, the vendor a page that says so.
	if st := h.admin("GET", "/admin/images", nil, nil); st != http.StatusNotFound {
		t.Fatalf("unpublished: %d", st)
	}
	if st, body := h.public(t, "/download"); st != 200 || !strings.Contains(body, "No release has been published") {
		t.Fatalf("unpublished page: %d %q", st, body)
	}
	if st, _ := h.public(t, "/download.json"); st != http.StatusNotFound {
		t.Fatalf("unpublished json: %d", st)
	}

	req := v1.AdminImagesPublish{
		BaseURL:           "https://github.com/org/scanner-appliance/releases/download/v1.2.3", // no trailing slash on purpose
		SignatureIdentity: "https://github.com/org/scanner-appliance/.github/workflows/release.yml@refs/tags/v1.2.3",
		FeedVersion:       "202610130559",
		Manifest:          testManifest(),
	}
	var view v1.ImagesView
	if st := h.admin("PUT", "/admin/images", req, &view); st != http.StatusCreated {
		t.Fatalf("publish: %d", st)
	}
	// The binaries are left out; the images come in hypervisor order.
	var kinds, names []string
	for _, img := range view.Images {
		kinds = append(kinds, img.Kind)
		names = append(names, img.Name)
	}
	if strings.Join(kinds, ",") != "ova,vhdx,qcow2,helpers" {
		t.Fatalf("images: %v", names)
	}
	ova := view.Images[0]
	if ova.URL != req.BaseURL+"/appliance-1.2.3.ova" || ova.SigURL != req.BaseURL+"/appliance-1.2.3.ova.sig" || ova.CertURL != req.BaseURL+"/appliance-1.2.3.ova.pem" {
		t.Fatalf("ova links: %+v", ova)
	}
	if ova.SHA256 != strings.Repeat("5", 64) || ova.Size != 840110080 || !strings.Contains(ova.For, "VMware") {
		t.Fatalf("ova: %+v", ova)
	}
	if view.OIDCIssuer != defaultOIDCIssuer || view.Version != "1.2.3" || view.FeedVersion != "202610130559" || view.Container == nil || view.PublishedAt.IsZero() {
		t.Fatalf("view: %+v", view)
	}
	if !strings.Contains(view.Images[1].Note, "extract") {
		t.Fatalf("vhdx note: %+v", view.Images[1])
	}

	// The portal and the public JSON see the same set; the page links it all.
	var again v1.ImagesView
	if st := h.admin("GET", "/admin/images", nil, &again); st != 200 || again.Version != "1.2.3" || len(again.Images) != 4 {
		t.Fatalf("get: %d %+v", st, again)
	}
	if st, body := h.public(t, "/download.json"); st != 200 || !strings.Contains(body, `"kind":"ova"`) {
		t.Fatalf("public json: %d %q", st, body)
	}
	st, page := h.public(t, "/download")
	if st != 200 {
		t.Fatalf("page: %d", st)
	}
	for _, want := range []string{
		`href="` + ova.URL + `"`, ova.SHA256, "801 MiB", "Hyper-V", "docker pull ghcr.io/org/scanner-appliance:1.2.3@sha256:",
		"cosign verify-blob --certificate appliance-1.2.3.ova.pem", "release.yml@refs/tags/v1.2.3", "feed 202610130559", "/transparency",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "applianced-linux-amd64") || strings.Contains(page, "cp-api-linux") {
		t.Fatal("page shows binaries")
	}

	// A later release replaces the set.
	next := req
	next.Manifest.Version = "1.3.0"
	next.BaseURL = "https://mirror.example/images/1.3.0/"
	next.SignatureIdentity = ""
	var later v1.ImagesView
	if st := h.admin("PUT", "/admin/images", next, &later); st != http.StatusCreated || later.Version != "1.3.0" || later.Images[0].CertURL != "" || later.OIDCIssuer != "" {
		t.Fatalf("republish: %d %+v", st, later)
	}
	if _, page = h.public(t, "/download"); !strings.Contains(page, "https://mirror.example/images/1.3.0/appliance-1.2.3.ova") || strings.Contains(page, "cosign verify-blob") {
		t.Fatalf("page after republish:\n%s", page)
	}

	// What is refused.
	bad := []struct {
		name string
		mod  func(r *v1.AdminImagesPublish)
	}{
		{"ftp base url", func(r *v1.AdminImagesPublish) { r.BaseURL = "ftp://x/" }},
		{"no version", func(r *v1.AdminImagesPublish) { r.Manifest.Version = "" }},
		{"binaries only", func(r *v1.AdminImagesPublish) { r.Manifest.Artifacts = r.Manifest.Artifacts[:1] }},
		{"helpers only", func(r *v1.AdminImagesPublish) { r.Manifest.Artifacts = r.Manifest.Artifacts[1:2] }},
		{"bad digest", func(r *v1.AdminImagesPublish) { r.Manifest.Artifacts[4].SHA256 = "abc" }},
		{"path in name", func(r *v1.AdminImagesPublish) { r.Manifest.Artifacts[4].Name = "../x.ova" }},
	}
	for _, b := range bad {
		r := req
		r.Manifest = testManifest()
		b.mod(&r)
		if st := h.admin("PUT", "/admin/images", r, nil); st != http.StatusBadRequest {
			t.Errorf("%s: %d", b.name, st)
		}
	}
	if st := h.admin("GET", "/admin/images", nil, &again); st != 200 || again.Version != "1.3.0" {
		t.Fatalf("set changed by a refused publish: %d %+v", st, again)
	}
}
