package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
)

// The download page (PLAN §18.1): the images of the current release with
// their checksums and signatures, for the vendor who is about to deploy an
// appliance. The release workflow, or `cp-api admin publish-images`, hands
// the control plane the release manifest and the address the files are
// served from; the files stay there (a GitHub release, a mirror) and the
// page links to them. The page is served without authentication on both
// listeners, like the transparency page; the portal reads GET /admin/images.

// imagesKey is where the image set lives in the object store, which every
// deployment has for bundles and releases.
const imagesKey = "images/current.json"

const defaultOIDCIssuer = "https://token.actions.githubusercontent.com"

// imageKinds maps an artifact name suffix to what the page says about it,
// in display order. Anything else in the manifest (the daemon and control
// plane binaries) is not for the vendor and is left out.
var imageKinds = []struct{ Suffix, Kind, For, Note string }{
	{".ova", "ova", "VMware vSphere 7+ (ESXi, vCenter), Workstation, Fusion", "the OVF deployment wizard asks for the enrollment code and the network settings"},
	{".vhdx.zip", "vhdx", "Microsoft Hyper-V 2019+ (Generation 2)", "a zip: extract it first; the VHDX inside is a dynamic disk of about 3 GB"},
	{".vhdx", "vhdx", "Microsoft Hyper-V 2019+ (Generation 2)", ""},
	{".qcow2", "qcow2", "KVM / libvirt (virt-install, Proxmox, OpenStack)", ""},
	{"-hypervisor-helpers.zip", "helpers", "Hyper-V and KVM: the VM creation scripts and the deployment guide", ""},
}

func plainName(s string) bool {
	return s != "" && !strings.ContainsAny(s, "/\\ ") && !strings.Contains(s, "..")
}

// imagesFromManifest turns a publish request into the stored view.
func imagesFromManifest(req v1.AdminImagesPublish, now time.Time) (*v1.ImagesView, error) {
	base, err := url.Parse(strings.TrimSpace(req.BaseURL))
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return nil, errors.New("base_url must be the http(s) URL the files are served under")
	}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	base.RawQuery, base.Fragment = "", ""
	prefix := base.String()
	m := req.Manifest
	if strings.TrimSpace(m.Version) == "" {
		return nil, errors.New("manifest.version required")
	}
	view := &v1.ImagesView{
		Version: m.Version, BuiltAt: m.BuiltAt, PublishedAt: now.UTC(), FeedVersion: req.FeedVersion,
		BaseURL: prefix, SignatureIdentity: req.SignatureIdentity, OIDCIssuer: req.OIDCIssuer, Container: m.Container,
	}
	if view.SignatureIdentity != "" && view.OIDCIssuer == "" {
		view.OIDCIssuer = defaultOIDCIssuer
	}
	rank := map[string]int{}
	hasImage := false
	for _, a := range m.Artifacts {
		kind := -1
		for i, k := range imageKinds {
			if strings.HasSuffix(a.Name, k.Suffix) {
				kind = i
				break
			}
		}
		if kind < 0 {
			continue
		}
		if !plainName(a.Name) {
			return nil, fmt.Errorf("artifact %q: the name must be a plain file name", a.Name)
		}
		if !isHex64(strings.ToLower(a.SHA256)) || a.Size <= 0 {
			return nil, fmt.Errorf("artifact %q: sha256 and size required", a.Name)
		}
		k := imageKinds[kind]
		img := v1.ImageDownload{Name: a.Name, Kind: k.Kind, For: k.For, Note: k.Note, Size: a.Size, SHA256: strings.ToLower(a.SHA256), URL: prefix + a.Name}
		if a.Sig != "" {
			if !plainName(a.Sig) {
				return nil, fmt.Errorf("artifact %q: the signature must be a plain file name", a.Name)
			}
			img.SigURL = prefix + a.Sig
			// The certificate only exists for keyless signing, which is
			// what an identity describes.
			if view.SignatureIdentity != "" {
				img.CertURL = prefix + a.Name + ".pem"
			}
		}
		if k.Kind != "helpers" {
			hasImage = true
		}
		rank[a.Name] = kind
		view.Images = append(view.Images, img)
	}
	if !hasImage {
		return nil, errors.New("manifest carries no appliance image (.ova, .vhdx.zip, .qcow2)")
	}
	sort.SliceStable(view.Images, func(i, j int) bool { return rank[view.Images[i].Name] < rank[view.Images[j].Name] })
	return view, nil
}

// loadImages returns nil, nil when nothing has been published.
func (s *Server) loadImages(ctx context.Context) (*v1.ImagesView, error) {
	rc, _, err := s.cfg.Objects.Get(ctx, imagesKey)
	if errors.Is(err, ErrObjectNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var v v1.ImagesView
	if err := json.NewDecoder(io.LimitReader(rc, 1<<20)).Decode(&v); err != nil {
		return nil, fmt.Errorf("images record: %w", err)
	}
	return &v, nil
}

func (s *Server) adminPublishImages(w http.ResponseWriter, r *http.Request) {
	if _, discard := s.cfg.Objects.(DiscardObjects); discard {
		writeErr(w, http.StatusServiceUnavailable, "no object store configured; the image set cannot be kept", "no_object_store")
		return
	}
	var req v1.AdminImagesPublish
	if err := decodeJSONLimit(r, &req, 4<<20); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	view, err := imagesFromManifest(req, s.cfg.Now())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_images")
		return
	}
	b, err := json.Marshal(view)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "encode")
		return
	}
	if _, err := s.cfg.Objects.Put(r.Context(), imagesKey, bytes.NewReader(b)); err != nil {
		writeErr(w, http.StatusInternalServerError, "store images: "+err.Error(), "store")
		return
	}
	s.log.Info("images published for the download page", "version", view.Version, "images", len(view.Images), "base_url", view.BaseURL)
	writeJSON(w, http.StatusCreated, view)
}

// adminGetImages also serves GET /download.json: the same data, public.
func (s *Server) adminGetImages(w http.ResponseWriter, r *http.Request) {
	v, err := s.loadImages(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	if v == nil {
		writeErr(w, http.StatusNotFound, "no images published yet", "no_images")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

type downloadRow struct {
	v1.ImageDownload
	SizeHuman string
}

type downloadPage struct {
	Product, Contact, JSONPath, TransparencyPath string
	Published                                    bool
	View                                         *v1.ImagesView
	Rows                                         []downloadRow
	First                                        downloadRow
	CosignCmd                                    string
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	product := s.cfg.Product
	if product == "" {
		product = "TPRM scanner appliance"
	}
	page := downloadPage{Product: product, Contact: s.cfg.Contact, JSONPath: "/download.json", TransparencyPath: "/transparency"}
	v, err := s.loadImages(r.Context())
	if err != nil {
		s.log.Warn("download page", "err", err)
	}
	if v != nil {
		page.Published, page.View = true, v
		for _, img := range v.Images {
			page.Rows = append(page.Rows, downloadRow{img, humanBytes(img.Size)})
		}
		page.First = page.Rows[0]
		if v.SignatureIdentity != "" && page.First.SigURL != "" {
			page.CosignCmd = fmt.Sprintf("cosign verify-blob --certificate %s.pem --signature %s.sig \\\n  --certificate-identity '%s' \\\n  --certificate-oidc-issuer %s %s",
				page.First.Name, page.First.Name, v.SignatureIdentity, v.OIDCIssuer, page.First.Name)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := downloadTmpl.Execute(w, page); err != nil {
		s.log.Warn("download page", "err", err)
	}
}

var downloadTmpl = template.Must(template.New("d").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{{.Product}}: download the appliance</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#222}h1,h2{line-height:1.2}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.3rem .6rem;text-align:left;vertical-align:top}pre{white-space:pre-wrap;background:#f6f6f6;padding:1rem;font-size:13px}code{background:#f6f6f6;padding:0 .2rem;word-break:break-all}small{color:#555}</style></head>
<body>
<h1>{{.Product}}: download the appliance</h1>
{{if not .Published}}<p>No release has been published to this control plane yet.{{if .Contact}} Ask {{.Contact}} for the image.{{end}}</p>
{{else}}<p>Release <strong>{{.View.Version}}</strong>, built {{.View.BuiltAt.Format "2006-01-02"}}{{if .View.FeedVersion}}, with vulnerability-test feed {{.View.FeedVersion}}{{end}}. Machine-readable copy: <a href="{{.JSONPath}}">{{.JSONPath}}</a>.{{if .Contact}} Questions: {{.Contact}}.{{end}}</p>
<p>Pick the file for your hypervisor; the OVA is the usual choice for VMware. Every file has a SHA-256 and a signature.</p>
<table><tr><th>File</th><th>For</th><th>Size</th><th>SHA-256</th><th>Signature</th></tr>
{{range .Rows}}<tr><td><a href="{{.URL}}">{{.Name}}</a>{{if .Note}}<br><small>{{.Note}}</small>{{end}}</td><td>{{.For}}</td><td>{{.SizeHuman}}</td><td><code>{{.SHA256}}</code></td><td>{{if .SigURL}}<a href="{{.SigURL}}">.sig</a>{{if .CertURL}} <a href="{{.CertURL}}">.pem</a>{{end}}{{else}}none{{end}}</td></tr>
{{end}}</table>
{{if .View.Container}}<h2>Container</h2><p>For a Docker host instead of a VM: <code>docker pull {{.View.Container.Image}}@{{.View.Container.Digest}}</code>. The digest is the signed one; the compose file and its instructions are in the deployment guide.</p>{{end}}
<h2>Check the download</h2>
<pre>sha256sum {{.First.Name}}
# must print {{.First.SHA256}}</pre>
{{if .CosignCmd}}<p>The signature was made by our release pipeline. With <a href="https://docs.sigstore.dev/cosign/">cosign</a>:</p><pre>{{.CosignCmd}}</pre>{{end}}
<h2>Then</h2>
<ol>
<li>Deploy it with 4 vCPUs, 8 GB of memory and two network adapters: the first with outbound TCP 443 to the control plane, direct or through an HTTP proxy that does not inspect TLS; the second in the segment to be scanned.</li>
<li>Have the enrollment code from the portal ready. On VMware the OVF deployment wizard asks for it; on Hyper-V and KVM it goes in on the console or on a small seed volume. It works once and expires after 14 days.</li>
<li>Power on. Within a few minutes the appliance shows as online in the portal. Nothing is scanned until a job is scheduled for it, within the agreed scope and window.</li>
</ol>
<p>What the appliance does, which tools it carries and what it collects: <a href="{{.TransparencyPath}}">{{.TransparencyPath}}</a>. The deployment guide travels in the helpers zip.</p>
{{end}}</body></html>
`))
