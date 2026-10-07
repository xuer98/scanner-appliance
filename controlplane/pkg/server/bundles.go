package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/controlplane/pkg/store"
	"github.com/tprm/scanner-appliance/internal/bundle"
)

// Bundles and releases (PLAN §13, §14, §17.2).
//
// Object layout:
//
//	bundles/files/<sha256>               content-addressed bundle files (shared across versions)
//	bundles/<version>/manifest.json      the signed manifest bytes
//	releases/<component>/<version>       daemon artifacts
//
// Publishing is delta-friendly: the publisher asks which digests are
// missing, uploads only those, then posts the manifest + signature. The
// server verifies the signature against the configured release keys and
// refuses a manifest that references a file it does not hold.

const (
	maxManifestSize = 64 << 20
	maxBundleFile   = 256 << 20
	maxReleaseSize  = 512 << 20

	// streamStall is how long a download may make no progress before the
	// server ends it.
	streamStall = 60 * time.Second

	HeaderBundleSig    = "X-Bundle-Signature"
	HeaderBundleSHA256 = "X-Bundle-SHA256"
	HeaderReleaseSigV1 = "X-Release-Signature"
)

func bundleFileKey(sha string) string       { return "bundles/files/" + sha }
func bundleManifestKey(v string) string     { return "bundles/" + v + "/manifest.json" }
func releaseKey(component, v string) string { return "releases/" + component + "/" + v }

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ---- appliance side (mTLS) ----

func (s *Server) streamObject(w http.ResponseWriter, r *http.Request, key string, headers map[string]string) {
	rc, n, err := s.cfg.Objects.Get(r.Context(), key)
	if errors.Is(err, ErrObjectNotFound) {
		writeErr(w, http.StatusNotFound, "object missing", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "object store: "+err.Error(), "objects")
		return
	}
	defer rc.Close()
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	w.WriteHeader(http.StatusOK)
	// The listener's WriteTimeout would end the response a fixed time after
	// the request, however well it is moving: the manifest of the full feed
	// is 16 MB, more than a 1 Mbit/s site link carries in a minute. The
	// deadline advances with every block written instead.
	ctl := http.NewResponseController(w)
	buf := make([]byte, 64<<10)
	for {
		nr, rerr := rc.Read(buf)
		if nr > 0 {
			_ = ctl.SetWriteDeadline(time.Now().Add(streamStall))
			if _, werr := w.Write(buf[:nr]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

func (s *Server) handleBundleManifest(w http.ResponseWriter, r *http.Request) {
	b, err := s.cfg.Store.GetBundle(r.Context(), r.PathValue("version"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such bundle", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	s.streamObject(w, r, b.ObjectKey, map[string]string{"Content-Type": "application/json", HeaderBundleSig: b.Sig, HeaderBundleSHA256: b.SHA256})
}

func (s *Server) handleBundleFile(w http.ResponseWriter, r *http.Request) {
	sha := strings.ToLower(r.PathValue("sha256"))
	if !isHex64(sha) {
		writeErr(w, http.StatusBadRequest, "bad digest", "bad_digest")
		return
	}
	s.streamObject(w, r, bundleFileKey(sha), map[string]string{"Content-Type": "application/octet-stream"})
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	rel, err := s.cfg.Store.GetRelease(r.Context(), r.PathValue("component"), r.PathValue("version"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such release", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error", "store")
		return
	}
	s.streamObject(w, r, rel.ObjectKey, map[string]string{"Content-Type": "application/octet-stream", HeaderReleaseSigV1: rel.Sig, v1.HeaderReleaseSHA256: rel.SHA256})
}

// ---- admin: bundles ----

func (s *Server) adminMissingBundleFiles(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminMissingFilesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	for _, sha := range req.SHA256 {
		if !isHex64(sha) {
			writeErr(w, http.StatusBadRequest, "bad digest "+sha, "bad_digest")
			return
		}
	}
	has, err := s.cfg.Store.HasBundleFiles(r.Context(), req.SHA256)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	out := v1.AdminMissingFilesResponse{Missing: []string{}}
	for _, sha := range req.SHA256 {
		if !has[sha] {
			out.Missing = append(out.Missing, sha)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// adminPutBundleFile stores one content-addressed file. The body is hashed
// while it is spooled; a digest mismatch discards it.
func (s *Server) adminPutBundleFile(w http.ResponseWriter, r *http.Request) {
	sha := strings.ToLower(r.PathValue("sha256"))
	if !isHex64(sha) {
		writeErr(w, http.StatusBadRequest, "bad digest", "bad_digest")
		return
	}
	tmp, err := os.CreateTemp("", "bundle-file-*")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "tmp")
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), http.MaxBytesReader(w, r.Body, maxBundleFile))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "upload failed: "+err.Error(), "upload")
		return
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sha {
		writeErr(w, http.StatusBadRequest, "digest mismatch: body is "+got, "digest_mismatch")
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "tmp")
		return
	}
	key := bundleFileKey(sha)
	if _, err := s.cfg.Objects.Put(r.Context(), key, tmp); err != nil {
		writeErr(w, http.StatusInternalServerError, "object store: "+err.Error(), "objects")
		return
	}
	if err := s.cfg.Store.PutBundleFiles(r.Context(), []store.BundleFileRec{{SHA256: sha, Size: n, ObjectKey: key}}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"sha256": sha, "size": n})
}

func (s *Server) adminPublishBundle(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminPublishBundleRequest
	// The manifest lists every file of the feed: about 14 MB for the
	// Community Feed's 95,000 files, far over the default body limit.
	if err := decodeJSONLimit(r, &req, maxManifestSize+maxJSONBody); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	if len(req.Manifest) == 0 || len(req.Manifest) > maxManifestSize {
		writeErr(w, http.StatusBadRequest, "manifest missing or too large", "bad_manifest")
		return
	}
	m, err := bundle.DecodeManifest(req.Manifest)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_manifest")
		return
	}
	if err := s.verifyReleaseSig(req.Manifest, req.Sig); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_signature")
		return
	}
	shas := make([]string, 0, len(m.Files))
	for _, f := range m.Files {
		shas = append(shas, f.SHA256)
	}
	has, err := s.cfg.Store.HasBundleFiles(r.Context(), shas)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	var missing []string
	for _, sha := range shas {
		if !has[sha] {
			missing = append(missing, sha)
		}
	}
	if len(missing) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "manifest references files not uploaded", "code": "files_missing", "missing": missing})
		return
	}
	if _, err := s.cfg.Store.GetBundle(r.Context(), m.Version); err == nil {
		writeErr(w, http.StatusConflict, "bundle version already published", "exists")
		return
	}
	// Store the exact bytes that were signed.
	key := bundleManifestKey(m.Version)
	if _, err := s.cfg.Objects.Put(r.Context(), key, bytes.NewReader(req.Manifest)); err != nil {
		writeErr(w, http.StatusInternalServerError, "object store: "+err.Error(), "objects")
		return
	}
	now := s.cfg.Now()
	canaryUntil := now.Add(s.canaryPeriod(req.CanaryHours))
	b := &store.Bundle{Version: m.Version, FeedVersion: m.FeedVersion, ObjectKey: key, SHA256: bundle.SHA256Hex(req.Manifest), Sig: req.Sig,
		Files: len(m.Files), Bytes: m.Bytes(), Status: v1.RolloutCanary, PublishedAt: now, CanaryUntil: &canaryUntil}
	if err := s.cfg.Store.PutBundle(r.Context(), b); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("bundle published", "version", b.Version, "feed_version", b.FeedVersion, "files", b.Files, "bytes", b.Bytes, "canary_until", canaryUntil)
	if err := s.rolloutTick(r.Context()); err != nil {
		s.log.Warn("rollout after publish", "err", err)
	}
	fleet, _ := s.cfg.Store.ListAppliances(r.Context())
	writeJSON(w, http.StatusCreated, bundleView(b, fleet))
}

func (s *Server) canaryPeriod(hours float64) time.Duration {
	if hours > 0 {
		return time.Duration(hours * float64(time.Hour))
	}
	if s.cfg.CanaryPeriod > 0 {
		return s.cfg.CanaryPeriod
	}
	return DefaultCanaryPeriod
}

// verifyReleaseSig checks a signature against the configured release keys.
// Without keys the server refuses to publish: shipping unsigned bundles to
// appliances that pin a key would only ever fail on the far side.
func (s *Server) verifyReleaseSig(b []byte, sig string) error {
	if len(s.cfg.ReleaseKeys) == 0 {
		return errors.New("no release signing key configured on the control plane (pki-dir/release-pub.pem)")
	}
	if strings.TrimSpace(sig) == "" {
		return errors.New("signature required")
	}
	return bundle.Verify(b, sig, s.cfg.ReleaseKeys)
}

func bundleView(b *store.Bundle, fleet []*store.Appliance) v1.AdminBundleView {
	v := v1.AdminBundleView{Version: b.Version, FeedVersion: b.FeedVersion, Files: b.Files, Bytes: b.Bytes, SHA256: b.SHA256,
		Status: b.Status, HeldReason: b.HeldReason, PublishedAt: b.PublishedAt, CanaryUntil: b.CanaryUntil}
	for _, a := range fleet {
		if a.Status != v1.StatusEnrolled {
			continue
		}
		v.Fleet++
		if a.BundleVersion == b.Version {
			v.Installed++
		}
	}
	return v
}

func (s *Server) adminListBundles(w http.ResponseWriter, r *http.Request) {
	list, err := s.cfg.Store.ListBundles(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	fleet, _ := s.cfg.Store.ListAppliances(r.Context())
	out := make([]v1.AdminBundleView, 0, len(list))
	for _, b := range list {
		out = append(out, bundleView(b, fleet))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminGetBundle(w http.ResponseWriter, r *http.Request) {
	b, err := s.cfg.Store.GetBundle(r.Context(), r.PathValue("version"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such bundle", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	fleet, _ := s.cfg.Store.ListAppliances(r.Context())
	writeJSON(w, http.StatusOK, bundleView(b, fleet))
}

func validRollout(status string) bool {
	switch status {
	case v1.RolloutCanary, v1.RolloutReleased, v1.RolloutHeld, v1.RolloutRetired:
		return true
	}
	return false
}

func (s *Server) adminBundleRollout(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminRolloutRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	if !validRollout(req.Status) {
		writeErr(w, http.StatusBadRequest, "status must be canary|released|held|retired", "bad_status")
		return
	}
	err := s.cfg.Store.SetBundleStatus(r.Context(), r.PathValue("version"), req.Status, req.Reason)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such bundle", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("bundle rollout state changed", "version", r.PathValue("version"), "status", req.Status, "reason", req.Reason)
	if err := s.rolloutTick(r.Context()); err != nil {
		s.log.Warn("rollout after state change", "err", err)
	}
	s.adminGetBundle(w, r)
}

// ---- admin: releases ----

func (s *Server) adminPutRelease(w http.ResponseWriter, r *http.Request) {
	component, version := r.PathValue("component"), r.PathValue("version")
	if !strings.HasPrefix(component, "applianced-") || strings.ContainsAny(component+version, "/\\ ") || strings.Contains(component+version, "..") {
		writeErr(w, http.StatusBadRequest, "component must be applianced-<os>-<arch> and version a plain string", "bad_component")
		return
	}
	want := strings.ToLower(r.Header.Get(v1.HeaderReleaseSHA256))
	sig := r.Header.Get(v1.HeaderReleaseSig)
	if !isHex64(want) || sig == "" {
		writeErr(w, http.StatusBadRequest, v1.HeaderReleaseSHA256+" and "+v1.HeaderReleaseSig+" headers required", "bad_headers")
		return
	}
	var canaryHours float64
	if h := r.Header.Get(v1.HeaderCanaryHours); h != "" {
		canaryHours, _ = strconv.ParseFloat(h, 64)
	}
	tmp, err := os.CreateTemp("", "release-*")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "tmp")
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), http.MaxBytesReader(w, r.Body, maxReleaseSize))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "upload failed: "+err.Error(), "upload")
		return
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		writeErr(w, http.StatusBadRequest, "digest mismatch: body is "+got, "digest_mismatch")
		return
	}
	// The daemon verifies the signature over the artifact bytes; check it
	// here the same way so a bad upload is caught at publish time.
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "tmp")
		return
	}
	body, err := io.ReadAll(tmp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "tmp")
		return
	}
	if err := s.verifyReleaseSig(body, sig); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_signature")
		return
	}
	key := releaseKey(component, version)
	if _, err := s.cfg.Objects.Put(r.Context(), key, bytes.NewReader(body)); err != nil {
		writeErr(w, http.StatusInternalServerError, "object store: "+err.Error(), "objects")
		return
	}
	now := s.cfg.Now()
	canaryUntil := now.Add(s.canaryPeriod(canaryHours))
	rel := &store.Release{Component: component, Version: version, ObjectKey: key, SHA256: want, Sig: sig, Bytes: n,
		Status: v1.RolloutCanary, PublishedAt: now, CanaryUntil: &canaryUntil}
	if err := s.cfg.Store.PutRelease(r.Context(), rel); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("release published", "component", component, "version", version, "bytes", n, "canary_until", canaryUntil)
	if err := s.rolloutTick(r.Context()); err != nil {
		s.log.Warn("rollout after publish", "err", err)
	}
	fleet, _ := s.cfg.Store.ListAppliances(r.Context())
	writeJSON(w, http.StatusCreated, releaseView(rel, fleet))
}

func releaseView(rel *store.Release, fleet []*store.Appliance) v1.AdminReleaseView {
	v := v1.AdminReleaseView{Component: rel.Component, Version: rel.Version, SHA256: rel.SHA256, Bytes: rel.Bytes, Status: rel.Status,
		HeldReason: rel.HeldReason, PublishedAt: rel.PublishedAt, CanaryUntil: rel.CanaryUntil}
	for _, a := range fleet {
		if a.Status != v1.StatusEnrolled || v1.ReleaseComponent(a.OS, a.Arch) != rel.Component {
			continue
		}
		v.Fleet++
		if a.Version == rel.Version {
			v.Installed++
		}
	}
	return v
}

func (s *Server) adminListReleases(w http.ResponseWriter, r *http.Request) {
	list, err := s.cfg.Store.ListReleases(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	fleet, _ := s.cfg.Store.ListAppliances(r.Context())
	out := make([]v1.AdminReleaseView, 0, len(list))
	for _, rel := range list {
		out = append(out, releaseView(rel, fleet))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminReleaseRollout(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminRolloutRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	if !validRollout(req.Status) {
		writeErr(w, http.StatusBadRequest, "status must be canary|released|held|retired", "bad_status")
		return
	}
	component, version := r.PathValue("component"), r.PathValue("version")
	err := s.cfg.Store.SetReleaseStatus(r.Context(), component, version, req.Status, req.Reason)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such release", "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error(), "store")
		return
	}
	s.log.Info("release rollout state changed", "component", component, "version", version, "status", req.Status, "reason", req.Reason)
	if err := s.rolloutTick(r.Context()); err != nil {
		s.log.Warn("rollout after state change", "err", err)
	}
	rel, _ := s.cfg.Store.GetRelease(r.Context(), component, version)
	fleet, _ := s.cfg.Store.ListAppliances(r.Context())
	writeJSON(w, http.StatusOK, releaseView(rel, fleet))
}

// ---- admin: appliance attributes ----

func (s *Server) adminUpdateAppliance(w http.ResponseWriter, r *http.Request) {
	var req v1.AdminApplianceUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error(), "bad_json")
		return
	}
	id := r.PathValue("id")
	if req.Canary != nil {
		err := s.cfg.Store.SetApplianceCanary(r.Context(), id, *req.Canary)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "no such appliance", "not_found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error(), "store")
			return
		}
		s.log.Info("appliance canary flag", "appliance", id, "canary", *req.Canary)
		if *req.Canary {
			if err := s.rolloutTick(r.Context()); err != nil {
				s.log.Warn("rollout after canary change", "err", err)
			}
		}
	}
	s.adminGetAppliance(w, r)
}

// ---- apt mirror (PLAN §14, §17.2) ----

// handleApt serves the security-pocket mirror from Config.AptDir over mTLS.
// The directory is populated out of band (debmirror/apt-mirror); only
// files are served, never listings.
func (s *Server) handleApt(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AptDir == "" {
		writeErr(w, http.StatusNotFound, "apt mirror not configured", "not_found")
		return
	}
	p := r.PathValue("path")
	if p == "" || strings.HasSuffix(p, "/") || badKey(p) {
		writeErr(w, http.StatusNotFound, "not found", "not_found")
		return
	}
	f, err := os.Open(fmt.Sprintf("%s/%s", strings.TrimRight(s.cfg.AptDir, "/"), p))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found", "not_found")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		writeErr(w, http.StatusNotFound, "not found", "not_found")
		return
	}
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}
