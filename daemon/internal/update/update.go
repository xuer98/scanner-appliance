// Package update applies signed bundles (PLAN §13) and daemon releases
// (PLAN §14) delivered by the update_bundle / update_daemon directives.
//
// Bundles are content-addressed: every file is kept in
// <state>/bundle/cas/<sha256> and hard-linked (or copied) into place, the
// feed under the openvas plugins directory and everything else under
// <state>/bundle/. The installed and previous manifests are retained, so
// a failed VT reload reverts the plugin directory from the retained file
// set. On the first apply the feed seeded into the image is adopted as
// the "installed" manifest, so even that first delta can be rolled back.
//
// Everything is fetched from the control plane over the appliance's mTLS
// session; a directive can only name control-plane paths.
package update

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/daemon/internal/osp"
	"github.com/tprm/scanner-appliance/internal/bundle"
)

const (
	// DefaultReloadTimeout bounds how long ospd may take to load a feed.
	DefaultReloadTimeout = 30 * time.Minute
	DefaultReloadPoll    = 10 * time.Second
	// noEngineGrace: an absent ospd socket for this long means "no engine
	// on this host" and the reload wait is skipped.
	noEngineGrace = 60 * time.Second

	maxManifestBytes = 64 << 20
	maxBundleFile    = 256 << 20
	maxArtifact      = 512 << 20

	feedPrefix = bundle.FeedDir + "/"
)

// ErrRestartRequired is returned once a new daemon binary is in place.
var ErrRestartRequired = errors.New("restart required to run the new daemon")

// ErrNotApplicable: containers are updated by pulling a new image.
var ErrNotApplicable = errors.New("daemon self-update does not apply to container images (pull a new image)")

// Fetcher downloads a control-plane path over the appliance's mTLS session.
type Fetcher interface {
	Download(ctx context.Context, path string, w io.Writer, max int64) (http.Header, int64, error)
}

// FetchFunc adapts a function to Fetcher.
type FetchFunc func(ctx context.Context, path string, w io.Writer, max int64) (http.Header, int64, error)

func (f FetchFunc) Download(ctx context.Context, path string, w io.Writer, max int64) (http.Header, int64, error) {
	return f(ctx, path, w, max)
}

// Manager applies updates. Zero values are filled by init().
type Manager struct {
	StateDir   string
	PluginsDir string // openvas plugins directory; "" keeps the feed under StateDir/bundle/nasl
	Keys       []*ecdsa.PublicKey
	OSP        *osp.Client // nil: no VT reload wait
	Fetch      Fetcher
	Log        *slog.Logger
	Now        func() time.Time

	ReloadTimeout time.Duration
	ReloadPoll    time.Duration

	// Daemon self-update (daemon.go).
	Version   string // running version
	ExePath   string // default os.Executable()
	Container bool   // ErrNotApplicable for update_daemon
	VersionOf func(ctx context.Context, path string) (string, error)
}

func (m *Manager) init() {
	if m.Log == nil {
		m.Log = slog.Default()
	}
	if m.Now == nil {
		m.Now = time.Now
	}
	if m.ReloadTimeout == 0 {
		m.ReloadTimeout = DefaultReloadTimeout
	}
	if m.ReloadPoll == 0 {
		m.ReloadPoll = DefaultReloadPoll
	}
	if m.VersionOf == nil {
		m.VersionOf = versionOf
	}
}

// Payload is the update_bundle / update_daemon directive payload.
type Payload struct {
	URL         string
	SHA256      string
	Sig         string
	Version     string
	FeedVersion string
}

// PayloadFrom validates a directive payload. The URL must be a
// control-plane path: artifacts never come from anywhere else.
func PayloadFrom(m map[string]any) (Payload, error) {
	get := func(k string) string { s, _ := m[k].(string); return strings.TrimSpace(s) }
	p := Payload{URL: get(v1.PayloadURL), SHA256: strings.ToLower(get(v1.PayloadSHA256)), Sig: get(v1.PayloadSig),
		Version: get(v1.PayloadVersion), FeedVersion: get(v1.PayloadFeedVersion)}
	if !strings.HasPrefix(p.URL, "/v1/") || strings.Contains(p.URL, "..") || strings.ContainsAny(p.URL, " \t\n?#") {
		return p, errors.New("payload url must be a /v1/ control-plane path")
	}
	if _, err := hex.DecodeString(p.SHA256); err != nil || len(p.SHA256) != 64 {
		return p, errors.New("payload sha256 must be 64 hex characters")
	}
	if p.Sig == "" {
		return p, errors.New("payload sig required")
	}
	if !bundle.ValidVersion(p.Version) {
		return p, errors.New("payload version is missing or malformed")
	}
	return p, nil
}

func (m *Manager) bundleDir() string         { return filepath.Join(m.StateDir, "bundle") }
func (m *Manager) casDir() string            { return filepath.Join(m.bundleDir(), "cas") }
func (m *Manager) casPath(sha string) string { return filepath.Join(m.casDir(), sha) }
func (m *Manager) manifestPath() string      { return filepath.Join(m.bundleDir(), "manifest.json") }
func (m *Manager) prevManifestPath() string {
	return filepath.Join(m.bundleDir(), "manifest.prev.json")
}

// Target returns where a bundle path lives on disk.
func (m *Manager) Target(p string) string {
	if strings.HasPrefix(p, feedPrefix) && m.PluginsDir != "" {
		return filepath.Join(m.PluginsDir, filepath.FromSlash(strings.TrimPrefix(p, feedPrefix)))
	}
	return filepath.Join(m.bundleDir(), filepath.FromSlash(p))
}

// ConfigsDir is where bundled scan configs land (internal/scanconfig).
func (m *Manager) ConfigsDir() string { return filepath.Join(m.bundleDir(), bundle.ConfigsDir) }

// TemplatesDir is where bundled nuclei templates land.
func (m *Manager) TemplatesDir() string { return filepath.Join(m.bundleDir(), bundle.TemplatesDir) }

// Installed returns the installed manifest, or nil when nothing was ever
// applied.
func (m *Manager) Installed() (*bundle.Manifest, error) {
	b, err := os.ReadFile(m.manifestPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return bundle.DecodeManifest(b)
}

// InstalledVersion is a convenience for status displays.
func (m *Manager) InstalledVersion() string {
	if mf, err := m.Installed(); err == nil && mf != nil {
		return mf.Version
	}
	return ""
}

func bundleErr(version string, err error) error { return fmt.Errorf("bundle %s: %w", version, err) }

// ApplyBundle fetches, verifies and installs the bundle named by the
// directive, waits for ospd to load a changed feed and rolls back when it
// does not. It is idempotent for an already-installed version.
func (m *Manager) ApplyBundle(ctx context.Context, p Payload) (*bundle.Manifest, error) {
	m.init()
	if m.Fetch == nil {
		return nil, bundleErr(p.Version, errors.New("no fetcher (not enrolled?)"))
	}
	log := m.Log.With("bundle", p.Version)
	var buf bytes.Buffer
	if _, _, err := m.Fetch.Download(ctx, p.URL, &buf, maxManifestBytes); err != nil {
		return nil, bundleErr(p.Version, fmt.Errorf("fetch manifest: %w", err))
	}
	mb := buf.Bytes()
	if got := bundle.SHA256Hex(mb); got != p.SHA256 {
		return nil, bundleErr(p.Version, fmt.Errorf("manifest digest %s does not match the directive", got[:12]))
	}
	if err := bundle.Verify(mb, p.Sig, m.Keys); err != nil {
		return nil, bundleErr(p.Version, err)
	}
	next, err := bundle.DecodeManifest(mb)
	if err != nil {
		return nil, bundleErr(p.Version, err)
	}
	if next.Version != p.Version {
		return nil, bundleErr(p.Version, fmt.Errorf("manifest is version %s", next.Version))
	}
	if p.FeedVersion != "" && next.FeedVersion != p.FeedVersion {
		return nil, bundleErr(p.Version, fmt.Errorf("manifest carries feed %s, directive says %s", next.FeedVersion, p.FeedVersion))
	}
	installed, err := m.Installed()
	if err != nil {
		return nil, bundleErr(p.Version, fmt.Errorf("installed manifest: %w", err))
	}
	if installed != nil && installed.Version == next.Version {
		log.Info("bundle already installed")
		return next, nil
	}
	if installed == nil {
		if installed, err = m.adoptSeed(); err != nil {
			return nil, bundleErr(p.Version, fmt.Errorf("adopt seeded feed: %w", err))
		}
	}
	fetch, remove := bundle.Diff(installed, next)
	var fetchBytes int64
	feedChanged := false
	for _, f := range fetch {
		fetchBytes += f.Size
		feedChanged = feedChanged || strings.HasPrefix(f.Path, feedPrefix)
	}
	for _, r := range remove {
		feedChanged = feedChanged || strings.HasPrefix(r, feedPrefix)
	}
	log.Info("applying bundle", "from", installed.Version, "feed", next.FeedVersion, "fetch", len(fetch), "fetch_bytes", fetchBytes, "remove", len(remove))

	base := strings.TrimSuffix(p.URL, "/manifest")
	for _, f := range fetch {
		if err := m.ensureCAS(ctx, base, f); err != nil {
			return nil, bundleErr(p.Version, err)
		}
	}
	// Everything is local; the swap itself is quick and reversible.
	if err := m.place(next, fetch); err != nil {
		log.Error("placing files failed; restoring", "err", err)
		_ = m.restore(installed, next)
		return nil, bundleErr(p.Version, err)
	}
	m.removeAll(remove)
	if err := m.writeManifests(installed, next); err != nil {
		_ = m.restore(installed, next)
		return nil, bundleErr(p.Version, err)
	}
	if feedChanged && m.OSP != nil {
		if err := m.waitFeed(ctx, next.FeedVersion); err != nil {
			log.Error("VT reload failed; rolling back", "err", err)
			if rerr := m.rollback(installed, next); rerr != nil {
				log.Error("rollback incomplete", "err", rerr)
			} else if installed.FeedVersion != "" {
				wctx, cancel := context.WithTimeout(ctx, m.ReloadTimeout)
				if werr := m.waitFeed(wctx, installed.FeedVersion); werr != nil {
					log.Warn("previous feed not confirmed after rollback", "err", werr)
				}
				cancel()
			}
			return nil, bundleErr(p.Version, err)
		}
	}
	m.gc(installed, next)
	log.Info("bundle applied", "feed", next.FeedVersion, "files", len(next.Files))
	return next, nil
}

// adoptSeed turns the feed the image shipped into the "installed"
// manifest so the first delta is a delta and can be rolled back.
func (m *Manager) adoptSeed() (*bundle.Manifest, error) {
	seed := &bundle.Manifest{Version: "seed", CreatedAt: m.Now().UTC().Truncate(time.Second), Files: []bundle.File{}}
	if m.PluginsDir != "" {
		if fi, err := os.Stat(m.PluginsDir); err == nil && fi.IsDir() {
			built, err := bundle.Build(m.PluginsDir, "seed", m.Now())
			if err != nil {
				return nil, err
			}
			for _, f := range built.Files {
				f.Path = feedPrefix + f.Path
				seed.Files = append(seed.Files, f)
			}
			// The plugins dir is the feed root itself, so the version file
			// sits at its top level.
			if fh, err := os.Open(filepath.Join(m.PluginsDir, bundle.FeedInfoFile)); err == nil {
				seed.FeedVersion = bundle.ParseFeedVersion(fh)
				_ = fh.Close()
			}
		}
	}
	if seed.FeedVersion != "" {
		seed.Version = "seed-" + seed.FeedVersion
	}
	if err := os.MkdirAll(m.casDir(), 0o755); err != nil {
		return nil, err
	}
	for _, f := range seed.Files {
		if err := m.importCAS(m.Target(f.Path), f.SHA256); err != nil {
			return nil, err
		}
	}
	m.Log.Info("adopted the seeded feed as the installed bundle", "feed", seed.FeedVersion, "files", len(seed.Files))
	return seed, m.writeManifestFile(m.manifestPath(), seed)
}

// ensureCAS downloads f into the store unless it is already there.
func (m *Manager) ensureCAS(ctx context.Context, base string, f bundle.File) error {
	dst := m.casPath(f.SHA256)
	if fi, err := os.Stat(dst); err == nil && fi.Size() == f.Size {
		return nil
	}
	if err := os.MkdirAll(m.casDir(), 0o755); err != nil {
		return err
	}
	tmp := dst + ".part"
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, n, err := m.Fetch.Download(ctx, base+"/files/"+f.SHA256, io.MultiWriter(fh, h), maxBundleFile)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("fetch %s: %w", f.Path, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != f.SHA256 || n != f.Size {
		_ = os.Remove(tmp)
		return fmt.Errorf("fetch %s: digest or size mismatch", f.Path)
	}
	return os.Rename(tmp, dst)
}

// importCAS records an existing file (the seeded feed) in the store.
func (m *Manager) importCAS(src, sha string) error {
	dst := m.casPath(sha)
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst, 0o644)
}

// place links every fetched file into its target and re-creates any
// unchanged file that went missing.
func (m *Manager) place(next *bundle.Manifest, fetch []bundle.File) error {
	fetched := map[string]bool{}
	for _, f := range fetch {
		fetched[f.Path] = true
	}
	for _, f := range next.Files {
		target := m.Target(f.Path)
		if !fetched[f.Path] {
			if fi, err := os.Stat(target); err == nil && fi.Size() == f.Size {
				continue
			}
		}
		if err := m.placeOne(m.casPath(f.SHA256), target); err != nil {
			return fmt.Errorf("install %s: %w", f.Path, err)
		}
	}
	return nil
}

func (m *Manager) placeOne(cas, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp := target + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Link(cas, tmp); err != nil {
		if err := copyFile(cas, tmp, 0o644); err != nil {
			return err
		}
	}
	_ = os.Chmod(tmp, 0o644)
	if m.PluginsDir != "" && strings.HasPrefix(target, m.PluginsDir) {
		if uid, gid, ok := dirOwner(m.PluginsDir); ok {
			_ = os.Chown(tmp, uid, gid)
		}
	}
	return os.Rename(tmp, target)
}

func (m *Manager) removeAll(paths []string) {
	for _, p := range paths {
		target := m.Target(p)
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			m.Log.Warn("remove", "path", p, "err", err)
		}
		m.pruneDirs(filepath.Dir(target), p)
	}
}

// pruneDirs removes now-empty directories below the target root.
func (m *Manager) pruneDirs(dir, bundlePath string) {
	root := m.bundleDir()
	if strings.HasPrefix(bundlePath, feedPrefix) && m.PluginsDir != "" {
		root = m.PluginsDir
	}
	for dir != root && strings.HasPrefix(dir, root) {
		if err := os.Remove(dir); err != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}

// restore puts prev's files back and drops files only next brought in.
// It is the mechanical part of a rollback (manifests are handled by the
// caller).
func (m *Manager) restore(prev, next *bundle.Manifest) error {
	if prev == nil {
		prev = &bundle.Manifest{}
	}
	have := prev.Index()
	var firstErr error
	for _, f := range prev.Files {
		target := m.Target(f.Path)
		if fi, err := os.Stat(target); err == nil && fi.Size() == f.Size {
			if cur, ok := next.Index()[f.Path]; ok && cur.SHA256 == f.SHA256 {
				continue
			}
		}
		if err := m.placeOne(m.casPath(f.SHA256), target); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("restore %s: %w", f.Path, err)
		}
	}
	var drop []string
	for _, f := range next.Files {
		if _, ok := have[f.Path]; !ok {
			drop = append(drop, f.Path)
		}
	}
	m.removeAll(drop)
	return firstErr
}

// rollback restores prev's files and manifests after a failed reload; the
// failed manifest is kept as manifest.failed.json for support bundles.
func (m *Manager) rollback(prev, next *bundle.Manifest) error {
	err := m.restore(prev, next)
	if werr := m.writeManifestFile(filepath.Join(m.bundleDir(), "manifest.failed.json"), next); werr != nil && err == nil {
		err = werr
	}
	if werr := m.writeManifestFile(m.manifestPath(), prev); werr != nil && err == nil {
		err = werr
	}
	_ = os.Remove(m.prevManifestPath())
	return err
}

func (m *Manager) writeManifests(prev, next *bundle.Manifest) error {
	if prev != nil {
		if err := m.writeManifestFile(m.prevManifestPath(), prev); err != nil {
			return err
		}
	}
	return m.writeManifestFile(m.manifestPath(), next)
}

func (m *Manager) writeManifestFile(path string, mf *bundle.Manifest) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := bundle.EncodeManifest(mf)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// gc drops store entries no retained manifest references.
func (m *Manager) gc(keep ...*bundle.Manifest) {
	live := map[string]bool{}
	for _, mf := range keep {
		if mf == nil {
			continue
		}
		for _, f := range mf.Files {
			live[f.SHA256] = true
		}
	}
	entries, err := os.ReadDir(m.casDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if !live[e.Name()] {
			_ = os.Remove(filepath.Join(m.casDir(), e.Name()))
		}
	}
}

// ReloadVTs waits for ospd to report the feed that is on disk (the
// reload_vts directive). want "" means the installed bundle's feed.
func (m *Manager) ReloadVTs(ctx context.Context, want string) error {
	m.init()
	if m.OSP == nil {
		return errors.New("reload_vts: no engine on this host")
	}
	if want == "" {
		if mf, _ := m.Installed(); mf != nil {
			want = mf.FeedVersion
		}
	}
	if want == "" && m.PluginsDir != "" {
		if fh, err := os.Open(filepath.Join(m.PluginsDir, bundle.FeedInfoFile)); err == nil {
			want = bundle.ParseFeedVersion(fh)
			_ = fh.Close()
		}
	}
	if want == "" {
		return errors.New("reload_vts: no feed version to wait for")
	}
	return m.waitFeed(ctx, want)
}

// waitFeed polls ospd until it reports want with the VT cache loaded.
func (m *Manager) waitFeed(ctx context.Context, want string) error {
	deadline := m.Now().Add(m.ReloadTimeout)
	var absentSince time.Time
	last := ""
	for {
		pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		h := m.OSP.Health(pctx)
		cancel()
		switch {
		case h.Error == "ospd socket absent":
			if absentSince.IsZero() {
				absentSince = m.Now()
			} else if m.Now().Sub(absentSince) >= noEngineGrace {
				m.Log.Warn("no ospd socket; skipping the VT reload wait", "want", want)
				return nil
			}
		case h.OSPDUp && h.VTCacheLoaded && h.FeedVersion == want:
			m.Log.Info("ospd loaded feed", "feed", want, "vts", h.VTCount)
			return nil
		default:
			absentSince = time.Time{}
			if h.FeedVersion != last {
				m.Log.Info("waiting for ospd to load feed", "want", want, "reports", h.FeedVersion, "cache_loaded", h.VTCacheLoaded)
				last = h.FeedVersion
			}
		}
		if m.Now().After(deadline) {
			return fmt.Errorf("ospd did not load feed %s within %s (reports %q, cache_loaded=%v)", want, m.ReloadTimeout, h.FeedVersion, h.VTCacheLoaded)
		}
		t := time.NewTimer(m.ReloadPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
