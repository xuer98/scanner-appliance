package main

// Phase 3 operations (PLAN §13, §14, §17.3): the release signing key, the
// daily bundle build from the feed mirror, publishing bundles and daemon
// releases through the admin API, and rollout control.

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/bundle"
	"github.com/tprm/scanner-appliance/internal/scanconfig"
	"gopkg.in/yaml.v3"
)

// DefaultFeedSource is the Greenbone Community Feed rsync module (PLAN §17.3).
const DefaultFeedSource = "rsync://feed.community.greenbone.net/community/vulnerability-feed/22.04/vt-data/nasl/"

var defaultFragilePorts = []int{9100, 515, 631, 161, 502, 44818}

// ensureReleaseKeys loads pki-dir/release-pub.pem, creating the key pair
// when allowed. nil,nil means "no key" (publishing disabled).
func ensureReleaseKeys(pkiDir string, create bool, log *slog.Logger) ([]*ecdsa.PublicKey, error) {
	pub := filepath.Join(pkiDir, "release-pub.pem")
	keys, err := bundle.LoadPublicKeys(pub)
	if err == nil {
		return keys, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("release key: %w", err)
	}
	if !create {
		return nil, nil
	}
	k, err := bundle.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := bundle.SavePrivate(filepath.Join(pkiDir, "release-key.pem"), k); err != nil {
		return nil, err
	}
	if err := bundle.SavePublic(pub, &k.PublicKey); err != nil {
		return nil, err
	}
	log.Info("generated release signing key", "private", filepath.Join(pkiDir, "release-key.pem"), "public", pub)
	return []*ecdsa.PublicKey{&k.PublicKey}, nil
}

// ---- cp-api bundle build ----

func bundleCmd(args []string) error {
	if len(args) < 1 || args[0] != "build" {
		return errors.New("usage: cp-api bundle build --out DIR [--feed DIR] [--configs DIR] [--nuclei-templates DIR [--nuclei BIN]] [--fragile-ports 9100,...] [--version V] --key release-key.pem")
	}
	fs := flag.NewFlagSet("bundle build", flag.ContinueOnError)
	out := fs.String("out", "", "output directory (manifest.json, manifest.sig, root/)")
	feed := fs.String("feed", "", "VT feed tree (directory holding plugin_feed_info.inc), e.g. the rsync mirror")
	configs := fs.String("configs", "", "directory of scan config JSON files (default: the shipped inventory/full)")
	templates := fs.String("nuclei-templates", "", "nuclei templates checkout to filter and ship (http templates without dos/fuzz/intrusive tags)")
	nucleiBin := fs.String("nuclei", os.Getenv("CP_NUCLEI"), "nuclei binary of the version the appliance image carries: templates it cannot load are left out")
	fragile := fs.String("fragile-ports", "", "comma-separated default fragile-device ports (default 9100,515,631,161,502,44818)")
	ver := fs.String("version", "", "bundle version (default: UTC timestamp)")
	key := fs.String("key", envOr("CP_RELEASE_KEY", "dev/pki/release-key.pem"), "release signing key PEM")
	excl := fs.String("exclude-tags", "dos,fuzz,intrusive", "nuclei template tags to drop")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out required")
	}
	if *ver == "" {
		*ver = time.Now().UTC().Format("20060102T150405Z")
	}
	if !bundle.ValidVersion(*ver) {
		return fmt.Errorf("bad version %q", *ver)
	}
	priv, err := bundle.LoadPrivate(*key)
	if err != nil {
		return fmt.Errorf("release key: %w", err)
	}
	root := filepath.Join(*out, "root")
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	summary := map[string]any{"version": *ver, "out": *out}
	if *feed != "" {
		// Greenbone's own checksum list stays with the mirror, where feed
		// sync checked it (bundle.FeedChecksumFiles).
		n, err := linkTree(*feed, filepath.Join(root, bundle.FeedDir), bundle.FeedChecksumFiles...)
		if err != nil {
			return fmt.Errorf("feed: %w", err)
		}
		summary["feed_files"] = n
	}
	cfgDir := filepath.Join(root, bundle.ConfigsDir)
	if *configs != "" {
		loaded, err := scanconfig.Load(*configs)
		if err != nil {
			return err
		}
		if _, err := linkTree(*configs, cfgDir); err != nil {
			return err
		}
		summary["configs"] = len(loaded)
	} else {
		if err := scanconfig.WriteDefaults(cfgDir); err != nil {
			return err
		}
		summary["configs"] = len(scanconfig.Defaults())
	}
	if *templates != "" {
		dst := filepath.Join(root, bundle.TemplatesDir)
		set, err := filterTemplates(*templates, dst, splitCSV(*excl))
		if err != nil {
			return fmt.Errorf("nuclei templates: %w", err)
		}
		if *nucleiBin != "" {
			if err := validateTemplates(*nucleiBin, dst, set); err != nil {
				return fmt.Errorf("nuclei templates: %w", err)
			}
		} else {
			fmt.Fprintln(os.Stderr, "[bundle] WARNING: no --nuclei: the templates were not checked with the appliance's nuclei; one that does not load there is skipped, and each web job reports how many were")
		}
		if set.Kept == 0 {
			// An appliance would take every template off its disk.
			return fmt.Errorf("nuclei templates: none of the templates in %s is shipped", *templates)
		}
		total := 0
		for _, n := range set.Dropped {
			total += n
		}
		summary["templates"] = set.Kept
		summary["template_helpers"] = set.Helpers()
		summary["templates_validated"] = *nucleiBin != ""
		summary["templates_dropped"] = total
		summary["templates_dropped_by"] = set.Dropped
	}
	ports := defaultFragilePorts
	if *fragile != "" {
		ports = nil
		for _, p := range splitCSV(*fragile) {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("bad fragile port %q", p)
			}
			ports = append(ports, n)
		}
	}
	fb, _ := json.Marshal(ports)
	if err := os.WriteFile(filepath.Join(root, bundle.FragileFile), append(fb, '\n'), 0o644); err != nil {
		return err
	}
	m, err := bundle.Build(root, *ver, time.Now())
	if err != nil {
		return err
	}
	if *feed != "" && m.FeedVersion == "" {
		// An appliance would take every feed file off its disk for a tree
		// the engine can never load, and roll back half an hour later.
		return fmt.Errorf("feed: %s has no %s that names a PLUGIN_SET: not a feed tree", *feed, bundle.FeedInfoFile)
	}
	mb, err := bundle.EncodeManifest(m)
	if err != nil {
		return err
	}
	sig, err := bundle.Sign(mb, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "manifest.json"), mb, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "manifest.sig"), []byte(sig+"\n"), 0o644); err != nil {
		return err
	}
	summary["feed_version"] = m.FeedVersion
	summary["files"] = len(m.Files)
	summary["bytes"] = m.Bytes()
	summary["sha256"] = bundle.SHA256Hex(mb)
	b, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(b))
	return nil
}

// linkTree mirrors src into dst by hard link (copy when that fails),
// skipping dotfiles and the files named in skip, which are paths below
// src; returns the file count.
func linkTree(src, dst string, skip ...string) (int, error) {
	n := 0
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "." {
			return nil
		}
		if slices.Contains(skip, filepath.ToSlash(rel)) {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.Link(p, target); err != nil {
			if err := copyPath(p, target); err != nil {
				return err
			}
		}
		n++
		return nil
	})
	return n, err
}

func copyPath(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// templateHead is the part of a nuclei template we filter on.
type templateHead struct {
	ID   string `yaml:"id"`
	Info struct {
		Tags any `yaml:"tags"`
	} `yaml:"info"`
	HTTP          any  `yaml:"http"`
	Requests      any  `yaml:"requests"` // legacy name of http
	SelfContained bool `yaml:"self-contained"`
}

// templateKeys are the top-level keys of a template that are not a
// protocol section. Any other key (tcp, dns, javascript, code, headless,
// ssl, websocket, ...) makes nuclei speak something other than HTTP, and
// on ports the scan did not pin. Unknown keys count as a protocol, so a
// new upstream section is dropped until it is listed here.
var templateKeys = map[string]bool{
	"id": true, "info": true, "http": true, "requests": true, "variables": true, "constants": true,
	"flow": true, "stop-at-first-match": true, "signature": true, "self-contained": true,
}

// templateDrop names why a template is left out of the bundle, "" to keep
// it. The web add-on promises HTTP checks against the target only.
func templateDrop(b []byte, exclude map[string]bool) string {
	var h templateHead
	if err := yaml.Unmarshal(b, &h); err != nil || h.ID == "" || (h.HTTP == nil && h.Requests == nil) {
		return "not_http"
	}
	var top map[string]any
	if err := yaml.Unmarshal(b, &top); err != nil {
		return "not_http"
	}
	for k := range top {
		if !templateKeys[k] {
			return "other_protocol"
		}
	}
	if h.SelfContained {
		// Self-contained templates call third-party services, not the target.
		return "self_contained"
	}
	for _, section := range []any{h.HTTP, h.Requests} {
		reqs, _ := section.([]any)
		for _, r := range reqs {
			if m, ok := r.(map[string]any); ok && m["fuzzing"] != nil {
				return "fuzzing"
			}
		}
	}
	for _, t := range templateTags(h.Info.Tags) {
		if exclude[strings.ToLower(t)] {
			return "excluded_tag"
		}
	}
	return ""
}

func templateTags(v any) []string {
	switch t := v.(type) {
	case string:
		return splitCSV(t)
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

// filterTemplates copies the templates that only speak HTTP to the target
// and carry none of the excluded tags (PLAN §13: dos, fuzz, intrusive
// removed), together with the helper files they name. Dropped counts the
// rest by reason (see templateDrop; missing_helper is a template whose
// helper file is not in the checkout).
func filterTemplates(src, dst string, exclude []string) (*templateSet, error) {
	ex := map[string]bool{}
	for _, e := range exclude {
		ex[strings.ToLower(strings.TrimSpace(e))] = true
	}
	set := &templateSet{Dropped: map[string]int{}, uses: map[string][]string{}, users: map[string]int{}}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && p != src {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if why := templateDrop(b, ex); why != "" {
			set.Dropped[why]++
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		rel = filepath.ToSlash(rel)
		var helpers []string
		for _, ref := range templateHelpers(b) {
			h, ok := resolveHelper(src, rel, ref)
			if !ok {
				set.Dropped["missing_helper"]++
				return nil
			}
			helpers = append(helpers, h)
		}
		for _, h := range helpers {
			if set.users[h] == 0 {
				if err := copyInto(filepath.Join(src, filepath.FromSlash(h)), filepath.Join(dst, filepath.FromSlash(h))); err != nil {
					return err
				}
			}
			set.users[h]++
		}
		target := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target, b, 0o644); err != nil {
			return err
		}
		set.uses[rel] = helpers
		set.Kept++
		return nil
	})
	return set, err
}

// ---- cp-api feed sync ----

func feedCmd(args []string) error {
	if len(args) < 1 || args[0] != "sync" {
		return errors.New("usage: cp-api feed sync --dest DIR [--source rsync://...] [--gpg-keyring FILE] [--no-verify]")
	}
	fs := flag.NewFlagSet("feed sync", flag.ContinueOnError)
	dest := fs.String("dest", "", "local mirror directory (becomes the --feed of bundle build)")
	source := fs.String("source", envOr("CP_FEED_SOURCE", DefaultFeedSource), "rsync source")
	rsyncBin := fs.String("rsync", "rsync", "rsync binary")
	keyring := fs.String("gpg-keyring", os.Getenv("CP_FEED_GPG_KEYRING"), "GPG keyring holding the Greenbone feed signing key (verifies sha256sums.asc)")
	noVerify := fs.Bool("no-verify", false, "skip the sha256sums / signature check")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dest == "" {
		return errors.New("--dest required")
	}
	if err := os.MkdirAll(*dest, 0o755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	cmd := exec.CommandContext(ctx, *rsyncBin, "-ltrz", "--delete", "--timeout=600", "--stats", *source, strings.TrimRight(*dest, "/")+"/")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	fmt.Fprintf(os.Stderr, "[feed] rsync %s -> %s\n", *source, *dest)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rsync: %w", err)
	}
	if !*noVerify {
		if err := verifyFeed(*dest, *keyring); err != nil {
			return err
		}
	}
	ver := ""
	if fh, err := os.Open(filepath.Join(*dest, bundle.FeedInfoFile)); err == nil {
		ver = bundle.ParseFeedVersion(fh)
		_ = fh.Close()
	}
	fmt.Printf("{\"feed_version\": %q, \"dest\": %q}\n", ver, *dest)
	return nil
}

// verifyFeed checks the sha256sums file Greenbone ships and, when gpg and
// a keyring are available, its detached signature.
func verifyFeed(dir, keyring string) error {
	sums := filepath.Join(dir, "sha256sums")
	b, err := os.ReadFile(sums)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "[feed] WARNING: no sha256sums in the mirror; integrity not verified")
		return nil
	}
	if err != nil {
		return err
	}
	if asc := sums + ".asc"; keyring != "" {
		if _, err := exec.LookPath("gpg"); err != nil {
			fmt.Fprintln(os.Stderr, "[feed] WARNING: gpg not installed; feed signature not verified")
		} else if _, err := os.Stat(asc); err == nil {
			out, err := exec.Command("gpg", "--no-default-keyring", "--keyring", keyring, "--verify", asc, sums).CombinedOutput()
			if err != nil {
				return fmt.Errorf("feed signature: %v: %s", err, strings.TrimSpace(string(out)))
			}
			fmt.Fprintln(os.Stderr, "[feed] sha256sums signature verified")
		}
	} else {
		fmt.Fprintln(os.Stderr, "[feed] WARNING: no --gpg-keyring; feed signature not verified")
	}
	bad, checked := 0, 0
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		want, rel := strings.ToLower(fields[0]), strings.TrimPrefix(fields[len(fields)-1], "./")
		if strings.Contains(rel, "..") {
			continue
		}
		got, _, err := bundle.HashFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil || got != want {
			bad++
			if bad <= 5 {
				fmt.Fprintf(os.Stderr, "[feed] mismatch: %s\n", rel)
			}
		}
		checked++
	}
	if bad > 0 {
		return fmt.Errorf("feed integrity: %d of %d files do not match sha256sums", bad, checked)
	}
	fmt.Fprintf(os.Stderr, "[feed] %d files match sha256sums\n", checked)
	return nil
}

// ---- admin publish / rollout helpers ----

type rawCaller func(method, path string, body io.Reader, headers map[string]string) (int, []byte, error)

// publishBundleDir uploads the files a bundle directory (from `bundle
// build`) that the server lacks, then publishes the signed manifest.
func publishBundleDir(call rawCaller, dir string, canaryHours float64) (int, []byte, error) {
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return 0, nil, err
	}
	sigB, err := os.ReadFile(filepath.Join(dir, "manifest.sig"))
	if err != nil {
		return 0, nil, err
	}
	m, err := bundle.DecodeManifest(mb)
	if err != nil {
		return 0, nil, err
	}
	byDigest := map[string]bundle.File{}
	var shas []string
	for _, f := range m.Files {
		if _, ok := byDigest[f.SHA256]; !ok {
			shas = append(shas, f.SHA256)
		}
		byDigest[f.SHA256] = f
	}
	fmt.Fprintf(os.Stderr, "[publish] bundle %s: %d files, %d bytes\n", m.Version, len(m.Files), m.Bytes())
	uploaded := 0
	for i := 0; i < len(shas); i += 5000 {
		j := min(i+5000, len(shas))
		reqBody, _ := json.Marshal(v1.AdminMissingFilesRequest{SHA256: shas[i:j]})
		st, out, err := call("POST", "/admin/bundles/missing", strings.NewReader(string(reqBody)), map[string]string{"Content-Type": "application/json"})
		if err != nil {
			return st, out, err
		}
		if st != 200 {
			return st, out, fmt.Errorf("missing-files query: http %d", st)
		}
		var missing v1.AdminMissingFilesResponse
		_ = json.Unmarshal(out, &missing)
		for _, sha := range missing.Missing {
			f := byDigest[sha]
			fh, err := os.Open(filepath.Join(dir, "root", filepath.FromSlash(f.Path)))
			if err != nil {
				return 0, nil, err
			}
			st, out, err := call("PUT", "/admin/bundles/files/"+sha, fh, map[string]string{"Content-Type": "application/octet-stream"})
			_ = fh.Close()
			if err != nil {
				return st, out, err
			}
			if st != 201 {
				return st, out, fmt.Errorf("upload %s: http %d: %s", f.Path, st, strings.TrimSpace(string(out)))
			}
			uploaded++
			if uploaded%500 == 0 {
				fmt.Fprintf(os.Stderr, "[publish] uploaded %d files\n", uploaded)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "[publish] uploaded %d new files; publishing manifest\n", uploaded)
	req, _ := json.Marshal(v1.AdminPublishBundleRequest{Manifest: mb, Sig: strings.TrimSpace(string(sigB)), CanaryHours: canaryHours})
	st, out, err := call("POST", "/admin/bundles", strings.NewReader(string(req)), map[string]string{"Content-Type": "application/json"})
	if err == nil && st == http.StatusOK {
		// Not an error: a day without a new feed ends here.
		var res v1.AdminPublishBundleResponse
		if json.Unmarshal(out, &res) == nil && res.Unchanged {
			fmt.Fprintf(os.Stderr, "[publish] nothing published: bundle %s (%s, feed %s) already carries exactly these files\n", res.Version, res.Status, res.FeedVersion)
		}
	}
	return st, out, err
}

// publishRelease signs an artifact with the release key and uploads it.
func publishRelease(call rawCaller, file, component, version, keyPath string, canaryHours float64) (int, []byte, error) {
	priv, err := bundle.LoadPrivate(keyPath)
	if err != nil {
		return 0, nil, fmt.Errorf("release key: %w", err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return 0, nil, err
	}
	sig, err := bundle.Sign(b, priv)
	if err != nil {
		return 0, nil, err
	}
	headers := map[string]string{"Content-Type": "application/octet-stream", v1.HeaderReleaseSHA256: bundle.SHA256Hex(b), v1.HeaderReleaseSig: sig}
	if canaryHours > 0 {
		headers[v1.HeaderCanaryHours] = strconv.FormatFloat(canaryHours, 'f', -1, 64)
	}
	return call("PUT", "/admin/releases/"+component+"/"+version, strings.NewReader(string(b)), headers)
}

// parseLANRoutes reads "10.31.0.0/16@10.30.5.1,10.32.0.0/16@10.30.5.1".
func parseLANRoutes(s string) ([]v1.LANRoute, error) {
	var out []v1.LANRoute
	for _, item := range splitCSV(s) {
		cidr, via, ok := strings.Cut(item, "@")
		if !ok {
			return nil, fmt.Errorf("lan route %q: want CIDR@gateway", item)
		}
		out = append(out, v1.LANRoute{CIDR: cidr, Via: via})
	}
	return out, nil
}

var _ = http.MethodPut
