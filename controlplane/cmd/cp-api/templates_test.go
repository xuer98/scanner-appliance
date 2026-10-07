package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	v1 "github.com/tprm/scanner-appliance/api/v1"
	"github.com/tprm/scanner-appliance/internal/bundle"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func listFiles(t *testing.T, root string) string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return strings.Join(out, " ")
}

// tpl is a template with one GET request and the given payloads block.
func tpl(id, tags, payloads string) string {
	s := "id: " + id + "\ninfo:\n  name: n\n  severity: high\n  tags: " + tags + "\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/{{p}}\"\n"
	if payloads != "" {
		s += "    payloads:\n" + payloads
	}
	return s
}

// A template may read its values from a helper file. Shipped without the
// file it does not load, and nuclei skips it with one line on stderr: with
// the real set (v10.5.0) that was 244 of 10,064 templates, six of them in
// the set a default job runs.
func TestTemplateHelpersAreShipped(t *testing.T) {
	base, dst, outside := t.TempDir(), t.TempDir(), t.TempDir()
	src := filepath.Join(base, "nuclei-templates")
	// What "../../etc/hostname" names from http/escape.yaml: a real file,
	// one directory above the templates.
	writeFiles(t, base, map[string]string{"etc/hostname": "build host"})
	writeFiles(t, src, map[string]string{
		// Named from the root of the templates, as upstream does.
		"http/technologies/wordpress/plugins/akismet.yaml": tpl("akismet", "tech", "      last_version: helpers/wordpress/plugins/akismet.txt\n"),
		"helpers/wordpress/plugins/akismet.txt":            "5.3\n",
		// A file and a list of values in one template.
		"http/cves/2021/grafana.yaml":           tpl("grafana", "cve", "      slug: helpers/wordlists/grafana-plugins.txt\n      n:\n        - 1\n        - 2\n"),
		"helpers/wordlists/grafana-plugins.txt": "alertlist\n",
		// Next to the template, and in a directory above it.
		"http/cves/2019/zabbix.yaml": tpl("zabbix", "cve", "      ids: ids.txt\n"),
		"http/cves/2019/ids.txt":     "1\n2\n",
		"http/cves/2019/parent.yaml": tpl("parent", "cve", "      x: lists/shared.txt\n"),
		"http/lists/shared.txt":      "a\n",
		// Two templates, one file.
		"http/cves/2024/gallery.yaml":   tpl("gallery", "cve", "      path: helpers/wordlists/numbers.txt\n"),
		"http/misconfig/gitlab.yaml":    tpl("gitlab", "enum", "      uid: helpers/wordlists/numbers.txt\n"),
		"helpers/wordlists/numbers.txt": "0\n1\n",
		// Lines of text are the values themselves, not a file.
		"http/inline.yaml": tpl("inline", "cve", "      p: |\n        one\n        two\n"),
		// Not shipped: the file is not there, the name is a directory, or
		// it leaves the tree.
		"http/missing.yaml":  tpl("missing", "cve", "      p: helpers/wordlists/gone.txt\n"),
		"http/dir.yaml":      tpl("dir", "cve", "      p: helpers/wordlists\n"),
		"http/escape.yaml":   tpl("escape", "cve", "      p: ../../etc/hostname\n"),
		"http/absolute.yaml": tpl("absolute", "cve", "      p: "+filepath.ToSlash(filepath.Join(outside, "secret.txt"))+"\n"),
		// A helper nobody ships a template for stays behind.
		"helpers/wordlists/unused.txt":         "x\n",
		"http/intrusive.yaml":                  tpl("intrusive", "cve,intrusive", "      p: helpers/wordlists/intrusive-only.txt\n"),
		"helpers/wordlists/intrusive-only.txt": "x\n",
	})
	writeFiles(t, outside, map[string]string{"secret.txt": "release key"})
	want := "helpers/wordlists/grafana-plugins.txt helpers/wordlists/numbers.txt helpers/wordpress/plugins/akismet.txt " +
		"http/cves/2019/ids.txt http/cves/2019/parent.yaml http/cves/2019/zabbix.yaml http/cves/2021/grafana.yaml http/cves/2024/gallery.yaml " +
		"http/inline.yaml http/lists/shared.txt http/misconfig/gitlab.yaml http/technologies/wordpress/plugins/akismet.yaml"
	wantDropped := map[string]int{"missing_helper": 4, "excluded_tag": 1}
	// A link out of the tree would put a file of the build host into the
	// bundle, and from there onto every appliance.
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(src, "helpers", "link.txt")); err == nil {
		writeFiles(t, src, map[string]string{"http/link.yaml": tpl("link", "cve", "      p: helpers/link.txt\n")})
		wantDropped["missing_helper"]++
	}

	set, err := filterTemplates(src, dst, []string{"dos", "fuzz", "intrusive"})
	if err != nil {
		t.Fatal(err)
	}
	if got := listFiles(t, dst); got != want {
		t.Fatalf("shipped:\n %s\nwant:\n %s", got, want)
	}
	if set.Kept != 7 || set.Helpers() != 5 {
		t.Fatalf("kept %d templates and %d helper files, want 7 and 5", set.Kept, set.Helpers())
	}
	for why, n := range wantDropped {
		if set.Dropped[why] != n {
			t.Fatalf("dropped[%s] = %d, want %d (all: %v)", why, set.Dropped[why], n, set.Dropped)
		}
	}
	if len(set.Dropped) != len(wantDropped) {
		t.Fatalf("drop reasons: %v", set.Dropped)
	}
}

// fakeNuclei stands in for `nuclei -validate`: a template whose text holds
// BROKEN does not load. It logs its arguments and its HOME.
func fakeNuclei(t *testing.T, logDir, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake is a POSIX shell script")
	}
	if body == "" {
		body = `dir=""
while [ $# -gt 0 ]; do [ "$1" = "-templates" ] && dir="$2"; shift; done
bad=0
for f in $(grep -rl BROKEN "$dir" --include='*.yaml'); do
  echo "[ERR] Error occurred parsing template $f: could not compile request: could not compile operators: Cannot transition token types from STRING [] to VARIABLE [models]" >&2
  bad=1
done
if [ $bad = 1 ]; then echo "[FTL] Could not validate templates: errors occurred during template validation" >&2; exit 1; fi
echo "[INF] All templates validated successfully" >&2
`
	}
	p := filepath.Join(t.TempDir(), "nuclei")
	script := "#!/bin/sh\necho \"$@\" >> \"" + logDir + "/args\"\necho \"$HOME\" >> \"" + logDir + "/home\"\n" + body
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// What loads depends on the nuclei version: eight templates of v10.5.0 do
// not compile on the image's v3.4.10. The build asks that nuclei and leaves
// those out, so the appliance does not skip them unseen.
func TestTemplatesAreValidated(t *testing.T) {
	logDir := t.TempDir()
	nuclei := fakeNuclei(t, logDir, "")
	build := func(good, broken int) (string, *templateSet) {
		t.Helper()
		src, dst := t.TempDir(), t.TempDir()
		files := map[string]string{"helpers/shared.txt": "1\n", "helpers/only-broken.txt": "1\n"}
		for i := 0; i < good; i++ {
			files["http/good/g"+string(rune('a'+i%26))+string(rune('a'+i/26))+".yaml"] = tpl("good", "cve", "      p: helpers/shared.txt\n")
		}
		for i := 0; i < broken; i++ {
			files["http/cves/2026/b"+string(rune('a'+i))+".yaml"] = tpl("bad", "cve", "      p: helpers/shared.txt\n      q: helpers/only-broken.txt\n") + "# BROKEN\n"
		}
		writeFiles(t, src, files)
		set, err := filterTemplates(src, dst, nil)
		if err != nil {
			t.Fatal(err)
		}
		return dst, set
	}

	// Two of fifty do not load: they go, and so does the helper only they used.
	dst, set := build(48, 2)
	if set.Kept != 50 || set.Helpers() != 2 {
		t.Fatalf("before validation: %d templates, %d helpers", set.Kept, set.Helpers())
	}
	if err := validateTemplates(nuclei, dst, set); err != nil {
		t.Fatal(err)
	}
	left := listFiles(t, dst)
	if set.Kept != 48 || set.Dropped["does_not_load"] != 2 || set.Helpers() != 1 || strings.Contains(left, "2026") || strings.Contains(left, "only-broken") || !strings.Contains(left, "helpers/shared.txt") {
		t.Fatalf("after validation: kept=%d dropped=%v helpers=%d files: %s", set.Kept, set.Dropped, set.Helpers(), left)
	}
	// It ran twice, the second time to confirm, with the bundle's directory
	// as nuclei's template directory and a home of its own.
	args := strings.Split(strings.TrimSpace(readFile(t, filepath.Join(logDir, "args"))), "\n")
	abs, _ := filepath.Abs(dst)
	if len(args) != 2 || !strings.Contains(args[0]+" ", "-validate ") || !strings.Contains(args[0]+" ", "-templates "+abs+" ") || !strings.Contains(args[0]+" ", "-update-template-dir "+abs+" ") {
		t.Fatalf("nuclei runs: %q", args)
	}
	if home, _ := os.UserHomeDir(); strings.Contains(readFile(t, filepath.Join(logDir, "home")), home+"\n") {
		t.Fatal("nuclei ran in the builder's home directory")
	}

	// All of them load: nothing changes.
	dst, set = build(10, 0)
	if err := validateTemplates(nuclei, dst, set); err != nil || set.Kept != 10 || len(set.Dropped) != 0 {
		t.Fatalf("clean set: %v kept=%d dropped=%v", err, set.Kept, set.Dropped)
	}
	// A third of them do not load: that is the wrong nuclei, not a few
	// templates ahead of it. The build stops and ships nothing.
	dst, set = build(20, 10)
	if err := validateTemplates(nuclei, dst, set); err == nil || !strings.Contains(err.Error(), "10 of 30") {
		t.Fatalf("mass failure: %v", err)
	}
	if set.Kept != 30 || !strings.Contains(listFiles(t, dst), "2026") {
		t.Fatal("templates were removed although the build was refused")
	}

	// Anything this does not understand stops the build as well.
	for name, body := range map[string]string{
		"not nuclei":               "exit 0\n",
		"fails without a template": "echo '[FTL] could not create runner' >&2; exit 2\n",
		"names an unknown file":    "dir=\"\"; while [ $# -gt 0 ]; do [ \"$1\" = \"-templates\" ] && dir=\"$2\"; shift; done\necho \"[ERR] Error occurred parsing template $dir/http/none.yaml: x\" >&2; exit 1\n",
		"names a file elsewhere":   "echo '[ERR] Error occurred parsing template /etc/hostname: x' >&2; exit 1\n",
		"never satisfied":          "dir=\"\"; while [ $# -gt 0 ]; do [ \"$1\" = \"-templates\" ] && dir=\"$2\"; shift; done\nf=$(ls \"$dir\"/http/good/*.yaml | head -1)\necho \"[ERR] Error occurred parsing template $f: x\" >&2; exit 1\n",
	} {
		dst, set = build(40, 0)
		if err := validateTemplates(fakeNuclei(t, t.TempDir(), body), dst, set); err == nil {
			t.Fatalf("%s: the build went on", name)
		}
	}
	if err := validateTemplates(filepath.Join(t.TempDir(), "no-such-nuclei"), dst, set); err == nil {
		t.Fatal("a missing nuclei binary went unnoticed")
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runBundleBuild runs `cp-api bundle build` and returns its summary.
func runBundleBuild(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	out, err := os.CreateTemp(t.TempDir(), "summary")
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = out
	err = bundleCmd(append([]string{"build"}, args...))
	os.Stdout = stdout
	_ = out.Close()
	var summary map[string]any
	_ = json.Unmarshal([]byte(readFile(t, out.Name())), &summary)
	return summary, err
}

// Greenbone's own checksum list names every script of the feed, so it
// changes with every release: 10.6 MB of a daily update whose scripts came
// to 0.35 MB. The engine on the appliance never reads it. It stays with
// the mirror, where feed sync checked the feed against it.
func TestBundleBuildLeavesOutTheFeedChecksumList(t *testing.T) {
	work := t.TempDir()
	key, err := bundle.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(work, "release-key.pem")
	if err := bundle.SavePrivate(keyFile, key); err != nil {
		t.Fatal(err)
	}
	feed := filepath.Join(work, "feed")
	writeFiles(t, feed, map[string]string{
		"plugin_feed_info.inc": "PLUGIN_SET = \"202610070608\";\n",
		"a.nasl":               "a",
		"2026/b.nasl":          "b",
		"sha256sums":           "0000  a.nasl\n",
		"sha256sums.asc":       "-----BEGIN PGP SIGNATURE-----\n",
		"2026/sha256sums":      "a script may have any name below the top",
	})
	out := filepath.Join(work, "out")
	summary, err := runBundleBuild(t, "--out", out, "--feed", feed, "--key", keyFile, "--version", "20261007T110000Z")
	if err != nil {
		t.Fatal(err)
	}
	mb := []byte(readFile(t, filepath.Join(out, "manifest.json")))
	m, err := bundle.DecodeManifest(mb)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range m.Files {
		if strings.HasPrefix(f.Path, bundle.FeedDir+"/") {
			paths = append(paths, f.Path)
		}
	}
	if got := strings.Join(paths, " "); got != "nasl/2026/b.nasl nasl/2026/sha256sums nasl/a.nasl nasl/plugin_feed_info.inc" {
		t.Fatalf("feed files in the bundle: %s", got)
	}
	if m.FeedVersion != "202610070608" || summary["feed_files"] != float64(4) || summary["feed_version"] != "202610070608" {
		t.Fatalf("feed version %q, summary %v", m.FeedVersion, summary)
	}
	if err := bundle.Verify(mb, readFile(t, filepath.Join(out, "manifest.sig")), nil); err == nil {
		t.Fatal("signature verified without a key")
	}
	if err := bundle.Verify(mb, readFile(t, filepath.Join(out, "manifest.sig")), bundle.ParsePublicKeys(bundle.EncodePublic(&key.PublicKey))); err != nil {
		t.Fatalf("manifest signature: %v", err)
	}
	// The mirror keeps its list.
	if _, err := os.Stat(filepath.Join(feed, "sha256sums")); err != nil {
		t.Fatal("the checksum list was taken from the mirror")
	}

	// A directory that is not a feed tree would empty the feed of every
	// appliance that took the bundle.
	notFeed := filepath.Join(work, "not-a-feed")
	writeFiles(t, notFeed, map[string]string{"a.nasl": "a"})
	if _, err := runBundleBuild(t, "--out", filepath.Join(work, "out2"), "--feed", notFeed, "--key", keyFile); err == nil || !strings.Contains(err.Error(), "PLUGIN_SET") {
		t.Fatalf("a tree without a feed version was built into a bundle: %v", err)
	}
	// So would a templates directory none of which is shipped.
	empty := filepath.Join(work, "no-templates")
	writeFiles(t, empty, map[string]string{"README.md": "x", "dns/only.yaml": "id: d\ndns:\n  - name: x\n"})
	if _, err := runBundleBuild(t, "--out", filepath.Join(work, "out3"), "--nuclei-templates", empty, "--key", keyFile); err == nil || !strings.Contains(err.Error(), "none of the templates") {
		t.Fatalf("a bundle without templates was built from a templates directory: %v", err)
	}

	// Templates: helper files and the validation show in the summary.
	if runtime.GOOS == "windows" {
		return
	}
	tpls := filepath.Join(work, "templates")
	files := map[string]string{"helpers/wordlists/numbers.txt": "0\n", "http/cves/2026/late.yaml": tpl("late", "cve", "") + "# BROKEN\n"}
	for i := 0; i < 30; i++ {
		files["http/cves/2024/c"+string(rune('a'+i))+".yaml"] = tpl("c", "cve", "      p: helpers/wordlists/numbers.txt\n")
	}
	writeFiles(t, tpls, files)
	out4 := filepath.Join(work, "out4")
	summary, err = runBundleBuild(t, "--out", out4, "--nuclei-templates", tpls, "--nuclei", fakeNuclei(t, t.TempDir(), ""), "--key", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	by, _ := summary["templates_dropped_by"].(map[string]any)
	if summary["templates"] != float64(30) || summary["template_helpers"] != float64(1) || summary["templates_validated"] != true || by["does_not_load"] != float64(1) {
		t.Fatalf("summary: %v", summary)
	}
	shipped := listFiles(t, filepath.Join(out4, "root", bundle.TemplatesDir))
	if strings.Contains(shipped, "late.yaml") || !strings.Contains(shipped, "helpers/wordlists/numbers.txt") {
		t.Fatalf("templates in the bundle: %s", shipped)
	}
	// Without --nuclei the template that does not load is shipped, and the
	// summary says the set was not validated.
	summary, err = runBundleBuild(t, "--out", filepath.Join(work, "out5"), "--nuclei-templates", tpls, "--nuclei", "", "--key", keyFile)
	if err != nil || summary["templates"] != float64(31) || summary["templates_validated"] != false {
		t.Fatalf("without validation: %v %v", err, summary)
	}
}

// A day without a new feed is not a failed publish.
func TestPublishOfUnchangedBundleSucceeds(t *testing.T) {
	work := t.TempDir()
	key, _ := bundle.GenerateKey()
	keyFile := filepath.Join(work, "release-key.pem")
	_ = bundle.SavePrivate(keyFile, key)
	feed := filepath.Join(work, "feed")
	writeFiles(t, feed, map[string]string{"plugin_feed_info.inc": "PLUGIN_SET = \"202610070608\";\n", "a.nasl": "a"})
	out := filepath.Join(work, "out")
	if _, err := runBundleBuild(t, "--out", out, "--feed", feed, "--key", keyFile, "--version", "20261008T110000Z"); err != nil {
		t.Fatal(err)
	}
	var uploads, posts int
	call := func(method, path string, body io.Reader, _ map[string]string) (int, []byte, error) {
		switch {
		case method == "POST" && path == "/admin/bundles/missing":
			return 200, []byte(`{"missing":[]}`), nil // the server has every file already
		case method == "PUT":
			uploads++
			return 201, nil, nil
		case method == "POST" && path == "/admin/bundles":
			posts++
			res, _ := json.Marshal(v1.AdminPublishBundleResponse{Unchanged: true,
				AdminBundleView: v1.AdminBundleView{Version: "20261007T110000Z", FeedVersion: "202610070608", Status: v1.RolloutCanary}})
			return http.StatusOK, res, nil
		}
		return 404, nil, nil
	}
	st, body, err := publishBundleDir(call, out, 48)
	if err != nil || st != 200 || uploads != 0 || posts != 1 {
		t.Fatalf("publish: status=%d err=%v uploads=%d posts=%d", st, err, uploads, posts)
	}
	var res v1.AdminPublishBundleResponse
	if json.Unmarshal(body, &res) != nil || !res.Unchanged || res.Version != "20261007T110000Z" {
		t.Fatalf("response: %s", body)
	}
}
