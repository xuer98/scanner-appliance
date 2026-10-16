package main

// The nuclei templates of a bundle, beyond the filter in ops.go: the helper
// files they name, and a check with the appliance's own nuclei that each
// one loads.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// templateSet is what filterTemplates and addExtraTemplates put into a bundle.
type templateSet struct {
	Kept    int
	Dropped map[string]int // templates left out, by reason

	uses   map[string][]string // template → the helper files it names (slash paths below the root)
	users  map[string]int      // helper file → shipped templates that name it
	ids    map[string]string   // template id → the first shipped template that carries it
	strict map[string]bool     // our own templates: one that does not load stops the build
}

func newTemplateSet() *templateSet {
	return &templateSet{Dropped: map[string]int{}, uses: map[string][]string{}, users: map[string]int{}, ids: map[string]string{}, strict: map[string]bool{}}
}

// extraTemplatesDir is where our own templates sit inside the bundle's
// template tree. nuclei finds a helper file named from the root of our
// directory through this parent of the template (checked with v3.4.10).
const extraTemplatesDir = "custom"

// dropReasons says, for the author of one of our templates, what the
// reasons of templateCheck mean.
var dropReasons = map[string]string{
	"not_http":       "no id, or no http section",
	"other_protocol": "a section other than http (tcp, dns, javascript, code, headless, ...): the web add-on speaks HTTP to the target only",
	"self_contained": "self-contained: it would call a third party, not the target",
	"fuzzing":        "a fuzzer",
	"excluded_tag":   "an excluded tag",
}

// addExtraTemplates ships the templates below src under dst/custom/ by the
// rules of filterTemplates, but where that filter drops a template this
// stops the build and says why: these templates are ours, written for
// this bundle, and a drop would be a mistake nobody sees. An id must not
// repeat, nor be one of the pinned set's, since nuclei keeps one template
// per id. A helper file must not sit where the pinned set has a file,
// since nuclei looks below the root first. The count is the templates
// shipped.
func addExtraTemplates(src, dst string, set *templateSet, exclude []string) (int, error) {
	ex := map[string]bool{}
	for _, e := range exclude {
		ex[strings.ToLower(strings.TrimSpace(e))] = true
	}
	if _, err := os.Lstat(filepath.Join(dst, extraTemplatesDir)); err == nil {
		return 0, fmt.Errorf("the pinned set ships files under %s/, where ours go", extraTemplatesDir)
	}
	n := 0
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
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
		rel, _ := filepath.Rel(src, p)
		rel = filepath.ToSlash(rel)
		id, why := templateCheck(b, ex)
		if why == "excluded_tag" {
			return fmt.Errorf("%s: %s (%s)", rel, dropReasons[why], strings.Join(exclude, ", "))
		}
		if why != "" {
			return fmt.Errorf("%s: %s", rel, dropReasons[why])
		}
		if prev, dup := set.ids[id]; dup {
			return fmt.Errorf("%s: id %q is also the id of %s", rel, id, prev)
		}
		target := path.Join(extraTemplatesDir, rel)
		var helpers []string
		for _, ref := range templateHelpers(b) {
			h, ok := resolveHelper(src, rel, ref)
			if !ok {
				return fmt.Errorf("%s: names %s, which is not a regular file below %s", rel, ref, src)
			}
			// nuclei tries the name below the root of the tree before the
			// template's own directory and its parents.
			if _, err := os.Lstat(filepath.Join(dst, filepath.FromSlash(ref))); err == nil {
				return fmt.Errorf("%s: names %s, which the pinned set also has at %s/%s: nuclei would open that one", rel, ref, filepath.Base(dst), ref)
			}
			helpers = append(helpers, path.Join(extraTemplatesDir, h))
		}
		for _, h := range helpers {
			if set.users[h] == 0 {
				srcRel := strings.TrimPrefix(h, extraTemplatesDir+"/")
				if err := copyInto(filepath.Join(src, filepath.FromSlash(srcRel)), filepath.Join(dst, filepath.FromSlash(h))); err != nil {
					return err
				}
			}
			set.users[h]++
		}
		full := filepath.Join(dst, filepath.FromSlash(target))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			return err
		}
		set.uses[target] = helpers
		set.ids[id] = target
		set.strict[target] = true
		set.Kept++
		n++
		return nil
	})
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("no templates (*.yaml) below %s", src)
	}
	return n, nil
}

// Helpers is the number of helper files shipped.
func (s *templateSet) Helpers() int {
	n := 0
	for _, c := range s.users {
		if c > 0 {
			n++
		}
	}
	return n
}

// templateHelpers lists the helper files a template names. A request's
// payloads map a name to a list of values or to one line of text, and one
// line of text is a file to nuclei: a list of plugin versions, of ids or of
// paths to try.
func templateHelpers(b []byte) []string {
	var t struct {
		HTTP     []map[string]any `yaml:"http"`
		Requests []map[string]any `yaml:"requests"`
	}
	if yaml.Unmarshal(b, &t) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, req := range append(t.HTTP, t.Requests...) {
		payloads, _ := req["payloads"].(map[string]any)
		for _, v := range payloads {
			s, ok := v.(string)
			if !ok || strings.Contains(s, "\n") {
				continue // a list, or lines of text: the values themselves
			}
			if s = strings.TrimSpace(s); s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// resolveHelper finds the file a template names the way nuclei does: below
// the root of the templates, then next to the template and in each
// directory above it. It returns the slash path below root. A name that
// leaves the tree, or that a link takes out of it, is not found: the file
// would be read on the build host and shipped to every appliance.
func resolveHelper(root, template, ref string) (string, bool) {
	ref = filepath.ToSlash(ref)
	if path.IsAbs(ref) || strings.Contains(ref, "\\") {
		return "", false
	}
	for _, seg := range strings.Split(ref, "/") {
		if seg == ".." {
			return "", false
		}
	}
	dirs := []string{"."}
	for d := path.Dir(template); d != "." && d != "/"; d = path.Dir(d) {
		dirs = append(dirs, d)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	for _, d := range dirs {
		rel := path.Join(d, ref)
		full := filepath.Join(root, filepath.FromSlash(rel))
		fi, err := os.Lstat(full)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		real, err := filepath.EvalSymlinks(full)
		if err != nil || !strings.HasPrefix(real, realRoot+string(filepath.Separator)) {
			continue
		}
		return rel, true
	}
	return "", false
}

func copyInto(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return copyPath(src, dst)
}

// maxTemplateLoss is the share of the templates that validation may remove
// before the build stops. A handful of templates written for a newer nuclei
// is normal. More means the wrong nuclei for these templates, and a bundle
// without them would make every appliance call their findings fixed.
const maxTemplateLoss = 0.05

var templateErrRe = regexp.MustCompile(`(?m)^\[ERR\] Error occurred (?:parsing|loading) template (.+?): (.*)$`)

// validateTemplates runs `nuclei -validate` over the templates in dir, the
// way the appliance runs them, and removes the ones that do not load: the
// appliance would skip them with one line on stderr. It needs the nuclei
// version the appliance image carries, since what loads depends on it. A
// second run has to pass, so a nuclei whose output this does not
// understand stops the build instead of going unnoticed.
func validateTemplates(bin, dir string, set *templateSet) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	broken, why, out, err := nucleiValidate(bin, dir)
	if err != nil {
		return err
	}
	for _, rel := range broken {
		if set.strict[rel] {
			return fmt.Errorf("our template %s does not load with %s: %s", rel, bin, why[rel])
		}
	}
	if len(broken) == 0 {
		if !strings.Contains(out, "validated successfully") {
			return fmt.Errorf("%s -validate did not report success: %s", bin, tail(out, 600))
		}
		return nil
	}
	if float64(len(broken)) > maxTemplateLoss*float64(set.Kept) {
		return fmt.Errorf("%d of %d templates do not load with %s, more than %.0f%%: is it the nuclei version of the appliance image? first: %s",
			len(broken), set.Kept, bin, maxTemplateLoss*100, broken[0])
	}
	for _, rel := range broken {
		if _, ok := set.uses[rel]; !ok {
			return fmt.Errorf("%s -validate names %s, which is not a shipped template", bin, rel)
		}
		if err := os.Remove(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			return err
		}
		// A helper file only the removed templates used goes with them.
		for _, h := range set.uses[rel] {
			if set.users[h]--; set.users[h] == 0 {
				if err := os.Remove(filepath.Join(dir, filepath.FromSlash(h))); err != nil {
					return err
				}
			}
		}
		delete(set.uses, rel)
		set.Kept--
		set.Dropped["does_not_load"]++
	}
	fmt.Fprintf(os.Stderr, "[bundle] %d templates do not load with %s and are left out, first: %s\n", len(broken), bin, broken[0])
	again, _, out, err := nucleiValidate(bin, dir)
	if err != nil {
		return err
	}
	if len(again) > 0 || !strings.Contains(out, "validated successfully") {
		return fmt.Errorf("templates still do not validate after removing %d: %s", len(broken), tail(out, 600))
	}
	return nil
}

// nucleiValidate returns the templates below dir that nuclei could not
// load, as slash paths below dir, what it said about each, and its whole
// output.
func nucleiValidate(bin, dir string) ([]string, map[string]string, string, error) {
	home, err := os.MkdirTemp("", "nuclei-home-")
	if err != nil {
		return nil, nil, "", err
	}
	defer os.RemoveAll(home)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	// -update-template-dir makes dir nuclei's own template directory, the
	// only place it opens helper files from; the appliance runs it the same
	// way (daemon/internal/engine/web.go).
	cmd := exec.CommandContext(ctx, bin, "-validate", "-no-color", "-disable-update-check", "-templates", dir, "-update-template-dir", dir)
	// A home of its own: nuclei keeps settings there, among them the
	// template directory of an earlier run.
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "XDG_CACHE_HOME="+filepath.Join(home, ".cache"),
		"NO_COLOR=1", "DISABLE_UPDATE_CHECK=1")
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	runErr := cmd.Run()
	out := buf.String()
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		return nil, nil, out, fmt.Errorf("%s -validate: %w", bin, runErr)
	}
	why := map[string]string{}
	var broken []string
	for _, m := range templateErrRe.FindAllStringSubmatch(out, -1) {
		rel, err := filepath.Rel(dir, strings.TrimSpace(m[1]))
		if err != nil || strings.HasPrefix(rel, "..") {
			return nil, nil, out, fmt.Errorf("%s -validate names a template outside %s: %s", bin, dir, m[1])
		}
		if rel = filepath.ToSlash(rel); why[rel] == "" {
			why[rel] = strings.TrimSpace(m[2])
			broken = append(broken, rel)
		}
	}
	sort.Strings(broken)
	if runErr != nil && len(broken) == 0 {
		return nil, nil, out, fmt.Errorf("%s -validate failed without naming a template: %v: %s", bin, runErr, tail(out, 600))
	}
	return broken, why, out, nil
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return s
}
