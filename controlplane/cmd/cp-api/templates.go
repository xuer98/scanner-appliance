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

// templateSet is what filterTemplates put into a bundle.
type templateSet struct {
	Kept    int
	Dropped map[string]int // templates left out, by reason

	uses  map[string][]string // template → the helper files it names (slash paths below the root)
	users map[string]int      // helper file → shipped templates that name it
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
	broken, out, err := nucleiValidate(bin, dir)
	if err != nil {
		return err
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
	again, out, err := nucleiValidate(bin, dir)
	if err != nil {
		return err
	}
	if len(again) > 0 || !strings.Contains(out, "validated successfully") {
		return fmt.Errorf("templates still do not validate after removing %d: %s", len(broken), tail(out, 600))
	}
	return nil
}

// nucleiValidate returns the templates below dir that nuclei could not
// load, as slash paths below dir, and nuclei's diagnostics.
func nucleiValidate(bin, dir string) ([]string, string, error) {
	home, err := os.MkdirTemp("", "nuclei-home-")
	if err != nil {
		return nil, "", err
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
		return nil, out, fmt.Errorf("%s -validate: %w", bin, runErr)
	}
	seen := map[string]bool{}
	var broken []string
	for _, m := range templateErrRe.FindAllStringSubmatch(out, -1) {
		rel, err := filepath.Rel(dir, strings.TrimSpace(m[1]))
		if err != nil || strings.HasPrefix(rel, "..") {
			return nil, out, fmt.Errorf("%s -validate names a template outside %s: %s", bin, dir, m[1])
		}
		if rel = filepath.ToSlash(rel); !seen[rel] {
			seen[rel] = true
			broken = append(broken, rel)
		}
	}
	sort.Strings(broken)
	if runErr != nil && len(broken) == 0 {
		return nil, out, fmt.Errorf("%s -validate failed without naming a template: %v: %s", bin, runErr, tail(out, 600))
	}
	return broken, out, nil
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return s
}
