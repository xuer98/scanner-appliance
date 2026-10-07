package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Flags after the positional arguments were dropped without a word, so a
// documented command ran with its defaults.
func TestParseInterleaved(t *testing.T) {
	for _, c := range []struct {
		args, rest, reason, filter string
		codify                     bool
	}{
		{"bundle 20261006T000000Z held --reason lab", "bundle 20261006T000000Z held", "lab", "", false},
		{"--reason lab bundle 20261006T000000Z held", "bundle 20261006T000000Z held", "lab", "", false},
		{"site_1 findings --status-filter fixed", "site_1 findings", "", "fixed", false},
		{"fnd_1 --reason=dup --codify --status-filter open extra", "fnd_1 extra", "dup", "open", true},
		{"site_1", "site_1", "", "", false},
		{"", "", "", "", false},
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		reason := fs.String("reason", "", "")
		filter := fs.String("status-filter", "", "")
		codify := fs.Bool("codify", false, "")
		rest, err := parseInterleaved(fs, strings.Fields(c.args))
		if err != nil {
			t.Fatalf("%q: %v", c.args, err)
		}
		if strings.Join(rest, " ") != c.rest || *reason != c.reason || *filter != c.filter || *codify != c.codify {
			t.Fatalf("%q: rest=%v reason=%q filter=%q codify=%v", c.args, rest, *reason, *filter, *codify)
		}
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if _, err := parseInterleaved(fs, []string{"site_1", "--no-such-flag"}); err == nil {
		t.Fatal("an unknown flag after a positional argument was accepted")
	}
}

// The publish commands send megabytes in one request; everything else
// keeps the short limit.
func TestAdminTimeout(t *testing.T) {
	for sub, long := range map[string]bool{"publish-bundle": true, "publish-release": true, "bundles": false, "create-job": false, "": false} {
		if got := adminTimeout(sub); (got >= 10*time.Minute) != long || got < 30*time.Second {
			t.Fatalf("%q: timeout %s", sub, got)
		}
	}
}

// The web add-on promises HTTP checks against the target. With the real
// template set (v10.5.0) the old filter also kept templates that carry a
// tcp or javascript section next to the http one, DAST fuzzers and
// templates that call third-party services.
func TestFilterTemplates(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const get = "  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
	write("http/keep.yaml", "id: keep\ninfo:\n  name: n\n  severity: high\n  tags: cve,panel\nvariables:\n  a: b\nflow: http(1)\nhttp:\n"+get)
	write("http/legacy.yaml", "id: legacy\ninfo:\n  severity: medium\nrequests:\n"+get)
	write("http/intrusive.yaml", "id: intrusive\ninfo:\n  tags:\n    - cve\n    - Intrusive\nhttp:\n"+get)
	write("network/mixed.yaml", "id: mixed\ninfo:\n  tags: cve\nhttp:\n"+get+"tcp:\n  - host:\n      - \"{{Hostname}}\"\n")
	write("javascript/mixed.yaml", "id: js\ninfo:\n  tags: cve\njavascript:\n  - code: \"1\"\nhttp:\n"+get)
	write("dast/fuzzer.yaml", "id: fuzzer\ninfo:\n  tags: dast\nhttp:\n  - pre-condition:\n      - type: dsl\n    fuzzing:\n      - part: query\n")
	write("http/osint.yaml", "id: osint\ninfo:\n  tags: osint\nself-contained: true\nhttp:\n"+get)
	write("http/future.yaml", "id: future\ninfo:\n  tags: cve\nhttp:\n"+get+"quic:\n  - x: y\n")
	write("dns/only.yaml", "id: dnsonly\ninfo:\n  tags: dns\ndns:\n  - name: \"{{FQDN}}\"\n")
	write("http/broken.yaml", "id: [\n")
	write("README.md", "not a template")
	write(".github/workflow.yaml", "id: hidden\nhttp:\n"+get)

	set, err := filterTemplates(src, dst, []string{"dos", "fuzz", "intrusive"})
	if err != nil {
		t.Fatal(err)
	}
	kept, dropped := set.Kept, set.Dropped
	if kept != 2 {
		t.Fatalf("kept %d templates, want keep.yaml and legacy.yaml", kept)
	}
	for _, rel := range []string{"http/keep.yaml", "http/legacy.yaml"} {
		if _, err := os.Stat(filepath.Join(dst, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("%s was not shipped", rel)
		}
	}
	want := map[string]int{"excluded_tag": 1, "other_protocol": 3, "fuzzing": 1, "self_contained": 1, "not_http": 2}
	for why, n := range want {
		if dropped[why] != n {
			t.Fatalf("dropped[%s] = %d, want %d (all: %v)", why, dropped[why], n, dropped)
		}
	}
	if len(dropped) != len(want) {
		t.Fatalf("unexpected drop reasons: %v", dropped)
	}
	var shipped int
	_ = filepath.WalkDir(dst, func(_ string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			shipped++
		}
		return nil
	})
	if shipped != kept {
		t.Fatalf("%d files in the bundle, %d counted as kept", shipped, kept)
	}
}
