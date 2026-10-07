package bundle

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBuildDiffSignVerify(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\nPLUGIN_FEED = \"Greenbone Community Feed\";\n",
		"nasl/a.nasl":               "script_oid(1);",
		"nasl/sub/b.nasl":           "script_oid(2);",
		"configs/inventory.json":    `{"name":"inventory"}`,
		".hidden":                   "ignored",
	})
	m, err := Build(root, "v1", time.Unix(1_790_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if m.FeedVersion != "202609260530" {
		t.Fatalf("feed version %q", m.FeedVersion)
	}
	if len(m.Files) != 4 {
		t.Fatalf("files %+v", m.Files)
	}
	if m.Files[0].Path != "configs/inventory.json" || m.Files[3].Path != "nasl/sub/b.nasl" {
		t.Fatalf("not sorted: %+v", m.Files)
	}

	// Delta: change a.nasl, add c.nasl, drop b.nasl.
	writeTree(t, root, map[string]string{"nasl/a.nasl": "script_oid(1); // v2", "nasl/c.nasl": "new"})
	_ = os.Remove(filepath.Join(root, "nasl", "sub", "b.nasl"))
	m2, err := Build(root, "v2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fetch, remove := Diff(m, m2)
	var fp []string
	for _, f := range fetch {
		fp = append(fp, f.Path)
	}
	if strings.Join(fp, ",") != "nasl/a.nasl,nasl/c.nasl" {
		t.Fatalf("fetch %v", fp)
	}
	if strings.Join(remove, ",") != "nasl/sub/b.nasl" {
		t.Fatalf("remove %v", remove)
	}
	if f, r := Diff(nil, m2); len(f) != len(m2.Files) || len(r) != 0 {
		t.Fatalf("first install diff: %d fetch %d remove", len(f), len(r))
	}

	key, _ := GenerateKey()
	b, _ := EncodeManifest(m2)
	sig, err := Sign(b, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(b, sig, []*ecdsa.PublicKey{&key.PublicKey}); err != nil {
		t.Fatal(err)
	}
	other, _ := GenerateKey()
	if err := Verify(b, sig, []*ecdsa.PublicKey{&other.PublicKey}); err == nil {
		t.Fatal("wrong key verified")
	}
	if err := Verify(append(b, ' '), sig, []*ecdsa.PublicKey{&key.PublicKey}); err == nil {
		t.Fatal("tampered manifest verified")
	}
	// Rotation: old + new key in one PEM.
	pemBoth := append(EncodePublic(&other.PublicKey), EncodePublic(&key.PublicKey)...)
	if keys := ParsePublicKeys(pemBoth); len(keys) != 2 || Verify(b, sig, keys) != nil {
		t.Fatal("multi-key PEM")
	}
	dec, err := DecodeManifest(b)
	if err != nil || dec.Version != "v2" || len(dec.Files) != 4 {
		t.Fatalf("decode: %v %+v", err, dec)
	}

	// Key files round-trip.
	dir := t.TempDir()
	if err := SavePrivate(filepath.Join(dir, "k.pem"), key); err != nil {
		t.Fatal(err)
	}
	if err := SavePublic(filepath.Join(dir, "p.pem"), &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	k2, err := LoadPrivate(filepath.Join(dir, "k.pem"))
	if err != nil || !k2.Equal(key) {
		t.Fatalf("load private: %v", err)
	}
	pubs, err := LoadPublicKeys(filepath.Join(dir, "p.pem"))
	if err != nil || len(pubs) != 1 || !pubs[0].Equal(&key.PublicKey) {
		t.Fatalf("load public: %v", err)
	}
}

func TestValidate(t *testing.T) {
	bad := []Manifest{
		{Version: ""},
		{Version: "../x"},
		{Version: "v", Files: []File{{Path: "../etc/passwd", SHA256: strings.Repeat("a", 64)}}},
		{Version: "v", Files: []File{{Path: "/abs", SHA256: strings.Repeat("a", 64)}}},
		{Version: "v", Files: []File{{Path: "a", SHA256: "zz"}}},
		{Version: "v", Files: []File{{Path: "a", SHA256: strings.Repeat("a", 64)}, {Path: "a", SHA256: strings.Repeat("a", 64)}}},
		{Version: "v", Files: []File{{Path: "a\\b", SHA256: strings.Repeat("a", 64)}}},
	}
	for i, m := range bad {
		if err := m.Validate(); err == nil {
			t.Errorf("case %d accepted: %+v", i, m)
		}
	}
	good := Manifest{Version: "20260926T120000Z", Files: []File{{Path: "nasl/x.nasl", SHA256: strings.Repeat("0", 64)}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseFeedVersion(t *testing.T) {
	if v := ParseFeedVersion(strings.NewReader("# comment\nPLUGIN_SET = \"202401010000\";\n")); v != "202401010000" {
		t.Fatal(v)
	}
	if v := ParseFeedVersion(strings.NewReader("nothing")); v != "" {
		t.Fatal(v)
	}
}

// The content digest names the files and nothing else: the daily build
// publishes only when it differs from the newest bundle's.
func TestContentDigest(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n", "nasl/a.nasl": "a", "configs/inventory.json": "{}"})
	monday, err := Build(root, "20260928T110000Z", time.Unix(1_790_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	// The next day's build of the same tree: another name, another time.
	tuesday, _ := Build(root, "20260929T110000Z", time.Unix(1_790_086_400, 0))
	if monday.ContentDigest() != tuesday.ContentDigest() || len(monday.ContentDigest()) != 64 {
		t.Fatalf("same files, digests %s and %s", monday.ContentDigest(), tuesday.ContentDigest())
	}
	mb, _ := EncodeManifest(monday)
	tb, _ := EncodeManifest(tuesday)
	if SHA256Hex(mb) == SHA256Hex(tb) {
		t.Fatal("the two manifests should differ in version and time")
	}
	// The order of the list does not matter.
	rev := &Manifest{Version: "x", Files: append([]File(nil), monday.Files...)}
	rev.Files[0], rev.Files[len(rev.Files)-1] = rev.Files[len(rev.Files)-1], rev.Files[0]
	if rev.ContentDigest() != monday.ContentDigest() {
		t.Fatal("digest depends on the order of the file list")
	}
	// Any difference in the files does: content, a new file, a removed
	// file, a file that moved.
	for name, files := range map[string]map[string]string{
		"changed": {"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n", "nasl/a.nasl": "b", "configs/inventory.json": "{}"},
		"added":   {"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n", "nasl/a.nasl": "a", "configs/inventory.json": "{}", "nasl/new.nasl": "n"},
		"removed": {"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n", "nasl/a.nasl": "a"},
		"moved":   {"nasl/plugin_feed_info.inc": "PLUGIN_SET = \"202609260530\";\n", "nasl/a.nasl": "a", "configs/full.json": "{}"},
	} {
		dir := t.TempDir()
		writeTree(t, dir, files)
		m, err := Build(dir, "20260928T110000Z", time.Unix(1_790_000_000, 0))
		if err != nil {
			t.Fatal(err)
		}
		if m.ContentDigest() == monday.ContentDigest() {
			t.Fatalf("%s: digest did not change", name)
		}
	}
}
