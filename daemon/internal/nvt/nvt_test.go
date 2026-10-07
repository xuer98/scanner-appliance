package nvt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tprm/scanner-appliance/daemon/internal/osp"
)

func TestCVSS(t *testing.T) {
	cases := map[string]float64{
		"AV:N/AC:L/Au:N/C:C/I:C/A:C": 10.0, // CVE-2019-0708 v2
		"AV:N/AC:L/Au:N/C:P/I:P/A:P": 7.5,
		"AV:N/AC:M/Au:N/C:N/I:P/A:N": 4.3,
		"AV:L/AC:H/Au:M/C:N/I:N/A:N": 0,
		"garbage":                    0,
	}
	for v, want := range cases {
		if got := ScoreV2(v); got != want {
			t.Fatalf("v2 %s: got %v want %v", v, got, want)
		}
	}
	cases3 := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 5.4,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases3 {
		if got := ScoreV3(v); got != want {
			t.Fatalf("v3 %s: got %v want %v", v, got, want)
		}
	}
	if Score("", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 2) != 7.5 || Score("", "", 2.5) != 2.5 {
		t.Fatal("Score preference")
	}
}

type fakeSrc struct {
	vts   map[string]*osp.VT
	calls int
	fail  bool
}

func (f *fakeSrc) GetVT(_ context.Context, oid string) (*osp.VT, error) {
	f.calls++
	if f.fail {
		return nil, errors.New("ospd down")
	}
	return f.vts[oid], nil
}

func TestCacheLookup(t *testing.T) {
	src := &fakeSrc{vts: map[string]*osp.VT{
		"1.1": {OID: "1.1", Name: "A", Family: "Windows", CVEs: []string{"CVE-2019-0708"}, QoD: 97, CVSSv2Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
	}}
	dir := t.TempDir()
	c := New(dir, src, nil)
	m, err := c.Lookup(context.Background(), "202609260530", []string{"1.1", "9.9", "1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if m["1.1"].CVSS != 10 || m["1.1"].Family != "Windows" || !m["9.9"].Missing || src.calls != 2 {
		t.Fatalf("%+v calls=%d", m["1.1"], src.calls)
	}
	// Second cache instance reads from disk; no source calls.
	c2 := New(dir, src, nil)
	m2, _ := c2.Lookup(context.Background(), "202609260530", []string{"1.1", "9.9"})
	if src.calls != 2 || m2["1.1"].Name != "A" {
		t.Fatalf("not cached: calls=%d", src.calls)
	}
	// New feed version → refetch; source failure surfaces but keeps going.
	src.fail = true
	if _, err := c2.Lookup(context.Background(), "202610010000", []string{"1.1"}); err == nil {
		t.Fatal("expected error")
	}
	if got := UniqueOIDs([]string{"b", "a", "", "b"}); len(got) != 2 || got[0] != "a" {
		t.Fatal(got)
	}
}

// bulkSrc is a source that can also do one pass over the feed.
type bulkSrc struct {
	fakeSrc
	passes  int
	failAt  int // stop the pass after this many VTs (0 = complete)
	lastAsk []string
}

func (b *bulkSrc) GetVTs(_ context.Context, oids []string) (map[string]*osp.VT, error) {
	b.passes++
	b.lastAsk = oids
	out := map[string]*osp.VT{}
	for _, oid := range oids {
		if vt := b.vts[oid]; vt != nil {
			if b.failAt > 0 && len(out) == b.failAt {
				return out, errors.New("stream cut")
			}
			out[oid] = vt
		}
	}
	return out, nil
}

func TestCacheLookupBulk(t *testing.T) {
	src := &bulkSrc{fakeSrc: fakeSrc{vts: map[string]*osp.VT{}}}
	var oids []string
	for i := 0; i < 10; i++ {
		oid := fmt.Sprintf("1.%d", i)
		oids = append(oids, oid)
		src.vts[oid] = &osp.VT{OID: oid, Name: "vt " + oid, Family: "Web Servers", QoD: 30, CVSSBase: 7.5}
	}
	c := New(t.TempDir(), src, nil)

	// Below the threshold: single lookups, no pass.
	few := oids[:bulkMin-1]
	if m, err := c.Lookup(context.Background(), "v1", few); err != nil || len(m) != len(few) || src.calls != len(few) || src.passes != 0 {
		t.Fatalf("few: len=%d calls=%d passes=%d err=%v", len(m), src.calls, src.passes, err)
	}

	// A new feed version empties the cache. From the threshold on: one pass
	// that asks only for the misses, each once, and marks the unknown ones.
	ask := append(append([]string{"9.9"}, oids...), oids[0], "9.8")
	m, err := c.Lookup(context.Background(), "v2", ask)
	if err != nil || src.passes != 1 || src.calls != len(few) {
		t.Fatalf("bulk: calls=%d passes=%d err=%v", src.calls, src.passes, err)
	}
	if len(src.lastAsk) != 12 || len(m) != 12 || !m["9.9"].Missing || !m["9.8"].Missing || m["1.3"].Missing || m["1.3"].Name != "vt 1.3" || m["1.3"].CVSS != 7.5 || m["1.3"].CVEs == nil {
		t.Fatalf("bulk result: asked=%d got=%d %+v", len(src.lastAsk), len(m), m["1.3"])
	}
	// Everything is cached now, on disk too: no further source use.
	c2 := New(c.Dir, src, nil)
	if m2, err := c2.Lookup(context.Background(), "v2", ask); err != nil || len(m2) != 12 || src.passes != 1 || src.calls != len(few) || !m2["9.9"].Missing {
		t.Fatalf("not cached: passes=%d calls=%d err=%v", src.passes, src.calls, err)
	}

	// A pass that breaks off keeps what it read, reports the error, and
	// leaves the rest unknown rather than marked missing.
	src.failAt = 3
	m3, err := c2.Lookup(context.Background(), "v3", ask)
	if err == nil || len(m3) != 3 {
		t.Fatalf("cut pass: got=%d err=%v", len(m3), err)
	}
	for _, e := range m3 {
		if e.Missing {
			t.Fatalf("an OID was marked missing after a cut pass: %+v", e)
		}
	}
	// The next lookup fetches only what is still unknown.
	src.failAt = 0
	if m4, err := c2.Lookup(context.Background(), "v3", ask); err != nil || len(m4) != 12 || len(src.lastAsk) != 9 || !m4["9.8"].Missing {
		t.Fatalf("retry: got=%d asked=%d err=%v", len(m4), len(src.lastAsk), err)
	}
}

// One cache file per feed version would pile up, a file a day: the lab
// appliance held six after one day of updates. Only the current one is kept.
func TestCacheKeepsOneFeedVersion(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSrc{vts: map[string]*osp.VT{"1.1": {OID: "1.1", Name: "A"}}}
	c := New(dir, src, nil)
	for _, feed := range []string{"202610050609", "202610050616", "202610060600"} {
		if _, err := c.Lookup(context.Background(), feed, []string{"1.1"}); err != nil {
			t.Fatal(err)
		}
	}
	// Something else in the directory is none of the cache's business.
	other := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lookup(context.Background(), "202610070600", []string{"1.1"}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "nvt-*"))
	if len(files) != 1 || filepath.Base(files[0]) != "nvt-202610070600.json" {
		t.Fatalf("cache files: %v", files)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("unrelated file removed: %v", err)
	}
	// The kept file still serves: a new cache on the same directory needs no fetch.
	before := src.calls
	if m, err := New(dir, src, nil).Lookup(context.Background(), "202610070600", []string{"1.1"}); err != nil || m["1.1"].Name != "A" || src.calls != before {
		t.Fatalf("reload: %v %v calls %d→%d", m, err, before, src.calls)
	}
}
